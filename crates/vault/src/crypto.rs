//! Vault cryptography — key derivation, per-value AEAD, and blind indexing.
//!
//! # Why per-value encryption instead of SQLCipher
//!
//! SQLCipher encrypts the whole file, which is strictly better at hiding
//! metadata. It also needs a C toolchain with Perl and NASM on every developer
//! machine and CI runner (see `decision D-9`). This module gets pure-Rust
//! confidentiality for the values that matter, at a stated cost in metadata.
//!
//! # What is encrypted, and what is not
//!
//! | Encrypted | Plaintext | Why |
//! |---|---|---|
//! | `real_name`, `scope_path`, file paths, dictionary terms | | The mapping *is* the secret |
//! | | `alias`, `uuid`, `entity_type`, `origin`, `status` | Already sent to the model by design |
//! | | row counts, table shape, byte offsets | Cost of using SQL as the engine |
//!
//! **Stated leak:** an attacker holding the file learns how many identities the
//! project has and of what types, but not a single name. That is the D-9
//! trade-off, and it must be in the security one-pager rather than discovered.
//!
//! # Two mechanisms that are easy to get wrong
//!
//! **Blind index.** Encrypted columns cannot carry a `UNIQUE` constraint or be
//! looked up by equality — AES-GCM is randomized, so the same name encrypts
//! differently every time. Each searchable column therefore also stores
//! `HMAC(index_key, normalized_value)`, which is deterministic, unique-indexable,
//! and reveals nothing without the key.
//!
//! **Associated data.** Every value is sealed with AAD naming its table, column,
//! and row. Without it, an attacker could move a ciphertext from one row to
//! another — swapping two identities' real names while every authentication tag
//! still verified.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::VaultError;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 12;
pub(crate) const SALT_LEN: usize = 16;

/// Domain separation for the derived subkeys. Reusing one key for both
/// encryption and indexing would let the index leak information about the
/// encryption key.
const ENC_CONTEXT: &[u8] = b"specshield:enc:v1";
const INDEX_CONTEXT: &[u8] = b"specshield:index:v1";

/// Derived key material for one open vault.
#[derive(ZeroizeOnDrop)]
pub(crate) struct Keys {
    enc: [u8; 32],
    index: [u8; 32],
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys(<redacted>)")
    }
}

impl Keys {
    /// Argon2id over the passphrase, then two domain-separated subkeys.
    pub(crate) fn derive(passphrase: &str, salt: &[u8]) -> Result<Self, VaultError> {
        let mut master = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut master)
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

        let keys = Self {
            enc: subkey(&master, ENC_CONTEXT),
            index: subkey(&master, INDEX_CONTEXT),
        };
        master.zeroize();
        Ok(keys)
    }

    /// Encrypt a value, binding it to where it lives.
    pub(crate) fn seal(&self, value: &str, aad: &str) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        crate::random_bytes(&mut nonce)?;

        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(self.enc));
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: value.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| VaultError::Decryption)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a value. Fails if the ciphertext, the AAD, or the key is wrong —
    /// the three are indistinguishable by design.
    pub(crate) fn unseal(&self, blob: &[u8], aad: &str) -> Result<String, VaultError> {
        if blob.len() <= NONCE_LEN {
            return Err(VaultError::Corrupt);
        }
        let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| VaultError::Corrupt)?;

        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(self.enc));
        let plaintext = cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| VaultError::Decryption)?;

        String::from_utf8(plaintext).map_err(|_| VaultError::Corrupt)
    }

    /// Deterministic searchable digest of a value.
    ///
    /// Case-sensitive on purpose: `Status` and `status` are different
    /// identifiers, and folding them here would silently merge two identities.
    pub(crate) fn blind_index(&self, value: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.index).expect("HMAC accepts any key length");
        mac.update(value.as_bytes());
        hex(&mac.finalize().into_bytes())
    }
}

fn subkey(master: &[u8; 32], context: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(master).expect("HMAC accepts any key length");
    mac.update(context);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        Keys::derive("passphrase", &[7u8; SALT_LEN]).unwrap()
    }

    #[test]
    fn seal_and_unseal_round_trip() {
        let k = keys();
        let blob = k.seal("CustomerSubscription", "identities:real_name:abc").unwrap();
        assert_eq!(
            k.unseal(&blob, "identities:real_name:abc").unwrap(),
            "CustomerSubscription"
        );
    }

    #[test]
    fn ciphertext_never_contains_the_plaintext() {
        let k = keys();
        let blob = k.seal("Vantor", "identities:real_name:abc").unwrap();
        assert!(
            !blob.windows(6).any(|w| w == b"Vantor"),
            "plaintext survived into the ciphertext"
        );
    }

    #[test]
    fn the_same_value_encrypts_differently_every_time() {
        // Randomized AEAD. This is why equality lookups need a blind index.
        let k = keys();
        let a = k.seal("Vantor", "identities:real_name:abc").unwrap();
        let b = k.seal("Vantor", "identities:real_name:abc").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_ciphertext_cannot_be_moved_to_another_row() {
        // Without AAD binding, an attacker could swap two identities' names
        // and every authentication tag would still verify.
        let k = keys();
        let blob = k.seal("Vantor", "identities:real_name:row-1").unwrap();
        assert!(matches!(
            k.unseal(&blob, "identities:real_name:row-2"),
            Err(VaultError::Decryption)
        ));
    }

    #[test]
    fn a_ciphertext_cannot_be_moved_to_another_column() {
        let k = keys();
        let blob = k.seal("Vantor", "identities:real_name:row-1").unwrap();
        assert!(matches!(
            k.unseal(&blob, "identities:scope_path:row-1"),
            Err(VaultError::Decryption)
        ));
    }

    #[test]
    fn tampering_is_detected() {
        let k = keys();
        let mut blob = k.seal("Vantor", "aad").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(matches!(k.unseal(&blob, "aad"), Err(VaultError::Decryption)));
    }

    #[test]
    fn a_different_passphrase_cannot_read_it() {
        let blob = keys().seal("Vantor", "aad").unwrap();
        let other = Keys::derive("wrong", &[7u8; SALT_LEN]).unwrap();
        assert!(matches!(other.unseal(&blob, "aad"), Err(VaultError::Decryption)));
    }

    #[test]
    fn blind_index_is_deterministic_and_key_dependent() {
        let a = keys().blind_index("Vantor");
        assert_eq!(a, keys().blind_index("Vantor"));
        assert_ne!(a, keys().blind_index("Paylane"));

        let other = Keys::derive("other", &[7u8; SALT_LEN]).unwrap();
        assert_ne!(a, other.blind_index("Vantor"), "index must not be key-independent");
    }

    #[test]
    fn blind_index_is_case_sensitive() {
        // Folding case here would merge `Status` and `status` into one identity.
        let k = keys();
        assert_ne!(k.blind_index("Status"), k.blind_index("status"));
    }

    #[test]
    fn blind_index_reveals_nothing_readable() {
        let index = keys().blind_index("CustomerSubscription");
        assert_eq!(index.len(), 64);
        assert!(!index.contains("ustomer"));
    }

    #[test]
    fn encryption_and_index_keys_are_independent() {
        let k = keys();
        assert_ne!(k.enc, k.index, "subkeys must be domain-separated");
    }
}
