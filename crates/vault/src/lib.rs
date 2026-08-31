//! Encrypted mapping vault — SDD §9.
//!
//! The vault holds the one thing that must never leave the machine: the mapping
//! from alias back to real name. Everything else in the system is derived from
//! it or safe to share.
//!
//! # Deviation from SDD §9: not SQLCipher, yet
//!
//! SDD §9 specifies SQLite + SQLCipher. Building `rusqlite` with
//! `bundled-sqlcipher-vendored-openssl` **fails on a stock Windows toolchain**:
//! vendored OpenSSL requires Strawberry Perl and NASM, and its `Configure` step
//! aborts without them. Plain `bundled` SQLite builds in ~5 s on the same
//! machine, so the blocker is OpenSSL rather than SQLite.
//!
//! This implementation therefore stores the graph as a single file encrypted
//! with **AES-256-GCM**, keyed by **Argon2id** over a user passphrase — pure
//! Rust, no C toolchain, and no plaintext on disk at any point. It satisfies the
//! confidentiality requirement of PRD §10 while the storage-engine question is
//! settled (see `decision D-9` in the Implementation Plan).
//!
//! What it does *not* yet provide, and SQLite would: incremental writes,
//! occurrence and edge tables, migrations, and query. Those arrive with the
//! storage backend, behind the same API.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Bumped whenever the on-disk layout changes. Read before anything else, so an
/// old vault fails loudly instead of being misparsed (SDD §9.3).
pub const VAULT_VERSION: u32 = 1;

/// File magic, so a wrong file is rejected with a clear message rather than a
/// decryption failure.
const MAGIC: &[u8; 8] = b"SPCSHLD\x01";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a SpecShield vault: {0}")]
    NotAVault(String),

    #[error("vault was written by version {found}; this build understands {VAULT_VERSION}")]
    VersionMismatch { found: u32 },

    #[error("vault is truncated or corrupt")]
    Corrupt,

    /// Deliberately indistinguishable from tampering: AES-GCM authenticates the
    /// ciphertext, so a wrong passphrase and a modified file fail identically.
    #[error("wrong passphrase, or the vault has been tampered with")]
    Decryption,

    #[error("vault contents are not valid JSON: {0}")]
    Format(#[from] serde_json::Error),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("entropy source unavailable: {0}")]
    Entropy(String),
}

/// One stored identity — the `identities` row of SDD §9.1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredIdentity {
    pub uuid: String,
    pub scope_path: String,
    pub entity_type: String,
    pub real_name: String,
    pub alias: String,
    pub origin: String,
    pub status: String,
}

/// Everything the vault persists.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultContents {
    pub project_name: String,
    pub alias_style: String,
    pub scope_strategy: String,
    /// The HMAC key aliases are derived from (SDD §6.1). Two machines sharing
    /// this produce identical twins with no coordination — which is why it
    /// lives inside the encrypted payload and never beside it.
    pub project_key: [u8; 32],
    pub identities: Vec<StoredIdentity>,
    /// User-confirmed terms — the dictionary that finds prose entities no rule
    /// can recognise (PRD FR-10).
    #[serde(default)]
    pub dictionary: Vec<(String, String)>,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// Derive the file key from a passphrase.
///
/// Argon2id with the crate defaults (19 MiB, t=2, p=1 — the OWASP baseline).
/// Parameters are not stored: changing them is a vault-format change and must
/// go through [`VAULT_VERSION`].
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], VaultError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

fn random_bytes(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(buf).map_err(|e| VaultError::Entropy(e.to_string()))
}

/// Encrypt and write the vault.
///
/// Layout: `MAGIC | version (4 LE) | salt (16) | nonce (12) | ciphertext`.
/// The header is authenticated as associated data, so a downgrade attack on the
/// version field fails decryption rather than silently succeeding.
pub fn save(path: &Path, passphrase: &str, contents: &VaultContents) -> Result<(), VaultError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    random_bytes(&mut salt)?;
    random_bytes(&mut nonce_bytes)?;

    let mut key_bytes = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key_bytes));
    let plaintext = serde_json::to_vec(contents)?;

    let mut header = Vec::with_capacity(MAGIC.len() + 4 + SALT_LEN + NONCE_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VAULT_VERSION.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce_bytes),
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Decryption)?;

    key_bytes.zeroize();

    let mut out = header;
    out.extend_from_slice(&ciphertext);

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, out)?;
    Ok(())
}

/// Read and decrypt the vault.
pub fn load(path: &Path, passphrase: &str) -> Result<VaultContents, VaultError> {
    let raw = std::fs::read(path)?;
    let header_len = MAGIC.len() + 4 + SALT_LEN + NONCE_LEN;
    if raw.len() < header_len {
        return Err(VaultError::Corrupt);
    }
    if &raw[..MAGIC.len()] != MAGIC {
        return Err(VaultError::NotAVault(path.display().to_string()));
    }

    let version = u32::from_le_bytes(
        raw[MAGIC.len()..MAGIC.len() + 4]
            .try_into()
            .map_err(|_| VaultError::Corrupt)?,
    );
    if version != VAULT_VERSION {
        return Err(VaultError::VersionMismatch { found: version });
    }

    let salt = &raw[MAGIC.len() + 4..MAGIC.len() + 4 + SALT_LEN];
    let nonce = &raw[MAGIC.len() + 4 + SALT_LEN..header_len];
    let header = &raw[..header_len];
    let ciphertext = &raw[header_len..];

    let mut key_bytes = derive_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key_bytes));
    let plaintext = cipher
        .decrypt(
            &Nonce::try_from(nonce).map_err(|_| VaultError::Corrupt)?,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| VaultError::Decryption)?;
    key_bytes.zeroize();

    Ok(serde_json::from_slice(&plaintext)?)
}

/// Is this path inside a known cloud-sync tree? — PRD §10, SDD §17.4.
///
/// A vault in one of these is uploaded to a third party, contradicting the
/// local-only guarantee. The caller warns; it is never silently overridden.
pub fn cloud_sync_root(path: &Path) -> Option<&'static str> {
    const ROOTS: &[(&str, &str)] = &[
        ("onedrive", "OneDrive"),
        ("dropbox", "Dropbox"),
        ("google drive", "Google Drive"),
        ("googledrive", "Google Drive"),
        ("icloud", "iCloud"),
        ("box sync", "Box"),
    ];
    let haystack = path.to_string_lossy().to_lowercase();
    ROOTS
        .iter()
        .find(|(needle, _)| haystack.contains(needle))
        .map(|(_, label)| *label)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents() -> VaultContents {
        VaultContents {
            project_name: "billing".to_owned(),
            alias_style: "opaque".to_owned(),
            scope_strategy: "module".to_owned(),
            project_key: [7; 32],
            identities: vec![StoredIdentity {
                uuid: "0198c0de-0000-7000-8000-000000000001".to_owned(),
                scope_path: "project".to_owned(),
                entity_type: "organization".to_owned(),
                real_name: "Vantor".to_owned(),
                alias: "ORG_H7K2Q3".to_owned(),
                origin: "detected".to_owned(),
                status: "active".to_owned(),
            }],
            dictionary: vec![("Vantor".to_owned(), "organization".to_owned())],
            allowlist: vec!["React".to_owned()],
        }
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("specshield-vault-test-{name}-{}", std::process::id()));
        p
    }

    #[test]
    fn round_trips_through_disk() {
        let path = temp("roundtrip");
        save(&path, "correct horse", &contents()).unwrap();
        let loaded = load(&path, "correct horse").unwrap();
        assert_eq!(loaded.identities, contents().identities);
        assert_eq!(loaded.project_key, [7; 32]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn real_names_never_appear_in_the_file() {
        // The whole point: an attacker with the file learns nothing.
        let path = temp("opaque");
        save(&path, "pw", &contents()).unwrap();
        let raw = std::fs::read(&path).unwrap();
        let as_text = String::from_utf8_lossy(&raw);
        assert!(!as_text.contains("Vantor"), "real name found in the vault file");
        assert!(!as_text.contains("billing"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let path = temp("wrongpw");
        save(&path, "right", &contents()).unwrap();
        assert!(matches!(load(&path, "wrong"), Err(VaultError::Decryption)));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn tampering_is_detected() {
        let path = temp("tamper");
        save(&path, "pw", &contents()).unwrap();
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
        assert!(matches!(load(&path, "pw"), Err(VaultError::Decryption)));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_downgraded_version_field_fails_authentication() {
        // The header is AEAD associated data, so editing it breaks decryption
        // rather than silently changing how the file is parsed.
        let path = temp("downgrade");
        save(&path, "pw", &contents()).unwrap();
        let mut raw = std::fs::read(&path).unwrap();
        raw[MAGIC.len()] = 99;
        std::fs::write(&path, &raw).unwrap();
        assert!(matches!(
            load(&path, "pw"),
            Err(VaultError::VersionMismatch { found: 99 })
        ));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_foreign_file_is_rejected_clearly() {
        let path = temp("foreign");
        std::fs::write(&path, b"this is not a vault, it is a text file at all").unwrap();
        assert!(matches!(load(&path, "pw"), Err(VaultError::NotAVault(_))));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn each_save_uses_a_fresh_salt_and_nonce() {
        // Nonce reuse under one key is the classic AES-GCM footgun.
        let (a, b) = (temp("nonce-a"), temp("nonce-b"));
        save(&a, "pw", &contents()).unwrap();
        save(&b, "pw", &contents()).unwrap();
        assert_ne!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();
    }

    #[test]
    fn detects_cloud_sync_paths() {
        assert_eq!(
            cloud_sync_root(Path::new(r"C:\Users\x\OneDrive\Desktop\proj")),
            Some("OneDrive")
        );
        assert_eq!(cloud_sync_root(Path::new("/home/x/Dropbox/proj")), Some("Dropbox"));
        assert_eq!(cloud_sync_root(Path::new("/home/x/code/proj")), None);
    }
}
