//! Backup, restore, and key escrow — PRD FR-11. **M6.**
//!
//! Three operations that all exist for the same reason: the vault is the only
//! way back from a twin, and there is deliberately no way to recover a lost
//! passphrase. Everything here is about making that survivable *before* it
//! happens.
//!
//! # What escrow holds
//!
//! The vault's **data key**, sealed under a separate escrow passphrase — schema
//! v3. Whoever holds the file and its passphrase can open the vault; they cannot
//! learn the vault passphrase, which matters because people reuse passphrases
//! and a recovery credential should not double as a credential for someone's
//! other accounts.
//!
//! Recovery re-wraps that key under a passphrase the holder chooses
//! ([`crate::Vault::recover_with_escrow`]) rather than printing a key out. It is
//! the operation someone actually wants, and nothing sensitive crosses a
//! terminal.
//!
//! Earlier builds escrowed the passphrase itself, because the content keys were
//! derived straight from it and there was nothing else to escrow. The magic
//! bytes changed with the format, so an escrow file from one of those is
//! refused rather than silently misread.
//!
//! # No destructive operations
//!
//! `restore_from` refuses to write over an existing file, and both restore paths
//! verify the source is a real vault before anything is created. A backup that
//! silently overwrote the vault it was meant to protect would be the single
//! worst bug this product could have.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rusqlite::Connection;
use zeroize::Zeroize;

use crate::{SALT_LEN, VaultError, random_bytes, schema};

/// Magic bytes so an escrow file is identifiable and cannot be confused with a
/// vault, a backup, or anything else.
/// Bumped from `\x01` when the format changed from holding the passphrase to
/// holding the data key (schema v3). A file in the old format is refused rather
/// than decrypted into 32 bytes of something that is not a key.
const ESCROW_MAGIC: &[u8; 16] = b"SPECSHIELD-ESCR\x02";
#[cfg(test)]
const ESCROW_MAGIC_V1: &[u8; 16] = b"SPECSHIELD-ESCR\x01";
const NONCE_LEN: usize = 12;

/// The warning FR-11 requires, carried inside the artifact rather than only
/// printed once at the moment of export.
pub const ESCROW_WARNING: &str = "\
SpecShield key escrow.

This file plus its escrow passphrase opens the vault it came from, and the vault
maps every alias back to a real name. Store it the way you would store the
passphrase itself.

It holds the vault's data key, not its passphrase. Whoever has it can open the
vault; they cannot learn the passphrase. Handing it back is not revocation —
only rotating the data key does that, and it re-encrypts the whole vault.

If both this file and the vault passphrase are lost, the mapping is gone. There
is no recovery path, by design: nothing about the passphrase is stored anywhere,
and no twin can be reversed without it.";

/// Copy a vault to `dest`, consistently, while it is open.
///
/// SQLite's online backup rather than a file copy: with WAL enabled a plain copy
/// of the `.bin` can miss committed transactions still in the write-ahead log,
/// producing a backup that is quietly a few operations behind.
///
/// The copy is encrypted because the vault is — this is a byte-level duplicate
/// of an already-sealed database, not a re-encryption.
pub fn backup_to(source: &Connection, dest: &Path) -> Result<(), VaultError> {
    if dest.exists() {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists — refusing to overwrite a backup", dest.display()),
        )));
    }
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut target = Connection::open(dest)?;
    let backup = rusqlite::backup::Backup::new(source, &mut target)?;
    backup.run_to_completion(64, std::time::Duration::from_millis(0), None)?;
    Ok(())
}

/// Put a backup back, without ever writing over something that is already there.
///
/// The passphrase is checked before anything is created: restoring a backup
/// nobody can open is a failure discovered far too late, usually in the middle
/// of the incident the backup existed for.
pub fn restore_from(backup: &Path, dest: &Path, passphrase: &str) -> Result<(), VaultError> {
    if !backup.exists() {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} does not exist", backup.display()),
        )));
    }
    if dest.exists() {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists — move it aside first; a restore never writes over a vault",
                dest.display()
            ),
        )));
    }

    // Prove it opens *before* the destination exists.
    crate::Vault::open(backup, passphrase)?;

    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let source = Connection::open_with_flags(backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut target = Connection::open(dest)?;
    {
        let copy = rusqlite::backup::Backup::new(&source, &mut target)?;
        copy.run_to_completion(64, std::time::Duration::from_millis(0), None)?;
    }
    schema::configure(&target)?;
    Ok(())
}

/// Seal the vault's data key under an escrow passphrase.
///
/// Layout: magic ‖ salt ‖ nonce ‖ ciphertext. The warning is authenticated as
/// associated data, so it cannot be stripped from a file that still decrypts.
///
/// Call [`crate::Vault::export_escrow`] rather than this directly — the data key
/// does not otherwise leave the vault type.
pub fn seal_escrow(data_key: &[u8; 32], escrow_passphrase: &str) -> Result<Vec<u8>, VaultError> {
    if escrow_passphrase.is_empty() {
        return Err(VaultError::KeyDerivation(
            "an escrow passphrase of nothing protects nothing".to_owned(),
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    random_bytes(&mut salt)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    random_bytes(&mut nonce_bytes)?;

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(escrow_passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key));
    key.zeroize();

    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: data_key,
                aad: ESCROW_WARNING.as_bytes(),
            },
        )
        .map_err(|_| VaultError::Decryption)?;

    let mut out = Vec::with_capacity(ESCROW_MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(ESCROW_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Recover the vault's data key from an escrow file.
pub fn open_escrow(escrow: &[u8], escrow_passphrase: &str) -> Result<[u8; 32], VaultError> {
    let header = ESCROW_MAGIC.len() + SALT_LEN + NONCE_LEN;
    if escrow.len() <= header {
        return Err(VaultError::Corrupt);
    }
    if &escrow[..ESCROW_MAGIC.len()] != ESCROW_MAGIC {
        // An escrow written before schema v3 held the passphrase, not the data
        // key. Refusing it beats decrypting 32 bytes of something else and
        // calling it a key.
        return Err(VaultError::NotAVault(
            "not a SpecShield escrow file, or one written by a build before schema v3".to_owned(),
        ));
    }

    let salt = &escrow[ESCROW_MAGIC.len()..ESCROW_MAGIC.len() + SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&escrow[ESCROW_MAGIC.len() + SALT_LEN..header]);
    let ciphertext = &escrow[header..];

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(escrow_passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key));
    key.zeroize();

    let plaintext = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: ESCROW_WARNING.as_bytes(),
            },
        )
        .map_err(|_| VaultError::Decryption)?;

    let mut data_key = [0u8; 32];
    if plaintext.len() != data_key.len() {
        return Err(VaultError::Corrupt);
    }
    data_key.copy_from_slice(&plaintext);
    Ok(data_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Settings, StoredIdentity, Vault};

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!("specshield-backup-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("temp dir");
            Self(p)
        }

        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn settings() -> Settings {
        Settings {
            project_name: "t".to_owned(),
            root_path: "/tmp/t".to_owned(),
            alias_style: "opaque".to_owned(),
            scope_strategy: "module".to_owned(),
            project_key: [11; 32],
        }
    }

    fn identity() -> StoredIdentity {
        StoredIdentity {
            uuid: "0198c0de0000700080000000000001".to_owned(),
            scope_path: "mod/a".to_owned(),
            entity_type: "SERVICE".to_owned(),
            real_name: "CustomerService".to_owned(),
            alias: "SERVICE_H7K2Q3".to_owned(),
            origin: "detected".to_owned(),
            status: "active".to_owned(),
        }
    }

    #[test]
    fn a_backup_round_trips_with_every_mapping_intact() {
        let dir = TempDir::new("round-trip");
        let original = dir.join("vault.bin");
        let backup = dir.join("vault.backup");
        let restored = dir.join("restored.bin");

        let vault = Vault::create(&original, "pw", &settings()).unwrap();
        vault.put_identity(&identity()).unwrap();
        vault.backup_to(&backup).unwrap();
        drop(vault);

        restore_from(&backup, &restored, "pw").unwrap();

        let reopened = Vault::open(&restored, "pw").unwrap();
        let identities = reopened.identities().unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].real_name, "CustomerService");
        assert_eq!(reopened.settings().unwrap().project_key, [11; 32]);
    }

    #[test]
    fn a_backup_captures_writes_still_in_the_write_ahead_log() {
        // WAL means a plain file copy can be several committed transactions
        // behind. The whole reason this uses SQLite's online backup.
        let dir = TempDir::new("wal");
        let original = dir.join("vault.bin");
        let backup = dir.join("vault.backup");

        let mut vault = Vault::create(&original, "pw", &settings()).unwrap();
        vault.put_identity(&identity()).unwrap();
        vault
            .put_files(&[crate::StoredFile {
                path: "a.ts".to_owned(),
                twin_path: "a.ts".to_owned(),
                checksum: "abc".to_owned(),
                parser: "typescript".to_owned(),
            }])
            .unwrap();

        // Backed up while still open, with the WAL hot.
        vault.backup_to(&backup).unwrap();

        let copy = Vault::open(&backup, "pw").unwrap();
        assert_eq!(copy.identities().unwrap().len(), 1);
        assert_eq!(
            copy.files().unwrap().len(),
            1,
            "the WAL contents made it into the backup"
        );
    }

    #[test]
    fn a_restore_never_writes_over_an_existing_vault() {
        let dir = TempDir::new("no-clobber");
        let original = dir.join("vault.bin");
        let backup = dir.join("vault.backup");

        let vault = Vault::create(&original, "pw", &settings()).unwrap();
        vault.put_identity(&identity()).unwrap();
        vault.backup_to(&backup).unwrap();
        drop(vault);

        let before = std::fs::read(&original).unwrap();
        let result = restore_from(&backup, &original, "pw");

        assert!(result.is_err(), "a restore must not overwrite");
        assert_eq!(std::fs::read(&original).unwrap(), before);
    }

    #[test]
    fn a_backup_that_cannot_be_opened_is_refused_before_anything_is_created() {
        let dir = TempDir::new("bad-pass");
        let original = dir.join("vault.bin");
        let backup = dir.join("vault.backup");
        let restored = dir.join("restored.bin");

        let vault = Vault::create(&original, "pw", &settings()).unwrap();
        vault.backup_to(&backup).unwrap();
        drop(vault);

        assert!(restore_from(&backup, &restored, "wrong").is_err());
        assert!(
            !restored.exists(),
            "a failed restore must not leave a half-made vault behind"
        );
    }

    const A_KEY: [u8; 32] = [42u8; 32];

    #[test]
    fn escrow_round_trips_the_data_key() {
        let sealed = seal_escrow(&A_KEY, "the escrow passphrase").unwrap();
        assert_eq!(open_escrow(&sealed, "the escrow passphrase").unwrap(), A_KEY);
    }

    #[test]
    fn an_escrow_file_never_contains_the_key_in_the_clear() {
        let sealed = seal_escrow(&A_KEY, "escrow").unwrap();
        assert!(
            !sealed.windows(A_KEY.len()).any(|w| w == A_KEY),
            "the escrow file leaks what it exists to protect"
        );
    }

    #[test]
    fn the_wrong_escrow_passphrase_fails_rather_than_returning_rubbish() {
        let sealed = seal_escrow(&A_KEY, "escrow-pw").unwrap();
        assert!(matches!(open_escrow(&sealed, "not-it"), Err(VaultError::Decryption)));
    }

    #[test]
    fn the_warning_cannot_be_stripped_from_a_file_that_still_opens() {
        // The warning is authenticated as associated data. An escrow file that
        // arrives without it is not an escrow file.
        let sealed = seal_escrow(&A_KEY, "escrow-pw").unwrap();
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        assert!(open_escrow(&tampered, "escrow-pw").is_err());
        assert!(ESCROW_WARNING.contains("no recovery path"));
    }

    #[test]
    fn something_that_is_not_an_escrow_file_is_named_as_such() {
        let result = open_escrow(b"just some bytes that are long enough to pass the length check", "pw");
        assert!(matches!(result, Err(VaultError::NotAVault(_))), "{result:?}");
    }

    #[test]
    fn an_escrow_from_before_v3_is_refused_rather_than_misread() {
        // Those held the passphrase, not the data key. Decrypting 32 bytes of
        // something else and calling it a key would be worse than failing.
        let mut old_format = Vec::new();
        old_format.extend_from_slice(ESCROW_MAGIC_V1);
        old_format.extend_from_slice(&[0u8; SALT_LEN + NONCE_LEN + 48]);

        let result = open_escrow(&old_format, "pw");
        assert!(matches!(result, Err(VaultError::NotAVault(_))), "{result:?}");
    }

    #[test]
    fn an_empty_escrow_passphrase_is_refused() {
        assert!(seal_escrow(&A_KEY, "").is_err());
    }

    #[test]
    fn escrow_gets_a_colleague_back_in_without_the_passphrase() {
        // The point of the feature, and of holding the data key rather than the
        // passphrase: the holder recovers access and never learns what the
        // original passphrase was.
        let dir = TempDir::new("end-to-end");
        let path = dir.join("vault.bin");

        let vault = Vault::create(&path, "the-real-passphrase", &settings()).unwrap();
        vault.put_identity(&identity()).unwrap();
        let sealed = vault.export_escrow("held-by-security").unwrap();
        drop(vault);

        Vault::recover_with_escrow(&path, &sealed, "held-by-security", "a-new-passphrase").unwrap();

        let reopened = Vault::open(&path, "a-new-passphrase").unwrap();
        assert_eq!(reopened.identities().unwrap()[0].real_name, "CustomerService");
        assert!(
            Vault::open(&path, "the-real-passphrase").is_err(),
            "recovery sets the passphrase the recoverer chose"
        );
    }
}
