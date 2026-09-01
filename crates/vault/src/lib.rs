//! Encrypted mapping vault — SDD §9.
//!
//! The vault holds the one thing that must never leave the machine: the mapping
//! from alias back to real name. Everything else is derived from it or safe to
//! share.
//!
//! # Storage engine — decision D-9
//!
//! Plain SQLite (`rusqlite`, bundled amalgamation) with **per-value AES-256-GCM
//! on the sensitive columns**, rather than SQLCipher.
//!
//! SQLCipher via `bundled-sqlcipher-vendored-openssl` does not build on a stock
//! Windows toolchain: vendored OpenSSL needs Strawberry Perl and NASM, and its
//! `Configure` step aborts without them. Plain bundled SQLite builds in about
//! five seconds on the same machine, so the blocker is OpenSSL, not SQLite.
//!
//! What this buys over the file vault it replaces: a real schema, migrations,
//! incremental writes, occurrence and edge tables, and query. What it costs
//! against SQLCipher: **metadata**. An attacker holding the file learns how many
//! identities the project has and of what types, but not one name. That belongs
//! in the security one-pager, not in a footnote.
//!
//! See [`crypto`] for the encryption and blind-index scheme.

mod crypto;
mod schema;

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{Keys, SALT_LEN};
pub use crate::schema::SCHEMA_VERSION;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("not a SpecShield vault: {0}")]
    NotAVault(String),

    #[error("vault was written by schema version {found}; this build understands {SCHEMA_VERSION}")]
    VersionMismatch { found: i64 },

    #[error("vault is truncated or corrupt")]
    Corrupt,

    /// Deliberately indistinguishable from tampering: AES-GCM authenticates the
    /// ciphertext, so a wrong passphrase and a modified value fail identically.
    #[error("wrong passphrase, or the vault has been tampered with")]
    Decryption,

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("entropy source unavailable: {0}")]
    Entropy(String),

    #[error("vault has no project row — it was not initialised")]
    NotInitialised,
}

pub(crate) fn random_bytes(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(buf).map_err(|e| VaultError::Entropy(e.to_string()))
}

/// Project settings. Everything here is non-secret except the project key.
///
/// Clears its key material on drop: `settings()` hands raw key bytes to a
/// caller, and a `Settings` living in a local outlasts the moment the key was
/// actually needed.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct Settings {
    #[zeroize(skip)]
    pub project_name: String,
    #[zeroize(skip)]
    pub root_path: String,
    #[zeroize(skip)]
    pub alias_style: String,
    #[zeroize(skip)]
    pub scope_strategy: String,
    /// The HMAC key aliases are derived from (SDD §6.1). Two machines sharing it
    /// produce identical twins with no coordination — which is why it is
    /// encrypted at rest rather than sitting beside the database.
    pub project_key: [u8; 32],
}

/// One indexed file — the `files` row of SDD §9.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    /// Project-root-relative, `/`-separated.
    pub path: String,
    /// Where this file lands in an exported twin. Equal to `path` until path
    /// aliasing renames it.
    pub twin_path: String,
    /// BLAKE3 of the content this record describes — the staleness gate's
    /// reference point (SDD §13.1).
    pub checksum: String,
    /// The parser that claimed it, or empty for a file no parser handles.
    pub parser: String,
}

/// One stored identity — the `identities` row of SDD §9.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdentity {
    pub uuid: String,
    pub scope_path: String,
    pub entity_type: String,
    pub real_name: String,
    pub alias: String,
    pub origin: String,
    pub status: String,
}

/// One occurrence — PRD FR-5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOccurrence {
    pub identity_uuid: String,
    pub file_id: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub kind: String,
}

/// One audit entry — PRD FR-9. Never contains names or content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub ts: i64,
    pub operation: String,
    pub file_count: Option<i64>,
    pub entity_count: Option<i64>,
    pub verification: Option<String>,
    pub destination: Option<String>,
}

/// An open vault.
#[derive(Debug)]
pub struct Vault {
    conn: Connection,
    keys: Keys,
    project_id: String,
}

impl Vault {
    /// Create a new vault. Fails if one already exists at `path`.
    pub fn create(path: &Path, passphrase: &str, settings: &Settings) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists", path.display()),
            )));
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        schema::configure(&conn)?;
        schema::migrate(&conn)?;

        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('kdf_salt', ?)",
            params![&salt[..]],
        )?;

        let keys = Keys::derive(passphrase, &salt)?;
        let project_id = new_uuid();

        conn.execute(
            "INSERT INTO project
                (id, name_enc, root_path_enc, alias_style, scope_strategy, project_key_enc, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                project_id,
                keys.seal(&settings.project_name, &aad("project", "name", &project_id))?,
                keys.seal(&settings.root_path, &aad("project", "root_path", &project_id))?,
                settings.alias_style,
                settings.scope_strategy,
                keys.seal(&hex(&settings.project_key), &aad("project", "project_key", &project_id))?,
                now(),
            ],
        )?;

        // A canary, so a wrong passphrase is reported as such on open rather
        // than as a confusing decode failure deep inside a later query.
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('canary', ?)",
            params![keys.seal("specshield", "meta:canary:0")?],
        )?;

        let vault = Self { conn, keys, project_id };
        vault.log("vault.create", None, None, None, None)?;
        Ok(vault)
    }

    /// Open an existing vault.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, VaultError> {
        if !path.exists() {
            return Err(VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} does not exist", path.display()),
            )));
        }
        let conn = Connection::open(path)?;
        schema::configure(&conn)?;

        // A file that is not our schema must be rejected clearly rather than
        // migrated into something unrecognisable.
        let has_meta = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'",
                [],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !has_meta {
            return Err(VaultError::NotAVault(path.display().to_string()));
        }
        schema::migrate(&conn)?;

        let salt: Vec<u8> = conn.query_row("SELECT value FROM meta WHERE key='kdf_salt'", [], |r| r.get(0))?;
        let keys = Keys::derive(passphrase, &salt)?;

        let canary: Vec<u8> = conn.query_row("SELECT value FROM meta WHERE key='canary'", [], |r| r.get(0))?;
        keys.unseal(&canary, "meta:canary:0")?;

        let project_id: String = conn
            .query_row("SELECT id FROM project LIMIT 1", [], |r| r.get(0))
            .optional()?
            .ok_or(VaultError::NotInitialised)?;

        Ok(Self { conn, keys, project_id })
    }

    pub fn settings(&self) -> Result<Settings, VaultError> {
        let (name_enc, root_enc, alias_style, scope_strategy, key_enc): (Vec<u8>, Vec<u8>, String, String, Vec<u8>) =
            self.conn.query_row(
                "SELECT name_enc, root_path_enc, alias_style, scope_strategy, project_key_enc
                 FROM project WHERE id = ?",
                params![self.project_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;

        let key_hex = self
            .keys
            .unseal(&key_enc, &aad("project", "project_key", &self.project_id))?;
        let mut project_key = [0u8; 32];
        unhex(&key_hex, &mut project_key)?;
        let mut key_hex = key_hex;
        key_hex.zeroize();

        Ok(Settings {
            project_name: self.keys.unseal(&name_enc, &aad("project", "name", &self.project_id))?,
            root_path: self
                .keys
                .unseal(&root_enc, &aad("project", "root_path", &self.project_id))?,
            alias_style,
            scope_strategy,
            project_key,
        })
    }

    /// Insert or update one identity. Idempotent on the identity key.
    pub fn put_identity(&self, identity: &StoredIdentity) -> Result<(), VaultError> {
        let idx = self.keys.blind_index(&identity_key(
            &identity.scope_path,
            &identity.entity_type,
            &identity.real_name,
        ));
        self.conn.execute(
            IDENTITY_UPSERT,
            params![
                identity.uuid,
                idx,
                self.keys
                    .seal(&identity.scope_path, &aad("identities", "scope_path", &identity.uuid))?,
                identity.entity_type,
                self.keys
                    .seal(&identity.real_name, &aad("identities", "real_name", &identity.uuid))?,
                identity.alias,
                identity.origin,
                identity.status,
                now(),
            ],
        )?;
        Ok(())
    }

    /// Write many identities in one transaction — SDD §9.2.
    ///
    /// Row-by-row commits across a full index will not meet the 30 s target.
    pub fn put_identities(&mut self, identities: &[StoredIdentity]) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        for identity in identities {
            let idx = self.keys.blind_index(&identity_key(
                &identity.scope_path,
                &identity.entity_type,
                &identity.real_name,
            ));
            tx.execute(
                IDENTITY_UPSERT,
                params![
                    identity.uuid,
                    idx,
                    self.keys
                        .seal(&identity.scope_path, &aad("identities", "scope_path", &identity.uuid))?,
                    identity.entity_type,
                    self.keys
                        .seal(&identity.real_name, &aad("identities", "real_name", &identity.uuid))?,
                    identity.alias,
                    identity.origin,
                    identity.status,
                    now(),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Record the index — SDD §9.1, §13.1.
    ///
    /// Paths are sealed: a file tree is proprietary on its own. `path_idx` is
    /// the blind index that makes a path findable and uniquely constrainable
    /// without storing it.
    ///
    /// The batch form to [`Vault::put_file`]'s single row: a 1,000-file rescan
    /// through one transaction rather than a thousand. The row id is derived
    /// from the path here, so a rescan lands on the row it wrote last time
    /// without the caller having to remember an id.
    pub fn put_files(&mut self, files: &[StoredFile]) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        for file in files {
            let idx = self.keys.blind_index(&file.path);
            // The row id is derived from the path, not random: an upsert must
            // land on the same row every rescan, and the AAD binds ciphertext to
            // that row.
            let id = idx.clone();
            tx.execute(
                FILE_UPSERT,
                params![
                    id,
                    idx,
                    self.keys.seal(&file.path, &aad("files", "path", &id))?,
                    self.keys.seal(&file.twin_path, &aad("files", "twin_path", &id))?,
                    file.checksum,
                    file.parser,
                    now(),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn files(&self) -> Result<Vec<StoredFile>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, path_enc, twin_path_enc, checksum, parser FROM files ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, path_enc, twin_enc, checksum, parser) = row?;
            out.push(StoredFile {
                path: self.keys.unseal(&path_enc, &aad("files", "path", &id))?,
                twin_path: self.keys.unseal(&twin_enc, &aad("files", "twin_path", &id))?,
                checksum,
                parser,
            });
        }
        Ok(out)
    }

    /// Drop index rows for files that no longer exist. A rescan that only ever
    /// upserts would keep a deleted file stale forever.
    pub fn forget_files(&mut self, paths: &[String]) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        for path in paths {
            tx.execute(
                "DELETE FROM files WHERE path_idx = ?",
                params![self.keys.blind_index(path)],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn identities(&self) -> Result<Vec<StoredIdentity>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT uuid, scope_path_enc, entity_type, real_name_enc, alias, origin, status
             FROM identities ORDER BY created_at, uuid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (uuid, scope_enc, entity_type, name_enc, alias, origin, status) = row?;
            out.push(StoredIdentity {
                scope_path: self.keys.unseal(&scope_enc, &aad("identities", "scope_path", &uuid))?,
                real_name: self.keys.unseal(&name_enc, &aad("identities", "real_name", &uuid))?,
                uuid,
                entity_type,
                alias,
                origin,
                status,
            });
        }
        Ok(out)
    }

    /// Look up one identity by its key, without decrypting the whole table.
    /// This is what the blind index exists for.
    pub fn find_identity(
        &self,
        scope_path: &str,
        entity_type: &str,
        real_name: &str,
    ) -> Result<Option<StoredIdentity>, VaultError> {
        let idx = self.keys.blind_index(&identity_key(scope_path, entity_type, real_name));
        let row: Option<(String, String, String, String)> = self
            .conn
            .query_row(
                "SELECT uuid, alias, origin, status FROM identities WHERE identity_idx = ?",
                params![idx],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;

        Ok(row.map(|(uuid, alias, origin, status)| StoredIdentity {
            uuid,
            scope_path: scope_path.to_owned(),
            entity_type: entity_type.to_owned(),
            real_name: real_name.to_owned(),
            alias,
            origin,
            status,
        }))
    }

    pub fn add_term(&self, term: &str, entity_type: &str) -> Result<(), VaultError> {
        let idx = self.keys.blind_index(term);
        self.conn.execute(
            "INSERT INTO dictionary (term_idx, term_enc, entity_type) VALUES (?, ?, ?)
             ON CONFLICT(term_idx) DO UPDATE SET entity_type = excluded.entity_type",
            params![
                idx,
                self.keys.seal(term, &aad("dictionary", "term", &idx))?,
                entity_type
            ],
        )?;
        Ok(())
    }

    pub fn dictionary(&self) -> Result<Vec<(String, String)>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT term_idx, term_enc, entity_type FROM dictionary")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, String>(2)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (idx, enc, entity_type) = row?;
            out.push((self.keys.unseal(&enc, &aad("dictionary", "term", &idx))?, entity_type));
        }
        Ok(out)
    }

    pub fn add_allowed(&self, term: &str, reason: Option<&str>) -> Result<(), VaultError> {
        let idx = self.keys.blind_index(term);
        let reason_enc = reason
            .map(|r| self.keys.seal(r, &aad("allowlist", "reason", &idx)))
            .transpose()?;
        self.conn.execute(
            "INSERT INTO allowlist (term_idx, term_enc, reason_enc) VALUES (?, ?, ?)
             ON CONFLICT(term_idx) DO NOTHING",
            params![idx, self.keys.seal(term, &aad("allowlist", "term", &idx))?, reason_enc],
        )?;
        Ok(())
    }

    pub fn allowlist(&self) -> Result<Vec<String>, VaultError> {
        let mut stmt = self.conn.prepare("SELECT term_idx, term_enc FROM allowlist")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (idx, enc) = row?;
            out.push(self.keys.unseal(&enc, &aad("allowlist", "term", &idx))?);
        }
        Ok(out)
    }

    /// Record a file. Paths are encrypted: `customer-subscription.ts` leaks the
    /// name it derives from.
    pub fn put_file(
        &self,
        id: &str,
        path: &str,
        twin_path: &str,
        checksum: &str,
        parser: &str,
    ) -> Result<(), VaultError> {
        let idx = self.keys.blind_index(path);
        self.conn.execute(
            "INSERT INTO files (id, path_idx, path_enc, twin_path_enc, checksum, parser, indexed_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(path_idx) DO UPDATE SET checksum = excluded.checksum, indexed_at = excluded.indexed_at",
            params![
                id,
                idx,
                self.keys.seal(path, &aad("files", "path", id))?,
                self.keys.seal(twin_path, &aad("files", "twin_path", id))?,
                checksum,
                parser,
                now(),
            ],
        )?;
        Ok(())
    }

    /// Record where identities appear — PRD FR-5.
    pub fn put_occurrences(&mut self, occurrences: &[StoredOccurrence]) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        for occurrence in occurrences {
            tx.execute(
                "INSERT INTO occurrences (identity_uuid, file_id, byte_start, byte_end, kind)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(file_id, byte_start) DO UPDATE SET
                    identity_uuid = excluded.identity_uuid,
                    byte_end = excluded.byte_end,
                    kind = excluded.kind",
                params![
                    occurrence.identity_uuid,
                    occurrence.file_id,
                    i64::try_from(occurrence.byte_start).unwrap_or(i64::MAX),
                    i64::try_from(occurrence.byte_end).unwrap_or(i64::MAX),
                    occurrence.kind,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn occurrences_of(&self, identity_uuid: &str) -> Result<Vec<StoredOccurrence>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT identity_uuid, file_id, byte_start, byte_end, kind
             FROM occurrences WHERE identity_uuid = ? ORDER BY file_id, byte_start",
        )?;
        let rows = stmt.query_map(params![identity_uuid], |r| {
            Ok(StoredOccurrence {
                identity_uuid: r.get(0)?,
                file_id: r.get(1)?,
                byte_start: usize::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                byte_end: usize::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                kind: r.get(4)?,
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Record a confirmed unification — SDD §5.
    ///
    /// Stored as a blind-indexed concept id per identity, so the vault knows
    /// which identities share a concept without holding the concept name in
    /// plaintext.
    pub fn put_concept(&self, identity_uuid: &str, concept: &str) -> Result<(), VaultError> {
        self.conn.execute(
            "INSERT INTO concepts (identity_uuid, concept_idx, concept_enc) VALUES (?, ?, ?)
             ON CONFLICT(identity_uuid) DO UPDATE SET
                concept_idx = excluded.concept_idx, concept_enc = excluded.concept_enc",
            params![
                identity_uuid,
                self.keys.blind_index(concept),
                self.keys.seal(concept, &aad("concepts", "concept", identity_uuid))?,
            ],
        )?;
        Ok(())
    }

    /// `(identity uuid, concept)` for every confirmed unification.
    pub fn concepts(&self) -> Result<Vec<(String, String)>, VaultError> {
        let mut stmt = self.conn.prepare("SELECT identity_uuid, concept_enc FROM concepts")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (uuid, enc) = row?;
            let concept = self.keys.unseal(&enc, &aad("concepts", "concept", &uuid))?;
            out.push((uuid, concept));
        }
        Ok(out)
    }

    /// Append an audit entry — PRD FR-9.
    ///
    /// Records that something happened and whether it verified. Never what was
    /// in it: no names, no aliases, no content.
    pub fn log(
        &self,
        operation: &str,
        file_count: Option<i64>,
        entity_count: Option<i64>,
        verification: Option<&str>,
        destination: Option<&str>,
    ) -> Result<(), VaultError> {
        self.conn.execute(
            "INSERT INTO audit_log (ts, operation, file_count, entity_count, verification, destination)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![now(), operation, file_count, entity_count, verification, destination],
        )?;
        Ok(())
    }

    pub fn audit_log(&self, limit: usize) -> Result<Vec<AuditEntry>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, operation, file_count, entity_count, verification, destination
             FROM audit_log ORDER BY id DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
            Ok(AuditEntry {
                ts: r.get(0)?,
                operation: r.get(1)?,
                file_count: r.get(2)?,
                entity_count: r.get(3)?,
                verification: r.get(4)?,
                destination: r.get(5)?,
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }
}

const FILE_UPSERT: &str = "INSERT INTO files
        (id, path_idx, path_enc, twin_path_enc, checksum, parser, indexed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(path_idx) DO UPDATE SET
        twin_path_enc = excluded.twin_path_enc,
        checksum = excluded.checksum,
        parser = excluded.parser,
        indexed_at = excluded.indexed_at";

const IDENTITY_UPSERT: &str = "INSERT INTO identities
        (uuid, identity_idx, scope_path_enc, entity_type, real_name_enc, alias, origin, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(identity_idx) DO UPDATE SET
        alias = excluded.alias, status = excluded.status";

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

/// Blind-index input for an identity. `0x1F` (unit separator) cannot appear in
/// any component, so distinct triples cannot collide into one index value.
fn identity_key(scope_path: &str, entity_type: &str, real_name: &str) -> String {
    format!("{scope_path}\u{1f}{entity_type}\u{1f}{real_name}")
}

/// Associated data binding a ciphertext to its table, column, and row.
fn aad(table: &str, column: &str, row: &str) -> String {
    format!("{table}:{column}:{row}")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn new_uuid() -> String {
    let mut bytes = [0u8; 16];
    let _ = random_bytes(&mut bytes);
    hex(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn unhex(s: &str, out: &mut [u8]) -> Result<(), VaultError> {
    if s.len() != out.len() * 2 {
        return Err(VaultError::Corrupt);
    }
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| VaultError::Corrupt)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempVault(std::path::PathBuf);

    impl TempVault {
        fn new(name: &str) -> Self {
            let mut p = std::env::temp_dir();
            let mut nonce = [0u8; 8];
            let _ = random_bytes(&mut nonce);
            p.push(format!("specshield-{name}-{}-{}.db", std::process::id(), hex(&nonce)));
            let _ = std::fs::remove_file(&p);
            Self(p)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempVault {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            for suffix in ["-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
            }
        }
    }

    fn settings() -> Settings {
        Settings {
            project_name: "billing".to_owned(),
            root_path: "/home/x/billing".to_owned(),
            alias_style: "opaque".to_owned(),
            scope_strategy: "module".to_owned(),
            project_key: [7; 32],
        }
    }

    fn identity() -> StoredIdentity {
        StoredIdentity {
            uuid: "0198c0de0000700080000000000001".to_owned(),
            scope_path: "project".to_owned(),
            entity_type: "ORG".to_owned(),
            real_name: "Vantor".to_owned(),
            alias: "ORG_H7K2Q3".to_owned(),
            origin: "detected".to_owned(),
            status: "active".to_owned(),
        }
    }

    #[test]
    fn create_open_round_trip() {
        let t = TempVault::new("roundtrip");
        {
            let v = Vault::create(t.path(), "pw", &settings()).unwrap();
            v.put_identity(&identity()).unwrap();
        }
        let v = Vault::open(t.path(), "pw").unwrap();
        assert_eq!(v.identities().unwrap(), vec![identity()]);
        assert_eq!(v.settings().unwrap().project_key, [7; 32]);
        assert_eq!(v.settings().unwrap().project_name, "billing");
    }

    #[test]
    fn real_names_never_appear_in_the_file() {
        // The whole point of D-9 option B.
        let t = TempVault::new("opaque");
        {
            let v = Vault::create(t.path(), "pw", &settings()).unwrap();
            v.put_identity(&identity()).unwrap();
            v.add_term("Meridian Freight", "ORG").unwrap();
        }
        let raw = std::fs::read(t.path()).unwrap();
        let text = String::from_utf8_lossy(&raw);
        for secret in ["Vantor", "Meridian Freight", "/home/x/billing"] {
            assert!(!text.contains(secret), "{secret:?} found in the vault file");
        }
        // ...while the alias, which is what goes to the model anyway, is
        // deliberately readable. That asymmetry is the design.
        assert!(text.contains("ORG_H7K2Q3"));
    }

    #[test]
    fn wrong_passphrase_is_rejected_before_any_row_is_read() {
        let t = TempVault::new("wrongpw");
        Vault::create(t.path(), "right", &settings()).unwrap();
        assert!(matches!(Vault::open(t.path(), "wrong"), Err(VaultError::Decryption)));
    }

    #[test]
    fn identity_lookup_uses_the_blind_index() {
        let t = TempVault::new("lookup");
        let v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.put_identity(&identity()).unwrap();

        let found = v.find_identity("project", "ORG", "Vantor").unwrap();
        assert_eq!(found.map(|i| i.alias), Some("ORG_H7K2Q3".to_owned()));
        assert!(v.find_identity("project", "ORG", "Paylane").unwrap().is_none());
    }

    #[test]
    fn the_same_identity_is_not_stored_twice() {
        let t = TempVault::new("upsert");
        let v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.put_identity(&identity()).unwrap();
        v.put_identity(&identity()).unwrap();
        assert_eq!(v.identities().unwrap().len(), 1);
    }

    #[test]
    fn distinct_scopes_are_distinct_identities() {
        // Design Review B1, enforced through the blind index rather than a
        // plaintext UNIQUE constraint.
        let t = TempVault::new("scopes");
        let v = Vault::create(t.path(), "pw", &settings()).unwrap();
        let mut a = identity();
        a.scope_path = "mod/a".to_owned();
        a.real_name = "Status".to_owned();
        a.alias = "ENUM_AAA111".to_owned();
        let mut b = a.clone();
        b.uuid = "0198c0de0000700080000000000002".to_owned();
        b.scope_path = "mod/b".to_owned();
        b.alias = "ENUM_BBB222".to_owned();

        v.put_identity(&a).unwrap();
        v.put_identity(&b).unwrap();
        assert_eq!(v.identities().unwrap().len(), 2);
    }

    #[test]
    fn the_file_index_round_trips_through_sealed_paths() {
        let t = TempVault::new("files");
        let mut v = Vault::create(t.path(), "pw", &settings()).unwrap();
        let files = vec![
            StoredFile {
                path: "src/domain/customer-subscription.ts".to_owned(),
                twin_path: "src/domain/PATH_A1B2C3.ts".to_owned(),
                checksum: "abc123".to_owned(),
                parser: "typescript".to_owned(),
            },
            StoredFile {
                path: "README.md".to_owned(),
                twin_path: "README.md".to_owned(),
                checksum: "def456".to_owned(),
                parser: "markdown".to_owned(),
            },
        ];
        v.put_files(&files).unwrap();

        let mut back = v.files().unwrap();
        back.sort_by(|a, b| a.path.cmp(&b.path));
        let mut expected = files.clone();
        expected.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(back, expected);

        // A rescan updates in place rather than accumulating rows.
        let mut edited = files.clone();
        edited[0].checksum = "999999".to_owned();
        v.put_files(&edited).unwrap();
        assert_eq!(v.files().unwrap().len(), 2);
        assert!(v.files().unwrap().iter().any(|f| f.checksum == "999999"));

        v.forget_files(&["README.md".to_owned()]).unwrap();
        let left = v.files().unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].path, "src/domain/customer-subscription.ts");
    }

    #[test]
    fn no_path_appears_in_the_vault_file() {
        // The tree itself is proprietary: a directory named after a client is a
        // leak with no identifier in it at all.
        let t = TempVault::new("paths-sealed");
        let mut v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.put_files(&[StoredFile {
            path: "src/meridian-freight/billing.ts".to_owned(),
            twin_path: "src/PATH_QQ11ZZ/billing.ts".to_owned(),
            checksum: "abc".to_owned(),
            parser: "typescript".to_owned(),
        }])
        .unwrap();
        drop(v);

        let raw = std::fs::read(t.path()).unwrap();
        let needle = b"meridian-freight";
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "a path reached the vault file in plaintext"
        );
    }

    #[test]
    fn occurrences_are_recorded_and_queryable() {
        let t = TempVault::new("occ");
        let mut v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.put_identity(&identity()).unwrap();
        v.put_file("f1", "docs/PRD.md", "docs/PATH_A1.md", "blake3", "markdown")
            .unwrap();
        v.put_occurrences(&[StoredOccurrence {
            identity_uuid: identity().uuid,
            file_id: "f1".to_owned(),
            byte_start: 58,
            byte_end: 64,
            kind: "reference".to_owned(),
        }])
        .unwrap();

        let found = v.occurrences_of(&identity().uuid).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].byte_start, found[0].byte_end), (58, 64));
    }

    #[test]
    fn file_paths_are_encrypted_too() {
        // `src/services/customer-subscription.ts` leaks the name it derives from.
        let t = TempVault::new("paths");
        {
            let v = Vault::create(t.path(), "pw", &settings()).unwrap();
            v.put_file("f1", "src/customer-subscription.ts", "src/PATH_A1.ts", "c", "text")
                .unwrap();
        }
        let raw = std::fs::read(t.path()).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("customer-subscription"));
    }

    #[test]
    fn dictionary_and_allowlist_round_trip() {
        let t = TempVault::new("dict");
        let v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.add_term("Vantor", "ORG").unwrap();
        v.add_term("Paylane", "ORG").unwrap();
        v.add_allowed("React", Some("framework")).unwrap();

        let mut terms = v.dictionary().unwrap();
        terms.sort();
        assert_eq!(
            terms,
            vec![
                ("Paylane".to_owned(), "ORG".to_owned()),
                ("Vantor".to_owned(), "ORG".to_owned())
            ]
        );
        assert_eq!(v.allowlist().unwrap(), vec!["React".to_owned()]);
    }

    #[test]
    fn audit_log_records_operations_without_content() {
        let t = TempVault::new("audit");
        let v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.log("sanitize", Some(1), Some(24), Some("clean"), Some("clipboard"))
            .unwrap();

        let entries = v.audit_log(10).unwrap();
        assert_eq!(entries[0].operation, "sanitize");
        assert_eq!(entries[0].entity_count, Some(24));
        assert_eq!(entries.len(), 2, "vault.create is logged too");
    }

    #[test]
    fn a_foreign_sqlite_file_is_rejected_clearly() {
        let t = TempVault::new("foreign");
        {
            let conn = Connection::open(t.path()).unwrap();
            conn.execute("CREATE TABLE something (x INTEGER)", []).unwrap();
        }
        assert!(matches!(Vault::open(t.path(), "pw"), Err(VaultError::NotAVault(_))));
    }

    #[test]
    fn creating_over_an_existing_vault_is_refused() {
        let t = TempVault::new("exists");
        Vault::create(t.path(), "pw", &settings()).unwrap();
        assert!(Vault::create(t.path(), "pw", &settings()).is_err());
    }

    #[test]
    fn batch_write_is_transactional_and_scales() {
        let t = TempVault::new("batch");
        let mut v = Vault::create(t.path(), "pw", &settings()).unwrap();
        let batch: Vec<StoredIdentity> = (0..200)
            .map(|i| StoredIdentity {
                uuid: format!("uuid-{i:040}"),
                scope_path: format!("mod/{i}"),
                entity_type: "SERVICE".to_owned(),
                real_name: format!("Service{i}"),
                alias: format!("SERVICE_A{i:05}"),
                origin: "detected".to_owned(),
                status: "active".to_owned(),
            })
            .collect();
        v.put_identities(&batch).unwrap();
        assert_eq!(v.identities().unwrap().len(), 200);
    }

    #[test]
    fn detects_cloud_sync_paths() {
        assert_eq!(
            cloud_sync_root(Path::new(r"C:\Users\x\OneDrive\Desktop\proj")),
            Some("OneDrive")
        );
        assert_eq!(cloud_sync_root(Path::new("/home/x/code/proj")), None);
    }
}
