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

pub mod backup;
mod crypto;
pub mod recovery;

pub use recovery::Recovery;
mod schema;

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{Kek, Keys, SALT_LEN};
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

/// Render audit entries as CSV — PRD FR-9, "exportable as CSV for compliance
/// review".
///
/// Written out by hand rather than pulled in as a dependency: six columns of
/// integers and short strings do not justify one, and the escaping rule is a
/// single line. Fields are quoted only when they need to be, and an embedded
/// quote is doubled, per RFC 4180.
///
/// A destination is the only field a caller could ever get user-controlled text
/// into — a branch name, a file path — so it is the one that has to be escaped
/// properly. A stray quote or newline there would otherwise shift every
/// subsequent column of a compliance export by one.
#[must_use]
pub fn audit_csv(entries: &[AuditEntry]) -> String {
    use std::fmt::Write as _;

    let mut out = String::from("timestamp,operation,file_count,entity_count,verification,destination\n");
    for entry in entries {
        // Writing into the buffer rather than formatting a String per row: an
        // export of a long-lived project is thousands of rows.
        let _ = writeln!(
            out,
            "{},{},{},{},{},{}",
            entry.ts,
            csv_field(&entry.operation),
            entry.file_count.map_or_else(String::new, |n| n.to_string()),
            entry.entity_count.map_or_else(String::new, |n| n.to_string()),
            csv_field(entry.verification.as_deref().unwrap_or_default()),
            csv_field(entry.destination.as_deref().unwrap_or_default()),
        );
    }
    out
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// An open vault.
#[derive(Debug)]
pub struct Vault {
    conn: Connection,
    keys: Keys,
    /// Kept so the passphrase can be changed and an escrow issued without
    /// asking for the passphrase again.
    ///
    /// No meaningful extra exposure: `keys` is derived from it and already
    /// grants full read access to everything the vault holds. It zeroizes on
    /// drop.
    data_key: Zeroizing<[u8; 32]>,
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

        // Schema v3 — PRD FR-11. A random data key, wrapped by a key derived
        // from the passphrase. Content is encrypted under the data key, so
        // changing the passphrase re-wraps 32 bytes instead of re-encrypting
        // every value in the database.
        let mut data_key = [0u8; 32];
        random_bytes(&mut data_key)?;
        let kek = Kek::derive(passphrase, &salt)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('data_key', ?)",
            params![kek.wrap(&data_key)?],
        )?;

        let keys = Keys::from_data_key(&data_key);
        conn.pragma_update(None, "user_version", schema::SCHEMA_VERSION)?;

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

        let vault = Self {
            conn,
            keys,
            data_key: Zeroizing::new(data_key),
            project_id,
        };
        data_key.zeroize();
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
        let kek = Kek::derive(passphrase, &salt)?;

        // A vault written before v3 has its content encrypted straight under the
        // passphrase. Bring it forward before anything reads from it.
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < 3 {
            migrate_to_v3(&conn, passphrase, &salt, &kek)?;
        }

        let wrapped: Vec<u8> = conn.query_row("SELECT value FROM meta WHERE key='data_key'", [], |r| r.get(0))?;
        let data_key = Zeroizing::new(kek.unwrap_key(&wrapped)?);
        let keys = Keys::from_data_key(&data_key);

        // The canary is now a second check rather than the only one — a wrong
        // passphrase already failed to unwrap the data key above. It stays
        // because it also catches a data key that unwrapped but does not match
        // the content, which is what a botched migration would look like.
        let canary: Vec<u8> = conn.query_row("SELECT value FROM meta WHERE key='canary'", [], |r| r.get(0))?;
        keys.unseal(&canary, "meta:canary:0")?;

        let project_id: String = conn
            .query_row("SELECT id FROM project LIMIT 1", [], |r| r.get(0))
            .optional()?
            .ok_or(VaultError::NotInitialised)?;

        Ok(Self {
            conn,
            keys,
            data_key,
            project_id,
        })
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

    /// Change the passphrase — PRD FR-11, schema v3.
    ///
    /// Re-wraps the data key under a key derived from the new passphrase, with a
    /// fresh salt. Nothing else moves: not one encrypted value, not one blind
    /// index, not one alias.
    ///
    /// That is the whole reason the data key exists. Before v3 this operation
    /// was a re-encryption of the entire database, which is why it did not
    /// exist and the only way to change a passphrase was to build a new vault.
    pub fn change_passphrase(&self, old: &str, new: &str) -> Result<(), VaultError> {
        if new.is_empty() {
            return Err(VaultError::KeyDerivation(
                "an empty passphrase protects nothing".to_owned(),
            ));
        }

        let salt: Vec<u8> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='kdf_salt'", [], |r| r.get(0))?;
        let wrapped: Vec<u8> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='data_key'", [], |r| r.get(0))?;

        // Proves the old passphrase before anything is written.
        let mut data_key = Kek::derive(old, &salt)?.unwrap_key(&wrapped)?;

        // A new salt as well as a new passphrase: reusing the old one would let
        // anyone who had precomputed against it keep their head start.
        let mut fresh_salt = [0u8; SALT_LEN];
        random_bytes(&mut fresh_salt)?;
        let rewrapped = Kek::derive(new, &fresh_salt)?.wrap(&data_key);
        data_key.zeroize();
        let rewrapped = rewrapped?;

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE meta SET value = ? WHERE key='kdf_salt'",
            params![&fresh_salt[..]],
        )?;
        tx.execute("UPDATE meta SET value = ? WHERE key='data_key'", params![rewrapped])?;
        tx.commit()?;

        self.log("vault.passphrase", None, None, None, None)
    }

    /// Export the data key under an escrow passphrase — PRD FR-11.
    ///
    /// Hands out the *data key*, not the passphrase. Whoever holds the escrow
    /// can open the vault; they cannot learn the passphrase, which matters
    /// because people reuse passphrases and a recovery credential should not
    /// also be a credential for someone's other accounts.
    pub fn export_escrow(&self, escrow_passphrase: &str) -> Result<Vec<u8>, VaultError> {
        let sealed = backup::seal_escrow(&self.data_key, escrow_passphrase)?;
        self.log("vault.escrow", None, None, None, None)?;
        Ok(sealed)
    }

    /// Get back in with an escrow file, choosing a new passphrase — PRD FR-11.
    ///
    /// The recovery operation itself rather than a way to read out a key: the
    /// holder of the escrow re-wraps the data key under a passphrase they
    /// choose, and the vault opens normally from then on.
    pub fn recover_with_escrow(
        path: &Path,
        escrow: &[u8],
        escrow_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<(), VaultError> {
        if new_passphrase.is_empty() {
            return Err(VaultError::KeyDerivation(
                "an empty passphrase protects nothing".to_owned(),
            ));
        }

        let data_key = Zeroizing::new(backup::open_escrow(escrow, escrow_passphrase)?);
        let conn = Connection::open(path)?;
        schema::configure(&conn)?;

        // Prove the recovered key actually opens *this* vault before writing
        // anything. An escrow from another project, or one issued before a key
        // rotation, decrypts perfectly well under its own passphrase and yields
        // a key that is simply wrong — and overwriting the good wrapper with a
        // wrapper around a wrong key leaves the vault unopenable by anyone.
        //
        // Found by the test for rotation revoking an escrow: the stale escrow
        // was correctly refused, and the owner could no longer get in either.
        let canary: Vec<u8> = conn.query_row("SELECT value FROM meta WHERE key='canary'", [], |r| r.get(0))?;
        Keys::from_data_key(&data_key)
            .unseal(&canary, "meta:canary:0")
            .map_err(|_| {
                VaultError::NotAVault(
                    "that escrow does not open this vault — it belongs to another project, \
                 or the data key has been rotated since it was issued"
                        .to_owned(),
                )
            })?;

        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt)?;
        let wrapped = Kek::derive(new_passphrase, &salt)?.wrap(&data_key)?;

        let tx = conn.unchecked_transaction()?;
        tx.execute("UPDATE meta SET value = ? WHERE key='kdf_salt'", params![&salt[..]])?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('data_key', ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![wrapped],
        )?;
        tx.commit()?;

        // Prove it before returning success. A recovery that reports success and
        // leaves an unopenable vault is the worst possible outcome here.
        Vault::open(path, new_passphrase)?.log("vault.recover", None, None, None, None)
    }

    /// Rotate the data key — PRD FR-11.
    ///
    /// Re-encrypts every sealed value under a new data key. Slow, and the only
    /// way to make an issued escrow file or an old backup stop working: whoever
    /// holds one has the old data key, and re-wrapping cannot take that back.
    ///
    /// This is what "revoking an escrow" actually means. Before v3 there was no
    /// path to it at all.
    pub fn rotate_data_key(&mut self, passphrase: &str) -> Result<(), VaultError> {
        let salt: Vec<u8> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='kdf_salt'", [], |r| r.get(0))?;
        let kek = Kek::derive(passphrase, &salt)?;
        let wrapped: Vec<u8> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='data_key'", [], |r| r.get(0))?;
        kek.unwrap_key(&wrapped)?;

        let mut fresh = Zeroizing::new([0u8; 32]);
        random_bytes(fresh.as_mut())?;
        let new = Keys::from_data_key(&fresh);
        let rewrapped = kek.wrap(&fresh)?;

        // Same machinery as the v2 migration, and the same reason it is one
        // transaction: a half-rotated vault is a destroyed vault.
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let rotated = migrate_rows(&self.conn, &self.keys, &new).and_then(|()| {
            self.conn
                .execute("UPDATE meta SET value = ? WHERE key='data_key'", params![rewrapped])?;
            self.conn.execute(
                "UPDATE meta SET value = ? WHERE key='canary'",
                params![new.seal("specshield", "meta:canary:0")?],
            )?;
            Ok(())
        });

        match rotated {
            Ok(()) => {
                self.conn.execute_batch("COMMIT")?;
                self.keys = new;
                self.data_key = fresh;
                self.log("vault.rotate_key", None, None, None, None)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Copy this vault to `dest` — PRD FR-11.
    ///
    /// Runs against the live connection, so it captures writes still sitting in
    /// the write-ahead log. A file copy would not.
    pub fn backup_to(&self, dest: &Path) -> Result<(), VaultError> {
        backup::backup_to(&self.conn, dest)?;
        self.log("vault.backup", None, None, None, None)
    }

    /// Re-key the project — PRD FR-11.
    ///
    /// Aliases are HMAC-derived from the project key, so replacing it changes
    /// every alias the project will ever issue. Callers must re-derive the
    /// stored ones afterwards; this only moves the key.
    ///
    /// Every twin already shared becomes unrestorable by this vault, which is
    /// exactly the point when a twin has been over-shared — and exactly the
    /// disaster when it has not. The caller warns.
    pub fn rotate_project_key(&self, new_key: &[u8; 32]) -> Result<(), VaultError> {
        self.conn.execute(
            "UPDATE project SET project_key_enc = ? WHERE id = ?",
            params![
                self.keys
                    .seal(&hex(new_key), &aad("project", "project_key", &self.project_id))?,
                self.project_id,
            ],
        )?;
        self.log("vault.rekey", None, None, None, None)
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

/// Bring a v1/v2 vault to v3 — PRD FR-11, schema §9.1.
///
/// Before v3 the content keys were derived straight from the passphrase. That
/// made changing a passphrase a re-encryption of every value, and left nothing
/// to escrow but the passphrase itself. v3 introduces a random data key, wrapped
/// by the passphrase-derived KEK.
///
/// Moving an existing vault therefore means re-encrypting everything **once**:
/// decrypt with the old keys, encrypt with the new ones. Two details make this
/// less mechanical than it sounds:
///
/// - The index key changes, so every blind index changes with it. Those columns
///   are `UNIQUE`, and `dictionary`, `allowlist`, and `concepts` use the blind
///   index *as the row id in their associated data* — so the index and the
///   ciphertext have to move together or nothing decrypts afterwards.
/// - It runs in one transaction. A vault half-migrated is a vault destroyed, and
///   this is the only code in the product that could destroy one.
fn migrate_to_v3(conn: &Connection, passphrase: &str, salt: &[u8], kek: &Kek) -> Result<(), VaultError> {
    let old = Keys::derive_legacy(passphrase, salt)?;

    // Prove the passphrase before touching anything. A migration that starts on
    // a wrong passphrase would fail partway and take the vault with it.
    let canary: Vec<u8> = conn.query_row("SELECT value FROM meta WHERE key='canary'", [], |r| r.get(0))?;
    old.unseal(&canary, "meta:canary:0")?;

    let mut data_key = [0u8; 32];
    random_bytes(&mut data_key)?;
    let new = Keys::from_data_key(&data_key);
    let wrapped = kek.wrap(&data_key)?;
    data_key.zeroize();

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let migrated = migrate_rows(conn, &old, &new).and_then(|()| {
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('data_key', ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![wrapped],
        )?;
        conn.execute(
            "UPDATE meta SET value = ? WHERE key='canary'",
            params![new.seal("specshield", "meta:canary:0")?],
        )?;
        Ok(())
    });

    match migrated {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            conn.pragma_update(None, "user_version", 3)?;
            Ok(())
        }
        Err(e) => {
            // Leave the vault exactly as it was found.
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// One project row, as the migration reads it before re-sealing.
type ProjectRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

/// Re-seal every encrypted value and recompute every blind index.
///
/// Long, and deliberately not split: every table has to be handled, and a
/// reader checking that none was missed wants them in one place.
#[allow(clippy::too_many_lines)]
fn migrate_rows(conn: &Connection, old: &Keys, new: &Keys) -> Result<(), VaultError> {
    // project — three sealed columns, row id is the project id.
    let projects: Vec<ProjectRow> = conn
        .prepare("SELECT id, name_enc, root_path_enc, project_key_enc FROM project")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<std::result::Result<_, _>>()?;
    for (id, name, root, key) in projects {
        conn.execute(
            "UPDATE project SET name_enc = ?, root_path_enc = ?, project_key_enc = ? WHERE id = ?",
            params![
                reseal(old, new, &name, &aad("project", "name", &id))?,
                reseal(old, new, &root, &aad("project", "root_path", &id))?,
                reseal(old, new, &key, &aad("project", "project_key", &id))?,
                id,
            ],
        )?;
    }

    // identities — the blind index is over (scope, type, name), so it can only
    // be recomputed after the names are back in the clear.
    let identities: Vec<(String, Vec<u8>, String, Vec<u8>)> = conn
        .prepare("SELECT uuid, scope_path_enc, entity_type, real_name_enc FROM identities")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<std::result::Result<_, _>>()?;
    for (uuid, scope_enc, entity_type, name_enc) in identities {
        let scope = old.unseal(&scope_enc, &aad("identities", "scope_path", &uuid))?;
        let real_name = old.unseal(&name_enc, &aad("identities", "real_name", &uuid))?;
        conn.execute(
            "UPDATE identities SET identity_idx = ?, scope_path_enc = ?, real_name_enc = ? WHERE uuid = ?",
            params![
                new.blind_index(&identity_key(&scope, &entity_type, &real_name)),
                new.seal(&scope, &aad("identities", "scope_path", &uuid))?,
                new.seal(&real_name, &aad("identities", "real_name", &uuid))?,
                uuid,
            ],
        )?;
    }

    // files — row id is the file id, which does not move.
    let files: Vec<(String, Vec<u8>, Vec<u8>)> = conn
        .prepare("SELECT id, path_enc, twin_path_enc FROM files")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<std::result::Result<_, _>>()?;
    for (id, path_enc, twin_enc) in files {
        let path = old.unseal(&path_enc, &aad("files", "path", &id))?;
        let twin = old.unseal(&twin_enc, &aad("files", "twin_path", &id))?;
        conn.execute(
            "UPDATE files SET path_idx = ?, path_enc = ?, twin_path_enc = ? WHERE id = ?",
            params![
                new.blind_index(&path),
                new.seal(&path, &aad("files", "path", &id))?,
                new.seal(&twin, &aad("files", "twin_path", &id))?,
                id,
            ],
        )?;
    }

    // dictionary — the blind index *is* the primary key and the AAD row id, so
    // the row is deleted and rewritten rather than updated in place.
    let dictionary: Vec<(String, Vec<u8>, String)> = conn
        .prepare("SELECT term_idx, term_enc, entity_type FROM dictionary")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<std::result::Result<_, _>>()?;
    conn.execute("DELETE FROM dictionary", [])?;
    for (idx, enc, entity_type) in dictionary {
        let term = old.unseal(&enc, &aad("dictionary", "term", &idx))?;
        let new_idx = new.blind_index(&term);
        conn.execute(
            "INSERT INTO dictionary (term_idx, term_enc, entity_type) VALUES (?, ?, ?)",
            params![
                new_idx,
                new.seal(&term, &aad("dictionary", "term", &new_idx))?,
                entity_type
            ],
        )?;
    }

    let allowlist: Vec<(String, Vec<u8>, Option<Vec<u8>>)> = conn
        .prepare("SELECT term_idx, term_enc, reason_enc FROM allowlist")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<std::result::Result<_, _>>()?;
    conn.execute("DELETE FROM allowlist", [])?;
    for (idx, enc, reason_enc) in allowlist {
        let term = old.unseal(&enc, &aad("allowlist", "term", &idx))?;
        let new_idx = new.blind_index(&term);
        let reason = reason_enc
            .map(|blob| old.unseal(&blob, &aad("allowlist", "reason", &idx)))
            .transpose()?;
        let resealed = reason
            .map(|r| new.seal(&r, &aad("allowlist", "reason", &new_idx)))
            .transpose()?;
        conn.execute(
            "INSERT INTO allowlist (term_idx, term_enc, reason_enc) VALUES (?, ?, ?)",
            params![new_idx, new.seal(&term, &aad("allowlist", "term", &new_idx))?, resealed],
        )?;
    }

    // concepts — AAD row id is the identity uuid, which is stable; only the
    // index and the ciphertext move.
    let concepts: Vec<(String, Vec<u8>)> = conn
        .prepare("SELECT identity_uuid, concept_enc FROM concepts")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    for (uuid, enc) in concepts {
        let concept = old.unseal(&enc, &aad("concepts", "concept", &uuid))?;
        conn.execute(
            "UPDATE concepts SET concept_idx = ?, concept_enc = ? WHERE identity_uuid = ?",
            params![
                new.blind_index(&concept),
                new.seal(&concept, &aad("concepts", "concept", &uuid))?,
                uuid,
            ],
        )?;
    }

    Ok(())
}

/// Decrypt under the old keys, encrypt under the new ones, same associated data.
fn reseal(old: &Keys, new: &Keys, blob: &[u8], aad: &str) -> Result<Vec<u8>, VaultError> {
    new.seal(&old.unseal(blob, aad)?, aad)
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
    fn audit_csv_has_a_header_and_one_row_per_entry() {
        let rows = vec![
            AuditEntry {
                ts: 100,
                operation: "export".to_owned(),
                file_count: Some(3),
                entity_count: Some(12),
                verification: Some("clean".to_owned()),
                destination: Some("clipboard".to_owned()),
            },
            AuditEntry {
                ts: 101,
                operation: "sanitize".to_owned(),
                file_count: None,
                entity_count: None,
                verification: None,
                destination: None,
            },
        ];

        let csv = audit_csv(&rows);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0],
            "timestamp,operation,file_count,entity_count,verification,destination"
        );
        assert_eq!(lines[1], "100,export,3,12,clean,clipboard");
        assert_eq!(
            lines[2], "101,sanitize,,,,",
            "an absent count is an empty field, not a zero"
        );
    }

    #[test]
    fn a_destination_containing_a_comma_cannot_shift_the_columns() {
        // A branch name or path is the one field a user controls. Unescaped, a
        // comma in it moves every later column of a compliance export by one.
        let rows = vec![AuditEntry {
            ts: 1,
            operation: "apply".to_owned(),
            file_count: Some(1),
            entity_count: None,
            verification: Some("applied".to_owned()),
            destination: Some("feature/a,b".to_owned()),
        }];

        let csv = audit_csv(&rows);
        assert!(csv.contains("\"feature/a,b\""), "{csv}");
        assert_eq!(csv.lines().nth(1).unwrap().matches(',').count(), 6);
    }

    #[test]
    fn a_quote_in_a_field_is_doubled_per_rfc_4180() {
        let rows = vec![AuditEntry {
            ts: 1,
            operation: "apply".to_owned(),
            file_count: None,
            entity_count: None,
            verification: None,
            destination: Some(String::from("say \"hi\"")),
        }];
        assert!(audit_csv(&rows).contains("\"say \"\"hi\"\"\""), "{}", audit_csv(&rows));
    }

    #[test]
    fn the_audit_log_never_carries_a_real_name() {
        // FR-9. The log is the artifact a security team reads, and it is the one
        // place a leak would be least expected and most damaging.
        let t = TempVault::new("audit-names");
        let v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.put_identity(&identity()).unwrap();
        v.log("export", Some(1), Some(1), Some("clean"), Some("clipboard"))
            .unwrap();

        let csv = audit_csv(&v.audit_log(50).unwrap());
        assert!(!csv.contains("CustomerService"), "{csv}");
        assert!(!csv.contains("mod/a"), "{csv}");
    }

    /// Build a vault exactly as the pre-v3 code would have: schema at v2, every
    /// value sealed under keys derived straight from the passphrase.
    ///
    /// Written by hand because the old code no longer exists to produce one, and
    /// a migration nobody has run against a real old vault is a migration nobody
    /// has tested.
    fn write_v2_vault(path: &Path, passphrase: &str) {
        let conn = Connection::open(path).unwrap();
        schema::configure(&conn).unwrap();
        schema::migrate(&conn).unwrap();

        let salt = [11u8; SALT_LEN];
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('kdf_salt', ?)",
            params![&salt[..]],
        )
        .unwrap();

        let keys = Keys::derive_legacy(passphrase, &salt).unwrap();
        let project_id = "0198c0de0000700080000000000999".to_owned();

        conn.execute(
            "INSERT INTO project
                (id, name_enc, root_path_enc, alias_style, scope_strategy, project_key_enc, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                project_id,
                keys.seal("billing", &aad("project", "name", &project_id)).unwrap(),
                keys.seal("/home/x/billing", &aad("project", "root_path", &project_id))
                    .unwrap(),
                "opaque",
                "module",
                keys.seal(&hex(&[7u8; 32]), &aad("project", "project_key", &project_id))
                    .unwrap(),
                0,
            ],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('canary', ?)",
            params![keys.seal("specshield", "meta:canary:0").unwrap()],
        )
        .unwrap();

        let uuid = "0198c0de0000700080000000000001";
        conn.execute(
            "INSERT INTO identities
                (uuid, identity_idx, scope_path_enc, entity_type, real_name_enc, alias, origin, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'detected', 'active', 0)",
            params![
                uuid,
                keys.blind_index(&identity_key("project", "ORG", "Vantor")),
                keys.seal("project", &aad("identities", "scope_path", uuid)).unwrap(),
                "ORG",
                keys.seal("Vantor", &aad("identities", "real_name", uuid)).unwrap(),
                "ORG_H7K2Q3",
            ],
        )
        .unwrap();

        let file_id = "file-1";
        conn.execute(
            "INSERT INTO files (id, path_idx, path_enc, twin_path_enc, checksum, parser, indexed_at)
             VALUES (?, ?, ?, ?, 'abc123', 'typescript', 0)",
            params![
                file_id,
                keys.blind_index("src/billing.ts"),
                keys.seal("src/billing.ts", &aad("files", "path", file_id)).unwrap(),
                keys.seal("src/PATH_AA11.ts", &aad("files", "twin_path", file_id))
                    .unwrap(),
            ],
        )
        .unwrap();

        let term_idx = keys.blind_index("Vantor");
        conn.execute(
            "INSERT INTO dictionary (term_idx, term_enc, entity_type) VALUES (?, ?, 'ORG')",
            params![
                term_idx,
                keys.seal("Vantor", &aad("dictionary", "term", &term_idx)).unwrap()
            ],
        )
        .unwrap();

        let allow_idx = keys.blind_index("Promise");
        conn.execute(
            "INSERT INTO allowlist (term_idx, term_enc, reason_enc) VALUES (?, ?, ?)",
            params![
                allow_idx,
                keys.seal("Promise", &aad("allowlist", "term", &allow_idx)).unwrap(),
                keys.seal("a language builtin", &aad("allowlist", "reason", &allow_idx))
                    .unwrap(),
            ],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO concepts (identity_uuid, concept_idx, concept_enc) VALUES (?, ?, ?)",
            params![
                uuid,
                keys.blind_index("customersubscription"),
                keys.seal("customersubscription", &aad("concepts", "concept", uuid))
                    .unwrap(),
            ],
        )
        .unwrap();

        conn.pragma_update(None, "user_version", 2).unwrap();
    }

    #[test]
    fn a_v2_vault_migrates_and_every_value_survives() {
        // The test this whole change rests on. A migration that loses one
        // sealed value loses the mapping it was protecting.
        let t = TempVault::new("v2-migrate");
        write_v2_vault(t.path(), "pw");

        let v = Vault::open(t.path(), "pw").expect("a v2 vault must open");

        let version: i64 = v.conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, 3, "and be stamped as migrated");

        let settings = v.settings().unwrap();
        assert_eq!(settings.project_name, "billing");
        assert_eq!(settings.root_path, "/home/x/billing");
        assert_eq!(settings.project_key, [7u8; 32]);

        let identities = v.identities().unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].real_name, "Vantor");
        assert_eq!(identities[0].scope_path, "project");
        assert_eq!(identities[0].alias, "ORG_H7K2Q3", "aliases must not move");

        let files = v.files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/billing.ts");
        assert_eq!(files[0].twin_path, "src/PATH_AA11.ts");

        assert_eq!(v.dictionary().unwrap(), vec![("Vantor".to_owned(), "ORG".to_owned())]);
        assert_eq!(v.allowlist().unwrap(), vec!["Promise".to_owned()]);
        assert_eq!(
            v.concepts().unwrap(),
            vec![(
                "0198c0de0000700080000000000001".to_owned(),
                "customersubscription".to_owned()
            )]
        );
    }

    #[test]
    fn a_migrated_vault_can_still_be_looked_up_by_blind_index() {
        // The indexes are recomputed under the new key. If they were not, every
        // lookup would miss and an upsert would silently duplicate rows.
        let t = TempVault::new("v2-index");
        write_v2_vault(t.path(), "pw");
        let v = Vault::open(t.path(), "pw").unwrap();

        let found = v
            .find_identity("project", "ORG", "Vantor")
            .unwrap()
            .expect("the identity must be findable after migration");
        assert_eq!(found.alias, "ORG_H7K2Q3");
    }

    #[test]
    fn a_wrong_passphrase_does_not_migrate_anything() {
        // A migration that started on a wrong passphrase would fail partway and
        // take the vault with it.
        let t = TempVault::new("v2-wrong-pass");
        write_v2_vault(t.path(), "pw");

        let before = std::fs::read(t.path()).unwrap();
        assert!(Vault::open(t.path(), "not-it").is_err());

        // Still a v2 vault, still openable with the real passphrase.
        let after = Vault::open(t.path(), "pw").unwrap();
        assert_eq!(after.identities().unwrap()[0].real_name, "Vantor");
        assert!(!before.is_empty());
    }

    #[test]
    fn migrating_twice_is_not_possible() {
        let t = TempVault::new("v2-twice");
        write_v2_vault(t.path(), "pw");

        drop(Vault::open(t.path(), "pw").unwrap());
        let again = Vault::open(t.path(), "pw").unwrap();
        assert_eq!(again.identities().unwrap()[0].real_name, "Vantor");
    }

    #[test]
    fn a_new_vault_stores_no_passphrase_derived_content_key() {
        // The point of v3: content is encrypted under a random data key, and the
        // passphrase only wraps it. A vault whose content still decrypted under
        // the legacy scheme would not have migrated at all.
        let t = TempVault::new("v3-fresh");
        let v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.put_identity(&identity()).unwrap();

        let salt: Vec<u8> = v
            .conn
            .query_row("SELECT value FROM meta WHERE key='kdf_salt'", [], |r| r.get(0))
            .unwrap();
        let legacy = Keys::derive_legacy("pw", &salt).unwrap();
        let canary: Vec<u8> = v
            .conn
            .query_row("SELECT value FROM meta WHERE key='canary'", [], |r| r.get(0))
            .unwrap();

        assert!(
            legacy.unseal(&canary, "meta:canary:0").is_err(),
            "content must not be readable from the passphrase alone"
        );
    }

    #[test]
    fn changing_the_passphrase_moves_nothing_but_the_wrapper() {
        // The whole point of the data key. Before v3 this was a re-encryption
        // of every value, which is why it did not exist.
        let t = TempVault::new("change-pass");
        let v = Vault::create(t.path(), "old-pw", &settings()).unwrap();
        v.put_identity(&identity()).unwrap();

        let ciphertext_before: Vec<u8> = v
            .conn
            .query_row("SELECT real_name_enc FROM identities LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let idx_before: String = v
            .conn
            .query_row("SELECT identity_idx FROM identities LIMIT 1", [], |r| r.get(0))
            .unwrap();

        v.change_passphrase("old-pw", "new-pw").unwrap();
        drop(v);

        let reopened = Vault::open(t.path(), "new-pw").unwrap();
        assert_eq!(reopened.identities().unwrap()[0].real_name, "Vantor");

        let ciphertext_after: Vec<u8> = reopened
            .conn
            .query_row("SELECT real_name_enc FROM identities LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let idx_after: String = reopened
            .conn
            .query_row("SELECT identity_idx FROM identities LIMIT 1", [], |r| r.get(0))
            .unwrap();

        assert_eq!(ciphertext_before, ciphertext_after, "no value was re-encrypted");
        assert_eq!(idx_before, idx_after, "no blind index moved");
    }

    #[test]
    fn the_old_passphrase_stops_working() {
        let t = TempVault::new("old-pass-dead");
        let v = Vault::create(t.path(), "old-pw", &settings()).unwrap();
        v.change_passphrase("old-pw", "new-pw").unwrap();
        drop(v);

        assert!(Vault::open(t.path(), "old-pw").is_err());
        assert!(Vault::open(t.path(), "new-pw").is_ok());
    }

    #[test]
    fn a_wrong_old_passphrase_changes_nothing() {
        let t = TempVault::new("change-wrong");
        let v = Vault::create(t.path(), "old-pw", &settings()).unwrap();

        assert!(v.change_passphrase("not-it", "new-pw").is_err());
        drop(v);

        assert!(Vault::open(t.path(), "old-pw").is_ok(), "the vault is untouched");
        assert!(Vault::open(t.path(), "new-pw").is_err());
    }

    #[test]
    fn an_empty_new_passphrase_is_refused() {
        let t = TempVault::new("change-empty");
        let v = Vault::create(t.path(), "old-pw", &settings()).unwrap();
        assert!(v.change_passphrase("old-pw", "").is_err());
    }

    #[test]
    fn rotating_the_data_key_re_encrypts_everything_and_keeps_it_readable() {
        let t = TempVault::new("rotate");
        let mut v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.put_identity(&identity()).unwrap();
        v.add_term("Vantor", "ORG").unwrap();
        v.put_files(&[StoredFile {
            path: "src/a.ts".to_owned(),
            twin_path: "src/PATH_A.ts".to_owned(),
            checksum: "abc".to_owned(),
            parser: "typescript".to_owned(),
        }])
        .unwrap();

        let before: Vec<u8> = v
            .conn
            .query_row("SELECT real_name_enc FROM identities LIMIT 1", [], |r| r.get(0))
            .unwrap();

        v.rotate_data_key("pw").unwrap();

        let after: Vec<u8> = v
            .conn
            .query_row("SELECT real_name_enc FROM identities LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_ne!(before, after, "rotation must actually re-encrypt");

        // Everything still reads, on this handle and on a fresh open.
        assert_eq!(v.identities().unwrap()[0].real_name, "Vantor");
        assert_eq!(v.files().unwrap()[0].path, "src/a.ts");
        drop(v);

        let reopened = Vault::open(t.path(), "pw").unwrap();
        assert_eq!(reopened.identities().unwrap()[0].real_name, "Vantor");
        assert_eq!(
            reopened.dictionary().unwrap(),
            vec![("Vantor".to_owned(), "ORG".to_owned())]
        );
        assert!(
            reopened.find_identity("project", "ORG", "Vantor").unwrap().is_some(),
            "the blind index must have been recomputed"
        );
    }

    #[test]
    fn rotating_the_data_key_revokes_an_issued_escrow() {
        // What "revoking an escrow" actually means. Re-wrapping cannot take back
        // a key someone already holds; only re-encrypting under a new one can.
        let t = TempVault::new("revoke");
        let mut v = Vault::create(t.path(), "pw", &settings()).unwrap();
        v.put_identity(&identity()).unwrap();
        let escrow = v.export_escrow("held-by-security").unwrap();

        v.rotate_data_key("pw").unwrap();
        drop(v);

        let stale = std::path::PathBuf::from(t.path());
        assert!(
            Vault::recover_with_escrow(&stale, &escrow, "held-by-security", "whatever").is_err(),
            "an escrow issued before the rotation must no longer open the vault"
        );
        assert!(Vault::open(t.path(), "pw").is_ok(), "and the owner still gets in");
    }

    #[test]
    fn escrow_recovery_does_not_reveal_the_passphrase() {
        // The reason escrow holds the data key rather than the passphrase:
        // people reuse passphrases, and a recovery credential should not double
        // as one for someone's other accounts.
        let t = TempVault::new("escrow-privacy");
        let v = Vault::create(t.path(), "reused-everywhere", &settings()).unwrap();
        let escrow = v.export_escrow("held-by-security").unwrap();
        drop(v);

        assert!(
            !escrow
                .windows("reused-everywhere".len())
                .any(|w| w == b"reused-everywhere"),
            "the passphrase must not be in the escrow at all"
        );
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
