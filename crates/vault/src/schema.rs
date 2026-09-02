//! Vault schema and migrations — SDD §9.1, §9.3.
//!
//! `PRAGMA user_version` drives the migration runner, present from the first
//! release. Retrofitting migrations onto an encrypted store is painful, and the
//! alias grammar is part of the versioned contract.
//!
//! Columns ending `_enc` hold AES-256-GCM ciphertext; the matching `_idx`
//! column holds the blind index that makes the value searchable and uniquely
//! constrainable. See [`crate::crypto`].

use rusqlite::Connection;

use crate::VaultError;

/// Current schema version. Bump *and* add a migration; never edit V1 in place.
pub const SCHEMA_VERSION: i64 = 3;

const V1: &str = r"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE project (
    id             TEXT PRIMARY KEY,
    name_enc       BLOB NOT NULL,
    root_path_enc  BLOB NOT NULL,
    alias_style    TEXT NOT NULL,
    scope_strategy TEXT NOT NULL,
    project_key_enc BLOB NOT NULL,
    created_at     INTEGER NOT NULL
);

-- Identity: the mapping that must never leave the machine.
-- `identity_idx` is HMAC(index_key, scope || 0x1F || type || 0x1F || name);
-- it is what makes the SDD §5 uniqueness constraint enforceable over
-- ciphertext.
CREATE TABLE identities (
    uuid           TEXT PRIMARY KEY,
    identity_idx   TEXT NOT NULL,
    scope_path_enc BLOB NOT NULL,
    entity_type    TEXT NOT NULL,
    real_name_enc  BLOB NOT NULL,
    alias          TEXT NOT NULL,
    origin         TEXT NOT NULL,
    status         TEXT NOT NULL,
    created_at     INTEGER NOT NULL
);
CREATE UNIQUE INDEX ux_identity ON identities(identity_idx);
CREATE UNIQUE INDEX ux_alias    ON identities(alias);

CREATE TABLE files (
    id            TEXT PRIMARY KEY,
    path_idx      TEXT NOT NULL,
    path_enc      BLOB NOT NULL,
    twin_path_enc BLOB NOT NULL,
    checksum      TEXT NOT NULL,
    parser        TEXT NOT NULL,
    indexed_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX ux_file_path ON files(path_idx);

-- PRD FR-5. Byte offsets are not secret on their own: without the names they
-- describe nothing.
CREATE TABLE occurrences (
    identity_uuid TEXT NOT NULL REFERENCES identities(uuid) ON DELETE CASCADE,
    file_id       TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    byte_start    INTEGER NOT NULL,
    byte_end      INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    PRIMARY KEY (file_id, byte_start)
);
CREATE INDEX ix_occurrence_identity ON occurrences(identity_uuid);

CREATE TABLE edges (
    from_uuid TEXT NOT NULL REFERENCES identities(uuid) ON DELETE CASCADE,
    to_uuid   TEXT NOT NULL REFERENCES identities(uuid) ON DELETE CASCADE,
    relation  TEXT NOT NULL,
    PRIMARY KEY (from_uuid, to_uuid, relation)
);

-- One-way. Holds no plaintext and no way back to it: `match_idx` exists only so
-- a rescan recognises a secret it has already seen.
CREATE TABLE redactions (
    id          TEXT PRIMARY KEY,
    file_id     TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    byte_start  INTEGER NOT NULL,
    byte_end    INTEGER NOT NULL,
    secret_type TEXT NOT NULL,
    match_idx   TEXT NOT NULL
);

-- PRD FR-10: the terms only the user can name.
CREATE TABLE dictionary (
    term_idx    TEXT PRIMARY KEY,
    term_enc    BLOB NOT NULL,
    entity_type TEXT NOT NULL
);

CREATE TABLE allowlist (
    term_idx   TEXT PRIMARY KEY,
    term_enc   BLOB NOT NULL,
    reason_enc BLOB
);

-- PRD FR-9. Local, append-only, never transmitted. Records that an export
-- happened and whether it verified — never what was in it.
CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    operation    TEXT NOT NULL,
    file_count   INTEGER,
    entity_count INTEGER,
    verification TEXT,
    destination  TEXT
);
";

/// Confirmed cross-artifact unifications — SDD §5.
///
/// Added in v2 rather than folded into V1: a vault written by the previous
/// build must upgrade, not be rejected, and editing V1 in place would leave
/// those vaults with no migration path.
const V2: &str = r"
CREATE TABLE concepts (
    identity_uuid TEXT PRIMARY KEY REFERENCES identities(uuid) ON DELETE CASCADE,
    concept_idx   TEXT NOT NULL,
    concept_enc   BLOB NOT NULL
);
CREATE INDEX ix_concept ON concepts(concept_idx);
";

/// The highest version this function can reach on its own.
///
/// v3 is not a DDL change. It re-encrypts every sealed value under a new data
/// key, which needs the passphrase, so `Vault::open` performs it and stamps the
/// version — see `crate::migrate_to_v3`. A vault that still reads 2 after this
/// runs is one waiting for that step.
const DDL_VERSION: i64 = 2;

/// Create or upgrade the schema.
pub(crate) fn migrate(conn: &Connection) -> Result<(), VaultError> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    if version > SCHEMA_VERSION {
        return Err(VaultError::VersionMismatch { found: version });
    }
    if version >= DDL_VERSION {
        return Ok(());
    }

    if version < 1 {
        conn.execute_batch(V1)?;
    }
    if version < 2 {
        conn.execute_batch(V2)?;
    }
    // Future DDL migrations append here, each guarded by `if version < N`.

    conn.pragma_update(None, "user_version", DDL_VERSION)?;
    Ok(())
}

/// Applied to every connection.
pub(crate) fn configure(conn: &Connection) -> Result<(), VaultError> {
    // WAL keeps readers from blocking the writer, and `foreign_keys` is off by
    // default in SQLite — without it the cascades above are decoration.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        configure(&c).unwrap();
        migrate(&c).unwrap();
        c
    }

    #[test]
    fn migration_creates_every_table() {
        let c = conn();
        let mut stmt = c
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        let tables: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|t| !t.starts_with("sqlite_"))
            .collect();

        for expected in [
            "allowlist",
            "audit_log",
            "concepts",
            "dictionary",
            "edges",
            "files",
            "identities",
            "meta",
            "occurrences",
            "project",
            "redactions",
        ] {
            assert!(tables.contains(&expected.to_owned()), "missing {expected}: {tables:?}");
        }
    }

    #[test]
    fn migration_is_idempotent() {
        let c = conn();
        migrate(&c).unwrap();
        migrate(&c).unwrap();
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, DDL_VERSION);
    }

    #[test]
    fn the_ddl_migration_stops_short_of_v3() {
        // v3 re-encrypts every sealed value under a new data key, which needs
        // the passphrase. `Vault::create` and `Vault::open` stamp it; this
        // function cannot, and must not pretend to — a vault marked v3 whose
        // content is still encrypted the old way would never open again.
        let c = conn();
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, DDL_VERSION);
        assert_ne!(DDL_VERSION, SCHEMA_VERSION, "v3 is not reachable by DDL alone");
    }

    #[test]
    fn a_newer_vault_is_refused_rather_than_misread() {
        let c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "user_version", SCHEMA_VERSION + 5).unwrap();
        assert!(matches!(migrate(&c), Err(VaultError::VersionMismatch { .. })));
    }

    #[test]
    fn duplicate_identity_keys_are_rejected() {
        // The SDD §5 uniqueness constraint, enforced over ciphertext via the
        // blind index.
        let c = conn();
        let insert = "INSERT INTO identities
             (uuid, identity_idx, scope_path_enc, entity_type, real_name_enc, alias, origin, status, created_at)
             VALUES (?, 'same-hash', x'00', 'SERVICE', x'00', ?, 'detected', 'active', 0)";
        c.execute(insert, rusqlite::params!["u1", "SERVICE_AAA111"]).unwrap();
        assert!(c.execute(insert, rusqlite::params!["u2", "SERVICE_BBB222"]).is_err());
    }

    #[test]
    fn duplicate_aliases_are_rejected() {
        // Two identities sharing an alias would make restore ambiguous — the
        // one failure mode with no safe recovery (SDD §10.4).
        let c = conn();
        let insert = "INSERT INTO identities
             (uuid, identity_idx, scope_path_enc, entity_type, real_name_enc, alias, origin, status, created_at)
             VALUES (?, ?, x'00', 'SERVICE', x'00', 'SERVICE_AAA111', 'detected', 'active', 0)";
        c.execute(insert, rusqlite::params!["u1", "hash-1"]).unwrap();
        assert!(c.execute(insert, rusqlite::params!["u2", "hash-2"]).is_err());
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let c = conn();
        let orphan = c.execute(
            "INSERT INTO occurrences (identity_uuid, file_id, byte_start, byte_end, kind)
             VALUES ('nope', 'nope', 0, 1, 'reference')",
            [],
        );
        assert!(orphan.is_err(), "foreign_keys pragma is not taking effect");
    }
}
