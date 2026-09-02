//! Read-only recovery mode — SDD §16. **M6.**
//!
//! A vault that will not open is the worst moment this product has. The mapping
//! is the only way back from a twin, there is no recovery of the passphrase by
//! design, and a flat refusal tells the user nothing about what they still have.
//!
//! So: open what can be opened, say plainly what is wrong, and write nothing.
//!
//! **Read-only by construction, not by a flag.** This type has no write methods
//! at all, so §16's "no destructive operations are permitted" is a property of
//! the API rather than a check somebody might forget. It also never opens the
//! database read-write — SQLite would otherwise be free to roll back a hot
//! journal or rewrite a WAL on a file that is already damaged.
//!
//! What survives without the passphrase is exactly what is stored in the clear:
//! aliases, entity types, origins, statuses, checksums, and the audit log. Every
//! real name is sealed and stays sealed. That is enough to answer the questions
//! a user actually has — how much was in here, what did it issue, when was it
//! last used — without weakening anything.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::{AuditEntry, SCHEMA_VERSION, VaultError};

/// A damaged or unopenable vault, opened for inspection only.
#[derive(Debug)]
pub struct Recovery {
    conn: Option<Connection>,
    diagnosis: String,
    schema_version: Option<i64>,
}

impl Recovery {
    /// Open a vault for inspection, whatever state it is in.
    ///
    /// Deliberately hard to fail. A missing file is the one thing that is not a
    /// recovery case — there is nothing to inspect — and everything else comes
    /// back as a `Recovery` carrying a diagnosis, because "here is what I can
    /// still read and here is what is wrong" beats an error string every time.
    pub fn open(path: &Path) -> Result<Self, VaultError> {
        if !path.exists() {
            return Err(VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} does not exist", path.display()),
            )));
        }

        // Read-only, and no journal recovery: a damaged file must not be
        // rewritten by the act of looking at it.
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
        let uri = format!("file:{}?immutable=1", path.display().to_string().replace('?', "%3f"));

        let Ok(conn) = Connection::open_with_flags(&uri, flags) else {
            return Ok(Self {
                conn: None,
                diagnosis: "the file could not be opened as a database at all — it is not a SpecShield vault, or it is damaged beyond the point where its structure can be read".to_owned(),
                schema_version: None,
            });
        };

        // A file of arbitrary bytes opens without complaint; the first real
        // query is what discovers it is not a database.
        let integrity: Result<String, _> = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0));
        let schema_version: Option<i64> = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).ok();

        let diagnosis = match integrity {
            Err(_) => {
                return Ok(Self {
                    conn: None,
                    diagnosis: "not a SpecShield vault: the file is not a readable SQLite database".to_owned(),
                    schema_version: None,
                });
            }
            Ok(report) if report != "ok" => {
                format!("the database is corrupt — SQLite reports: {report}")
            }
            Ok(_) => match schema_version {
                Some(version) if version > SCHEMA_VERSION => format!(
                    "written by schema version {version}; this build understands {SCHEMA_VERSION}. Upgrade SpecShield rather than opening it here."
                ),
                Some(0) | None => "the file is a database but carries no SpecShield schema".to_owned(),
                Some(_) => {
                    "the database itself is intact — if it will not open normally, the passphrase is wrong. There is no recovery of a lost passphrase; restore from a backup or an escrow export.".to_owned()
                }
            },
        };

        Ok(Self {
            conn: Some(conn),
            diagnosis,
            schema_version,
        })
    }

    /// What is wrong, in words meant for the person holding the broken vault.
    #[must_use]
    pub fn diagnosis(&self) -> &str {
        &self.diagnosis
    }

    /// The schema version, if the file has one.
    #[must_use]
    pub const fn schema_version(&self) -> Option<i64> {
        self.schema_version
    }

    /// Whether any structured content could be read at all.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.conn.is_some()
    }

    /// How many identities the vault holds.
    ///
    /// The number a user most wants: it says how much mapping is at stake.
    #[must_use]
    pub fn identity_count(&self) -> usize {
        self.count("identities")
    }

    #[must_use]
    pub fn file_count(&self) -> usize {
        self.count("files")
    }

    /// Every alias the project ever issued.
    ///
    /// Stored in the clear because uniqueness has to be enforceable over
    /// ciphertext (SDD §9.1), and useful here for exactly that reason: a user
    /// can tell which twins were produced by this vault even when nothing can
    /// be mapped back.
    #[must_use]
    pub fn aliases(&self) -> Vec<String> {
        self.strings("SELECT alias FROM identities ORDER BY alias")
    }

    /// Entity type and count, so the shape of what was lost is visible.
    #[must_use]
    pub fn entity_types(&self) -> Vec<(String, usize)> {
        let Some(conn) = &self.conn else {
            return Vec::new();
        };
        let Ok(mut stmt) =
            conn.prepare("SELECT entity_type, COUNT(*) FROM identities GROUP BY entity_type ORDER BY entity_type")
        else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                usize::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
            ))
        }) else {
            return Vec::new();
        };
        rows.filter_map(Result::ok).collect()
    }

    /// The audit log — PRD FR-9. Holds no names and no content, so it survives
    /// the loss of the key intact.
    #[must_use]
    pub fn audit_log(&self, limit: usize) -> Vec<AuditEntry> {
        let Some(conn) = &self.conn else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT ts, operation, file_count, entity_count, verification, destination
             FROM audit_log ORDER BY id DESC LIMIT ?",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
            Ok(AuditEntry {
                ts: r.get(0)?,
                operation: r.get(1)?,
                file_count: r.get(2)?,
                entity_count: r.get(3)?,
                verification: r.get(4)?,
                destination: r.get(5)?,
            })
        }) else {
            return Vec::new();
        };
        rows.filter_map(Result::ok).collect()
    }

    fn count(&self, table: &str) -> usize {
        let Some(conn) = &self.conn else {
            return 0;
        };
        // `table` is a literal from this module, never user input.
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0))
            .map_or(0, |n| usize::try_from(n).unwrap_or(0))
    }

    fn strings(&self, sql: &str) -> Vec<String> {
        let Some(conn) = &self.conn else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(sql) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) else {
            return Vec::new();
        };
        rows.filter_map(Result::ok).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Settings, Vault};

    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(name: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!("specshield-recovery-{name}-{}.bin", std::process::id()));
            let _ = std::fs::remove_file(&p);
            Self(p)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn settings() -> Settings {
        Settings {
            project_name: "t".to_owned(),
            root_path: "/tmp/t".to_owned(),
            alias_style: "opaque".to_owned(),
            scope_strategy: "module".to_owned(),
            project_key: [7; 32],
        }
    }

    #[test]
    fn a_file_of_garbage_is_diagnosed_rather_than_refused() {
        let file = TempFile::new("garbage");
        std::fs::write(file.path(), b"this is not a vault at all").unwrap();

        let recovery = Recovery::open(file.path()).expect("recovery must not be a dead end");
        assert!(!recovery.is_readable());
        assert!(
            recovery.diagnosis().contains("not a SpecShield vault"),
            "{}",
            recovery.diagnosis()
        );
        assert_eq!(recovery.identity_count(), 0);
    }

    #[test]
    fn a_healthy_vault_reports_what_it_holds_without_the_passphrase() {
        let file = TempFile::new("healthy");
        let vault = Vault::create(file.path(), "pw", &settings()).unwrap();
        vault
            .put_identity(&crate::StoredIdentity {
                uuid: "0198c0de0000700080000000000001".to_owned(),
                scope_path: "mod/a".to_owned(),
                entity_type: "SERVICE".to_owned(),
                real_name: "CustomerService".to_owned(),
                alias: "SERVICE_H7K2Q3".to_owned(),
                origin: "detected".to_owned(),
                status: "active".to_owned(),
            })
            .unwrap();
        drop(vault);

        let recovery = Recovery::open(file.path()).expect("recovery");
        assert!(recovery.is_readable());
        assert_eq!(recovery.identity_count(), 1);
        assert_eq!(recovery.aliases(), vec!["SERVICE_H7K2Q3"]);
        assert_eq!(recovery.entity_types(), vec![("SERVICE".to_owned(), 1)]);
        assert_eq!(recovery.schema_version(), Some(SCHEMA_VERSION));
        assert!(
            recovery.diagnosis().contains("passphrase is wrong"),
            "an intact file that will not open is a passphrase problem, and saying so is the \
             whole value of recovery mode: {}",
            recovery.diagnosis()
        );
    }

    #[test]
    fn no_real_name_is_readable_without_the_key() {
        // The point of recovery mode is to be useful without being a bypass.
        let file = TempFile::new("sealed");
        let vault = Vault::create(file.path(), "pw", &settings()).unwrap();
        vault
            .put_identity(&crate::StoredIdentity {
                uuid: "0198c0de0000700080000000000002".to_owned(),
                scope_path: "mod/a".to_owned(),
                entity_type: "ORG".to_owned(),
                real_name: "MeridianFreight".to_owned(),
                alias: "ORG_ZZ11YY".to_owned(),
                origin: "detected".to_owned(),
                status: "active".to_owned(),
            })
            .unwrap();
        drop(vault);

        let recovery = Recovery::open(file.path()).expect("recovery");
        let everything = format!(
            "{:?}{:?}{:?}{}",
            recovery.aliases(),
            recovery.entity_types(),
            recovery.audit_log(100),
            recovery.diagnosis()
        );
        assert!(
            !everything.contains("MeridianFreight"),
            "recovery mode must not become a way around the passphrase"
        );
    }

    #[test]
    fn the_audit_log_survives_the_loss_of_the_key() {
        // FR-9: it holds no names and no content, so it is readable when
        // nothing else is — which is what a security team needs after an
        // incident.
        let file = TempFile::new("audit");
        let vault = Vault::create(file.path(), "pw", &settings()).unwrap();
        vault
            .log("export", Some(3), Some(12), Some("clean"), Some("clipboard"))
            .unwrap();
        drop(vault);

        let recovery = Recovery::open(file.path()).expect("recovery");
        let entries = recovery.audit_log(10);
        assert!(entries.iter().any(|e| e.operation == "export"), "{entries:#?}");
    }

    #[test]
    fn opening_for_recovery_does_not_modify_the_file() {
        // §16: no destructive operations are permitted. SQLite will rewrite a
        // damaged file to recover a journal given half a chance, and the one
        // thing a user in this position cannot afford is for inspection to
        // change what they are inspecting.
        let file = TempFile::new("untouched");
        let vault = Vault::create(file.path(), "pw", &settings()).unwrap();
        drop(vault);

        let before = std::fs::read(file.path()).unwrap();
        let recovery = Recovery::open(file.path()).expect("recovery");
        let _ = recovery.identity_count();
        let _ = recovery.audit_log(10);
        let after = std::fs::read(file.path()).unwrap();

        assert_eq!(before, after, "inspection rewrote the vault");
    }

    #[test]
    fn a_missing_file_is_not_a_recovery_case() {
        let file = TempFile::new("absent");
        assert!(Recovery::open(file.path()).is_err());
    }
}
