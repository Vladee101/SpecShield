//! The two side tables an export fills in — PRD FR-5 (`occurrences`) and
//! SDD §4.3 (`redactions`). **P3-5.**
//!
//! Both existed in the schema from v1 with no writer. These tests are about the
//! properties that make a writer worth having: that what is recorded points at
//! the user's own files, that it stops describing things that have gone, and
//! that the one-way index does the one job it is for.

use std::path::{Path, PathBuf};

use specshield_project as project;
use specshield_vault::{Settings, Vault};

/// A throwaway project tree with a vault in it.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let mut root = std::env::temp_dir();
        root.push(format!("specshield-sides-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();

        let fixture = Self { root };
        let vault = Vault::create(&fixture.vault_path(), "pw", &fixture.settings()).unwrap();
        // Named, because a DTO is not aliased on its own any more (PRD §4.1).
        // These tests are about the occurrence and redaction tables, and both
        // need something actually aliased to record.
        vault.add_term("CustomerInvoice", "DTO").unwrap();
        drop(vault);
        fixture
    }

    fn settings(&self) -> Settings {
        Settings {
            project_name: "sides".to_owned(),
            root_path: self.root.display().to_string(),
            alias_style: "opaque".to_owned(),
            scope_strategy: "module".to_owned(),
            project_key: [3; 32],
        }
    }

    fn vault_path(&self) -> PathBuf {
        self.root.join(".specshield").join("vault.bin")
    }

    fn vault(&self) -> Vault {
        Vault::open(&self.vault_path(), "pw").unwrap()
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn remove(&self, relative: &str) {
        std::fs::remove_file(self.root.join(relative)).unwrap();
    }

    /// Export into a fresh directory each time — `export` refuses to write into
    /// one that exists, which is deliberate.
    fn export(&self, attempt: u32) -> project::Exported {
        let dest = self.root.parent().unwrap().join(format!(
            "{}-twin-{attempt}",
            self.root.file_name().unwrap().to_string_lossy()
        ));
        let _ = std::fs::remove_dir_all(&dest);
        let mut vault = self.vault();
        project::export(&self.root, &dest, &mut vault, false).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
        if let Some(parent) = self.root.parent() {
            for attempt in 0..4 {
                let name = format!("{}-twin-{attempt}", self.root.file_name().unwrap().to_string_lossy());
                let _ = std::fs::remove_dir_all(parent.join(name));
            }
        }
    }
}

const TOKEN: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbb";

fn slice(root: &Path, relative: &str, start: usize, end: usize) -> String {
    let text = std::fs::read_to_string(root.join(relative)).unwrap();
    text[start..end].to_owned()
}

#[test]
fn a_recorded_occurrence_slices_the_user_s_own_file() {
    // The property that makes the table useful at all. The alias pass runs over
    // text in which secrets have already become markers of a different length,
    // so an offset taken straight from it points into a string that exists
    // nowhere on disk.
    let f = Fixture::new("slices");
    f.write(
        "src/config.ts",
        &format!("const TOKEN = \"{TOKEN}\";\nexport interface CustomerInvoice {{ id: string }}\n"),
    );

    let exported = f.export(0);
    assert!(!exported.is_blocked());
    assert!(exported.occurrences > 0, "something must have been recorded");

    let vault = f.vault();
    let found = project::locate(&vault, "CustomerInvoice").unwrap();
    let invoice = found.first().expect("CustomerInvoice is in the vault");
    let first = invoice.appearances.first().expect("and was seen somewhere");

    assert_eq!(
        slice(&f.root, &first.path, first.byte_start, first.byte_end),
        "CustomerInvoice",
        "the recorded span must slice the real file, past a redacted secret"
    );
}

#[test]
fn locate_answers_to_the_alias_as_well_as_the_name() {
    // The direction that matters when a model hands back a reply full of
    // aliases: what was this, and where did it come from.
    let f = Fixture::new("alias");
    f.write("src/domain.ts", "export interface CustomerInvoice { id: string }\n");
    f.export(0);

    let vault = f.vault();
    let by_name = project::locate(&vault, "customerinvoice").unwrap();
    assert_eq!(by_name.len(), 1, "real names match ignoring case");

    let alias = by_name[0].alias.clone();
    let by_alias = project::locate(&vault, &alias).unwrap();
    assert_eq!(by_alias.len(), 1);
    assert_eq!(by_alias[0].real_name, "CustomerInvoice");

    assert!(
        project::locate(&vault, &alias.to_lowercase()).unwrap().is_empty(),
        "an alias is issued, not remembered: a near miss is not a typo"
    );
}

#[test]
fn a_name_a_file_stopped_using_stops_being_reported() {
    // An upsert alone would leave the old row standing forever, and a stale
    // occurrence does not point at nothing — it points at whatever moved into
    // that offset.
    let f = Fixture::new("stale");
    f.write(
        "src/domain.ts",
        "export interface CustomerInvoice { id: string }\nexport const other: CustomerInvoice = { id: \"1\" };\n",
    );
    f.export(0);

    let vault = f.vault();
    let before = project::locate(&vault, "CustomerInvoice").unwrap()[0].appearances.len();
    assert!(before >= 2);
    drop(vault);

    f.write("src/domain.ts", "export interface CustomerInvoice { id: string }\n");
    f.export(1);

    let vault = f.vault();
    let after = project::locate(&vault, "CustomerInvoice").unwrap()[0].appearances.len();
    assert!(after < before, "{after} occurrences must be fewer than {before}");
}

#[test]
fn the_one_way_index_tells_a_returning_secret_from_a_new_one() {
    // The entire purpose of `match_idx`, and the only thing it can do.
    let f = Fixture::new("known");
    f.write("src/config.ts", &format!("const TOKEN = \"{TOKEN}\";\n"));

    let first = f.export(0);
    assert_eq!(first.redacted, 1);
    assert_eq!(first.redacted_new, 1, "never seen before");

    let second = f.export(1);
    assert_eq!(second.redacted, 1);
    assert_eq!(second.redacted_new, 0, "the same credential, still here");

    f.write(
        "src/config.ts",
        &format!("const TOKEN = \"{TOKEN}\";\nconst OTHER = \"ghp_cccccccccccccccccccccccccccccdddd\";\n"),
    );
    let third = f.export(2);
    assert_eq!(third.redacted, 2);
    assert_eq!(third.redacted_new, 1, "one of the two is new");
}

#[test]
fn deleting_a_file_stops_the_vault_describing_it() {
    // Found by running the thing: `rescan` forgot deleted files and `export`
    // did not, so `specshield secrets` went on naming a file that was gone —
    // with no line number, because there was no longer a file to count lines in.
    let f = Fixture::new("deleted");
    f.write("src/config.ts", &format!("const TOKEN = \"{TOKEN}\";\n"));
    f.write("src/domain.ts", "export interface CustomerInvoice { id: string }\n");

    f.export(0);
    assert_eq!(project::secret_sites(&f.vault()).unwrap().len(), 1);

    f.remove("src/config.ts");
    f.export(1);

    assert!(
        project::secret_sites(&f.vault()).unwrap().is_empty(),
        "a secret in a file that no longer exists is not a secret this project has"
    );
}

#[test]
fn a_rescan_does_not_throw_away_the_twin_path_mapping() {
    // Found by running the thing, and the worst defect this work turned up:
    // `files.twin_path` is the only record of where an exported file went, and
    // `restore_project` is the only thing that can put it back. Both `index` and
    // `rescan` used to overwrite the column with the real path, so a routine
    // rescan silently orphaned every twin tree already produced — restore found
    // no mapping and left each file sitting at its alias name.
    // A compound filename, so path aliasing actually renames it.
    let f = Fixture::new("twinpath");
    f.write(
        "src/customer-subscription.ts",
        "export interface CustomerSubscription { id: string }\n",
    );
    f.export(0);

    let exported: Vec<(String, String)> = f
        .vault()
        .files()
        .unwrap()
        .into_iter()
        .map(|file| (file.path, file.twin_path))
        .collect();
    assert!(
        exported.iter().any(|(path, twin)| path != twin),
        "the fixture must actually get a renamed path, or this proves nothing"
    );

    let mut vault = f.vault();
    project::rescan_project(&f.root, &mut vault).unwrap();
    drop(vault);

    let after: Vec<(String, String)> = f
        .vault()
        .files()
        .unwrap()
        .into_iter()
        .map(|file| (file.path, file.twin_path))
        .collect();
    assert_eq!(
        after, exported,
        "walking the project is a read; it must not undo an export"
    );
}

#[test]
fn a_position_is_none_rather_than_wrong_when_the_file_has_moved_on() {
    // Occurrences are byte offsets into the file as it was at the last export.
    // A file that has since been edited or deleted cannot yield a position, and
    // a confidently wrong line number is worse than an absent one: the reader
    // has no way to tell which they got.
    let f = Fixture::new("position");
    f.write("src/domain.ts", "export interface CustomerInvoice { id: string }\n");

    assert_eq!(
        project::line_and_column(&f.root, "src/domain.ts", 17),
        Some((1, 18)),
        "one-indexed line and column, counting characters"
    );
    assert_eq!(project::line_and_column(&f.root, "src/gone.ts", 0), None);
    assert_eq!(
        project::line_and_column(&f.root, "src/domain.ts", 9_000),
        None,
        "an offset the file no longer covers"
    );
}
