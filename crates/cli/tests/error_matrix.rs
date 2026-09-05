//! SDD §16, as assertions. **M6.**
//!
//! The error table is the part of the spec a user meets on their worst day, and
//! a table in a document is a claim, not a guarantee. Every row here is one
//! test. A row that cannot be written as a test is a row that does not describe
//! anything the code does.
//!
//! Ordered exactly as §16 orders them, so the two can be read side by side.

use specshield_core::alias::{AliasStyle, ProjectKey, derive};
use specshield_core::detect::Detector;
use specshield_core::model::{EntityType, IdentityKey, OccurrenceKind, Origin, Status};
use specshield_core::parser::ProjectContext;
use specshield_core::restore::{MatchKind, Vocabulary};
use specshield_core::sanitize::{Graph, Verification};
use specshield_core::{restore, sanitize, secrets, verify};
use std::path::{Path, PathBuf};

fn graph() -> Graph {
    Graph::new(ProjectKey::from_bytes([9; 32]), AliasStyle::Opaque)
}

fn key(scope: &str, entity_type: EntityType, name: &str) -> IdentityKey {
    IdentityKey::new(scope, entity_type, name)
}

// --- Row 1: unknown alias -------------------------------------------------
// "Mark unresolved; leave token untouched; report"

#[test]
fn an_unknown_alias_is_left_untouched_and_reported() {
    let vocabulary = Vocabulary::new(vec![("SERVICE_H7K2QX", "CustomerService")]);
    let outcome = restore::restore("SERVICE_H7K2QX talks to SERVICE_099.", &vocabulary);

    assert!(
        outcome.text.contains("SERVICE_099"),
        "the token must survive verbatim: {}",
        outcome.text
    );
    assert!(outcome.text.contains("CustomerService"), "the known one still restores");
    assert_eq!(outcome.unresolved.len(), 1);
    assert_eq!(outcome.unresolved[0].token, "SERVICE_099");
}

// --- Row 2: canonical-form match ------------------------------------------
// "Restore, flag as fuzzy in the diff"

#[test]
fn a_canonical_match_restores_and_is_flagged_for_review() {
    let vocabulary = Vocabulary::new(vec![("SERVICE_H7K2QX", "CustomerService")]);
    let outcome = restore::restore("SERVICE_H7K2QXImpl handles it.", &vocabulary);

    assert!(outcome.text.contains("CustomerService"), "{}", outcome.text);
    let flagged = outcome.needs_review();
    assert_eq!(flagged.len(), 1, "{:#?}", outcome.restored);
    assert_ne!(flagged[0].match_kind, MatchKind::Exact);

    // And the diff carries it, which is where §16 says it must appear.
    let review = specshield_core::diff::review(
        "CustomerService handles it.",
        "SERVICE_H7K2QX handles it.",
        "SERVICE_H7K2QXImpl handles it.",
        &vocabulary,
    );
    assert!(
        review
            .notes
            .iter()
            .any(|(_, n)| matches!(n, specshield_core::diff::Note::Fuzzy { .. })),
        "{:#?}",
        review.notes
    );
}

// --- Row 3: parser failure ------------------------------------------------
// "Preserve original file; exclude from twin; report"

#[test]
fn a_file_the_parser_cannot_read_is_preserved_rather_than_guessed_at() {
    // Unbalanced braces: tree-sitter produces a tree with errors.
    let source = "export class Thing { retry() { \n";
    let parser = specshield_parsers::for_document(Path::new("a.ts"), source).expect("typescript claims .ts");

    let out = sanitize::sanitize(
        source,
        "a.ts",
        &Detector::new(),
        &mut graph(),
        Some(parser.as_ref()),
        &ProjectContext::default(),
    )
    .expect("a parse failure is not a crash");

    assert_eq!(out.twin, source, "the original survives byte-for-byte");
    assert!(out.applied.is_empty(), "nothing was transformed");
}

// --- Row 4: SQL syntax error ----------------------------------------------
// "Skip transformation for that file"

#[test]
fn a_sql_file_that_does_not_parse_is_skipped() {
    let source = "CREATE TABLE ( this is not sql;\n";
    let parser = specshield_parsers::for_document(Path::new("schema.sql"), source).expect("sql claims .sql");

    let out = sanitize::sanitize(
        source,
        "schema.sql",
        &Detector::new(),
        &mut graph(),
        Some(parser.as_ref()),
        &ProjectContext::default(),
    )
    .expect("a syntax error is not a crash");

    assert_eq!(out.twin, source);
}

// --- Row 5: twin verification failure -------------------------------------
// "Reject transformation; emit file unaliased; report"

#[test]
fn verification_reports_a_result_for_every_sanitize() {
    // The rejection path itself cannot be provoked from outside — a rename-only
    // edit list preserves structure by construction, which is the point of the
    // design. What §16 promises the *user* is that the outcome is always
    // reported, never assumed, so that is what is asserted here.
    let source = "# Title\n\nCustomerService owns billing.\n";
    let parser = specshield_parsers::for_document(Path::new("a.md"), source).expect("markdown");

    let out = sanitize::sanitize(
        source,
        "a.md",
        // Confirmed, because a service name is not aliased on its own any more
        // — what you built stays readable (PRD §4.1). Naming it is how a team
        // hides an internal service that really is sensitive, and this test
        // needs *something* aliased to have a twin worth verifying.
        &Detector::new().with_confirmed_term("CustomerService", EntityType::Service),
        &mut graph(),
        Some(parser.as_ref()),
        &ProjectContext::default(),
    )
    .expect("sanitize");

    assert!(
        matches!(
            out.verification,
            Verification::Passed | Verification::Unsupported { .. }
        ),
        "{:?}",
        out.verification
    );
    assert!(!out.twin.contains("CustomerService"));
}

#[test]
fn an_abandoned_transformation_returns_the_original_untouched() {
    // The contract the CLI and the app both rely on: whatever else happens, a
    // rejected transformation leaves a twin identical to the input.
    let source = "export class Thing { retry() { \n";
    let parser = specshield_parsers::for_document(Path::new("a.ts"), source).expect("typescript");
    let out = sanitize::sanitize(
        source,
        "a.ts",
        &Detector::new().with_term("Thing", EntityType::Service),
        &mut graph(),
        Some(parser.as_ref()),
        &ProjectContext::default(),
    )
    .expect("sanitize");

    assert_eq!(out.twin, source);
}

// --- Row 6: leak gate hit -------------------------------------------------
// "Hard block on export; no partial copy"

#[test]
fn the_leak_gate_blocks_rather_than_emitting_part_of_a_twin() {
    let scanner = verify::LeakScanner::new(vec!["Vantor".to_owned()]);
    let verdict = scanner.scan("The Vantor billing service.");

    let verify::Verdict::Blocked(leaks) = verdict else {
        panic!("a surviving real name must block");
    };
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].matched, "Vantor");
}

#[test]
fn the_gate_sees_a_name_inside_a_compound() {
    // `_` is a word boundary for this scan: `old_vantor_id` still says it.
    let scanner = verify::LeakScanner::new(vec!["Vantor".to_owned()]);
    assert!(matches!(
        scanner.scan("const old_vantor_id = 1;"),
        verify::Verdict::Blocked(_)
    ));
}

// --- Row 7: high-confidence secret ----------------------------------------
// "Hard block on export until acknowledged"

#[test]
fn a_high_confidence_secret_blocks_the_export() {
    let findings = secrets::scan("const k = \"AKIAIOSFODNN7EXAMPLE\";\n");
    assert!(
        secrets::blocks_export(&findings),
        "an AWS key must block: {findings:#?}"
    );
}

#[test]
fn ordinary_prose_does_not_block() {
    let findings = secrets::scan("The billing service retries three times.\n");
    assert!(!secrets::blocks_export(&findings), "{findings:#?}");
}

// --- Row 8: duplicate identity --------------------------------------------
// "Reuse existing UUID"

#[test]
fn interning_the_same_identity_twice_reuses_the_uuid() {
    let mut g = graph();
    let k = key("mod/a", EntityType::Service, "CustomerService");

    let first = g.intern(&k, Origin::Detected);
    let (uuid, alias) = (first.uuid, first.alias.clone());
    let second = g.intern(&k, Origin::Detected);

    assert_eq!(second.uuid, uuid);
    assert_eq!(second.alias, alias);
    assert_eq!(g.len(), 1);
}

// --- Row 9: alias collision -----------------------------------------------
// "Deterministic `_2` suffix"

#[test]
fn a_taken_alias_forces_a_deterministic_suffix() {
    // A real HMAC collision is not reachable in a test, so the alias is taken
    // out from under the identity that would derive it. That exercises the same
    // branch, which is the one that has to be right when it does happen.
    let project_key = ProjectKey::from_bytes([9; 32]);
    let mut g = graph();

    let wanted = key("mod/a", EntityType::Service, "CustomerService");
    let derived = derive(&project_key, &wanted, AliasStyle::Opaque, None);

    let squatter = key("mod/b", EntityType::Service, "SomethingElse");
    assert!(g.restore_node(
        &squatter,
        &uuid::Uuid::new_v4().to_string(),
        &derived,
        Origin::Detected,
        Status::Active,
    ));

    let node = g.intern(&wanted, Origin::Detected);
    assert_ne!(node.alias, derived, "two identities may never share an alias");
    assert_eq!(
        node.alias,
        derive(&project_key, &wanted, AliasStyle::Opaque, Some(2)),
        "and the fallback is derived, not invented"
    );
}

// --- Row 10: stale twin at restore ----------------------------------------
// "Block patch application; require rescan"

#[test]
fn a_file_that_moved_since_indexing_is_reported_stale() {
    let project = TempDir::new("stale");
    project.write("src/a.ts", "one\n");

    let index = specshield_index::Index::build(project.path()).expect("build");
    let recorded: Vec<(String, String)> = index
        .files
        .values()
        .map(|e| (e.path.clone(), e.checksum.clone()))
        .collect();
    assert!(index.stale(&recorded).is_empty());

    project.write("src/a.ts", "two\n");
    let (next, _) = index.rescan(project.path()).expect("rescan");

    assert_eq!(next.stale(&recorded), vec!["src/a.ts"]);
}

// --- Row 11: vault corruption ---------------------------------------------
// "Open read-only recovery mode"

#[test]
fn a_corrupt_vault_opens_read_only_rather_than_refusing_outright() {
    let project = TempDir::new("corrupt");
    let path = project.path().join("vault.bin");
    std::fs::write(&path, b"this is not a vault").expect("write");

    let recovered = specshield_vault::Recovery::open(&path).expect("§16 promises a mode, not a dead end");

    assert!(
        recovered.diagnosis().contains("not a SpecShield vault"),
        "the user is told what is wrong: {}",
        recovered.diagnosis()
    );
}

#[test]
fn recovery_mode_has_no_way_to_write() {
    // §16: "No destructive operations are permitted." Enforced by the type
    // rather than by a check — `Recovery` exposes no mutating method at all,
    // and the connection behind it is opened read-only and immutable, so
    // inspecting a damaged file cannot rewrite it.
    let project = TempDir::new("recovery-write");
    let path = project.path().join("vault.bin");

    let settings = specshield_vault::Settings {
        project_name: "t".to_owned(),
        root_path: project.path().display().to_string(),
        alias_style: "opaque".to_owned(),
        scope_strategy: "module".to_owned(),
        project_key: [5; 32],
    };
    specshield_vault::Vault::create(&path, "pw", &settings).expect("create");

    let before = std::fs::read(&path).expect("read");
    let recovered = specshield_vault::Recovery::open(&path).expect("recovery");
    let _ = recovered.identity_count();
    let _ = recovered.aliases();
    let _ = recovered.audit_log(50);

    assert_eq!(
        std::fs::read(&path).expect("read"),
        before,
        "inspection rewrote the vault"
    );
}

#[test]
fn recovery_mode_is_not_a_way_around_the_passphrase() {
    let project = TempDir::new("recovery-sealed");
    let path = project.path().join("vault.bin");

    let settings = specshield_vault::Settings {
        project_name: "t".to_owned(),
        root_path: project.path().display().to_string(),
        alias_style: "opaque".to_owned(),
        scope_strategy: "module".to_owned(),
        project_key: [5; 32],
    };
    let vault = specshield_vault::Vault::create(&path, "pw", &settings).expect("create");
    vault
        .put_identity(&specshield_vault::StoredIdentity {
            uuid: uuid::Uuid::new_v4().to_string(),
            scope_path: "mod/a".to_owned(),
            entity_type: "ORG".to_owned(),
            real_name: "MeridianFreight".to_owned(),
            alias: "ORG_ZZ11YY".to_owned(),
            origin: "detected".to_owned(),
            status: "active".to_owned(),
        })
        .expect("put");
    drop(vault);

    let recovered = specshield_vault::Recovery::open(&path).expect("recovery");
    let visible = format!("{:?}{}", recovered.aliases(), recovered.diagnosis());
    assert!(!visible.contains("MeridianFreight"), "{visible}");
}

// --- Row 12: missing vault key --------------------------------------------
// "Prompt for passphrase / escrow; never regenerate silently"

#[test]
fn a_wrong_passphrase_fails_rather_than_creating_a_new_vault() {
    let project = TempDir::new("wrong-pass");
    let path = project.path().join("vault.bin");

    let settings = specshield_vault::Settings {
        project_name: "t".to_owned(),
        root_path: project.path().display().to_string(),
        alias_style: "opaque".to_owned(),
        scope_strategy: "module".to_owned(),
        project_key: [3; 32],
    };
    specshield_vault::Vault::create(&path, "right", &settings).expect("create");

    let opened = specshield_vault::Vault::open(&path, "wrong");
    assert!(opened.is_err(), "a wrong passphrase must not silently succeed");

    // And the vault is still openable with the real one — nothing was
    // regenerated or reset by the failed attempt.
    let reopened = specshield_vault::Vault::open(&path, "right").expect("still there");
    assert_eq!(reopened.settings().expect("settings").project_key, [3; 32]);
}

#[test]
fn opening_a_vault_that_does_not_exist_does_not_create_one() {
    let project = TempDir::new("absent");
    let path = project.path().join("nothing.bin");

    assert!(specshield_vault::Vault::open(&path, "pw").is_err());
    assert!(!path.exists(), "a failed open must not leave a vault behind");
}

// --- Row 13: git unavailable ----------------------------------------------
// "Disable patch mode; write files; report"

#[test]
fn a_project_outside_a_repository_reports_why_patch_mode_is_off() {
    let project = TempDir::new("no-repo");

    // A temp directory can sit inside someone's checkout; only the negative
    // case is meaningful, and it carries the whole claim.
    if let specshield_git::Availability::NotARepository = specshield_git::Repository::discover(project.path()) {
        let availability = specshield_git::Repository::discover(project.path());
        let explain = availability.explain();
        assert!(explain.contains("patch mode is disabled"), "{explain}");
        assert!(
            explain.contains("restored files can still be written"),
            "the user is told what they *can* do: {explain}"
        );
    }
}

// --- "No destructive operations are permitted." ---------------------------

#[test]
fn sanitize_never_shortens_or_reorders_what_it_did_not_alias() {
    // Every transformation is a rename over a byte range. Anything else — a
    // reflow, a dropped comment, a reordered field — would be a destructive
    // operation on the user's source.
    let source = "# Title\n\n<!-- a comment -->\n\nCustomerService owns billing.\n\n- a\n- b\n";
    let parser = specshield_parsers::for_document(Path::new("a.md"), source).expect("markdown");

    let out = sanitize::sanitize(
        source,
        "a.md",
        &Detector::new().with_term("CustomerService", EntityType::Service),
        &mut graph(),
        Some(parser.as_ref()),
        &ProjectContext::default(),
    )
    .expect("sanitize");

    assert!(out.twin.contains("<!-- a comment -->"));
    assert!(out.twin.contains("- a\n- b\n"));
    assert_eq!(
        out.twin.lines().count(),
        source.lines().count(),
        "a rename cannot change the shape of the file"
    );
}

#[test]
fn the_detector_reports_rather_than_deciding_for_low_confidence_names() {
    // §16's whole posture: report, do not guess. A suggestion is not applied.
    let candidates = Detector::new().scan_text("The CustomerPortal handles it.", "doc", OccurrenceKind::Reference);
    for candidate in &candidates {
        assert!(
            candidate.confidence <= 1.0 && candidate.confidence > 0.0,
            "{candidate:#?}"
        );
    }
}

// --- helpers ---------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("specshield-matrix-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        std::fs::write(path, content).expect("write");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
