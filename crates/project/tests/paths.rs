//! What the twin's file tree keeps and what it rewrites — PRD §7, FR-3b.
//!
//! The tree is the one place where getting this wrong is silent. A twin whose
//! contents are perfect and whose imports point at files that are not there
//! still exports cleanly, still passes the gate, and is useless the moment a
//! model tries to build on it. Every assertion here is on the exported tree and
//! the exported text together, because neither is evidence on its own.

use std::path::{Path, PathBuf};

use specshield_vault::{Settings, Vault};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let mut root = std::env::temp_dir();
        root.push(format!("specshield-paths-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fixture = Self { root };
        let vault = Vault::create(
            &fixture.vault_path(),
            "pw",
            &Settings {
                project_name: "paths".to_owned(),
                root_path: fixture.root.display().to_string(),
                scope_strategy: "module".to_owned(),
            },
        )
        .unwrap();
        vault.add_term("Vantor", "ORG").unwrap();
        drop(vault);
        fixture
    }

    fn vault_path(&self) -> PathBuf {
        self.root.join(".specshield").join("vault.bin")
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// Export, and return the twin tree's relative paths plus a reader for it.
    fn export(&self) -> (Vec<String>, PathBuf) {
        let dest = self.root.with_extension("twin");
        let _ = std::fs::remove_dir_all(&dest);
        let mut vault = Vault::open(&self.vault_path(), "pw").unwrap();
        specshield_project::export(&self.root, &dest, &mut vault, false).unwrap();
        (tree(&dest, &dest), dest)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(self.root.with_extension("twin"));
    }
}

fn tree(dir: &Path, base: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(tree(&path, base));
        } else {
            out.push(path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"));
        }
    }
    out.sort();
    out
}

#[test]
fn only_the_identity_half_of_a_directory_name_is_rewritten() {
    // The user's own answer to how paths should work: rename the identity part.
    // `vantor-billing` is two facts in one directory — whose it is, and what it
    // does. Only the first travels.
    let f = Fixture::new("half");
    f.write("src/vantor-billing/charge.ts", "export function charge(): void {}\n");
    f.write(
        "src/domain/customer-subscription.ts",
        "export interface CustomerSubscription { id: string }\n",
    );

    let (paths, _dest) = f.export();
    assert_eq!(
        paths,
        vec!["src/ORG_001-billing/charge.ts", "src/domain/customer-subscription.ts",],
        "identity out, structure in"
    );
}

#[test]
fn a_renamed_directory_and_the_imports_of_it_agree() {
    // The defect this test exists for. Path segments used to be aliased whole
    // and unconditionally, while the file *contents* stopped aliasing structure
    // — so `customer-subscription.ts` was written as `PATH_002.ts` while every
    // import of it still said `customer-subscription`, and the twin was no
    // longer a TypeScript project that resolves. Nothing failed: the export
    // succeeded and the gate passed.
    let f = Fixture::new("agree");
    f.write("src/vantor-billing/index.ts", "export const rate = 1;\n");
    f.write(
        "src/dto/create-subscription.dto.ts",
        "export interface CreateSubscription { id: string }\n",
    );
    f.write(
        "src/main.ts",
        "import { rate } from \"./vantor-billing\";\n\
         import { CreateSubscription } from \"./dto/create-subscription.dto\";\n",
    );

    let (paths, dest) = f.export();
    let main = std::fs::read_to_string(dest.join("src/main.ts")).unwrap();

    // Every import specifier in the twin must name a file the twin actually has.
    for line in main.lines() {
        let Some(start) = line.find('"') else { continue };
        let Some(end) = line[start + 1..].find('"') else {
            continue;
        };
        let specifier = &line[start + 1..start + 1 + end];
        let resolved = specifier.trim_start_matches("./");
        assert!(
            paths.iter().any(|p| {
                let stem = p.trim_start_matches("src/");
                stem == format!("{resolved}.ts") || stem == format!("{resolved}/index.ts")
            }),
            "the twin imports {specifier:?}, which is not in its own tree: {paths:?}\n{main}"
        );
    }
}

#[test]
fn one_organization_keeps_one_alias_across_the_whole_project() {
    // Identity is project-scoped, structure is per-file — `IdentityKey::new`.
    // Per-file scoping gave the same company `ORG_001` in one file and
    // `ORG_002` in the next, which reads to a model as two companies. Restore
    // still round-tripped, so nothing caught it.
    let f = Fixture::new("scope");
    f.write(
        "a.md",
        "Vantor runs billing.
",
    );
    f.write(
        "docs/b.md",
        "Vantor also runs shipping.
",
    );

    let (_paths, dest) = f.export();
    assert_eq!(
        std::fs::read_to_string(dest.join("a.md")).unwrap(),
        "ORG_001 runs billing.
"
    );
    assert_eq!(
        std::fs::read_to_string(dest.join("docs/b.md")).unwrap(),
        "ORG_001 also runs shipping.
"
    );
}

#[test]
fn every_directory_named_after_the_same_company_gets_the_same_alias() {
    // The project-wide scope again, on the tree side.
    let f = Fixture::new("dirs");
    f.write(
        "src/vantor-billing/index.ts",
        "export const rate = 1;
",
    );
    f.write(
        "src/vantor-shipping/index.ts",
        "export const speed = 2;
",
    );

    let (paths, _dest) = f.export();
    let aliases: Vec<&str> = paths
        .iter()
        .filter_map(|p| p.strip_prefix("src/"))
        .filter_map(|p| p.split('-').next())
        .collect();
    assert_eq!(aliases, vec!["ORG_001", "ORG_001"], "one company, one alias: {paths:?}");
}

#[test]
fn a_lowercase_spelling_is_a_separate_identity_and_that_is_deliberate() {
    // A known limit, asserted so it is a decision rather than a surprise.
    //
    // Restore is byte-for-byte, so an alias maps to exactly one spelling. If
    // `Vantor` in prose and `vantor` in a directory name shared `ORG_001`, one
    // of the two would come back with the wrong case and the round-trip
    // property would fail. They therefore get separate numbers — the model sees
    // two names where a person sees one spelling of one company.
    //
    // The fix is an alias grammar that carries case (`org_001` for a lowercase
    // surface), which changes the format PRD §13 publishes and the shape the
    // export gate looks for. Not something to do quietly inside a path change.
    let f = Fixture::new("case");
    f.write(
        "a.md",
        "Vantor runs billing.
",
    );
    f.write(
        "src/vantor-billing/index.ts",
        "export const rate = 1;
",
    );

    let (paths, dest) = f.export();
    let prose = std::fs::read_to_string(dest.join("a.md")).unwrap();
    let directory = paths
        .iter()
        .find(|p| p.contains("-billing"))
        .expect("the directory was rewritten");

    assert!(prose.starts_with("ORG_"), "{prose}");
    assert!(directory.starts_with("src/ORG_"), "{directory}");
    assert_ne!(
        prose.split_whitespace().next().unwrap(),
        directory.trim_start_matches("src/").split('-').next().unwrap(),
        "if these ever agree, case-carrying aliases landed and this test should          become an equality assertion"
    );
}
