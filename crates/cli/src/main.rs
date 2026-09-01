//! `specshield` — the headless driver.
//!
//! The CLI exists before the desktop shell on purpose (Implementation Plan §0):
//! the core invariant `restore(sanitize(x)) == x` is only testable in a headless
//! harness, the golden corpus has to be runnable in CI from day one, and a
//! headless core makes the V2 GitHub Actions gateway nearly free.
//!
//! The UI never owns logic. Anything this binary can do, `specshield-core` can
//! do without it.

mod report;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use specshield_core::alias::{AliasStyle, ProjectKey};
use specshield_core::detect::Detector;
use specshield_core::model::{EntityType, Origin, Status};
use specshield_core::restore::Vocabulary;
use specshield_core::sanitize::Graph;
use specshield_core::{restore, sanitize, secrets, verify};
use specshield_vault as vault;
use zeroize::Zeroize;

/// Default vault filename inside a project.
const VAULT_FILE: &str = ".specshield/vault.bin";

#[derive(Parser, Debug)]
#[command(
    name = "specshield",
    version,
    about = "Semantic gateway for secure agentic software development"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a project vault, identity graph, and settings.
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Alias readability, traded against protection (SDD §6.2).
        #[arg(long, value_enum, default_value_t = AliasStyleArg::Typed)]
        alias_style: AliasStyleArg,
        /// Vault passphrase. Prefer `SPECSHIELD_PASSPHRASE` over this flag:
        /// arguments are visible in the process list.
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Add a confirmed term to the dictionary (PRD FR-10).
    ///
    /// This is how prose entities are found. `Vantor` is not recognisable as a
    /// company by any rule; once named, it is found everywhere, forever.
    Term {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        name: String,
        #[arg(long, value_enum, default_value_t = EntityTypeArg::Organization)]
        entity_type: EntityTypeArg,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Report what would be detected in a file, without producing a twin.
    ///
    /// The review step of Workflow A: see the entities, secrets, and
    /// suggestions before anything is aliased.
    Scan {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        file: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Generate the semantic twin for a file, verify it, and print it.
    Sanitize {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        file: PathBuf,
        /// Write the twin here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Also print the prompt envelope (SDD §11, FR-6b).
        #[arg(long)]
        envelope: bool,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Run the export verification gate (SDD §8) over a file.
    ///
    /// Exits non-zero on a leak, which is what makes it usable as a CI gate.
    Verify {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        file: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Restore aliases in AI output back to real identifiers.
    Restore {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// File containing the model's response; reads stdin when omitted.
        ///
        /// A directory is taken as a twin project: every file in it is
        /// restored, and each one is written back at its real path.
        input: Option<PathBuf>,
        /// Where to write a restored twin project. Required for a directory.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Show cross-artifact unification proposals, or confirm one (SDD §5).
    ///
    /// Nothing is unified until confirmed. A name match is not evidence: three
    /// unrelated `Status` enums share a name and are three concepts.
    Unify {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// Confirm this concept, linking every identity that matches it.
        #[arg(long)]
        confirm: Option<String>,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Walk the project, hash every file, and record the index (SDD §4.1).
    ///
    /// Ignored files are ignored: `node_modules` is not the user's code.
    Index {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Re-walk and report what changed since the last index (SDD §13.1).
    ///
    /// The staleness half of the same operation: a twin made from a file that
    /// has since been edited would revert that edit when its patch is applied.
    Rescan {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Sanitize every parseable file in the project into a twin directory.
    ///
    /// The gate runs per file. One blocked file blocks the export: a directory
    /// that is clean apart from one leak is not clean.
    Export {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// Directory to write the twin project into. Must not already exist.
        dest: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Review what AI output would change in a real file — SDD §13.
    ///
    /// Three versions are compared: the file on disk, the twin that was sent,
    /// and the twin that came back. Nothing is written.
    Diff {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// The real file the twin was made from.
        file: PathBuf,
        /// The model's response.
        #[arg(long)]
        ai: PathBuf,
        /// The twin that was sent. Regenerated from `file` when omitted.
        #[arg(long)]
        twin: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Name an entity the model invented — SDD §12.
    ///
    /// Nothing is guessed. An alias-shaped token the vault never issued stays
    /// in the restored text, and blocks patching, until it is named here.
    Resolve {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// The token from the model's output, e.g. `SERVICE_099`.
        alias: String,
        #[arg(long)]
        name: String,
        #[arg(long, value_enum, default_value_t = EntityTypeArg::Service)]
        entity_type: EntityTypeArg,
        #[arg(long, default_value = "project")]
        scope: String,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Restore AI output and apply it as a patch on a branch — SDD §14.
    ///
    /// Refuses on unresolved identities and on a stale file, dry-runs the patch
    /// before touching anything, and never applies to `main`.
    Apply {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        file: PathBuf,
        #[arg(long)]
        ai: PathBuf,
        #[arg(long)]
        twin: Option<PathBuf>,
        #[arg(long, default_value = DEFAULT_BRANCH)]
        branch: String,
        /// Check that the patch applies, then stop.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Reverse the last applied patch.
    Undo {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Measure detection recall and precision against the labelled corpus
    /// (PRD §5). Consumed by CI.
    Report {
        #[arg(default_value = "corpus")]
        corpus: PathBuf,
        /// Fail with a non-zero exit if the targets are missed.
        #[arg(long)]
        strict: bool,
        /// List every detection that is not in ground truth.
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum AliasStyleArg {
    Opaque,
    Typed,
    Pseudonymous,
}

impl From<AliasStyleArg> for AliasStyle {
    fn from(value: AliasStyleArg) -> Self {
        match value {
            AliasStyleArg::Opaque => Self::Opaque,
            AliasStyleArg::Typed => Self::Typed,
            AliasStyleArg::Pseudonymous => Self::Pseudonymous,
        }
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum EntityTypeArg {
    Organization,
    Service,
    Api,
    Dto,
    Enum,
    Event,
    Table,
    Column,
    Host,
    EnvVar,
}

impl From<EntityTypeArg> for EntityType {
    fn from(value: EntityTypeArg) -> Self {
        match value {
            EntityTypeArg::Organization => Self::Organization,
            EntityTypeArg::Service => Self::Service,
            EntityTypeArg::Api => Self::Api,
            EntityTypeArg::Dto => Self::Dto,
            EntityTypeArg::Enum => Self::Enum,
            EntityTypeArg::Event => Self::Event,
            EntityTypeArg::Table => Self::Table,
            EntityTypeArg::Column => Self::Column,
            EntityTypeArg::Host => Self::Host,
            EntityTypeArg::EnvVar => Self::EnvVar,
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init {
            path,
            alias_style,
            passphrase,
        } => init(&path, alias_style.into(), passphrase.as_deref()),
        Command::Term {
            project,
            name,
            entity_type,
            passphrase,
        } => add_term(&project, &name, entity_type.into(), passphrase.as_deref()),
        Command::Scan {
            project,
            file,
            passphrase,
        } => run_scan(&project, &file, passphrase.as_deref()),
        Command::Sanitize {
            project,
            file,
            out,
            envelope,
            passphrase,
        } => run_sanitize(&project, &file, out.as_deref(), envelope, passphrase.as_deref()),
        Command::Verify {
            project,
            file,
            passphrase,
        } => run_verify(&project, &file, passphrase.as_deref()),
        Command::Restore {
            project,
            out,
            input,
            passphrase,
        } => run_restore(&project, input.as_deref(), out.as_deref(), passphrase.as_deref()),
        Command::Unify {
            project,
            confirm,
            passphrase,
        } => run_unify(&project, confirm.as_deref(), passphrase.as_deref()),
        Command::Index { project, passphrase } => run_index(&project, passphrase.as_deref()),
        Command::Rescan { project, passphrase } => run_rescan(&project, passphrase.as_deref()),
        Command::Export {
            project,
            dest,
            passphrase,
        } => run_export(&project, &dest, passphrase.as_deref()),
        Command::Diff {
            project,
            file,
            ai,
            twin,
            passphrase,
        } => run_diff(&project, &file, &ai, twin.as_deref(), passphrase.as_deref()),
        Command::Resolve {
            project,
            alias,
            name,
            entity_type,
            scope,
            passphrase,
        } => run_resolve(
            &project,
            &alias,
            &name,
            entity_type.into(),
            &scope,
            passphrase.as_deref(),
        ),
        Command::Apply {
            project,
            file,
            ai,
            twin,
            branch,
            dry_run,
            passphrase,
        } => run_apply(
            &project,
            &file,
            &ai,
            twin.as_deref(),
            &branch,
            dry_run,
            passphrase.as_deref(),
        ),
        Command::Undo { project, passphrase } => run_undo(&project, passphrase.as_deref()),
        Command::Report {
            corpus,
            strict,
            verbose,
        } => report::run(&corpus, strict, verbose),
    }
}

// ---------------------------------------------------------------------------
// Project plumbing
// ---------------------------------------------------------------------------

fn vault_path(project: &Path) -> PathBuf {
    project.join(VAULT_FILE)
}

/// Resolve the passphrase, preferring the environment over the command line —
/// process arguments are visible to other users on the machine.
fn passphrase(explicit: Option<&str>) -> Result<String> {
    if let Some(p) = explicit {
        return Ok(p.to_owned());
    }
    std::env::var("SPECSHIELD_PASSPHRASE").context(
        "no passphrase: set SPECSHIELD_PASSPHRASE or pass --passphrase \
         (interactive prompting arrives with the desktop shell in M2)",
    )
}

fn open(project: &Path, explicit: Option<&str>) -> Result<vault::Vault> {
    let path = vault_path(project);
    if !path.exists() {
        bail!("no vault at {} — run `specshield init` first", path.display());
    }
    Ok(vault::Vault::open(&path, &passphrase(explicit)?)?)
}

/// Rebuild the in-memory graph from stored identities, so aliases stay stable
/// across invocations (SDD §6.5).
fn graph_from(vault: &vault::Vault) -> Result<Graph> {
    let settings = vault.settings()?;
    let style = match settings.alias_style.as_str() {
        "opaque" => AliasStyle::Opaque,
        "pseudonymous" => AliasStyle::Pseudonymous,
        _ => AliasStyle::Typed,
    };
    let mut settings = settings;
    let mut graph = Graph::new(ProjectKey::take_bytes(&mut settings.project_key), style);
    let concepts: std::collections::HashMap<String, String> = vault.concepts()?.into_iter().collect();
    for stored in vault.identities()? {
        let entity_type: EntityType = stored
            .entity_type
            .parse()
            .with_context(|| format!("vault holds unknown entity type {:?}", stored.entity_type))?;
        if let Some(concept) = concepts.get(&stored.uuid) {
            graph.confirm_concept(
                &[specshield_core::model::IdentityKey::new(
                    &stored.scope_path,
                    entity_type,
                    &stored.real_name,
                )],
                concept,
            );
        }
        graph.restore_node(
            &specshield_core::model::IdentityKey::new(&stored.scope_path, entity_type, &stored.real_name),
            &stored.uuid,
            &stored.alias,
            Origin::Detected,
            Status::Active,
        );
    }
    Ok(graph)
}

/// What the project knows, for parsers that cannot resolve everything from one
/// file — see `ProjectContext`.
fn context_from(vault: &vault::Vault) -> Result<specshield_core::parser::ProjectContext> {
    let identities = vault.identities()?;
    let members = identities
        .iter()
        .filter(|i| i.entity_type == EntityType::Column.prefix())
        .map(|i| i.real_name.clone());
    let names = identities.iter().map(|i| i.real_name.clone());
    Ok(specshield_core::parser::ProjectContext::new(members, names))
}

/// The same context, but from the graph as it stands mid-run rather than from
/// the vault. The path pass needs what the *content* passes just learned, and
/// that is not in the vault until `persist`.
fn context_from_graph(graph: &Graph) -> specshield_core::parser::ProjectContext {
    let members = graph
        .nodes()
        .filter(|n| n.key.entity_type == EntityType::Column)
        .map(|n| n.key.real_name.clone());
    let names = graph.nodes().map(|n| n.key.real_name.clone());
    specshield_core::parser::ProjectContext::new(members, names)
}

/// Intern every path segment that is an entity, and return the twin path for
/// each real path — PRD FR-3b.
///
/// Run after the content passes, so `thing18.ts` can be recognised as naming
/// the `Thing18` those passes found. The identities are the same ones the
/// TypeScript parser uses for import specifiers (`specshield_core::paths`), so
/// a renamed file and every import of it agree by construction.
fn twin_paths(
    index: &specshield_index::Index,
    detector: &Detector,
    graph: &mut Graph,
) -> Result<HashMap<String, String>> {
    use specshield_core::paths::Component;

    let context = context_from_graph(graph);
    let mut out = HashMap::new();

    for path in index.files.keys() {
        let mut failed = None;
        let twin = specshield_core::paths::twin_path(path, &context, |component| match component {
            Component::Segment { key, suffix } => {
                format!("{}{suffix}", graph.intern(key, Origin::Detected).alias)
            }
            // Sanitizing the component as if it were a document is not a trick:
            // it is the same call the file's *contents* go through, which is
            // exactly why the tree and the import strings come out agreeing.
            Component::Text { text, suffix } => match sanitize::sanitize(
                text,
                specshield_core::paths::PATH_SCOPE,
                detector,
                graph,
                None,
                &context,
            ) {
                Ok(result) => format!("{}{suffix}", result.twin),
                Err(e) => {
                    failed = Some(e);
                    format!("{text}{suffix}")
                }
            },
        });

        if let Some(e) = failed {
            return Err(e).with_context(|| format!("aliasing the path {path}"));
        }
        out.insert(path.clone(), twin);
    }

    Ok(out)
}

fn detector_from(vault: &vault::Vault) -> Result<Detector> {
    let mut detector = Detector::new();

    // Names learned from any artifact are found in every artifact — SDD §5.
    //
    // The SQL scan interns the table `invoice`; the OpenAPI spec then says
    // "Fetch a single invoice" in a summary and the gate blocks, because the
    // vault knows that name and the twin still contains it. Seeding the detector
    // with what the project already knows is what makes a name consistent
    // across files rather than per-file.
    //
    // It aliases common words that happen to be table names — `invoice`,
    // `account` — wherever they appear. That is the safe direction, and PRD
    // FR-10's allowlist is the escape hatch for a user who disagrees.
    for identity in vault.identities()? {
        if let Ok(entity_type) = identity.entity_type.parse() {
            detector = detector.with_term(identity.real_name, entity_type);
        }
    }

    for (name, type_name) in vault.dictionary()? {
        let entity_type: EntityType = type_name
            .parse()
            .with_context(|| format!("dictionary holds unknown entity type {type_name:?}"))?;
        detector = detector.with_term(name, entity_type);
    }
    for term in vault.allowlist()? {
        detector = detector.with_allowed(term);
    }
    Ok(detector)
}

/// Write the graph back. Identities are upserted in one transaction — SDD §9.2.
fn persist(vault: &mut vault::Vault, graph: &Graph) -> Result<()> {
    let identities: Vec<vault::StoredIdentity> = graph
        .nodes()
        .map(|n| vault::StoredIdentity {
            uuid: n.uuid.to_string(),
            scope_path: n.key.scope_path.clone(),
            entity_type: n.key.entity_type.prefix().to_owned(),
            real_name: n.key.real_name.clone(),
            alias: n.alias.clone(),
            origin: "detected".to_owned(),
            status: "active".to_owned(),
        })
        .collect();
    vault.put_identities(&identities)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn init(project: &Path, style: AliasStyle, explicit: Option<&str>) -> Result<()> {
    let path = vault_path(project);
    if path.exists() {
        bail!("vault already exists at {}", path.display());
    }

    // PRD §10 / SDD §17.4 — a vault inside a sync root is uploaded to a third
    // party, which contradicts the local-only guarantee.
    if let Some(provider) = vault::cloud_sync_root(project) {
        eprintln!("warning: this project is inside a {provider} folder.");
        eprintln!("         The vault will be synced to {provider}'s cloud, which");
        eprintln!("         contradicts SpecShield's local-only guarantee (PRD §10).");
        eprintln!("         Move the project to a local-only path before storing real data.");
        eprintln!();
    }

    let pw = passphrase(explicit)?;
    let mut project_key = [0u8; 32];
    getrandom::fill(&mut project_key).map_err(|e| anyhow::anyhow!("entropy unavailable: {e}"))?;

    let settings = vault::Settings {
        project_name: project
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "project".to_owned()),
        root_path: project.display().to_string(),
        alias_style: format!("{style:?}").to_lowercase(),
        scope_strategy: "module".to_owned(),
        project_key,
    };
    // The vault owns the key now; clear our copy off the stack.
    project_key.zeroize();
    vault::Vault::create(&path, &pw, &settings)?;

    println!("Initialized vault at {}", path.display());
    println!("Alias style: {style:?}");
    println!();
    println!("Next: add the terms only you can name, then sanitize.");
    println!("  specshield term \"Your Company\" --entity-type organization");
    Ok(())
}

fn add_term(project: &Path, name: &str, entity_type: EntityType, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    vault.add_term(name, entity_type.prefix())?;
    vault.log("term.add", None, Some(1), None, None)?;
    println!("Added {name:?} as {}", entity_type.prefix());
    Ok(())
}

/// Refuse to process a format we have no parser for.
///
/// Running the prose scan over a TypeScript file would alias the names it
/// happens to recognise and silently leave every declaration, import, and
/// property untouched — producing a twin that *looks* sanitized and is not. A
/// tool whose whole job is preventing leaks must not do that; it says no.
fn require_parser(file: &Path, content: &str) -> Result<Box<dyn specshield_core::parser::ArtifactParser>> {
    match specshield_parsers::for_document(file, content) {
        Some(parser) => Ok(parser),
        None => bail!(
            "no parser for {} in this build (have: {}).\n\
             Refusing to process it: the prose scan alone would produce a twin that\n\
             looks sanitized but leaves declarations and identifiers untouched.\n\
             OpenAPI specifications arrive with the openapi parser in M3; TypeScript in M4.",
            file.display(),
            specshield_parsers::implemented().join(", ")
        ),
    }
}

fn run_scan(project: &Path, file: &Path, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    let source = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let parser = require_parser(file, &source)?;

    let detector = detector_from(&vault)?;
    let findings = secrets::scan(&source);
    let redacted = secrets::redact(&source, &findings);
    let candidates = detector.scan_text(
        &redacted,
        &file.to_string_lossy().replace('\\', "/"),
        specshield_core::model::OccurrenceKind::Reference,
    );

    let (confident, suggestions): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|c| c.confidence >= sanitize::AUTO_APPLY_CONFIDENCE);

    println!("{} ({})\n", file.display(), parser.name());
    println!("{} entit(ies) would be aliased:", confident.len());
    for c in &confident {
        println!("  {:>5}  {:<10} {}", c.byte_start, c.entity_type.prefix(), c.real_name);
    }
    if !suggestions.is_empty() {
        println!(
            "\n{} suggestion(s) NOT applied — confirm with `term`:",
            suggestions.len()
        );
        for c in &suggestions {
            println!("  {:>5}  {:.2}       {}", c.byte_start, c.confidence, c.real_name);
        }
    }
    if !findings.is_empty() {
        println!("\n{} secret(s) would be redacted one-way:", findings.len());
        for f in &findings {
            println!("  line {:<4} {:?}  {}", f.line, f.confidence, f.secret_type);
        }
    }
    Ok(())
}

fn run_sanitize(project: &Path, file: &Path, out: Option<&Path>, envelope: bool, explicit: Option<&str>) -> Result<()> {
    let mut vault = open(project, explicit)?;
    let source = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let parser = require_parser(file, &source)?;

    let mut graph = graph_from(&vault)?;
    let detector = detector_from(&vault)?;
    let scope = file.to_string_lossy().replace('\\', "/");

    let context = context_from(&vault)?;
    let result = sanitize::sanitize(&source, &scope, &detector, &mut graph, Some(parser.as_ref()), &context)?;

    // SDD §8 — nothing is emitted before the gate passes.
    let scanner = verify::LeakScanner::new(graph.real_names());
    let verdict = scanner.scan(&result.twin);
    let secret_findings = secrets::scan(&result.twin);

    persist(&mut vault, &graph)?;

    if let verify::Verdict::Blocked(leaks) = &verdict {
        vault.log("sanitize", Some(1), None, Some("blocked"), None)?;
        eprintln!("EXPORT BLOCKED — {} real name(s) survived into the twin:", leaks.len());
        for leak in leaks {
            eprintln!("  {}:{}:{}  {:?}", file.display(), leak.line, leak.column, leak.matched);
        }
        bail!("verification gate refused the export");
    }
    if secrets::blocks_export(&secret_findings) {
        eprintln!("EXPORT BLOCKED — unredacted secret(s) in the twin:");
        for finding in secret_findings
            .iter()
            .filter(|f| f.confidence == secrets::Confidence::High)
        {
            eprintln!("  line {}: {}", finding.line, finding.secret_type);
        }
        bail!("verification gate refused the export");
    }

    if let Some(path) = out {
        std::fs::write(path, &result.twin)?;
        eprintln!("Twin written to {}", path.display());
    } else {
        if envelope {
            println!("{}\n", prompt_envelope());
        }
        print!("{}", result.twin);
    }

    eprintln!();
    eprintln!(
        "verified clean: {} identities applied, {} patterns checked",
        result.applied.len(),
        scanner.pattern_count()
    );
    // Two different checks, reported separately. The gate above proves no vault
    // name survived; this proves the twin still has the original's shape.
    match &result.verification {
        sanitize::Verification::Passed => {
            eprintln!("  structure verified against the original (SDD §7.2)");
        }
        sanitize::Verification::Unsupported { parser } => {
            eprintln!("  structure NOT checked: the {parser} parser has no structure to compare");
        }
        sanitize::Verification::NotAttempted => {
            eprintln!("  structure NOT checked: no parser supplied");
        }
        sanitize::Verification::TwinDidNotParse { parser } => {
            eprintln!("  aliasing ABANDONED: the twin no longer parses as {parser}");
        }
        sanitize::Verification::StructureChanged { parser, differences } => {
            eprintln!("  aliasing ABANDONED: {parser} structure changed");
            for (kind, before, after) in differences {
                eprintln!("      {kind}: {before} -> {after}");
            }
        }
    }
    eprintln!(
        "  {} secret(s) redacted (one-way, never restored)",
        result.secrets.len()
    );
    if !result.suggestions.is_empty() {
        eprintln!(
            "  {} suggestion(s) NOT applied — review with `term`:",
            result.suggestions.len()
        );
        for s in result.suggestions.iter().take(5) {
            eprintln!("      {:?}", s.real_name);
        }
    }
    eprintln!();
    eprintln!("NOT checked: business logic in prose, algorithms, architecture shape (PRD §4.3).");
    Ok(())
}

fn run_verify(project: &Path, file: &Path, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    let text = std::fs::read_to_string(file)?;
    let graph = graph_from(&vault)?;

    let scanner = verify::LeakScanner::new(graph.real_names());
    let verdict = scanner.scan(&text);
    let secret_findings = secrets::scan(&text);

    match &verdict {
        verify::Verdict::Clean => {
            println!("clean — {} patterns checked", scanner.pattern_count());
        }
        verify::Verdict::Blocked(leaks) => {
            for leak in leaks {
                println!(
                    "{}:{}:{}: leak {:?}",
                    file.display(),
                    leak.line,
                    leak.column,
                    leak.matched
                );
            }
        }
    }
    for finding in &secret_findings {
        println!("{}:{}: secret {}", file.display(), finding.line, finding.secret_type);
    }

    if !verdict.is_clean() || secrets::blocks_export(&secret_findings) {
        std::process::exit(1);
    }
    Ok(())
}

/// Restore a whole twin project, putting every file back at its real path.
///
/// The inverse of `export`, and the half of path aliasing that makes it usable:
/// a twin tree whose directories and filenames are aliases is only reversible
/// because the vault recorded the mapping. A twin path the vault does not know
/// is written where it stands rather than guessed at — the alias grammar is
/// recognisable, but a filename that merely looks like one is not evidence.
fn restore_project(vault: &vault::Vault, twin_root: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        bail!("{} already exists — refusing to write into it", dest.display());
    }

    let graph = graph_from(vault)?;
    let vocabulary = Vocabulary::new(graph.vocabulary());

    let real_of: HashMap<String, String> = vault.files()?.into_iter().map(|f| (f.twin_path, f.path)).collect();

    let index = specshield_index::Index::build(twin_root)?;
    let mut written = 0usize;
    let mut unmapped = Vec::new();
    let mut restored = 0usize;

    for entry in index.files.values() {
        let source = twin_root.join(&entry.path);
        let target_relative = real_of.get(&entry.path).cloned().unwrap_or_else(|| {
            unmapped.push(entry.path.clone());
            entry.path.clone()
        });

        if !entry.is_text {
            write_into(dest, &target_relative, |target| {
                std::fs::copy(&source, target).map(|_| ())
            })?;
            written += 1;
            continue;
        }

        let text = std::fs::read_to_string(&source)?;
        let outcome = restore::restore(&text, &vocabulary);
        restored += outcome.restored.len();
        write_into(dest, &target_relative, |target| std::fs::write(target, &outcome.text))?;
        written += 1;
    }

    println!("Restored {written} file(s) into {}", dest.display());
    println!("  {restored} alias occurrence(s) resolved");
    if unmapped.is_empty() {
        println!("  every twin path mapped back to a real path");
    } else {
        println!(
            "  {} file(s) the vault has no path mapping for, left where they stand:",
            unmapped.len()
        );
        for path in unmapped.iter().take(20) {
            println!("      {path}");
        }
    }
    Ok(())
}

fn run_restore(project: &Path, input: Option<&Path>, out: Option<&Path>, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;

    if input.is_some_and(Path::is_dir) {
        let Some(out) = out else {
            bail!("restoring a twin project needs --out: a directory of twins maps back to real paths");
        };
        return restore_project(&vault, input.unwrap_or(Path::new(".")), out);
    }

    let text = match input {
        Some(path) => std::fs::read_to_string(path)?,
        None => std::io::read_to_string(std::io::stdin())?,
    };

    let graph = graph_from(&vault)?;
    let outcome = restore::restore(&text, &Vocabulary::new(graph.vocabulary()));
    print!("{}", outcome.text);

    eprintln!();
    eprintln!("restored {} alias(es)", outcome.restored.len());
    for r in outcome.needs_review() {
        eprintln!(
            "  review line {}: {:?} matched {:?} ({:?})",
            r.line, r.found, r.real_name, r.match_kind
        );
    }
    if !outcome.unresolved.is_empty() {
        eprintln!(
            "  {} unresolved identit(ies) — name them before applying:",
            outcome.unresolved.len()
        );
        for u in &outcome.unresolved {
            eprintln!("      line {}: {}", u.line, u.token);
        }
    }
    if outcome.redactions_preserved > 0 {
        eprintln!(
            "  {} redaction marker(s) left in place (one-way)",
            outcome.redactions_preserved
        );
    }
    Ok(())
}

/// Walk the project and record what is in it — SDD §4.1.
///
/// The index is what makes the other repo-scale commands possible: `rescan`
/// compares against it, and `export` iterates it rather than re-walking.
fn run_index(project: &Path, explicit: Option<&str>) -> Result<()> {
    let mut vault = open(project, explicit)?;

    let started = std::time::Instant::now();
    let index = specshield_index::Index::build(project)?;
    let walked = started.elapsed();

    let files: Vec<vault::StoredFile> = index
        .files
        .values()
        .map(|entry| vault::StoredFile {
            path: entry.path.clone(),
            // Path aliasing has not run yet. The twin path is the real path
            // until something renames it, and saying so is better than storing
            // an empty column that later reads as "no twin".
            twin_path: entry.path.clone(),
            checksum: entry.checksum.clone(),
            parser: parser_for(project, entry),
        })
        .collect();

    vault.put_files(&files)?;
    vault.log(
        "index",
        Some(i64::try_from(files.len()).unwrap_or(i64::MAX)),
        None,
        None,
        None,
    )?;

    let text = index.text_files().count();
    let parseable = files.iter().filter(|f| !f.parser.is_empty()).count();

    println!("Indexed {} file(s) in {:.2}s", index.len(), walked.as_secs_f64());
    println!("  {text} text, {parseable} with a parser in this build");
    println!("  {} binary or unparseable", index.len() - parseable);
    Ok(())
}

/// Re-walk and say what moved — SDD §13.1.
fn run_rescan(project: &Path, explicit: Option<&str>) -> Result<()> {
    let mut vault = open(project, explicit)?;

    let recorded = vault.files()?;
    if recorded.is_empty() {
        bail!("no index for this project yet — run `specshield index` first");
    }

    let previous = specshield_index::Index {
        root: project.to_path_buf(),
        files: recorded
            .iter()
            .map(|f| {
                (
                    f.path.clone(),
                    specshield_index::Entry {
                        path: f.path.clone(),
                        checksum: f.checksum.clone(),
                        size: 0,
                        modified: None,
                        is_text: true,
                    },
                )
            })
            .collect(),
    };

    let started = std::time::Instant::now();
    let (index, changes) = previous.rescan(project)?;
    let elapsed = started.elapsed();

    let updated: Vec<vault::StoredFile> = index
        .files
        .values()
        .map(|entry| vault::StoredFile {
            path: entry.path.clone(),
            twin_path: entry.path.clone(),
            checksum: entry.checksum.clone(),
            parser: parser_for(project, entry),
        })
        .collect();
    vault.put_files(&updated)?;
    vault.forget_files(&changes.removed)?;

    println!("Rescanned {} file(s) in {:.2}s", index.len(), elapsed.as_secs_f64());
    println!(
        "  {} added, {} modified, {} removed, {} unchanged",
        changes.added.len(),
        changes.modified.len(),
        changes.removed.len(),
        changes.unchanged
    );

    for (label, paths) in [
        ("added", &changes.added),
        ("modified", &changes.modified),
        ("removed", &changes.removed),
    ] {
        for path in paths.iter().take(20) {
            println!("  {label:>8}  {path}");
        }
        if paths.len() > 20 {
            println!("  {:>8}  … and {} more", "", paths.len() - 20);
        }
    }

    // The point of the exercise: which twins can no longer be trusted.
    let pairs: Vec<(String, String)> = recorded.into_iter().map(|f| (f.path, f.checksum)).collect();
    let stale = index.stale(&pairs);
    if stale.is_empty() {
        println!("\nNo stale twins: every recorded checksum still matches the file on disk.");
    } else {
        println!(
            "\n{} file(s) have changed since their twin was made. Applying a patch",
            stale.len()
        );
        println!("built from those twins would revert the intervening edits — re-sanitize first:");
        for path in stale.iter().take(20) {
            println!("  {path}");
        }
    }
    Ok(())
}

/// Sanitize the whole project into a directory — the M4 twin export.
///
/// Every file is written, not only the parseable ones: a twin project that is
/// missing its `package.json` is not the project. Files no parser handles are
/// copied through unchanged, and the gate still runs over them — a name in an
/// unparsed file is a leak exactly like a name in a parsed one.
/// Place one file in the twin tree, creating the directories it needs.
fn write_into(dest: &Path, relative: &str, put: impl FnOnce(&Path) -> std::io::Result<()>) -> Result<()> {
    let target = dest.join(relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    put(&target).with_context(|| format!("writing {}", target.display()))
}

fn report_export(
    dest: &Path,
    written: usize,
    aliased: usize,
    identities: usize,
    unchecked: usize,
    abandoned: &[(String, String)],
    renamed: usize,
) {
    println!("Exported {} file(s) to {}", written, dest.display());
    println!("  {aliased} alias applications, {identities} identities in the vault");
    println!("  every file passed the gate (SDD §8), paths included");
    println!("  {renamed} path(s) renamed in the twin tree");
    println!("  {unchecked} file(s) had no structure to verify against");
    if abandoned.is_empty() {
        println!("  every parsed file verified structurally (SDD §7.2)");
    } else {
        println!(
            "  {} file(s) exported UNALIASED — aliasing was abandoned:",
            abandoned.len()
        );
        for (path, why) in abandoned.iter().take(20) {
            println!("      {path}: {why}");
        }
    }
}

fn report_blocked(blocked: &[(String, Vec<String>)]) {
    eprintln!("EXPORT BLOCKED — {} file(s) did not verify:", blocked.len());
    for (path, leaks) in blocked.iter().take(20) {
        eprintln!("  {path}");
        for leak in leaks.iter().take(5) {
            eprintln!("      {leak}");
        }
    }
}

/// The first of the export's two passes: sanitize everything and keep only what
/// it taught the graph.
///
/// A single pass has no order that works. `customerId` is declared in the DTO
/// and merely *used* in the service; whichever file the walk reaches first, the
/// other one was sanitized by a build that had not learned the name yet — and
/// the gate, which runs over the finished graph, then blocks on it.
///
/// This is the rule that already holds between CLI invocations — a name found
/// in one artifact is found in every artifact — applied inside one command.
fn learn_project(
    project: &Path,
    index: &specshield_index::Index,
    vault: &mut vault::Vault,
    graph: &mut Graph,
) -> Result<()> {
    let detector = detector_from(vault)?;
    let context = context_from(vault)?;

    for entry in index.files.values().filter(|e| e.is_text) {
        let source_path = project.join(&entry.path);
        let Ok(source) = std::fs::read_to_string(&source_path) else {
            continue;
        };
        let parser = specshield_parsers::for_document(&source_path, &source);
        sanitize::sanitize(&source, &entry.path, &detector, graph, parser.as_deref(), &context)?;
    }

    // Filenames last: `thing18.ts` is only recognisable as naming `Thing18`
    // once the content pass above has found that type.
    twin_paths(index, &detector, graph)?;

    persist(vault, graph)
}

/// What an exported file carries: a sanitized twin, or the original bytes.
enum Payload {
    Text(String),
    /// A binary. Nothing to sanitize and nothing to verify — it carries no
    /// identifiers a parser or the gate can read — but it is copied so the
    /// exported tree is still the project.
    Copy(PathBuf),
}

/// Everything the sanitize pass produced, held until the gate has run.
#[derive(Default)]
struct Twins {
    staged: Vec<(String, Payload)>,
    records: Vec<vault::StoredFile>,
    blocked: Vec<(String, Vec<String>)>,
    abandoned: Vec<(String, String)>,
    aliased: usize,
    unchecked: usize,
}

/// Sanitize every file in the project, producing twins but writing nothing.
fn sanitize_tree(
    project: &Path,
    index: &specshield_index::Index,
    detector: &Detector,
    context: &specshield_core::parser::ProjectContext,
    graph: &mut Graph,
    twin_of: &impl Fn(&String) -> String,
) -> Result<Twins> {
    let mut twins = Twins::default();

    for entry in index.files.values() {
        let source_path = project.join(&entry.path);

        if !entry.is_text {
            twins.records.push(vault::StoredFile {
                path: entry.path.clone(),
                twin_path: twin_of(&entry.path),
                checksum: entry.checksum.clone(),
                parser: String::new(),
            });
            twins.staged.push((entry.path.clone(), Payload::Copy(source_path)));
            continue;
        }

        let source =
            std::fs::read_to_string(&source_path).with_context(|| format!("reading {}", source_path.display()))?;
        let parser = specshield_parsers::for_document(&source_path, &source);

        let result = sanitize::sanitize(&source, &entry.path, detector, graph, parser.as_deref(), context)?;

        if secrets::blocks_export(&secrets::scan(&result.twin)) {
            twins
                .blocked
                .push((entry.path.clone(), vec!["unredacted secret".to_owned()]));
            continue;
        }

        // SDD §7.2. An abandoned file is not a failure — the original is
        // preserved, which is the correct outcome — but it is a file the model
        // will see unaliased, and an export that did not say so would be
        // reporting a clean run it did not have.
        match &result.verification {
            sanitize::Verification::Passed => {}
            sanitize::Verification::TwinDidNotParse { parser } => {
                twins
                    .abandoned
                    .push((entry.path.clone(), format!("twin no longer parses as {parser}")));
            }
            sanitize::Verification::StructureChanged { parser, .. } => {
                twins
                    .abandoned
                    .push((entry.path.clone(), format!("{parser} structure changed")));
            }
            sanitize::Verification::Unsupported { .. } | sanitize::Verification::NotAttempted => {
                twins.unchecked += 1;
            }
        }

        twins.aliased += result.applied.len();
        twins.records.push(vault::StoredFile {
            path: entry.path.clone(),
            twin_path: twin_of(&entry.path),
            checksum: entry.checksum.clone(),
            parser: parser.as_ref().map_or(String::new(), |p| p.name().to_owned()),
        });
        twins.staged.push((entry.path.clone(), Payload::Text(result.twin)));
    }

    Ok(twins)
}

fn run_export(project: &Path, dest: &Path, explicit: Option<&str>) -> Result<()> {
    if dest.exists() {
        bail!("{} already exists — refusing to write into it", dest.display());
    }

    let mut vault = open(project, explicit)?;
    let index = specshield_index::Index::build(project)?;

    let mut graph = graph_from(&vault)?;

    learn_project(project, &index, &mut vault, &mut graph)?;

    let detector = detector_from(&vault)?;
    let context = context_from(&vault)?;
    // Every real path to the path it is written under in the twin. Interning
    // happened in the learning pass; this is the same derivation, so it returns
    // the aliases already in the graph.
    let twins = twin_paths(&index, &detector, &mut graph)?;
    let twin_of = |path: &String| twins.get(path).cloned().unwrap_or_else(|| path.clone());

    let mut twins = sanitize_tree(project, &index, &detector, &context, &mut graph, &twin_of)?;

    // The graph is persisted either way: those aliases were derived, and
    // throwing them away would hand different aliases to the next run.
    persist(&mut vault, &graph)?;

    // One gate over the finished graph, not one per file.
    //
    // Stronger and faster for the same reason: the vault knows more after the
    // last file than it did after the first, so a name interned in file 900 is
    // now checked against file 3's twin — which a per-file scan would have
    // passed. Building the automaton once also takes the export from minutes to
    // seconds on a thousand files; it is O(names) to build and the graph grows
    // with every file.
    let scanner = verify::LeakScanner::new(graph.real_names());
    for (path, content) in &twins.staged {
        let Payload::Text(twin) = content else { continue };
        if let verify::Verdict::Blocked(leaks) = scanner.scan(twin) {
            twins.blocked.push((
                path.clone(),
                leaks
                    .iter()
                    .map(|l| format!("{}:{} {:?}", l.line, l.column, l.matched))
                    .collect(),
            ));
        }
    }

    // The tree is part of the export. A directory named after a client leaks
    // with no identifier in it at all, so the twin path goes through the same
    // gate the content does.
    for record in &twins.records {
        if let verify::Verdict::Blocked(leaks) = scanner.scan(&record.twin_path) {
            twins.blocked.push((
                record.path.clone(),
                leaks
                    .iter()
                    .map(|l| format!("twin path {:?} still contains {:?}", record.twin_path, l.matched))
                    .collect(),
            ));
        }
    }

    if !twins.blocked.is_empty() {
        vault.log("export", None, None, Some("blocked"), None)?;
        report_blocked(&twins.blocked);
        bail!("nothing was written: a partially clean twin project is not clean");
    }

    // Only now does anything reach the disk. Writing as we went and deleting
    // the directory on a block would leave "nothing was written" depending on a
    // cleanup succeeding.
    let mut written = 0usize;
    for (path, content) in &twins.staged {
        write_into(dest, &twin_of(path), |target| match content {
            Payload::Text(twin) => std::fs::write(target, twin),
            Payload::Copy(source) => std::fs::copy(source, target).map(|_| ()),
        })?;
        written += 1;
    }

    vault.put_files(&twins.records)?;
    vault.log(
        "export",
        Some(i64::try_from(written).unwrap_or(i64::MAX)),
        Some(i64::try_from(graph.len()).unwrap_or(i64::MAX)),
        Some("clean"),
        Some(&dest.to_string_lossy()),
    )?;

    let renamed = twins.records.iter().filter(|r| r.path != r.twin_path).count();
    report_export(
        dest,
        written,
        twins.aliased,
        graph.len(),
        twins.unchecked,
        &twins.abandoned,
        renamed,
    );
    Ok(())
}

/// Which parser claims this file, or empty. Reads the file only when a parser
/// might need the content to decide — OpenAPI is a YAML file until you look.
fn parser_for(project: &Path, entry: &specshield_index::Entry) -> String {
    if !entry.is_text {
        return String::new();
    }
    let path = project.join(&entry.path);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    specshield_parsers::for_document(&path, &content).map_or(String::new(), |p| p.name().to_owned())
}

/// Where an applied patch is kept so `undo` can reverse it.
///
/// Beside the vault, and in plaintext: it holds real identifiers. That is not a
/// new exposure — the source files it was built from sit in the same tree,
/// unencrypted, which is the whole reason this product exists — but it is a file
/// that must not be committed, and `.specshield/` is already ignored.
const LAST_PATCH: &str = ".specshield/last-apply.patch";
const LAST_APPLY: &str = ".specshield/last-apply.json";

/// The branch a restored patch lands on. Never `main` — see SDD §14.
const DEFAULT_BRANCH: &str = "specshield/restore";

/// Assemble the three versions a review needs.
///
/// `twin` is regenerated by sanitizing the original when the caller does not
/// supply it. Derivation is deterministic, so that reproduces what was sent —
/// as long as the vault has not learned new names since. It usually has not; when
/// it has, the twin-side diff shows the difference rather than hiding it, which
/// is why regeneration is safe to offer at all.
fn assemble(
    vault: &vault::Vault,
    project: &Path,
    file: &Path,
    twin: Option<&Path>,
    ai: &Path,
) -> Result<(String, String, String, Graph)> {
    let original = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let ai_twin = std::fs::read_to_string(ai).with_context(|| format!("reading {}", ai.display()))?;

    let mut graph = graph_from(vault)?;

    let twin_text = if let Some(path) = twin {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
    } else {
        let detector = detector_from(vault)?;
        let context = context_from(vault)?;
        let parser = specshield_parsers::for_document(file, &original);
        let scope = relative_to_project(project, file);
        // Not persisted. Regenerating a twin for comparison is a read, and it
        // should not quietly grow the vault.
        sanitize::sanitize(&original, &scope, &detector, &mut graph, parser.as_deref(), &context)?.twin
    };

    Ok((original, twin_text, ai_twin, graph))
}

/// A project-relative, `/`-separated path — the form the vault and a patch
/// header both use.
fn relative_to_project(project: &Path, file: &Path) -> String {
    let absolute = std::fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
    let root = std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());

    absolute
        .strip_prefix(&root)
        .unwrap_or(file)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Has the real file moved since the twin was made? — SDD §13.1.
///
/// Returns the recorded checksum when it no longer matches. A patch built from a
/// twin of older content does not merely fail to apply — it can apply cleanly and
/// silently revert whatever was done in between, which is worse.
fn staleness(vault: &vault::Vault, project: &Path, file: &Path) -> Result<Option<String>> {
    let relative = relative_to_project(project, file);
    let Some(record) = vault.files()?.into_iter().find(|f| f.path == relative) else {
        // Never indexed. Not stale — there is nothing to be stale against — and
        // the caller is told separately that no checksum was on file.
        return Ok(None);
    };

    let current = specshield_index::checksum_of(file)?;
    Ok((current != record.checksum).then_some(record.checksum))
}

fn print_review(review: &specshield_core::diff::Review, file: &Path) {
    use specshield_core::diff::{ChangeKind, Note, Side};

    println!("# {}", file.display());
    println!();

    if review.changes.is_empty() {
        println!("No changes: the restored output is identical to the file on disk.");
    }

    for hunk in &review.changes {
        let label = match hunk.kind {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Changed => "changed",
            ChangeKind::Formatting => "formatting only",
        };
        println!(
            "@@ -{},{} +{},{} @@ {label}",
            hunk.before.0, hunk.before.1, hunk.after.0, hunk.after.1
        );
        for line in &hunk.lines {
            let sign = match line.side {
                Side::Before => '-',
                Side::After => '+',
            };
            print!("{sign}{}", line.text);
            if !line.text.ends_with('\n') {
                println!();
            }
        }
        println!();
    }

    if !review.notes.is_empty() {
        println!("## Review");
        println!();
        for (line, note) in &review.notes {
            match note {
                Note::Fuzzy { found, real_name, kind } => {
                    println!(
                        "  line {line}: {found:?} -> {real_name:?} ({kind:?}) — matched loosely, not byte-for-byte"
                    );
                }
                Note::Unresolved { token } => {
                    println!("  line {line}: {token} is an alias this project has never issued");
                }
                Note::Redaction { marker } => {
                    println!("  line {line}: {marker} stays — redaction is one-way");
                }
            }
        }
        println!();
    }

    println!(
        "{} change(s), {} substantive, {} model-side edit(s)",
        review.changes.len(),
        review.substantive().count(),
        review.model_changes.len()
    );
}

fn run_diff(project: &Path, file: &Path, ai: &Path, twin: Option<&Path>, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    let (original, twin_text, ai_twin, graph) = assemble(&vault, project, file, twin, ai)?;

    let review = specshield_core::diff::review(&original, &twin_text, &ai_twin, &Vocabulary::new(graph.vocabulary()));
    print_review(&review, file);

    if let Some(recorded) = staleness(&vault, project, file)? {
        println!();
        println!("STALE — {} has changed since it was indexed.", file.display());
        println!("  recorded {recorded}");
        println!("  Applying a patch built from this twin would revert the intervening edits.");
    }
    if review.blocks_patch() {
        println!();
        println!("This cannot be applied while unresolved identities remain — see `specshield resolve`.");
    }
    Ok(())
}

/// SDD §12: the user names an entity the model invented.
///
/// The model's own token becomes the identity's alias rather than a freshly
/// derived one. The SDD says "an alias is derived for it in the normal way",
/// which cannot work: the response being restored contains `SERVICE_099`, so a
/// derived `SERVICE_4K2P8X` would leave that response unrestorable and need a
/// second table mapping one to the other. The token is already alias-shaped by
/// the same grammar (§6.3) and is opaque in exactly the same way, so it is kept.
fn run_resolve(
    project: &Path,
    alias: &str,
    name: &str,
    entity_type: EntityType,
    scope: &str,
    explicit: Option<&str>,
) -> Result<()> {
    if !specshield_core::alias::is_alias_shaped(alias) {
        bail!("{alias:?} is not alias-shaped — resolve names tokens the model invented, not arbitrary text");
    }

    let vault = open(project, explicit)?;

    if let Some(existing) = vault.identities()?.into_iter().find(|i| i.alias == alias) {
        bail!(
            "{alias} is already issued for {:?} — nothing to resolve",
            existing.real_name
        );
    }

    vault.put_identity(&vault::StoredIdentity {
        uuid: uuid::Uuid::new_v4().to_string(),
        scope_path: scope.to_owned(),
        entity_type: entity_type.prefix().to_owned(),
        real_name: name.to_owned(),
        alias: alias.to_owned(),
        origin: "ai_new".to_owned(),
        status: "active".to_owned(),
    })?;
    vault.log("resolve", None, Some(1), None, None)?;

    println!(
        "{alias} now names {name:?} ({}) in scope {scope}.",
        entity_type.prefix()
    );
    println!("Re-run the diff: the token will restore from here on.");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_apply(
    project: &Path,
    file: &Path,
    ai: &Path,
    twin: Option<&Path>,
    branch: &str,
    dry_run: bool,
    explicit: Option<&str>,
) -> Result<()> {
    let vault = open(project, explicit)?;
    let (original, twin_text, ai_twin, graph) = assemble(&vault, project, file, twin, ai)?;

    let review = specshield_core::diff::review(&original, &twin_text, &ai_twin, &Vocabulary::new(graph.vocabulary()));

    // SDD §12. An alias written into real source is a wrong identifier
    // committed, and there is no safe way to guess the right one.
    if review.blocks_patch() {
        eprintln!("REFUSED — {} unresolved identit(ies):", review.outcome.unresolved.len());
        for hit in &review.outcome.unresolved {
            eprintln!("  line {}: {}", hit.line, hit.token);
        }
        eprintln!();
        eprintln!("Name each one first:");
        eprintln!("  specshield resolve <ALIAS> --name <RealName> --entity-type <type>");
        bail!("nothing was applied");
    }

    // SDD §13.1.
    if let Some(recorded) = staleness(&vault, project, file)? {
        eprintln!("REFUSED — {} has changed since it was indexed.", file.display());
        eprintln!("  recorded {recorded}");
        eprintln!("  current  {}", specshield_index::checksum_of(file)?);
        eprintln!();
        eprintln!("This twin was made from content that is no longer there. Applying the patch");
        eprintln!("could cleanly revert whatever was edited in between — re-sanitize the file and");
        eprintln!("run the request again, then `specshield index` to record the new checksum.");
        bail!("nothing was applied");
    }

    let relative = relative_to_project(project, file);
    let Some(patch) = specshield_git::patch([(relative.as_str(), original.as_str(), review.restored.as_str())]) else {
        println!("No changes: the restored output is identical to the file on disk.");
        return Ok(());
    };

    let repository = match specshield_git::Repository::discover(project) {
        specshield_git::Availability::Ready(repository) => repository,
        unavailable => {
            // Never a silent overwrite (SDD §14). The restored content goes
            // beside the file, and the user moves it.
            let out = file.with_extension(format!(
                "{}.restored",
                file.extension()
                    .map_or_else(String::new, |e| e.to_string_lossy().into_owned())
            ));
            std::fs::write(&out, &review.restored)?;
            println!("{}", unavailable.explain());
            println!("Restored content written to {}", out.display());
            println!("The original is untouched; move the file yourself when you have reviewed it.");
            return Ok(());
        }
    };

    if dry_run {
        repository.check(&patch)?;
        println!("Dry run: the patch applies cleanly to {}.", repository.root().display());
        println!(
            "{} change(s), {} substantive",
            review.changes.len(),
            review.substantive().count()
        );
        return Ok(());
    }

    if repository.is_dirty()? {
        println!("Note: the working tree has uncommitted changes. `undo` reverses this patch and");
        println!("will fail if your edits overlap it — commit first if you want a clean undo.");
    }

    let applied = repository.apply_to_branch(&patch, branch, 1)?;

    // Saved so `undo` has something to reverse.
    let patch_path = project.join(LAST_PATCH);
    std::fs::write(&patch_path, &patch)?;
    std::fs::write(
        project.join(LAST_APPLY),
        format!(
            "{{\"branch\":{:?},\"previous_branch\":{:?},\"created_branch\":{}}}\n",
            applied.branch, applied.previous_branch, applied.created_branch
        ),
    )?;

    vault.log(
        "apply",
        Some(1),
        Some(i64::try_from(review.outcome.restored.len()).unwrap_or(i64::MAX)),
        Some("applied"),
        Some(&applied.branch),
    )?;

    println!("Applied to branch {}.", applied.branch);
    if applied.created_branch {
        println!("  branch created; you were on {}", applied.previous_branch);
    }
    println!("  {} alias occurrence(s) restored", review.outcome.restored.len());
    if review.needs_review() {
        println!(
            "  {} item(s) worth checking — run `specshield diff` to see them",
            review.notes.len()
        );
    }
    println!("  undo with: specshield undo");
    println!();
    println!("Review with `git diff`, then commit normally.");
    Ok(())
}

fn run_undo(project: &Path, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;

    let patch_path = project.join(LAST_PATCH);
    let patch = std::fs::read_to_string(&patch_path)
        .with_context(|| format!("no patch to undo — {} is missing", patch_path.display()))?;
    let record = std::fs::read_to_string(project.join(LAST_APPLY)).unwrap_or_default();

    let field = |name: &str| -> String {
        record
            .split(&format!("\"{name}\":\""))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default()
            .to_owned()
    };
    let applied = specshield_git::Applied {
        branch: field("branch"),
        previous_branch: field("previous_branch"),
        created_branch: record.contains("\"created_branch\":true"),
        files: 1,
    };

    let specshield_git::Availability::Ready(repository) = specshield_git::Repository::discover(project) else {
        bail!("git is not available here — there is nothing this command can reverse");
    };

    repository.undo(&patch, &applied)?;
    vault.log("undo", Some(1), None, Some("reverted"), None)?;

    let _ = std::fs::remove_file(&patch_path);
    let _ = std::fs::remove_file(project.join(LAST_APPLY));

    println!("Reversed. You are on {}.", repository.current_branch()?);
    Ok(())
}

fn run_unify(project: &Path, confirm: Option<&str>, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    let stored = vault.identities()?;

    let keys: Vec<specshield_core::model::IdentityKey> = stored
        .iter()
        .filter_map(|s| {
            s.entity_type
                .parse()
                .ok()
                .map(|t| specshield_core::model::IdentityKey::new(&s.scope_path, t, &s.real_name))
        })
        .collect();

    let proposals = specshield_core::unify::propose(&keys);

    if let Some(concept) = confirm {
        let Some(proposal) = proposals.iter().find(|p| p.concept == concept) else {
            bail!("no proposal for concept {concept:?} — run `specshield unify` to list them");
        };
        let mut linked = 0;
        for member in &proposal.members {
            let Some(found) =
                vault.find_identity(&member.scope_path, member.entity_type.prefix(), &member.real_name)?
            else {
                continue;
            };
            vault.put_concept(&found.uuid, concept)?;
            linked += 1;
        }

        // Re-derive every alias. A stored alias normally wins (SDD §6.5), so
        // without this the confirmation would apply only to identities interned
        // *after* it — which is none of them, since `unify` runs on a project
        // that has already been scanned. The feature would be silently inert.
        let changed = rekey(&vault)?;
        vault.log("unify.confirm", None, Some(i64::from(linked)), None, None)?;

        println!("Linked {linked} identities as concept {concept:?}.");
        println!("Re-derived {changed} alias(es).");
        if changed > 0 {
            println!();
            println!("Those aliases changed, so any twin already sent to a model is orphaned:");
            println!("its aliases no longer resolve. Re-sanitize before the next request.");
        }
        return Ok(());
    }

    if proposals.is_empty() {
        println!("No unification proposals.");
        println!();
        println!("A proposal needs a compatible pair of *different* kinds — a table and a DTO,");
        println!("a service and an API. Identities sharing a name and a kind are a collision,");
        println!("not a concept.");
        return Ok(());
    }

    println!(
        "{} proposal(s). Nothing is unified until confirmed.
",
        proposals.len()
    );
    for proposal in &proposals {
        println!(
            "concept {:?}  (confidence {:.2})",
            proposal.concept, proposal.confidence
        );
        for member in &proposal.members {
            println!(
                "  {:<10} {:<28} {}",
                member.entity_type.prefix(),
                member.real_name,
                member.scope_path
            );
        }
        if let Some(caveat) = &proposal.caveat {
            println!("  caveat: {caveat}");
        }
        println!("  confirm with: specshield unify --confirm {}", proposal.concept);
        println!();
    }
    Ok(())
}

/// Re-derive every alias in the project — a scoped re-key (SDD §9.5).
///
/// Derivation is deterministic, so an identity whose concept did not change
/// keeps exactly the alias it had. Only members of a newly confirmed concept
/// move.
///
/// Returns how many aliases actually changed, so the caller can warn only when
/// there is something to warn about.
fn rekey(vault: &vault::Vault) -> Result<u32> {
    use std::collections::HashSet;

    let settings = vault.settings()?;
    let style = match settings.alias_style.as_str() {
        "opaque" => AliasStyle::Opaque,
        "pseudonymous" => AliasStyle::Pseudonymous,
        _ => AliasStyle::Typed,
    };
    let key = ProjectKey::from_bytes(settings.project_key);
    let concepts: std::collections::HashMap<String, String> = vault.concepts()?.into_iter().collect();

    // Stable order, or the disambiguator suffixes would shuffle between runs.
    let mut identities = vault.identities()?;
    identities.sort_by(|a, b| a.uuid.cmp(&b.uuid));

    let mut used: HashSet<String> = HashSet::new();
    let mut changed = 0;

    for mut stored in identities {
        let Ok(entity_type) = stored.entity_type.parse::<EntityType>() else {
            continue;
        };
        let identity = specshield_core::model::IdentityKey::new(&stored.scope_path, entity_type, &stored.real_name);
        let concept = concepts.get(&stored.uuid).map(String::as_str);

        let mut disambiguator = None;
        let alias = loop {
            let candidate = specshield_core::alias::derive_in_concept(&key, &identity, style, disambiguator, concept);
            if used.insert(candidate.clone()) {
                break candidate;
            }
            disambiguator = Some(disambiguator.unwrap_or(1) + 1);
        };

        if alias != stored.alias {
            changed += 1;
            stored.alias = alias;
            vault.put_identity(&stored)?;
        }
    }
    Ok(changed)
}

/// SDD §11 / PRD FR-6b.
fn prompt_envelope() -> String {
    format!(
        "Tokens matching `{}` are opaque anonymized identifiers. Preserve them \
         exactly — do not rename, expand, translate, pluralize, or reformat them. \
         If you introduce a new entity, name it `NEW_<n>` and list every such name \
         at the end of your response.",
        specshield_core::alias::ENVELOPE_PATTERN
    )
}
