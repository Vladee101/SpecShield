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
        input: Option<PathBuf>,
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
            input,
            passphrase,
        } => run_restore(&project, input.as_deref(), passphrase.as_deref()),
        Command::Report { corpus, strict } => report::run(&corpus, strict),
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

fn open(project: &Path, explicit: Option<&str>) -> Result<(vault::VaultContents, String)> {
    let path = vault_path(project);
    if !path.exists() {
        bail!("no vault at {} — run `specshield init` first", path.display());
    }
    let pw = passphrase(explicit)?;
    let contents = vault::load(&path, &pw)?;
    Ok((contents, pw))
}

/// Rebuild the in-memory graph from stored identities, so aliases stay stable
/// across invocations (SDD §6.5).
fn graph_from(contents: &vault::VaultContents) -> Result<Graph> {
    let style = match contents.alias_style.as_str() {
        "opaque" => AliasStyle::Opaque,
        "pseudonymous" => AliasStyle::Pseudonymous,
        _ => AliasStyle::Typed,
    };
    let mut graph = Graph::new(ProjectKey::from_bytes(contents.project_key), style);
    for stored in &contents.identities {
        let entity_type: EntityType = stored
            .entity_type
            .parse()
            .with_context(|| format!("vault holds unknown entity type {:?}", stored.entity_type))?;
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

fn detector_from(contents: &vault::VaultContents) -> Result<Detector> {
    let mut detector = Detector::new();
    for (name, type_name) in &contents.dictionary {
        let entity_type: EntityType = type_name
            .parse()
            .with_context(|| format!("dictionary holds unknown entity type {type_name:?}"))?;
        detector = detector.with_term(name, entity_type);
    }
    for term in &contents.allowlist {
        detector = detector.with_allowed(term);
    }
    Ok(detector)
}

fn persist(project: &Path, pw: &str, contents: &mut vault::VaultContents, graph: &Graph) -> Result<()> {
    contents.identities = graph
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
    vault::save(&vault_path(project), pw, contents)?;
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

    let contents = vault::VaultContents {
        project_name: project
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "project".to_owned()),
        alias_style: format!("{style:?}").to_lowercase(),
        scope_strategy: "module".to_owned(),
        project_key,
        identities: Vec::new(),
        dictionary: Vec::new(),
        allowlist: Vec::new(),
    };
    vault::save(&path, &pw, &contents)?;

    println!("Initialized vault at {}", path.display());
    println!("Alias style: {style:?}");
    println!();
    println!("Next: add the terms only you can name, then sanitize.");
    println!("  specshield term \"Your Company\" --entity-type organization");
    Ok(())
}

fn add_term(project: &Path, name: &str, entity_type: EntityType, explicit: Option<&str>) -> Result<()> {
    let (mut contents, pw) = open(project, explicit)?;
    let type_name = entity_type.prefix().to_owned();

    if contents.dictionary.iter().any(|(n, _)| n == name) {
        println!("{name:?} is already in the dictionary");
        return Ok(());
    }
    contents.dictionary.push((name.to_owned(), type_name));
    vault::save(&vault_path(project), &pw, &contents)?;
    println!("Added {name:?} as {}", entity_type.prefix());
    Ok(())
}

fn run_sanitize(project: &Path, file: &Path, out: Option<&Path>, envelope: bool, explicit: Option<&str>) -> Result<()> {
    let (mut contents, pw) = open(project, explicit)?;
    let source = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;

    let mut graph = graph_from(&contents)?;
    let detector = detector_from(&contents)?;
    let scope = file.to_string_lossy().replace('\\', "/");

    let result = sanitize::sanitize(&source, &scope, &detector, &mut graph)?;

    // SDD §8 — nothing is emitted before the gate passes.
    let scanner = verify::LeakScanner::new(graph.real_names());
    let verdict = scanner.scan(&result.twin);
    let secret_findings = secrets::scan(&result.twin);

    persist(project, &pw, &mut contents, &graph)?;

    if let verify::Verdict::Blocked(leaks) = &verdict {
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
    let (contents, _) = open(project, explicit)?;
    let text = std::fs::read_to_string(file)?;
    let graph = graph_from(&contents)?;

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

fn run_restore(project: &Path, input: Option<&Path>, explicit: Option<&str>) -> Result<()> {
    let (contents, _) = open(project, explicit)?;
    let text = match input {
        Some(path) => std::fs::read_to_string(path)?,
        None => std::io::read_to_string(std::io::stdin())?,
    };

    let graph = graph_from(&contents)?;
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
