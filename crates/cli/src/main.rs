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
use specshield_core::alias::AliasStyle;
use specshield_core::model::EntityType;
use specshield_core::restore::Vocabulary;
use specshield_core::sanitize::Graph;
use specshield_core::{restore, sanitize, secrets, verify};
use specshield_project as project;
use specshield_project::{context_from, detector_from, graph_from, persist};
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

    /// Mark a term as never-alias — PRD FR-10.
    ///
    /// The other half of the dictionary: `term` says "this is proprietary,
    /// always alias it", and this says "this is a false positive, leave it
    /// alone". Precision is a first-class target — a twin full of aliased
    /// common words is unreadable, and measurably degrades the model's output.
    Allow {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        term: String,
        #[arg(long)]
        reason: Option<String>,
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

    /// Show the local audit log — PRD FR-9.
    ///
    /// Records that an operation happened, never what was in it. Distinct from
    /// telemetry, which this product does not have.
    Audit {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Emit CSV for compliance review.
        #[arg(long)]
        csv: bool,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Copy the vault somewhere safe — PRD FR-11.
    Backup {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        dest: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Put a backup back. Never writes over an existing vault.
    RestoreVault {
        backup: PathBuf,
        #[arg(long)]
        into: PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Export a passphrase-protected key escrow — PRD FR-11.
    ///
    /// The escrow passphrase is a second, separate one. Whoever holds this file
    /// and that passphrase can open the vault.
    Escrow {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        out: PathBuf,
        #[arg(long)]
        escrow_passphrase: String,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Recover a vault passphrase from an escrow file — PRD FR-11.
    ///
    /// Prints the passphrase on stdout so it can be piped straight into
    /// `SPECSHIELD_PASSPHRASE`; everything explanatory goes to stderr.
    EscrowOpen {
        file: PathBuf,
        #[arg(long)]
        escrow_passphrase: String,
        /// Check it against this project's vault before printing anything.
        #[arg(long)]
        verify_against: Option<PathBuf>,
    },

    /// Regenerate every alias under a new project key — PRD FR-11.
    ///
    /// Orphans every twin already shared. Prints what it would do unless
    /// `--confirm` is given.
    Rekey {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Inspect a vault that will not open — SDD §16 read-only recovery.
    ///
    /// Needs no passphrase and reveals no real name. Reports what the vault
    /// holds and what is wrong with it.
    Recover {
        #[arg(long, default_value = ".")]
        project: PathBuf,
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
    Endpoint,
    Table,
    Column,
    Dto,
    Interface,
    Enum,
    Event,
    Index,
    EnvVar,
    Host,
    PathSegment,
}

impl From<EntityTypeArg> for EntityType {
    fn from(value: EntityTypeArg) -> Self {
        match value {
            EntityTypeArg::Organization => Self::Organization,
            EntityTypeArg::Service => Self::Service,
            EntityTypeArg::Api => Self::Api,
            EntityTypeArg::Endpoint => Self::Endpoint,
            EntityTypeArg::Table => Self::Table,
            EntityTypeArg::Column => Self::Column,
            EntityTypeArg::Dto => Self::Dto,
            EntityTypeArg::Interface => Self::Interface,
            EntityTypeArg::Enum => Self::Enum,
            EntityTypeArg::Event => Self::Event,
            EntityTypeArg::Index => Self::Index,
            EntityTypeArg::EnvVar => Self::EnvVar,
            EntityTypeArg::Host => Self::Host,
            EntityTypeArg::PathSegment => Self::PathSegment,
        }
    }
}

/// One flat dispatch table.
///
/// Over the line limit and staying that way: the value of this function is that
/// every command and its arguments can be read in one place, and splitting it by
/// category to satisfy a line count would cost exactly that.
#[allow(clippy::too_many_lines)]
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
        Command::Allow {
            project,
            term,
            reason,
            passphrase,
        } => run_allow(&project, &term, reason.as_deref(), passphrase.as_deref()),
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
        Command::Audit {
            project,
            limit,
            csv,
            passphrase,
        } => run_audit(&project, limit, csv, passphrase.as_deref()),
        Command::Backup {
            project,
            dest,
            passphrase,
        } => run_backup(&project, &dest, passphrase.as_deref()),
        Command::RestoreVault {
            backup,
            into,
            passphrase,
        } => run_restore_vault(&backup, &into, passphrase.as_deref()),
        Command::Escrow {
            project,
            out,
            escrow_passphrase,
            passphrase,
        } => run_escrow(&project, &out, &escrow_passphrase, passphrase.as_deref()),
        Command::EscrowOpen {
            file,
            escrow_passphrase,
            verify_against,
        } => run_escrow_open(&file, &escrow_passphrase, verify_against.as_deref()),
        Command::Rekey {
            project,
            confirm,
            passphrase,
        } => run_rekey(&project, confirm, passphrase.as_deref()),
        Command::Recover { project } => run_recover(&project),
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

    // SDD §16 routes vault corruption to read-only recovery. A raw
    // "file is not a database" is technically accurate and completely useless
    // to someone whose mapping has just stopped opening.
    vault::Vault::open(&path, &passphrase(explicit)?).map_err(|e| match e {
        vault::VaultError::Decryption => anyhow::anyhow!(
            "wrong passphrase, or the vault has been tampered with. There is no passphrase \
             recovery by design — restore from a backup or an escrow export. \
             `specshield recover` reports what the vault holds without one."
        ),
        other => anyhow::Error::new(other).context(format!(
            "{} would not open. `specshield recover` inspects it read-only and says what is wrong.",
            path.display()
        )),
    })
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

/// PRD FR-10 — the allowlist.
///
/// The other half of the dictionary. `term` says "this is proprietary, always
/// alias it"; this says "this is a false positive, leave it alone". Precision is
/// a first-class target: a twin full of aliased common words is unreadable, and
/// measurably degrades the output generated from it.
fn run_allow(project: &Path, term: &str, reason: Option<&str>, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    vault.add_allowed(term, reason)?;
    vault.log("allow.add", None, Some(1), None, None)?;

    println!("{term:?} will never be aliased in this project.");
    println!("{} term(s) on the allowlist.", vault.allowlist()?.len());
    Ok(())
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
        // A vault with no interned identities has nothing to scan for, so
        // everything is "clean". That is the shape of a silent pass: a CI job
        // gating on this would go green having checked nothing at all. Say so,
        // and exit non-zero — a gate that cannot fail is not a gate.
        verify::Verdict::Clean if scanner.pattern_count() == 0 => {
            eprintln!("NOT CHECKED — this project has no identities yet, so there was nothing to");
            eprintln!("scan for. A dictionary term is not enough: a name is interned the first");
            eprintln!("time it is aliased. Run `specshield sanitize` or `specshield export` first.");
            std::process::exit(2);
        }
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
    let result = project::restore_project(vault, twin_root, dest)?;

    println!("Restored {} file(s) into {}", result.written, dest.display());
    println!("  {} alias occurrence(s) resolved", result.aliases_resolved);
    if result.unmapped.is_empty() {
        println!("  every twin path mapped back to a real path");
    } else {
        println!(
            "  {} file(s) the vault has no path mapping for, left where they stand:",
            result.unmapped.len()
        );
        for path in result.unmapped.iter().take(20) {
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
    let index = project::index_project(project, &mut vault)?;
    let walked = started.elapsed();

    let text = index.text_files().count();
    let parseable = index
        .files
        .values()
        .filter(|e| !project::parser_for(project, e).is_empty())
        .count();

    println!("Indexed {} file(s) in {:.2}s", index.len(), walked.as_secs_f64());
    println!("  {text} text, {parseable} with a parser in this build");
    println!("  {} binary or unparseable", index.len() - parseable);
    Ok(())
}

/// Re-walk and say what moved — SDD §13.1.
fn run_rescan(project: &Path, explicit: Option<&str>) -> Result<()> {
    let mut vault = open(project, explicit)?;
    if vault.files()?.is_empty() {
        bail!("no index for this project yet — run `specshield index` first");
    }

    let started = std::time::Instant::now();
    let (index, changes, stale) = project::rescan_project(project, &mut vault)?;
    let elapsed = started.elapsed();

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
    if stale.is_empty() {
        println!(
            "
No stale twins: every recorded checksum still matches the file on disk."
        );
    } else {
        println!(
            "
{} file(s) have changed since their twin was made. Applying a patch",
            stale.len()
        );
        println!("built from those twins would revert the intervening edits — re-sanitize first:");
        for path in stale.iter().take(20) {
            println!("  {path}");
        }
    }
    Ok(())
}

fn report_export(dest: &Path, result: &project::Exported) {
    println!("Exported {} file(s) to {}", result.written, dest.display());
    println!(
        "  {} alias applications, {} identities in the vault",
        result.aliased, result.identities
    );
    println!("  every file passed the gate (SDD §8), paths included");
    println!("  {} path(s) renamed in the twin tree", result.renamed);
    println!("  {} file(s) had no structure to verify against", result.unchecked);
    if result.abandoned.is_empty() {
        println!("  every parsed file verified structurally (SDD §7.2)");
    } else {
        println!(
            "  {} file(s) exported UNALIASED — aliasing was abandoned:",
            result.abandoned.len()
        );
        for (path, why) in result.abandoned.iter().take(20) {
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

fn run_export(project: &Path, dest: &Path, explicit: Option<&str>) -> Result<()> {
    let mut vault = open(project, explicit)?;
    let result = project::export(project, dest, &mut vault)?;

    if result.is_blocked() {
        report_blocked(&result.blocked);
        bail!("nothing was written: a partially clean twin project is not clean");
    }

    report_export(dest, &result);
    Ok(())
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

/// PRD FR-9 — the log a security team reads.
fn run_audit(project: &Path, limit: usize, csv: bool, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    let entries = vault.audit_log(limit)?;

    if csv {
        print!("{}", vault::audit_csv(&entries));
        return Ok(());
    }

    if entries.is_empty() {
        println!("No entries yet.");
        return Ok(());
    }

    println!("when                 operation         files entities  result     destination");
    for entry in &entries {
        println!(
            "{:<20} {:<16} {:>5} {:>7}  {:<10} {}",
            entry.ts,
            entry.operation,
            entry.file_count.map_or_else(|| "-".to_owned(), |n| n.to_string()),
            entry.entity_count.map_or_else(|| "-".to_owned(), |n| n.to_string()),
            entry.verification.as_deref().unwrap_or("-"),
            entry.destination.as_deref().unwrap_or("-"),
        );
    }
    println!();
    println!("{} entr(ies). No real names, no content — FR-9.", entries.len());
    Ok(())
}

/// PRD FR-11 — a consistent copy of the vault.
fn run_backup(project: &Path, dest: &Path, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    vault.backup_to(dest)?;

    println!("Backed up to {}", dest.display());
    println!("  The copy is encrypted exactly as the vault is, and opens with the same passphrase.");
    println!("  It is not a second factor: someone who has this file and the passphrase has the mapping.");
    Ok(())
}

/// PRD FR-11 — put a backup back, without ever overwriting.
fn run_restore_vault(backup: &Path, into: &Path, explicit: Option<&str>) -> Result<()> {
    let passphrase = passphrase(explicit)?;
    vault::backup::restore_from(backup, into, &passphrase)?;

    println!("Restored {} to {}", backup.display(), into.display());
    println!("  Verified it opens before anything was written.");
    Ok(())
}

/// PRD FR-11 — passphrase-protected key escrow.
fn run_escrow(project: &Path, out: &Path, escrow_passphrase: &str, explicit: Option<&str>) -> Result<()> {
    if out.exists() {
        bail!(
            "{} already exists — refusing to overwrite an escrow file",
            out.display()
        );
    }
    // Opening proves the passphrase is the right one before it is escrowed. An
    // escrow file holding a wrong passphrase is worse than none: it is a
    // recovery plan that fails only when it is needed.
    let passphrase = passphrase(explicit)?;
    let vault = vault::Vault::open(&vault_path(project), &passphrase)?;

    let sealed = vault::backup::export_escrow(&passphrase, escrow_passphrase)?;
    std::fs::write(out, &sealed)?;
    vault.log("vault.escrow", None, None, None, None)?;

    println!("Escrow written to {}", out.display());
    println!();
    println!("{}", vault::backup::ESCROW_WARNING);
    Ok(())
}

/// PRD FR-11 — the other half of escrow.
///
/// An escrow file nobody can open is not a recovery plan, it is a reassurance.
/// This is the verb that makes it real.
fn run_escrow_open(file: &Path, escrow_passphrase: &str, verify_against: Option<&Path>) -> Result<()> {
    let sealed = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let recovered = vault::backup::open_escrow(&sealed, escrow_passphrase)?;

    if let Some(project) = verify_against {
        // Better to fail here than to hand someone a passphrase that turns out
        // to belong to a different vault.
        vault::Vault::open(&vault_path(project), &recovered)
            .context("the escrowed passphrase does not open that project's vault")?;
        eprintln!("Verified against {}.", vault_path(project).display());
    }

    eprintln!(
        "Recovered from {}. Treat what follows as the passphrase itself.",
        file.display()
    );
    println!("{recovered}");
    Ok(())
}

/// PRD FR-11 — re-key: every alias in the project changes.
///
/// The operation with the worst failure mode in the product. Aliases are
/// HMAC-derived from the project key, so a new key means every twin already
/// sent to a model is orphaned — its aliases no longer resolve to anything.
/// That is the point when a twin has been over-shared, and a disaster otherwise,
/// so it is confirmed explicitly rather than assumed.
fn run_rekey(project: &Path, confirm: bool, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    let before = vault.identities()?.len();

    if !confirm {
        println!("Re-keying would change every one of the {before} alias(es) in this project.");
        println!();
        println!("Every twin already shared becomes unrestorable: its aliases will no longer");
        println!("resolve to anything. Do this when a twin has been over-shared, or when the");
        println!("alias style changes — not otherwise.");
        println!();
        println!("Back up first:  specshield backup <path>");
        println!("Then:           specshield rekey --confirm");
        return Ok(());
    }

    let mut fresh = [0u8; 32];
    getrandom::fill(&mut fresh).map_err(|e| anyhow::anyhow!("entropy source unavailable: {e}"))?;
    let changed = project::rotate_key(&vault, &fresh)?;
    fresh.zeroize();

    println!("Re-keyed. {changed} of {before} alias(es) changed.");
    println!();
    println!("Every twin produced before now is orphaned. Re-sanitize and re-send anything");
    println!("still in flight with a model.");
    Ok(())
}

/// SDD §16 — read-only recovery mode.
///
/// Reached when the vault will not open normally, which is the moment a user
/// most needs to be told something other than "no".
fn run_recover(project: &Path) -> Result<()> {
    let path = vault_path(project);
    let recovery = vault::Recovery::open(&path)?;

    println!("# Recovery — {}", path.display());
    println!();
    println!("{}", recovery.diagnosis());
    println!();

    if !recovery.is_readable() {
        println!("Nothing could be read from the file.");
        return Ok(());
    }

    println!("schema version: {}", recovery.schema_version().unwrap_or(0));
    println!("identities:     {}", recovery.identity_count());
    println!("indexed files:  {}", recovery.file_count());

    let types = recovery.entity_types();
    if !types.is_empty() {
        println!();
        println!("By type:");
        for (kind, count) in &types {
            println!("  {kind:<10} {count}");
        }
    }

    let entries = recovery.audit_log(10);
    if !entries.is_empty() {
        println!();
        println!("Last {} audit entr(ies):", entries.len());
        for entry in &entries {
            println!(
                "  {} {:<16} {}",
                entry.ts,
                entry.operation,
                entry.verification.as_deref().unwrap_or("-")
            );
        }
    }

    println!();
    println!("Read-only. Nothing here was modified, and no real name is readable without");
    println!("the passphrase — recovery mode reports what a vault holds, it is not a way in.");
    Ok(())
}

fn run_unify(project: &Path, confirm: Option<&str>, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
    let proposals = project::unify_proposals(&vault)?;

    if let Some(concept) = confirm {
        if !proposals.iter().any(|p| p.concept == concept) {
            bail!("no proposal for concept {concept:?} — run `specshield unify` to list them");
        }
        let (linked, changed) = project::unify_confirm(&vault, concept)?;

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
