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
        input: Option<PathBuf>,
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
            input,
            passphrase,
        } => run_restore(&project, input.as_deref(), passphrase.as_deref()),
        Command::Unify {
            project,
            confirm,
            passphrase,
        } => run_unify(&project, confirm.as_deref(), passphrase.as_deref()),
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
    let mut context = specshield_core::parser::ProjectContext::default();
    for identity in vault.identities()? {
        if identity.entity_type == EntityType::Column.prefix() {
            context.known_members.insert(identity.real_name);
        }
    }
    Ok(context)
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

fn run_restore(project: &Path, input: Option<&Path>, explicit: Option<&str>) -> Result<()> {
    let vault = open(project, explicit)?;
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
