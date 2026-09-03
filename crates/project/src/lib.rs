//! The project pipeline — everything that operates on a whole project rather
//! than one document. **M6.**
//!
//! This crate exists because there are two front-ends. The command line and the
//! desktop application both need to build a graph from a vault, seed a detector
//! from it, learn a project, alias a file tree, and export a twin. Two copies of
//! that would be two chances to drift, and drift here is not cosmetic: an alias
//! derived one way in one surface and another way in the other means a twin
//! produced by one cannot be restored by the other.
//!
//! It sits above `specshield-parsers` because the pipeline needs parsers, and
//! `specshield-core` cannot depend on them — parsers depend on core.
//!
//! **Nothing here prints.** Every function returns what happened and lets the
//! caller decide how to say it. That is what makes the same pipeline usable
//! behind a terminal and behind a window.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use specshield_core::detect::Detector;
use specshield_core::model::{EntityType, IdentityKey, Origin, Status};
use specshield_core::parser::ProjectContext;
use specshield_core::sanitize::{self, Graph};
use specshield_core::{alias, paths, secrets, verify};
use specshield_index::Index;
use specshield_vault as vault;

#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("{0}")]
    Vault(#[from] vault::VaultError),
    #[error("{0}")]
    Index(#[from] specshield_index::IndexError),
    #[error("{0}")]
    Sanitize(#[from] sanitize::SanitizeError),
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("writing {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("vault holds unknown entity type {0:?}")]
    UnknownEntityType(String),
    #[error("{0} already exists — refusing to write into it")]
    DestinationExists(PathBuf),
    #[error("no proposal for concept {0:?}")]
    NoSuchConcept(String),
}

type Result<T> = std::result::Result<T, ProjectError>;

/// Written out so the escape cannot be mangled by a source rewrite.
const NEWLINE: char = '\n';

/// The stored style name to the enum. One place, because three call sites had
/// their own copy and a fourth would have been a coin toss.
#[must_use]
pub fn alias_style(stored: &str) -> alias::AliasStyle {
    match stored {
        "opaque" => alias::AliasStyle::Opaque,
        "pseudonymous" => alias::AliasStyle::Pseudonymous,
        _ => alias::AliasStyle::Typed,
    }
}

/// Rebuild the in-memory graph from stored identities, so aliases stay stable
/// across invocations — SDD §6.5.
pub fn graph_from(vault: &vault::Vault) -> Result<Graph> {
    let mut settings = vault.settings()?;
    let style = alias_style(&settings.alias_style);
    let mut graph = Graph::new(alias::ProjectKey::take_bytes(&mut settings.project_key), style);

    let concepts: HashMap<String, String> = vault.concepts()?.into_iter().collect();
    for stored in vault.identities()? {
        let entity_type: EntityType = stored
            .entity_type
            .parse()
            .map_err(|_| ProjectError::UnknownEntityType(stored.entity_type.clone()))?;
        let key = IdentityKey::new(&stored.scope_path, entity_type, &stored.real_name);

        if let Some(concept) = concepts.get(&stored.uuid) {
            graph.confirm_concept(std::slice::from_ref(&key), concept);
        }
        graph.restore_node(&key, &stored.uuid, &stored.alias, Origin::Detected, Status::Active);
    }
    Ok(graph)
}

/// Write the graph back. Identities are upserted in one transaction — SDD §9.2.
pub fn persist(vault: &mut vault::Vault, graph: &Graph) -> Result<()> {
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

/// What the project knows, for parsers that cannot resolve everything from one
/// file — see [`ProjectContext`].
pub fn context_from(vault: &vault::Vault) -> Result<ProjectContext> {
    let identities = vault.identities()?;
    let members = identities
        .iter()
        .filter(|i| i.entity_type == EntityType::Column.prefix())
        .map(|i| i.real_name.clone());
    let names = identities.iter().map(|i| i.real_name.clone());
    Ok(ProjectContext::new(members, names))
}

/// The same context, but from the graph as it stands mid-run rather than from
/// the vault. The path pass needs what the *content* passes just learned, and
/// that is not in the vault until [`persist`].
#[must_use]
pub fn context_from_graph(graph: &Graph) -> ProjectContext {
    let members = graph
        .nodes()
        .filter(|n| n.key.entity_type == EntityType::Column)
        .map(|n| n.key.real_name.clone());
    let names = graph.nodes().map(|n| n.key.real_name.clone());
    ProjectContext::new(members, names)
}

/// The names the user has marked never-alias — PRD FR-10.
///
/// Needed by the gate as well as the detector: allowlisting a name the vault
/// already knows would otherwise stop it being aliased and then block every
/// export on it. See [`specshield_core::verify::LeakScanner::with_allowlist`].
pub fn allowlist(vault: &vault::Vault) -> Result<std::collections::BTreeSet<String>> {
    Ok(vault.allowlist()?.into_iter().collect())
}

/// A gate that honours the project's allowlist.
pub fn gate(vault: &vault::Vault, graph: &Graph) -> Result<verify::LeakScanner> {
    Ok(verify::LeakScanner::with_allowlist(
        graph.real_names(),
        &allowlist(vault)?,
    ))
}

/// Seed a detector from everything the project knows — SDD §5.
///
/// The SQL scan interns the table `invoice`; the OpenAPI spec next to it then
/// says "Fetch a single invoice" in a summary and the gate blocks, because the
/// vault knows that name and the twin still contains it. Seeding the detector
/// with what the project already knows is what makes a name consistent across
/// files rather than per-file.
///
/// It aliases common words that happen to be table names — `invoice`, `account`
/// — wherever they appear. That is the safe direction, and PRD FR-10's allowlist
/// is the escape hatch for a user who disagrees.
pub fn detector_from(vault: &vault::Vault) -> Result<Detector> {
    let mut detector = Detector::new();

    for identity in vault.identities()? {
        if let Ok(entity_type) = identity.entity_type.parse() {
            detector = detector.with_term(identity.real_name, entity_type);
        }
    }
    for (name, type_name) in vault.dictionary()? {
        let entity_type: EntityType = type_name
            .parse()
            .map_err(|_| ProjectError::UnknownEntityType(type_name.clone()))?;
        detector = detector.with_term(name, entity_type);
    }
    for term in vault.allowlist()? {
        detector = detector.with_allowed(term);
    }
    Ok(detector)
}

/// Intern every path segment that is an entity, and return the twin path for
/// each real path — PRD FR-3b.
///
/// Run after the content passes, so `thing18.ts` can be recognised as naming the
/// `Thing18` those passes found. The identities are the same ones the TypeScript
/// parser uses for import specifiers (`specshield_core::paths`), so a renamed
/// file and every import of it agree by construction.
pub fn twin_paths(index: &Index, detector: &Detector, graph: &mut Graph) -> Result<HashMap<String, String>> {
    use paths::Component;

    let context = context_from_graph(graph);
    let mut out = HashMap::new();

    for path in index.files.keys() {
        let mut failed = None;
        let twin = paths::twin_path(path, &context, |component| match component {
            Component::Segment { key, suffix } => {
                format!("{}{suffix}", graph.intern(key, Origin::Detected).alias)
            }
            // Sanitizing the component as if it were a document is not a trick:
            // it is the same call the file's *contents* go through, which is
            // exactly why the tree and the import strings come out agreeing.
            Component::Text { text, suffix } => {
                match sanitize::sanitize(text, paths::PATH_SCOPE, detector, graph, None, &context) {
                    Ok(result) => format!("{}{suffix}", result.twin),
                    Err(e) => {
                        failed = Some(e);
                        format!("{text}{suffix}")
                    }
                }
            }
        });

        if let Some(e) = failed {
            return Err(e.into());
        }
        out.insert(path.clone(), twin);
    }

    Ok(out)
}

/// Learn the whole project before producing anything from it.
///
/// A first pass over every file, so that by the time file two is sanitized the
/// vault already knows what file nine hundred declared. Without it, a name is
/// only found in files that come after the one that declared it.
pub fn learn(project: &Path, index: &Index, vault: &mut vault::Vault, graph: &mut Graph) -> Result<()> {
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

    // Filenames last: `thing18.ts` is only recognisable as naming `Thing18` once
    // the content pass above has found that type.
    twin_paths(index, &detector, graph)?;

    persist(vault, graph)
}

/// What an exported file carries: a sanitized twin, or the original bytes.
#[derive(Debug)]
pub enum Payload {
    Text(String),
    /// A binary. Nothing to sanitize and nothing to verify — it carries no
    /// identifiers a parser or the gate can read — but it is copied so the
    /// exported tree is still the project.
    Copy(PathBuf),
}

/// Where one identity was found in one file — PRD FR-5, before the vault has
/// been asked for the file's row id.
#[derive(Debug, Clone)]
pub struct Sighting {
    pub path: String,
    pub identity_uuid: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub kind: specshield_core::model::OccurrenceKind,
}

/// One secret that was redacted out of one file — SDD §4.3.
///
/// **Carries no plaintext.** `match_idx` is computed at the point of the match
/// and the matched text is dropped there; a struct that held the secret until
/// the end of an export would keep every credential in the project alive in
/// memory for the length of it.
#[derive(Debug, Clone)]
pub struct Redacted {
    pub path: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub secret_type: String,
    pub match_idx: String,
}

/// Everything the sanitize pass produced, held until the gate has run.
#[derive(Debug, Default)]
pub struct Twins {
    pub staged: Vec<(String, Payload)>,
    pub records: Vec<vault::StoredFile>,
    pub blocked: Vec<(String, Vec<String>)>,
    pub abandoned: Vec<(String, String)>,
    pub aliased: usize,
    pub unchecked: usize,
    /// Every place an alias was applied — PRD FR-5. Empty for a file whose
    /// aliasing was abandoned, which is correct: nothing was applied there.
    pub sightings: Vec<Sighting>,
    /// Every secret redacted on the way — SDD §4.3.
    pub redacted: Vec<Redacted>,
    /// Files a parser claimed and could not read. Reported separately from
    /// `abandoned` and from `unchecked`, because nothing was abandoned and
    /// nothing was skipped: the file simply went through untouched.
    pub unreadable: Vec<(String, String)>,
}

/// Sanitize every file in the project, producing twins but writing nothing.
///
/// `secret_index` turns a matched secret into the one-way index the vault
/// stores — `specshield_vault::Vault::secret_index`. It is a closure rather
/// than a vault reference so the plaintext never outlives the line that matched
/// it: the secret is hashed here and dropped here.
pub fn sanitize_tree(
    project: &Path,
    index: &Index,
    detector: &Detector,
    context: &ProjectContext,
    graph: &mut Graph,
    twin_of: &impl Fn(&String) -> String,
    secret_index: &impl Fn(&str) -> String,
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

        let source = std::fs::read_to_string(&source_path).map_err(|source| ProjectError::Read {
            path: source_path.clone(),
            source,
        })?;
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
            // Not "unchecked": the parser claimed this file and could not read
            // it, so it contributed no candidates either. The file goes to the
            // model essentially untouched, and counting it alongside plain text
            // that genuinely has no shape would bury that.
            sanitize::Verification::OriginalDidNotParse { parser } => {
                twins
                    .unreadable
                    .push((entry.path.clone(), format!("the {parser} parser could not read it")));
            }
            sanitize::Verification::Unsupported { .. } | sanitize::Verification::NotAttempted => {
                twins.unchecked += 1;
            }
        }

        // Recorded from the *original* source, because that is what the byte
        // offsets index and what the user still has on disk. The twin has a
        // marker where the secret was; the file they need to go clean up does
        // not.
        for finding in &result.secrets {
            twins.redacted.push(Redacted {
                path: entry.path.clone(),
                byte_start: finding.byte_start,
                byte_end: finding.byte_end,
                secret_type: finding.secret_type.to_owned(),
                match_idx: secret_index(source.get(finding.byte_start..finding.byte_end).unwrap_or_default()),
            });
        }

        for hit in &result.applied {
            twins.sightings.push(Sighting {
                path: entry.path.clone(),
                identity_uuid: hit.uuid.to_string(),
                byte_start: hit.byte_start,
                byte_end: hit.byte_end,
                kind: hit.kind,
            });
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

/// What an export did, for a caller to report however it likes.
#[derive(Debug, Default)]
pub struct Exported {
    pub written: usize,
    pub aliased: usize,
    pub identities: usize,
    pub renamed: usize,
    pub unchecked: usize,
    pub abandoned: Vec<(String, String)>,
    /// Non-empty means nothing was written. A partially clean twin project is
    /// not clean.
    pub blocked: Vec<(String, Vec<String>)>,
    /// How many vault names the gate was told to ignore — PRD FR-10. Reported
    /// because an open gate must never be silent.
    pub allowlisted: usize,
    /// Files a parser claimed and could not read — see [`Twins::unreadable`].
    /// These went to the model with no structural aliasing and no check.
    pub unreadable: Vec<(String, String)>,
    /// Places recorded in the vault — PRD FR-5. Larger than `aliased` never,
    /// smaller when a file's aliasing was abandoned.
    pub occurrences: usize,
    /// Secrets redacted on the way out — SDD §4.3.
    pub redacted: usize,
    /// How many of those this vault had never seen before. The rest were in the
    /// project at the last export too, which is the difference between "someone
    /// just committed a credential" and "this one is still here".
    pub redacted_new: usize,
}

impl Exported {
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        !self.blocked.is_empty()
    }
}

/// Sanitize a whole project into a twin directory.
///
/// The gate runs once over the finished graph rather than once per file. That is
/// both stronger and faster for the same reason: the vault knows more after the
/// last file than after the first, so a name interned in file 900 is checked
/// against file 3's twin — which a per-file scan would have passed — and the
/// automaton is built once instead of a thousand times.
///
/// Nothing reaches the disk until every file has passed. Writing as we went and
/// deleting the directory on a block would make "nothing was written" depend on
/// a cleanup succeeding.
pub fn export(project: &Path, dest: &Path, vault: &mut vault::Vault) -> Result<Exported> {
    if dest.exists() {
        return Err(ProjectError::DestinationExists(dest.to_path_buf()));
    }

    let index = Index::build(project)?;
    // What the vault thinks the project contains, read before this export
    // changes it.
    let recorded: Vec<String> = vault.files()?.into_iter().map(|f| f.path).collect();

    let mut graph = graph_from(vault)?;
    learn(project, &index, vault, &mut graph)?;

    let detector = detector_from(vault)?;
    let context = context_from(vault)?;
    let twins_by_path = twin_paths(&index, &detector, &mut graph)?;
    let twin_of = |path: &String| twins_by_path.get(path).cloned().unwrap_or_else(|| path.clone());

    let known = vault.known_secrets()?;
    let secret_index = |matched: &str| vault.secret_index(matched);

    let mut twins = sanitize_tree(
        project,
        &index,
        &detector,
        &context,
        &mut graph,
        &twin_of,
        &secret_index,
    )?;

    // The graph is persisted either way: those aliases were derived, and
    // throwing them away would hand different aliases to the next run.
    persist(vault, &graph)?;

    run_gate(&gate(vault, &graph)?, &mut twins);

    let renamed = twins.records.iter().filter(|r| r.path != r.twin_path).count();
    let redacted_new = twins.redacted.iter().filter(|r| !known.contains(&r.match_idx)).count();

    if twins.is_blocked_now() {
        vault.log("export", None, None, Some("blocked"), None)?;
        // Nothing is recorded on a block. The `files` rows were never written
        // either, and an occurrence row is meaningless without the file row it
        // points at — but the deeper reason is that a blocked export is not an
        // export: it must leave the vault describing the last one that was.
        return Ok(Exported {
            blocked: twins.blocked,
            abandoned: twins.abandoned,
            aliased: twins.aliased,
            identities: graph.len(),
            renamed,
            unchecked: twins.unchecked,
            written: 0,
            allowlisted: allowlist(vault)?.len(),
            unreadable: twins.unreadable,
            occurrences: 0,
            redacted: twins.redacted.len(),
            redacted_new,
        });
    }

    let mut written = 0;
    for (path, content) in &twins.staged {
        let target = dest.join(twin_of(path));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ProjectError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let result = match content {
            Payload::Text(twin) => std::fs::write(&target, twin),
            Payload::Copy(source) => std::fs::copy(source, &target).map(|_| ()),
        };
        result.map_err(|source| ProjectError::Write {
            path: target.clone(),
            source,
        })?;
        written += 1;
    }

    vault.put_files(&twins.records)?;

    // Files that have gone since the last export. Without this the vault keeps
    // describing them: `specshield secrets` names a file that does not exist,
    // and `specshield where` reports occurrences nobody can go and look at.
    // `forget_files` cascades, so the side tables go with them.
    let present: std::collections::BTreeSet<&String> = twins.records.iter().map(|r| &r.path).collect();
    let gone: Vec<String> = recorded.into_iter().filter(|p| !present.contains(p)).collect();
    vault.forget_files(&gone)?;

    let occurrence_count = record_sides(vault, &twins)?;

    vault.log(
        "export",
        Some(i64::try_from(written).unwrap_or(i64::MAX)),
        Some(i64::try_from(graph.len()).unwrap_or(i64::MAX)),
        Some("clean"),
        Some(&dest.to_string_lossy()),
    )?;

    Ok(Exported {
        written,
        aliased: twins.aliased,
        identities: graph.len(),
        renamed,
        unchecked: twins.unchecked,
        abandoned: twins.abandoned,
        blocked: Vec::new(),
        allowlisted: allowlist(vault)?.len(),
        unreadable: twins.unreadable,
        occurrences: occurrence_count,
        redacted: twins.redacted.len(),
        redacted_new,
    })
}

/// Run the export gate over everything staged — SDD §8.
///
/// Content and tree both. A directory named after a client leaks with no
/// identifier in it at all, so a twin path goes through the same scanner the
/// file contents do.
fn run_gate(scanner: &verify::LeakScanner, twins: &mut Twins) {
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
}

/// Write the two side tables an export fills in — PRD FR-5, SDD §4.3.
///
/// Returns how many occurrences were recorded.
///
/// **Must run after `put_files`.** Both tables carry a foreign key to
/// `files(id)`, and that id is read back from the vault rather than derived: it
/// starts life as the path's blind index but a data-key rotation moves the index
/// and deliberately leaves the id alone.
fn record_sides(vault: &mut vault::Vault, twins: &Twins) -> Result<usize> {
    let ids: HashMap<String, String> = vault
        .files_with_ids()?
        .into_iter()
        .map(|(id, file)| (file.path, id))
        .collect();

    // Every file this export wrote, whether or not it turned out to hold
    // anything. A file that no longer mentions a name has to be listed here, or
    // the row saying it does would stand forever.
    let touched: Vec<String> = twins.records.iter().filter_map(|r| ids.get(&r.path).cloned()).collect();

    let occurrences: Vec<vault::StoredOccurrence> = twins
        .sightings
        .iter()
        .filter_map(|s| {
            Some(vault::StoredOccurrence {
                identity_uuid: s.identity_uuid.clone(),
                file_id: ids.get(&s.path)?.clone(),
                byte_start: s.byte_start,
                byte_end: s.byte_end,
                kind: s.kind.as_str().to_owned(),
            })
        })
        .collect();
    let redactions: Vec<vault::StoredRedaction> = twins
        .redacted
        .iter()
        .filter_map(|r| {
            Some(vault::StoredRedaction {
                file_id: ids.get(&r.path)?.clone(),
                byte_start: r.byte_start,
                byte_end: r.byte_end,
                secret_type: r.secret_type.clone(),
                match_idx: r.match_idx.clone(),
            })
        })
        .collect();

    let count = occurrences.len();
    vault.replace_occurrences(&touched, &occurrences)?;
    vault.replace_redactions(&touched, &redactions)?;
    Ok(count)
}

impl Twins {
    fn is_blocked_now(&self) -> bool {
        !self.blocked.is_empty()
    }
}

/// What each recorded file's twin is called, so a later walk does not throw it
/// away.
///
/// `files.twin_path` is the only record of where an exported file went, and
/// `restore_project` is the only thing that can put it back. An index or a
/// rescan that overwrote the column with the real path would silently orphan
/// every twin tree already produced — restore would find no mapping and leave
/// each file sitting at its alias name. Walking the project is a read; it must
/// not destroy the one thing an export wrote.
fn recorded_twins(vault: &vault::Vault) -> Result<HashMap<String, String>> {
    Ok(vault.files()?.into_iter().map(|f| (f.path, f.twin_path)).collect())
}

/// Walk the project and record what is in it — SDD §4.1.
pub fn index_project(project: &Path, vault: &mut vault::Vault) -> Result<Index> {
    let index = Index::build(project)?;
    let twins = recorded_twins(vault)?;

    let files: Vec<vault::StoredFile> = index
        .files
        .values()
        .map(|entry| vault::StoredFile {
            path: entry.path.clone(),
            // A file nothing has exported yet has no twin name, and the real
            // path is a better answer than an empty column that later reads as
            // "no twin". One that *has* been exported keeps the name it got.
            twin_path: twins.get(&entry.path).cloned().unwrap_or_else(|| entry.path.clone()),
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
    Ok(index)
}

/// Re-walk, classify what moved, and report which recorded twins are now stale.
pub fn rescan_project(
    project: &Path,
    vault: &mut vault::Vault,
) -> Result<(Index, specshield_index::Changes, Vec<String>)> {
    let recorded = vault.files()?;

    let previous = Index {
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

    let (index, changes) = previous.rescan(project)?;

    let twins = recorded_twins(vault)?;
    let updated: Vec<vault::StoredFile> = index
        .files
        .values()
        .map(|entry| vault::StoredFile {
            path: entry.path.clone(),
            twin_path: twins.get(&entry.path).cloned().unwrap_or_else(|| entry.path.clone()),
            checksum: entry.checksum.clone(),
            parser: parser_for(project, entry),
        })
        .collect();
    vault.put_files(&updated)?;
    vault.forget_files(&changes.removed)?;

    // A modified file's recorded positions describe bytes that have moved. They
    // are cleared rather than kept: a stale occurrence is not a slightly wrong
    // answer to "where does this appear", it points at whatever happens to sit
    // at that offset now. The next export records them again.
    //
    // Removed files need no help — `files(id)` cascades.
    let ids: HashMap<String, String> = vault
        .files_with_ids()?
        .into_iter()
        .map(|(id, file)| (file.path, id))
        .collect();
    let moved: Vec<String> = changes
        .modified
        .iter()
        .filter_map(|path| ids.get(path).cloned())
        .collect();
    vault.replace_occurrences(&moved, &[])?;
    vault.replace_redactions(&moved, &[])?;

    let pairs: Vec<(String, String)> = recorded.into_iter().map(|f| (f.path, f.checksum)).collect();
    let stale: Vec<String> = index.stale(&pairs).into_iter().map(str::to_owned).collect();

    Ok((index, changes, stale))
}

/// Re-derive every alias in the project — PRD FR-11, SDD §9.5.
///
/// Returns how many actually changed. Derivation is deterministic, so under the
/// same project key an identity whose scope, type, name, and concept are
/// unchanged keeps exactly the alias it had; only members of a newly confirmed
/// concept move. Under a *new* key, everything does.
pub fn rekey(vault: &vault::Vault) -> Result<usize> {
    let settings = vault.settings()?;
    let style = alias_style(&settings.alias_style);
    let key = alias::ProjectKey::from_bytes(settings.project_key);
    let concepts: HashMap<String, String> = vault.concepts()?.into_iter().collect();

    let stored = vault.identities()?;
    let mut identities: Vec<specshield_core::rekey::Rekeyed> = stored
        .iter()
        .filter_map(|s| {
            let entity_type = s.entity_type.parse().ok()?;
            Some(specshield_core::rekey::Rekeyed {
                uuid: s.uuid.clone(),
                key: IdentityKey::new(&s.scope_path, entity_type, &s.real_name),
                alias: s.alias.clone(),
                concept: concepts.get(&s.uuid).cloned(),
            })
        })
        .collect();

    let changed = specshield_core::rekey::rederive(&key, style, &mut identities);

    let by_uuid: HashMap<&str, &specshield_core::rekey::Rekeyed> =
        identities.iter().map(|i| (i.uuid.as_str(), i)).collect();
    for mut row in stored {
        let Some(rekeyed) = by_uuid.get(row.uuid.as_str()) else {
            continue;
        };
        if rekeyed.alias != row.alias {
            row.alias = rekeyed.alias.clone();
            vault.put_identity(&row)?;
        }
    }

    Ok(changed)
}

/// One recorded appearance of an identity, resolved back to a real path.
#[derive(Debug, Clone)]
pub struct Appearance {
    pub path: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub kind: String,
}

/// An identity and everywhere the last export saw it — PRD FR-5.
#[derive(Debug, Clone)]
pub struct Located {
    pub real_name: String,
    pub alias: String,
    pub entity_type: String,
    pub scope_path: String,
    pub appearances: Vec<Appearance>,
}

/// Find an identity by real name or by alias, and say where it appears.
///
/// Both directions, because both questions are real and the vault answers them
/// with the same table. "Where does `CustomerService` appear" is what a user
/// asks before renaming something; "what is `SERVICE_H7K2Q3` and where did it
/// come from" is what they ask holding a model's output.
///
/// Real names match case-insensitively — the caller is typing from memory.
/// Aliases match exactly, because they are issued, not remembered, and a
/// near-miss on an alias is a different identity rather than a typo.
///
/// An identity with no appearances is still returned. "This name is in the
/// vault but the last export never saw it" is an answer, and a silent empty
/// result would read as "no such name".
pub fn locate(vault: &vault::Vault, needle: &str) -> Result<Vec<Located>> {
    let paths: HashMap<String, String> = vault
        .files_with_ids()?
        .into_iter()
        .map(|(id, file)| (id, file.path))
        .collect();

    let mut out = Vec::new();
    for stored in vault.identities()? {
        if !stored.real_name.eq_ignore_ascii_case(needle) && stored.alias != needle {
            continue;
        }
        let mut appearances: Vec<Appearance> = vault
            .occurrences_of(&stored.uuid)?
            .into_iter()
            .filter_map(|o| {
                Some(Appearance {
                    // A row whose file has since been forgotten is dropped
                    // rather than shown with an opaque id: the cascade should
                    // have taken it, and inventing a path for it would be worse.
                    path: paths.get(&o.file_id)?.clone(),
                    byte_start: o.byte_start,
                    byte_end: o.byte_end,
                    kind: o.kind,
                })
            })
            .collect();
        appearances.sort_by(|a, b| a.path.cmp(&b.path).then(a.byte_start.cmp(&b.byte_start)));

        out.push(Located {
            real_name: stored.real_name,
            alias: stored.alias,
            entity_type: stored.entity_type,
            scope_path: stored.scope_path,
            appearances,
        });
    }
    out.sort_by(|a, b| a.scope_path.cmp(&b.scope_path).then(a.alias.cmp(&b.alias)));
    Ok(out)
}

/// `(line, column)` for a byte offset into a project file, or `None`.
///
/// Both front-ends need this and neither can compute it: an occurrence is stored
/// as a byte offset, a person reads line and column, and the webview has no
/// filesystem access at all. Two copies of the arithmetic would be two chances
/// for the CLI and the app to disagree about where the same recorded name is.
///
/// **Best-effort on purpose.** These offsets describe the file as it was at the
/// last export; it may have been edited or deleted since. `None` where the file
/// cannot be read or no longer covers the offset — a confidently wrong line
/// number is worse than an absent one, because the reader has no way to tell.
#[must_use]
pub fn line_and_column(project: &Path, relative: &str, byte: usize) -> Option<(usize, usize)> {
    let text = std::fs::read_to_string(project.join(relative)).ok()?;
    if byte > text.len() || !text.is_char_boundary(byte) {
        return None;
    }
    let before = &text[..byte];
    let line = before.matches(NEWLINE).count() + 1;
    let column = before.rsplit(NEWLINE).next().map_or(1, |l| l.chars().count() + 1);
    Some((line, column))
}

/// A file the last export redacted secrets out of — SDD §4.3.
#[derive(Debug, Clone)]
pub struct SecretSite {
    pub path: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub secret_type: String,
}

/// Every secret this project redacted, by file — SDD §4.3.
///
/// Reports a position and a rule, never a value: the vault never held one. What
/// it is for is the sentence that follows from it — those credentials are still
/// in the working tree, in the clear, and the twin being safe did nothing about
/// that.
pub fn secret_sites(vault: &vault::Vault) -> Result<Vec<SecretSite>> {
    let paths: HashMap<String, String> = vault
        .files_with_ids()?
        .into_iter()
        .map(|(id, file)| (id, file.path))
        .collect();

    let mut out: Vec<SecretSite> = vault
        .redactions()?
        .into_iter()
        .filter_map(|r| {
            Some(SecretSite {
                path: paths.get(&r.file_id)?.clone(),
                byte_start: r.byte_start,
                byte_end: r.byte_end,
                secret_type: r.secret_type,
            })
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.byte_start.cmp(&b.byte_start)));
    Ok(out)
}

/// Replace the project key and re-derive every alias — PRD FR-11.
///
/// Orphans every twin already shared, which is the point when one has escaped
/// and a disaster otherwise. The caller confirms.
pub fn rotate_key(vault: &vault::Vault, new_key: &[u8; 32]) -> Result<usize> {
    vault.rotate_project_key(new_key)?;
    rekey(vault)
}

/// Cross-artifact unification proposals — SDD §5.
pub fn unify_proposals(vault: &vault::Vault) -> Result<Vec<specshield_core::unify::Proposal>> {
    let keys: Vec<IdentityKey> = vault
        .identities()?
        .iter()
        .filter_map(|s| {
            let entity_type = s.entity_type.parse().ok()?;
            Some(IdentityKey::new(&s.scope_path, entity_type, &s.real_name))
        })
        .collect();
    Ok(specshield_core::unify::propose(&keys))
}

/// Confirm one proposal, then re-derive — SDD §5.
///
/// The re-derivation is not optional. A stored alias normally wins (SDD §6.5),
/// so without it the confirmation would apply only to identities interned
/// *after* it — which is none of them, since unification runs on a project that
/// has already been scanned. The feature would be silently inert, which is
/// exactly the bug it once was.
///
/// Returns `(identities linked, aliases changed)`.
pub fn unify_confirm(vault: &vault::Vault, concept: &str) -> Result<(usize, usize)> {
    let proposals = unify_proposals(vault)?;
    let Some(proposal) = proposals.iter().find(|p| p.concept == concept) else {
        return Err(ProjectError::NoSuchConcept(concept.to_owned()));
    };

    let mut linked = 0;
    for member in &proposal.members {
        let Some(found) = vault.find_identity(&member.scope_path, member.entity_type.prefix(), &member.real_name)?
        else {
            continue;
        };
        vault.put_concept(&found.uuid, concept)?;
        linked += 1;
    }

    let changed = rekey(vault)?;
    vault.log(
        "unify.confirm",
        None,
        Some(i64::try_from(linked).unwrap_or(i64::MAX)),
        None,
        None,
    )?;
    Ok((linked, changed))
}

/// What restoring a twin project did.
#[derive(Debug, Default)]
pub struct Restored {
    pub written: usize,
    pub aliases_resolved: usize,
    /// Twin paths the vault has no mapping for. Written where they stand rather
    /// than guessed at — the alias grammar is recognisable, but a filename that
    /// merely looks like one is not evidence.
    pub unmapped: Vec<String>,
}

/// Restore a whole twin project, putting every file back at its real path.
///
/// The inverse of [`export`], and the half of path aliasing that makes it
/// usable: a twin tree whose directories and filenames are aliases is only
/// reversible because the vault recorded the mapping.
pub fn restore_project(vault: &vault::Vault, twin_root: &Path, dest: &Path) -> Result<Restored> {
    if dest.exists() {
        return Err(ProjectError::DestinationExists(dest.to_path_buf()));
    }

    let graph = graph_from(vault)?;
    let vocabulary = specshield_core::restore::Vocabulary::new(graph.vocabulary());
    let real_of: HashMap<String, String> = vault.files()?.into_iter().map(|f| (f.twin_path, f.path)).collect();

    let index = Index::build(twin_root)?;
    let mut out = Restored::default();

    for entry in index.files.values() {
        let source = twin_root.join(&entry.path);
        let target_relative = real_of.get(&entry.path).cloned().unwrap_or_else(|| {
            out.unmapped.push(entry.path.clone());
            entry.path.clone()
        });
        let target = dest.join(&target_relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ProjectError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        if entry.is_text {
            let text = std::fs::read_to_string(&source).map_err(|e| ProjectError::Read {
                path: source.clone(),
                source: e,
            })?;
            let outcome = specshield_core::restore::restore(&text, &vocabulary);
            out.aliases_resolved += outcome.restored.len();
            std::fs::write(&target, &outcome.text).map_err(|e| ProjectError::Write {
                path: target.clone(),
                source: e,
            })?;
        } else {
            std::fs::copy(&source, &target).map_err(|e| ProjectError::Write {
                path: target.clone(),
                source: e,
            })?;
        }
        out.written += 1;
    }

    Ok(out)
}

/// Which parser claims this file, or empty. Reads the file only when a parser
/// might need the content to decide — OpenAPI is a YAML file until you look.
#[must_use]
pub fn parser_for(project: &Path, entry: &specshield_index::Entry) -> String {
    if !entry.is_text {
        return String::new();
    }
    let path = project.join(&entry.path);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    specshield_parsers::for_document(&path, &content).map_or(String::new(), |p| p.name().to_owned())
}
