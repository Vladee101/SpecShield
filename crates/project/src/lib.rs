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

/// Everything the sanitize pass produced, held until the gate has run.
#[derive(Debug, Default)]
pub struct Twins {
    pub staged: Vec<(String, Payload)>,
    pub records: Vec<vault::StoredFile>,
    pub blocked: Vec<(String, Vec<String>)>,
    pub abandoned: Vec<(String, String)>,
    pub aliased: usize,
    pub unchecked: usize,
}

/// Sanitize every file in the project, producing twins but writing nothing.
pub fn sanitize_tree(
    project: &Path,
    index: &Index,
    detector: &Detector,
    context: &ProjectContext,
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
    let mut graph = graph_from(vault)?;
    learn(project, &index, vault, &mut graph)?;

    let detector = detector_from(vault)?;
    let context = context_from(vault)?;
    let twins_by_path = twin_paths(&index, &detector, &mut graph)?;
    let twin_of = |path: &String| twins_by_path.get(path).cloned().unwrap_or_else(|| path.clone());

    let mut twins = sanitize_tree(project, &index, &detector, &context, &mut graph, &twin_of)?;

    // The graph is persisted either way: those aliases were derived, and
    // throwing them away would hand different aliases to the next run.
    persist(vault, &graph)?;

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

    let renamed = twins.records.iter().filter(|r| r.path != r.twin_path).count();

    if twins.is_blocked_now() {
        vault.log("export", None, None, Some("blocked"), None)?;
        return Ok(Exported {
            blocked: twins.blocked,
            abandoned: twins.abandoned,
            aliased: twins.aliased,
            identities: graph.len(),
            renamed,
            unchecked: twins.unchecked,
            written: 0,
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
    })
}

impl Twins {
    fn is_blocked_now(&self) -> bool {
        !self.blocked.is_empty()
    }
}

/// Walk the project and record what is in it — SDD §4.1.
pub fn index_project(project: &Path, vault: &mut vault::Vault) -> Result<Index> {
    let index = Index::build(project)?;

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
