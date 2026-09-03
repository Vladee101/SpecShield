//! The uniform parser contract — SDD §4.2.1.
//!
//! Each format gets its own parser, but all of them share one identity graph and
//! one output representation: a list of [`Edit`]s over byte ranges. Adding a
//! language means implementing this trait; nothing else in the pipeline changes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use uuid::Uuid;

use crate::edit::Edit;
use crate::model::{EntityType, OccurrenceKind};

/// A file as imported, before any transformation — SDD §4.1.
#[derive(Debug, Clone)]
pub struct Document {
    pub id: Uuid,
    pub path: String,
    pub twin_path: String,
    pub content: String,
    /// BLAKE3, drives staleness detection (SDD §13.1).
    pub checksum: String,
}

/// A parsed document. Parsers keep their own tree behind this handle; the
/// pipeline only needs the source and its byte offsets.
#[derive(Debug)]
pub struct Parsed<'a> {
    pub document: &'a Document,
    /// Format-specific tree, type-erased so the pipeline stays language
    /// agnostic. Downcast inside the owning parser only.
    pub tree: Box<dyn std::any::Any + Send + Sync>,
}

/// A discovered entity, before it is admitted to the identity graph.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub real_name: String,
    pub entity_type: EntityType,
    /// Resolver-dependent qualifier — see [`IdentityKey::scope_path`].
    ///
    /// [`IdentityKey::scope_path`]: crate::model::IdentityKey::scope_path
    pub scope_path: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub kind: OccurrenceKind,
    /// 0.0–1.0. Feeds the precision target in PRD §5; low-confidence
    /// candidates are surfaced for review rather than applied silently.
    pub confidence: f32,
}

/// Resolved alias lookup handed to [`ArtifactParser::plan_edits`].
pub type AliasMap = HashMap<Uuid, String>;

/// Implemented once per supported format — SDD §4.2.
pub trait ArtifactParser: Send + Sync {
    /// Short stable name, stored in `files.parser`.
    fn name(&self) -> &'static str;

    /// Content is passed as well as the path because OpenAPI is recognised by
    /// what is inside the file, not by its extension (PRD FR-2).
    fn can_handle(&self, path: &Path, content: &str) -> bool;

    /// Parse without mutating. Implementations must retain byte offsets.
    fn parse<'a>(&self, doc: &'a Document) -> Result<Parsed<'a>, ParseError>;

    /// Discover entities, with byte spans and a scope path.
    fn extract(&self, parsed: &Parsed<'_>) -> Vec<Candidate>;

    /// Plan non-overlapping replacements. Never rewrites the file itself —
    /// the returned edits are validated and applied by [`crate::edit::apply`].
    fn plan_edits(&self, parsed: &Parsed<'_>, aliases: &AliasMap) -> Vec<Edit>;

    /// Entities the format's own syntax identifies, with byte spans.
    ///
    /// This is where a parser earns its place over the prose scan: the AST
    /// knows that `customer_id` in one table is a different identity from
    /// `customer_id` in another, and no heuristic over text can.
    ///
    /// The default is empty — Markdown and plain text have no syntax to read,
    /// and every entity they carry comes from the prose scan. The caller merges
    /// both, with these taking precedence where they overlap.
    fn structural_candidates(&self, source: &str, scope: &str) -> Vec<Candidate> {
        let (_, _) = (source, scope);
        Vec::new()
    }

    /// Entities the format's syntax identifies, given what the project already
    /// knows.
    ///
    /// A single file is not enough for every language. TypeScript's
    /// `dto.customerId` is a property reference, but the file that *uses* it
    /// rarely declares it — the interface lives in another module. Without
    /// project context the reference is invisible, and the twin ends up with the
    /// declaration aliased and every use of it intact.
    ///
    /// Defaults to the context-free form, which is right for SQL, OpenAPI, and
    /// Markdown: their names are all resolvable within one file.
    fn structural_candidates_in(&self, source: &str, scope: &str, context: &ProjectContext) -> Vec<Candidate> {
        let _ = context;
        self.structural_candidates(source, scope)
    }

    /// Byte ranges the prose scan may look in, or `None` for the whole file.
    ///
    /// Formats with syntax need this. In YAML, keys are the format's own
    /// vocabulary — `apiVersion`, `properties`, `type` — and letting a
    /// heuristic loose on them aliases the document into unreadability. The
    /// proprietary names are in the values.
    ///
    /// `None` means every byte is eligible, which is right for Markdown and
    /// plain text: they are prose all the way down.
    fn prose_regions(&self, source: &str) -> Option<Vec<(usize, usize)>> {
        let _ = source;
        None
    }

    /// Structural fingerprint of `source`, for the SDD §7.2 verification pass.
    ///
    /// Sanitization replaces identifiers; it must not change a document's
    /// *shape*. Comparing this fingerprint before and after is what turns "we
    /// think the transformation was right" into "the twin parses and has the
    /// same structure as the original".
    ///
    /// Returns `None` when this parser has no structure to compare — which is
    /// reported as [`Verification::Unsupported`] rather than silently treated
    /// as a pass. Returning `Some` for input that does not parse is a bug;
    /// return `None` for unparseable input and the caller will reject the
    /// twin.
    ///
    /// [`Verification::Unsupported`]: crate::sanitize::Verification::Unsupported
    fn structural_counts(&self, source: &str) -> Option<StructuralCounts> {
        let _ = source;
        None
    }

    /// Does this parser have a fingerprint at all?
    ///
    /// Without this, `None` from [`ArtifactParser::structural_counts`] means
    /// two very different things at once: *plain text has no shape worth
    /// comparing*, and *I claimed this file and could not read it*. The first
    /// is fine. The second means the file went through with no structural
    /// candidates and no check, and reporting it as the first tells a user
    /// their unaliased source was **verified clean** — which is how a whole
    /// React codebase went to a model in the clear before P3-4 caught it.
    ///
    /// Defaults to `false`, matching the default `structural_counts` above. Any
    /// parser that overrides one must override the other.
    fn fingerprints(&self) -> bool {
        false
    }
}

/// What the project already knows, for parsers that cannot resolve everything
/// from one file.
///
/// Populated from the vault, so knowledge accumulates as artifacts are scanned:
/// the DTO file teaches the project that `customerId` is a member, and the
/// service file that merely uses it can then see that too.
/// Built once per run, never per file. The sets are the size of the project, so
/// rebuilding them for each document is quadratic in file count — it took a
/// 1,000-file export from seconds to over ten minutes before the fields were
/// closed off behind this constructor.
#[derive(Debug, Default, Clone)]
pub struct ProjectContext {
    members: HashSet<String>,
    names: HashSet<String>,
    folded: HashSet<String>,
}

impl ProjectContext {
    /// `members` are property, field, and column names; `names` is every name
    /// the project knows, of any type.
    #[must_use]
    pub fn new(members: impl IntoIterator<Item = String>, names: impl IntoIterator<Item = String>) -> Self {
        let names: HashSet<String> = names.into_iter().collect();
        Self {
            members: members.into_iter().collect(),
            folded: names.iter().map(|n| fold_name(n)).collect(),
            names,
        }
    }

    /// Is this a member name — a property, field, or column — anywhere in the
    /// project?
    #[must_use]
    pub fn is_member(&self, name: &str) -> bool {
        self.members.contains(name)
    }

    /// Does the project know this name, ignoring case and separators?
    ///
    /// A file named `thing18.ts` says `Thing18` out loud; without project-wide
    /// names a parser cannot tell that from `helpers.ts`, which says nothing.
    #[must_use]
    pub fn knows_folded(&self, folded: &str) -> bool {
        self.folded.contains(folded)
    }

    pub fn members(&self) -> impl Iterator<Item = &String> {
        self.members.iter()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty() && self.names.is_empty()
    }
}

/// A name reduced to what a filename and an identifier have in common:
/// lowercase, no separators. `customer-subscription` and `CustomerSubscription`
/// both become `customersubscription`.
#[must_use]
pub fn fold_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// A parser's structural fingerprint of a document — SDD §7.2.
///
/// Deliberately a bag of named counts rather than a fixed struct: what counts
/// as structure differs per format. Markdown cares about headings and fences;
/// TypeScript will care about declarations and references.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuralCounts {
    counts: BTreeMap<&'static str, usize>,
}

impl StructuralCounts {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, kind: &'static str, count: usize) -> Self {
        self.counts.insert(kind, count);
        self
    }

    pub fn get(&self, kind: &str) -> usize {
        self.counts.get(kind).copied().unwrap_or(0)
    }

    /// Kinds whose counts differ, with both values. Empty means the structures
    /// match.
    pub fn differences(&self, other: &Self) -> Vec<(&'static str, usize, usize)> {
        self.counts
            .keys()
            .chain(other.counts.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter_map(|kind| {
                let (before, after) = (self.get(kind), other.get(kind));
                (before != after).then_some((*kind, before, after))
            })
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The file could not be parsed. Per SDD §16 this is never fatal: the
    /// original is preserved and excluded from the twin.
    #[error("{parser} failed to parse {path}: {detail}")]
    Failed {
        parser: &'static str,
        path: String,
        detail: String,
    },
}
