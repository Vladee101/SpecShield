//! The uniform parser contract — SDD §4.2.1.
//!
//! Each format gets its own parser, but all of them share one identity graph and
//! one output representation: a list of [`Edit`]s over byte ranges. Adding a
//! language means implementing this trait; nothing else in the pipeline changes.

use std::collections::{BTreeMap, HashMap};
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
