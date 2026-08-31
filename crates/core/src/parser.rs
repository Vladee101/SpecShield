//! The uniform parser contract — SDD §4.2.1.
//!
//! Each format gets its own parser, but all of them share one identity graph and
//! one output representation: a list of [`Edit`]s over byte ranges. Adding a
//! language means implementing this trait; nothing else in the pipeline changes.

use std::collections::HashMap;
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
