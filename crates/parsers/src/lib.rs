//! Format parsers — SDD §4.2.
//!
//! Every parser implements [`ArtifactParser`] and emits byte-range edits.
//! Adding a language means adding a module here; nothing else in the pipeline
//! changes.
//!
//! | Format | Parser | Milestone |
//! |---|---|---|
//! | Markdown, plain text | prose scan over the raw source | M1 |
//! | SQL | `sqlparser`, AST-driven with byte spans | M3 |
//! | YAML, JSON | `saphyr`, spanned nodes; JSON read as YAML 1.2 | M3 |
//! | OpenAPI | semantic layer over the YAML/JSON CST | M3 |
//! | TypeScript / JavaScript | Tree-sitter + heuristic scoping | M4 |
//!
//! Three deliberate choices, all from the design review or the M0 spikes:
//!
//! - **Not `serde_yaml`** (archived 2024), and not a `serde_json` round-trip:
//!   deserializing to a value model and re-serializing destroys comments and key
//!   order, which SDD §4.2 requires preserving.
//! - **Tree-sitter has no name resolution.** MVP uses heuristic scoping and the
//!   weaker parse-and-count guarantee of SDD §7.2; per-type property renaming
//!   waits for V1.1 (`spikes/M0-tree-sitter-rename.md`).
//! - **Markdown needs no AST for M1.** Entity replacement is byte-range
//!   substitution over the source, which preserves formatting exactly — an AST
//!   would add a dependency and buy nothing until we want structure-aware rules
//!   such as skipping fenced code. See [`markdown`].

pub mod markdown;
pub mod sql;
pub mod text;
pub mod yaml;

use std::path::Path;

pub use specshield_core::parser::{ArtifactParser, Candidate, Document, ParseError, Parsed};

pub use crate::markdown::MarkdownParser;
pub use crate::sql::SqlParser;
pub use crate::text::TextParser;
pub use crate::yaml::{JsonParser, YamlParser};

/// Every parser this build supports, in priority order.
///
/// The names match the `requires` field in the corpus specs, so the corpus
/// report can gate only the projects whose formats actually have a parser.
pub fn registry() -> Vec<Box<dyn ArtifactParser>> {
    vec![
        Box::new(MarkdownParser),
        Box::new(SqlParser),
        Box::new(YamlParser),
        Box::new(JsonParser),
        Box::new(TextParser),
    ]
}

/// Names of the implemented parsers — `["markdown", "text"]` today.
pub fn implemented() -> Vec<&'static str> {
    registry().iter().map(|p| p.name()).collect()
}

/// Pick the parser for a document, or `None` if the format is not supported yet.
pub fn for_document(path: &Path, content: &str) -> Option<Box<dyn ArtifactParser>> {
    registry().into_iter().find(|p| p.can_handle(path, content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_wins_over_plain_text() {
        let parser = for_document(Path::new("README.md"), "# Title").expect("a parser");
        assert_eq!(parser.name(), "markdown");
    }

    #[test]
    fn plain_text_is_the_fallback() {
        let parser = for_document(Path::new("notes.txt"), "hello").expect("a parser");
        assert_eq!(parser.name(), "text");
    }

    #[test]
    fn unsupported_formats_return_none() {
        // SQL, YAML, and TypeScript arrive in M3 and M4. Claiming them now
        // would silently produce an unaliased twin.
        for path in ["service.ts", "image.png"] {
            assert!(
                for_document(Path::new(path), "").is_none(),
                "{path} should not be claimed yet"
            );
        }
    }

    #[test]
    fn implemented_names_are_stable() {
        assert_eq!(implemented(), vec!["markdown", "sql", "yaml", "json", "text"]);
    }
}
