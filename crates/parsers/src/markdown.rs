//! Markdown — SDD §4.2.
//!
//! # Why there is no AST here
//!
//! SDD §4.2 lists "Markdown AST with source offsets". For M1 there is nothing
//! for an AST to do. Anonymization replaces identifier spans with aliases, and
//! that is a byte-range substitution over the source — which preserves
//! formatting, link syntax, tables, and fenced code *exactly*, with no
//! dependency and no risk of a re-serializer normalizing the user's document
//! out from under them.
//!
//! An AST becomes necessary the moment we want structure-aware behaviour:
//! skipping fenced code blocks, treating headings as scopes, or resolving
//! reference-style links. None of that is in MVP scope. The dependency is
//! deferred rather than declined.
//!
//! What this parser *does* add over [`TextParser`] is a heading path, so an
//! entity found under `## Plan tiers` carries that context into the review UI.
//!
//! [`TextParser`]: crate::text::TextParser

use std::path::Path;

use specshield_core::detect::Detector;
use specshield_core::edit::Edit;
use specshield_core::model::OccurrenceKind;
use specshield_core::parser::{AliasMap, ArtifactParser, Candidate, Document, ParseError, Parsed};

use crate::text::plan_from_candidates;

const EXTENSIONS: &[&str] = &["md", "markdown", "mdown", "mkd"];

#[derive(Debug, Default, Clone, Copy)]
pub struct MarkdownParser;

/// Heading offsets, so a candidate can be attributed to the section it sits in.
#[derive(Debug, Default)]
pub struct Outline {
    /// `(byte_offset, depth, title)` for each ATX heading, in document order.
    pub headings: Vec<(usize, usize, String)>,
}

impl Outline {
    /// The heading a byte offset falls under, if any.
    pub fn section_at(&self, offset: usize) -> Option<&str> {
        self.headings
            .iter()
            .rev()
            .find(|(start, _, _)| *start <= offset)
            .map(|(_, _, title)| title.as_str())
    }
}

impl ArtifactParser for MarkdownParser {
    fn name(&self) -> &'static str {
        "markdown"
    }

    fn can_handle(&self, path: &Path, _content: &str) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXTENSIONS.contains(&e.to_lowercase().as_str()))
    }

    fn parse<'a>(&self, doc: &'a Document) -> Result<Parsed<'a>, ParseError> {
        Ok(Parsed {
            document: doc,
            tree: Box::new(outline(&doc.content)),
        })
    }

    fn extract(&self, parsed: &Parsed<'_>) -> Vec<Candidate> {
        Detector::new().scan_text(
            &parsed.document.content,
            &crate::text::scope_of(parsed),
            OccurrenceKind::Reference,
        )
    }

    fn plan_edits(&self, parsed: &Parsed<'_>, aliases: &AliasMap) -> Vec<Edit> {
        plan_from_candidates(&self.extract(parsed), aliases)
    }
}

impl MarkdownParser {
    /// Extract using a configured detector — the path the pipeline takes.
    pub fn extract_with(parsed: &Parsed<'_>, detector: &Detector, kind: OccurrenceKind) -> Vec<Candidate> {
        detector.scan_text(&parsed.document.content, &crate::text::scope_of(parsed), kind)
    }

    /// The heading outline computed during [`ArtifactParser::parse`].
    pub fn outline_of<'p>(parsed: &'p Parsed<'_>) -> Option<&'p Outline> {
        parsed.tree.downcast_ref::<Outline>()
    }
}

/// Collect ATX headings with their byte offsets.
///
/// Fenced code is tracked so a `#` comment inside a code block is not mistaken
/// for a heading — the one piece of Markdown structure that matters even for a
/// byte-range parser.
fn outline(source: &str) -> Outline {
    let mut headings = Vec::new();
    let mut offset = 0;
    let mut in_fence = false;

    for line in source.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
        } else if !in_fence && trimmed.starts_with('#') {
            let depth = trimmed.chars().take_while(|c| *c == '#').count();
            if (1..=6).contains(&depth) {
                let title = trimmed[depth..].trim().to_owned();
                if !title.is_empty() {
                    headings.push((offset, depth, title));
                }
            }
        }
        offset += line.len();
    }

    Outline { headings }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(content: &str) -> Document {
        Document {
            id: uuid::Uuid::nil(),
            path: "PRD.md".to_owned(),
            twin_path: "PRD.md".to_owned(),
            content: content.to_owned(),
            checksum: String::new(),
        }
    }

    #[test]
    fn claims_markdown_extensions() {
        let p = MarkdownParser;
        assert!(p.can_handle(Path::new("PRD.md"), ""));
        assert!(p.can_handle(Path::new("NOTES.MARKDOWN"), ""));
        assert!(!p.can_handle(Path::new("notes.txt"), ""));
    }

    #[test]
    fn builds_a_heading_outline() {
        let d = doc("# Title\n\nbody\n\n## Section\n\nmore\n");
        let parsed = MarkdownParser.parse(&d).unwrap();
        let outline = MarkdownParser::outline_of(&parsed).expect("outline");
        assert_eq!(outline.headings.len(), 2);
        assert_eq!(outline.headings[0].2, "Title");
        assert_eq!(outline.headings[1].2, "Section");
    }

    #[test]
    fn attributes_offsets_to_their_section() {
        let source = "# One\n\nalpha\n\n## Two\n\nbeta\n";
        let d = doc(source);
        let parsed = MarkdownParser.parse(&d).unwrap();
        let outline = MarkdownParser::outline_of(&parsed).unwrap();
        assert_eq!(outline.section_at(source.find("alpha").unwrap()), Some("One"));
        assert_eq!(outline.section_at(source.find("beta").unwrap()), Some("Two"));
    }

    #[test]
    fn hash_inside_a_fence_is_not_a_heading() {
        // A shell snippet in a fenced block is the obvious way to get this
        // wrong, and it would misattribute every entity below it.
        let d = doc("# Real\n\n```sh\n# not a heading\necho hi\n```\n\ntext\n");
        let parsed = MarkdownParser.parse(&d).unwrap();
        let outline = MarkdownParser::outline_of(&parsed).unwrap();
        assert_eq!(outline.headings.len(), 1, "{:?}", outline.headings);
        assert_eq!(outline.headings[0].2, "Real");
    }

    #[test]
    fn extraction_finds_prose_entities() {
        let d = doc("Contact billing.vantor.internal for access.");
        let parsed = MarkdownParser.parse(&d).unwrap();
        let names: Vec<_> = MarkdownParser
            .extract(&parsed)
            .into_iter()
            .map(|c| c.real_name)
            .collect();
        assert!(names.contains(&"billing.vantor.internal".to_owned()));
    }

    #[test]
    fn a_document_with_no_headings_has_an_empty_outline() {
        let d = doc("just prose, no structure at all\n");
        let parsed = MarkdownParser.parse(&d).unwrap();
        assert!(MarkdownParser::outline_of(&parsed).unwrap().headings.is_empty());
    }
}
