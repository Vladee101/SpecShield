//! Plain text — SDD §4.2.
//!
//! The simplest possible parser, and the fallback for anything without
//! structure worth modelling. Entities come from the prose scan; edits are byte
//! ranges over the source, so formatting survives exactly.

use std::path::Path;

use specshield_core::detect::Detector;
use specshield_core::edit::Edit;
use specshield_core::model::OccurrenceKind;
use specshield_core::parser::{AliasMap, ArtifactParser, Candidate, Document, ParseError, Parsed};

/// Extensions this parser claims.
const EXTENSIONS: &[&str] = &["txt", "text", "log", "csv"];

#[derive(Debug, Default, Clone, Copy)]
pub struct TextParser;

impl ArtifactParser for TextParser {
    fn name(&self) -> &'static str {
        "text"
    }

    fn can_handle(&self, path: &Path, _content: &str) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXTENSIONS.contains(&e.to_lowercase().as_str()))
    }

    fn parse<'a>(&self, doc: &'a Document) -> Result<Parsed<'a>, ParseError> {
        Ok(Parsed {
            document: doc,
            tree: Box::new(()),
        })
    }

    fn extract(&self, parsed: &Parsed<'_>) -> Vec<Candidate> {
        // Without a project dictionary this finds only rule-detectable
        // entities. The caller supplies the configured detector via
        // [`extract_with`]; this default exists so the trait stays usable
        // standalone.
        Detector::new().scan_text(&parsed.document.content, &scope_of(parsed), OccurrenceKind::Reference)
    }

    fn plan_edits(&self, parsed: &Parsed<'_>, aliases: &AliasMap) -> Vec<Edit> {
        plan_from_candidates(&self.extract(parsed), aliases)
    }

    // `structural_counts` is deliberately left at its default `None`. Plain text
    // has no structure to preserve, and inventing one — comparing word or line
    // counts — would reject correct sanitizes: a multi-word entity legitimately
    // becomes a single token. The caller reports this as
    // `Verification::Unsupported` rather than as a pass.
}

impl TextParser {
    /// Extract using a configured detector — the path the pipeline actually
    /// takes, since prose entities live in the project dictionary.
    pub fn extract_with(parsed: &Parsed<'_>, detector: &Detector, kind: OccurrenceKind) -> Vec<Candidate> {
        detector.scan_text(&parsed.document.content, &scope_of(parsed), kind)
    }
}

/// Prose has no module structure, so every identity in a text document shares
/// the project scope (SDD §4.4).
pub(crate) fn scope_of(parsed: &Parsed<'_>) -> String {
    parsed.document.path.replace('\\', "/")
}

/// Turn candidates into edits, dropping any whose identity has no alias.
pub(crate) fn plan_from_candidates(candidates: &[Candidate], aliases: &AliasMap) -> Vec<Edit> {
    candidates
        .iter()
        .filter_map(|c| {
            aliases
                .iter()
                .find(|(_, alias)| alias.as_str() == c.real_name)
                .map(|(uuid, alias)| Edit::new(c.byte_start, c.byte_end, alias.clone(), Some(*uuid)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(path: &str, content: &str) -> Document {
        Document {
            id: uuid::Uuid::nil(),
            path: path.to_owned(),
            twin_path: path.to_owned(),
            content: content.to_owned(),
            checksum: String::new(),
        }
    }

    #[test]
    fn claims_text_extensions_only() {
        let p = TextParser;
        assert!(p.can_handle(Path::new("notes.txt"), ""));
        assert!(p.can_handle(Path::new("DATA.CSV"), ""));
        assert!(!p.can_handle(Path::new("main.rs"), ""));
        assert!(!p.can_handle(Path::new("README.md"), ""));
    }

    #[test]
    fn extracts_rule_detectable_entities() {
        let d = doc(
            "notes.txt",
            "Deploy to billing.vantor.internal using VANTOR_BILLING_URL.",
        );
        let parsed = TextParser.parse(&d).unwrap();
        let names: Vec<_> = TextParser.extract(&parsed).into_iter().map(|c| c.real_name).collect();
        assert!(names.contains(&"billing.vantor.internal".to_owned()));
        assert!(names.contains(&"VANTOR_BILLING_URL".to_owned()));
    }

    #[test]
    fn scope_is_the_document_path() {
        let d = doc("docs\\notes.txt", "x");
        let parsed = TextParser.parse(&d).unwrap();
        assert_eq!(scope_of(&parsed), "docs/notes.txt");
    }
}
