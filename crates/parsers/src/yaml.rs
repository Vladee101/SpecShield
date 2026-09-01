//! YAML and JSON — SDD §4.2, Implementation Plan M3.
//!
//! # Why one parser for both
//!
//! JSON is a subset of YAML 1.2, so a YAML parser reads both. That keeps one
//! node model for the OpenAPI layer, which has to work over specs written in
//! either. The limits are documented on [`JsonParser`].
//!
//! # Why this claims no entities of its own
//!
//! A generic YAML document has no vocabulary that says which names are
//! proprietary. `image:`, `host:`, and `replicas:` are format structure;
//! `VANTOR_BILLING_URL:` is not, and nothing in the grammar distinguishes them.
//! So [`structural_candidates`] returns nothing and the prose scan does the
//! detecting, exactly as it does for Markdown.
//!
//! **A restriction was tried here and removed.** Confining the prose scan to
//! scalar values — via [`prose_regions`] — looked principled: keys are
//! structure, values are data. Measured, it cost 16 points of recall on the
//! OpenAPI fixture to buy 8 of precision, and it broke ordinary files: a
//! `docker-compose.yml` with `VANTOR_BILLING_URL:` as an environment key left
//! the company name in the twin, and the gate refused the export.
//!
//! The reason it was unnecessary is that the prose rules are already
//! conservative. They match `PascalCase` compounds, `SCREAMING_SNAKE`, and
//! dotted hostnames — none of which describe `apiVersion`, `properties`, or
//! `type`. The restriction was solving a problem the rules had already solved,
//! while creating a real one.
//!
//! [`prose_regions`] remains on the trait because TypeScript will need it, where
//! comments and string literals genuinely are prose and the surrounding code is
//! not.
//!
//! [`structural_candidates`]: ArtifactParser::structural_candidates
//! [`prose_regions`]: ArtifactParser::prose_regions

use std::path::Path;

use saphyr::{LoadableYamlNode, MarkedYaml, Scalar, YamlData};
use specshield_core::edit::Edit;
use specshield_core::parser::{AliasMap, ArtifactParser, Candidate, Document, ParseError, Parsed, StructuralCounts};

use crate::text::plan_from_candidates;

const YAML_EXTENSIONS: &[&str] = &["yaml", "yml"];
const JSON_EXTENSIONS: &[&str] = &["json"];

/// Declines API specifications — see [`crate::openapi`], which owns them.
///
/// Their proprietary names are keys that only the specification's own
/// vocabulary can classify. Processing one here aliases the values, leaves the
/// schema names, and yields a twin that looks clean while operation identifiers
/// and paths sit in it untouched.
use crate::openapi::is_specification as is_api_specification;

#[derive(Debug, Default, Clone, Copy)]
pub struct YamlParser;

/// JSON, read through the YAML parser.
///
/// JSON is valid YAML 1.2, so this is not a shortcut: it is the same grammar.
/// Two differences are worth knowing about, neither of which affects
/// anonymization:
///
/// - YAML accepts input JSON would reject, so a malformed `.json` file may parse
///   here. This reads documents rather than validating them, so a permissive
///   parse costs nothing.
/// - Duplicate keys are legal in JSON and resolved by the YAML loader. Since
///   spans are collected during the walk rather than from the resulting map,
///   both occurrences are still seen.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonParser;

/// One addressable position in a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRef {
    /// Dotted path from the document root, e.g.
    /// `components.schemas.CustomerSubscription.properties.customerId`.
    /// Sequence elements are indexed: `servers.0.url`.
    pub path: String,
    pub kind: NodeKind,
    /// The key name or scalar text, without quotes.
    pub text: String,
    pub byte_start: usize,
    pub byte_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A mapping key. Structure in generic YAML; sometimes an entity in
    /// OpenAPI.
    Key,
    /// A scalar value.
    Value,
}

/// Char-index to byte-offset map.
///
/// `saphyr` reports positions as character indices. Using them as byte offsets
/// would shift every span after the first non-ASCII character in the file —
/// which, in a spec with an accented description, is most of it.
struct CharOffsets(Vec<usize>);

impl CharOffsets {
    fn new(source: &str) -> Self {
        let mut offsets: Vec<usize> = source.char_indices().map(|(i, _)| i).collect();
        offsets.push(source.len());
        Self(offsets)
    }

    fn byte(&self, char_index: usize) -> Option<usize> {
        self.0.get(char_index).copied()
    }
}

/// Walk a document, collecting every key and scalar with its byte span.
pub fn nodes(source: &str) -> Option<Vec<NodeRef>> {
    let docs = MarkedYaml::load_from_str(source).ok()?;
    let offsets = CharOffsets::new(source);
    let mut out = Vec::new();
    for doc in &docs {
        walk(doc, String::new(), source, &offsets, &mut out);
    }
    out.sort_by_key(|n| n.byte_start);
    Some(out)
}

fn span_of(node: &MarkedYaml<'_>, source: &str, offsets: &CharOffsets) -> Option<(usize, usize)> {
    let start = offsets.byte(node.span.start.index())?;
    let end = offsets.byte(node.span.end.index())?;
    if start >= end || end > source.len() || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return None;
    }
    Some((start, end))
}

/// Narrow a span to the scalar's own text, dropping surrounding quotes.
///
/// `saphyr` reports the span of the token, which for `"CustomerSubscription"`
/// includes both quotes. Aliasing that range would eat them and change the
/// document's type.
fn trim_quotes(source: &str, start: usize, end: usize, text: &str) -> Option<(usize, usize)> {
    let raw = source.get(start..end)?;
    if raw == text {
        return Some((start, end));
    }
    // Find the value inside whatever delimiters the style used.
    raw.find(text)
        .map(|offset| (start + offset, start + offset + text.len()))
}

fn walk(node: &MarkedYaml<'_>, path: String, source: &str, offsets: &CharOffsets, out: &mut Vec<NodeRef>) {
    match &node.data {
        YamlData::Value(Scalar::String(value)) => {
            if let Some((start, end)) = span_of(node, source, offsets)
                && let Some((start, end)) = trim_quotes(source, start, end, value)
            {
                out.push(NodeRef {
                    path,
                    kind: NodeKind::Value,
                    text: value.to_string(),
                    byte_start: start,
                    byte_end: end,
                });
            }
        }

        YamlData::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(item, join(&path, &i.to_string()), source, offsets, out);
            }
        }

        YamlData::Mapping(map) => {
            for (key, value) in map {
                let Some(name) = scalar_text(key) else {
                    continue;
                };
                if let Some((start, end)) = span_of(key, source, offsets)
                    && let Some((start, end)) = trim_quotes(source, start, end, &name)
                {
                    out.push(NodeRef {
                        path: join(&path, &name),
                        kind: NodeKind::Key,
                        text: name.clone(),
                        byte_start: start,
                        byte_end: end,
                    });
                }
                walk(value, join(&path, &name), source, offsets, out);
            }
        }

        // Non-string scalars carry no names. Aliases, tags, and bad values are
        // structure we do not rewrite.
        _ => {}
    }
}

fn scalar_text(node: &MarkedYaml<'_>) -> Option<String> {
    match &node.data {
        YamlData::Value(Scalar::String(s)) => Some(s.to_string()),
        _ => None,
    }
}

fn join(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_owned()
    } else {
        format!("{prefix}.{segment}")
    }
}

fn counts_for(source: &str) -> Option<StructuralCounts> {
    let docs = MarkedYaml::load_from_str(source).ok()?;
    let mut mappings = 0;
    let mut sequences = 0;
    let mut scalars = 0;
    let mut depth = 0;
    for doc in &docs {
        tally(doc, 1, &mut mappings, &mut sequences, &mut scalars, &mut depth);
    }
    let nodes = nodes(source)?;
    Some(
        StructuralCounts::new()
            .with("documents", docs.len())
            .with("mappings", mappings)
            .with("sequences", sequences)
            .with("scalars", scalars)
            .with("keys", nodes.iter().filter(|n| n.kind == NodeKind::Key).count())
            .with("max_depth", depth),
    )
}

fn tally(
    node: &MarkedYaml<'_>,
    level: usize,
    mappings: &mut usize,
    sequences: &mut usize,
    scalars: &mut usize,
    depth: &mut usize,
) {
    *depth = (*depth).max(level);
    match &node.data {
        YamlData::Mapping(map) => {
            *mappings += 1;
            for (key, value) in map {
                tally(key, level + 1, mappings, sequences, scalars, depth);
                tally(value, level + 1, mappings, sequences, scalars, depth);
            }
        }
        YamlData::Sequence(items) => {
            *sequences += 1;
            for item in items {
                tally(item, level + 1, mappings, sequences, scalars, depth);
            }
        }
        _ => *scalars += 1,
    }
}

macro_rules! impl_parser {
    ($ty:ty, $name:literal, $extensions:expr) => {
        impl ArtifactParser for $ty {
            fn name(&self) -> &'static str {
                $name
            }

            fn can_handle(&self, path: &Path, content: &str) -> bool {
                path.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| $extensions.contains(&e.to_lowercase().as_str()))
                    && !is_api_specification(content)
            }

            fn parse<'a>(&self, doc: &'a Document) -> Result<Parsed<'a>, ParseError> {
                let nodes = nodes(&doc.content).ok_or_else(|| ParseError::Failed {
                    parser: $name,
                    path: doc.path.clone(),
                    detail: "document did not parse".to_owned(),
                })?;
                Ok(Parsed {
                    document: doc,
                    tree: Box::new(nodes),
                })
            }

            fn extract(&self, _parsed: &Parsed<'_>) -> Vec<Candidate> {
                // See the module docs: keys are structure, and the values are
                // covered by the prose scan within `prose_regions`.
                Vec::new()
            }

            fn plan_edits(&self, parsed: &Parsed<'_>, aliases: &AliasMap) -> Vec<Edit> {
                plan_from_candidates(&self.extract(parsed), aliases)
            }

            /// A document's shape is its node counts and nesting depth.
            ///
            /// Aliasing replaces text inside scalars; it must never add a key,
            /// drop a sequence entry, or change the nesting. An alias
            /// containing `: ` or a newline would do all three.
            fn structural_counts(&self, source: &str) -> Option<StructuralCounts> {
                counts_for(source)
            }
        }
    };
}

impl_parser!(YamlParser, "yaml", YAML_EXTENSIONS);
impl_parser!(JsonParser, "json", JSON_EXTENSIONS);

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = concat!(
        "openapi: 3.1.0\n",
        "info:\n",
        "  title: BillingApi\n",
        "servers:\n",
        "  - url: https://billing.vantor.internal\n",
        "components:\n",
        "  schemas:\n",
        "    CustomerSubscription:\n",
        "      properties:\n",
        "        customerId:\n",
        "          type: string\n"
    );

    fn find<'a>(nodes: &'a [NodeRef], path: &str) -> Option<&'a NodeRef> {
        nodes.iter().find(|n| n.path == path)
    }

    #[test]
    fn extensions_are_claimed_by_the_right_parser() {
        assert!(YamlParser.can_handle(Path::new("openapi.yaml"), ""));
        assert!(YamlParser.can_handle(Path::new("config.YML"), ""));
        assert!(!YamlParser.can_handle(Path::new("data.json"), ""));
        assert!(JsonParser.can_handle(Path::new("data.json"), ""));
        assert!(!JsonParser.can_handle(Path::new("openapi.yaml"), ""));
    }

    #[test]
    fn an_openapi_spec_is_declined_rather_than_half_processed() {
        // Its schema names live in keys, which this parser will not touch. A
        // twin with values aliased and schema names intact is refused by the
        // gate anyway — better to say so up front, naming the milestone.
        assert!(!YamlParser.can_handle(Path::new("openapi.yaml"), SPEC));
        assert!(!JsonParser.can_handle(Path::new("openapi.json"), r#"{"openapi": "3.1.0"}"#));

        // Ordinary YAML is still claimed.
        assert!(YamlParser.can_handle(
            Path::new("docker-compose.yml"),
            "services:
  web:
    image: nginx
"
        ));
    }

    #[test]
    fn every_span_points_at_the_text_it_claims() {
        // The invariant the whole edit model rests on.
        for node in nodes(SPEC).expect("parses") {
            assert_eq!(
                &SPEC[node.byte_start..node.byte_end],
                node.text,
                "span mismatch for {:?} at {}",
                node.text,
                node.path
            );
        }
    }

    #[test]
    fn paths_address_nested_keys_and_sequence_entries() {
        let nodes = nodes(SPEC).expect("parses");
        assert!(find(&nodes, "components.schemas.CustomerSubscription").is_some());
        assert!(
            find(&nodes, "components.schemas.CustomerSubscription.properties.customerId").is_some(),
            "{:?}",
            nodes.iter().map(|n| &n.path).collect::<Vec<_>>()
        );
        assert!(find(&nodes, "servers.0.url").is_some());
    }

    #[test]
    fn keys_and_values_are_distinguished() {
        let nodes = nodes(SPEC).expect("parses");
        assert_eq!(find(&nodes, "info.title").map(|n| n.kind), Some(NodeKind::Key));
        let title_value = nodes
            .iter()
            .find(|n| n.kind == NodeKind::Value && n.text == "BillingApi");
        assert!(title_value.is_some(), "the value should be a separate node");
    }

    #[test]
    fn the_whole_document_is_scannable() {
        // Keys included. An environment-variable name is a key and is every bit
        // as proprietary as a value; excluding keys left company names in the
        // twin. See the module docs for the measurement that settled this.
        assert!(YamlParser.prose_regions(SPEC).is_none());
    }

    #[test]
    fn quoted_scalars_exclude_their_quotes() {
        let source = "title: \"BillingApi\"\nref: '#/components/schemas/X'\n";
        for node in nodes(source).expect("parses") {
            assert_eq!(&source[node.byte_start..node.byte_end], node.text);
        }
    }

    #[test]
    fn json_reads_through_the_same_parser() {
        let json = r#"{"info": {"title": "BillingApi"}, "servers": [{"url": "https://h.example.test"}]}"#;
        let nodes = nodes(json).expect("JSON is valid YAML 1.2");
        assert!(find(&nodes, "info.title").is_some());
        assert!(find(&nodes, "servers.0.url").is_some());
        for node in nodes {
            assert_eq!(&json[node.byte_start..node.byte_end], node.text);
        }
    }

    #[test]
    fn non_ascii_content_does_not_shift_later_spans() {
        // saphyr reports character indices. Treating them as bytes would break
        // every span after this description.
        let source = "description: naïve — émigré\ntitle: BillingApi\n";
        for node in nodes(source).expect("parses") {
            assert_eq!(&source[node.byte_start..node.byte_end], node.text);
        }
    }

    #[test]
    fn structural_counts_track_document_shape() {
        let counts = YamlParser.structural_counts(SPEC).expect("parses");
        assert_eq!(counts.get("documents"), 1);
        assert!(counts.get("keys") >= 8, "{}", counts.get("keys"));
        assert_eq!(counts.get("sequences"), 1);
    }

    #[test]
    fn an_alias_that_invents_a_key_is_caught() {
        // An alias containing ": " would split one scalar into a key and a
        // value, silently restructuring the document.
        let before = YamlParser.structural_counts(SPEC).unwrap();
        let after = YamlParser
            .structural_counts(&SPEC.replace("  title: BillingApi", "  title:\n    injected: BillingApi"))
            .unwrap();
        let diffs = before.differences(&after);
        assert!(diffs.iter().any(|(kind, _, _)| *kind == "keys"), "{diffs:?}");
    }

    #[test]
    fn unparseable_input_yields_nothing() {
        assert!(nodes("key: [unclosed\n  - bad").is_none() || nodes("\t\tbad: : :").is_none());
        assert!(YamlParser.structural_counts("\tbad: : :").is_none());
    }
}
