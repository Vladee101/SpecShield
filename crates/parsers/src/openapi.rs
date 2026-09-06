//! OpenAPI — SDD §4.2, Implementation Plan M3.
//!
//! A semantic layer over the YAML/JSON node index, not a second parser. The
//! grammar is already read by [`crate::yaml`]; what this adds is the one thing
//! that grammar cannot supply — **which keys are names**.
//!
//! In a generic YAML document nothing distinguishes `properties:` (structure)
//! from `CustomerSubscription:` (a schema name). The OpenAPI specification does:
//! everything under `components.schemas` is a name the API author chose, and
//! everything under `.properties` beneath it is a field they chose. That is why
//! the generic parser declines API specifications rather than half-processing
//! them.
//!
//! # What is detected
//!
//! | Location | Entity |
//! |---|---|
//! | `info.title` | Api |
//! | `components.schemas.X` | Dto, or Enum if that schema has an `enum` |
//! | `components.schemas.X.properties.p` | Column, scoped to X |
//! | `components.schemas.X.required[i]` | Column, scoped to X |
//! | `…operationId` | Endpoint |
//! | `…parameters[i].name` | Column |
//! | `$ref` targets | the schema they name |
//! | `{param}` in a path template | the parameter it names |
//!
//! The last two matter more than they look. A `$ref` that still points at
//! `#/components/schemas/CustomerSubscription` after the schema was renamed
//! leaves the real name in the twin *and* produces a spec that no longer
//! resolves — and `/invoices/{invoiceId}` carries a field name in the URL.

use std::collections::BTreeSet;
use std::path::Path;

use specshield_core::edit::Edit;
use specshield_core::model::{EntityType, OccurrenceKind};
use specshield_core::parser::{AliasMap, ArtifactParser, Candidate, Document, ParseError, Parsed, StructuralCounts};

use crate::text::plan_from_candidates;
use crate::yaml::{NodeKind, NodeRef, nodes};

const EXTENSIONS: &[&str] = &["yaml", "yml", "json"];

#[derive(Debug, Default, Clone, Copy)]
pub struct OpenApiParser;

/// Recognised by content, not extension — PRD FR-2. A spec can be `.yaml`,
/// `.yml`, or `.json`, and the extension says nothing about what is inside.
pub fn is_specification(content: &str) -> bool {
    content
        .lines()
        .take(40)
        .any(|line| line.starts_with("openapi:") || line.starts_with("swagger:"))
        || content.contains("\"openapi\":")
        || content.contains("\"swagger\":")
}

impl ArtifactParser for OpenApiParser {
    fn name(&self) -> &'static str {
        "openapi"
    }

    fn can_handle(&self, path: &Path, content: &str) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXTENSIONS.contains(&e.to_lowercase().as_str()))
            && is_specification(content)
    }

    fn parse<'a>(&self, doc: &'a Document) -> Result<Parsed<'a>, ParseError> {
        let nodes = nodes(&doc.content).ok_or_else(|| ParseError::Failed {
            parser: "openapi",
            path: doc.path.clone(),
            detail: "specification did not parse".to_owned(),
        })?;
        Ok(Parsed {
            document: doc,
            tree: Box::new(nodes),
        })
    }

    fn extract(&self, parsed: &Parsed<'_>) -> Vec<Candidate> {
        self.structural_candidates(&parsed.document.content, &crate::text::scope_of(parsed))
    }

    fn plan_edits(&self, parsed: &Parsed<'_>, aliases: &AliasMap) -> Vec<Edit> {
        plan_from_candidates(&self.extract(parsed), aliases)
    }

    fn structural_candidates(&self, source: &str, _scope: &str) -> Vec<Candidate> {
        let Some(nodes) = nodes(source) else {
            return Vec::new();
        };
        let enums = enum_schemas(&nodes);
        let mut out = Vec::new();

        for node in &nodes {
            classify(node, &enums, &mut out);
        }

        out.sort_by_key(|c| c.byte_start);
        out.dedup_by_key(|c| c.byte_start);
        out
    }

    fn fingerprints(&self) -> bool {
        true
    }

    fn structural_counts(&self, source: &str) -> Option<StructuralCounts> {
        let nodes = nodes(source)?;
        let base = crate::yaml::YamlParser.structural_counts(source)?;
        Some(
            base.with("schemas", count_at_depth(&nodes, "components.schemas", 3))
                .with("paths", count_at_depth(&nodes, "paths", 2))
                .with(
                    "operations",
                    nodes.iter().filter(|n| is_operation_id(&n.path, n.kind)).count(),
                ),
        )
    }
}

/// Schemas that declare an `enum`, so `PlanTier` is typed as one rather than as
/// a DTO. The alias prefix is the only thing this changes, but a spec reads
/// badly when its enums are called `DTO_…`.
fn enum_schemas(nodes: &[NodeRef]) -> BTreeSet<String> {
    nodes
        .iter()
        .filter_map(|n| {
            let rest = n.path.strip_prefix("components.schemas.")?;
            let mut parts = rest.split('.');
            let name = parts.next()?;
            (parts.next() == Some("enum")).then(|| name.to_owned())
        })
        .collect()
}

fn count_at_depth(nodes: &[NodeRef], prefix: &str, depth: usize) -> usize {
    nodes
        .iter()
        .filter(|n| {
            n.kind == NodeKind::Key && n.path.starts_with(&format!("{prefix}.")) && n.path.split('.').count() == depth
        })
        .count()
}

fn is_operation_id(path: &str, kind: NodeKind) -> bool {
    kind == NodeKind::Value && path.ends_with(".operationId")
}

fn candidate(
    real_name: &str,
    entity_type: EntityType,
    scope: String,
    byte_start: usize,
    byte_end: usize,
    kind: OccurrenceKind,
) -> Candidate {
    Candidate {
        real_name: real_name.to_owned(),
        entity_type,
        scope_path: scope,
        byte_start,
        byte_end,
        kind,
        // The specification says what this is. Nothing heuristic about it.
        confidence: 1.0,
    }
}

#[allow(clippy::too_many_lines)]
fn classify(node: &NodeRef, enums: &BTreeSet<String>, out: &mut Vec<Candidate>) {
    let segments: Vec<&str> = node.path.split('.').collect();

    // `info.title` — the API's own name.
    if node.kind == NodeKind::Value && node.path == "info.title" {
        out.push(candidate(
            &node.text,
            EntityType::Api,
            "#/info/title".to_owned(),
            node.byte_start,
            node.byte_end,
            OccurrenceKind::Declaration,
        ));
        return;
    }

    // `components.schemas.X` — a schema name.
    if node.kind == NodeKind::Key && segments.len() == 3 && segments[0] == "components" && segments[1] == "schemas" {
        let name = segments[2];
        let entity_type = if enums.contains(name) {
            EntityType::Enum
        } else {
            EntityType::Dto
        };
        out.push(candidate(
            name,
            entity_type,
            format!("#/components/schemas/{name}"),
            node.byte_start,
            node.byte_end,
            OccurrenceKind::Declaration,
        ));
        return;
    }

    // `components.schemas.X.properties.p` — a field of that schema.
    if node.kind == NodeKind::Key
        && segments.len() == 5
        && segments[0] == "components"
        && segments[1] == "schemas"
        && segments[3] == "properties"
    {
        let (schema, property) = (segments[2], segments[4]);
        out.push(candidate(
            property,
            EntityType::Column,
            format!("#/components/schemas/{schema}.{property}"),
            node.byte_start,
            node.byte_end,
            OccurrenceKind::Declaration,
        ));
        return;
    }

    // `components.schemas.X.required[i]` — the same fields, named again.
    // A `required` list still holding the real field name after the property
    // was aliased leaves the name in the twin and invalidates the schema.
    if node.kind == NodeKind::Value
        && segments.len() == 5
        && segments[0] == "components"
        && segments[1] == "schemas"
        && segments[3] == "required"
    {
        let schema = segments[2];
        out.push(candidate(
            &node.text,
            EntityType::Column,
            format!("#/components/schemas/{schema}.{}", node.text),
            node.byte_start,
            node.byte_end,
            OccurrenceKind::Reference,
        ));
        return;
    }

    // `operationId` — the endpoint's identifier.
    if is_operation_id(&node.path, node.kind) {
        out.push(candidate(
            &node.text,
            EntityType::Endpoint,
            format!("#/{}", node.path.replace('.', "/")),
            node.byte_start,
            node.byte_end,
            OccurrenceKind::Declaration,
        ));
        return;
    }

    // `parameters[i].name` — a parameter, which is a field name in the URL.
    if node.kind == NodeKind::Value
        && segments.len() >= 3
        && segments[segments.len() - 1] == "name"
        && segments[segments.len() - 3] == "parameters"
    {
        out.push(candidate(
            &node.text,
            EntityType::Column,
            format!("#/{}", node.path.replace('.', "/")),
            node.byte_start,
            node.byte_end,
            OccurrenceKind::Declaration,
        ));
        return;
    }

    // `$ref: "#/components/schemas/X"` — only the target name is an entity; the
    // pointer around it is structure.
    if node.kind == NodeKind::Value && node.path.ends_with("$ref") {
        if let Some(index) = node.text.rfind('/') {
            let name = &node.text[index + 1..];
            if !name.is_empty() {
                let entity_type = if enums.contains(name) {
                    EntityType::Enum
                } else {
                    EntityType::Dto
                };
                out.push(candidate(
                    name,
                    entity_type,
                    format!("#/components/schemas/{name}"),
                    node.byte_start + index + 1,
                    node.byte_end,
                    OccurrenceKind::Reference,
                ));
            }
        }
        return;
    }

    // `paths./invoices/{invoiceId}` — the template names a resource and carries
    // a field name in the URL. Both are entities; the slashes are not.
    //
    // PRD §13 lists `ENDPOINT` among the structural types, and the literal
    // segment is the half that reveals the resource: a project whose table is
    // `invoice` and whose path is `/invoices` has said the table name out loud.
    // The verification gate catches exactly that, which is how this was found.
    if node.kind == NodeKind::Key && segments.len() == 2 && segments[0] == "paths" {
        for (offset, name) in literal_segments(&node.text) {
            out.push(candidate(
                name,
                EntityType::Endpoint,
                format!("#/paths/{}", node.text),
                node.byte_start + offset,
                node.byte_start + offset + name.len(),
                OccurrenceKind::Declaration,
            ));
        }
        for (offset, name) in braced_parameters(&node.text) {
            out.push(candidate(
                name,
                EntityType::Column,
                format!("#/paths/{}", node.text),
                node.byte_start + offset,
                node.byte_start + offset + name.len(),
                OccurrenceKind::Reference,
            ));
        }
    }
}

/// Literal path segments, as `(byte offset, segment)`. Braced parameters are
/// excluded — they are field names, handled separately.
fn literal_segments(template: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut offset = 0;
    for segment in template.split('/') {
        if !segment.is_empty() && !segment.starts_with('{') {
            out.push((offset, segment));
        }
        offset += segment.len() + 1;
    }
    out
}

/// `{param}` occurrences in a path template, as `(byte offset of the name, name)`.
fn braced_parameters(template: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut rest = template;
    let mut base = 0;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}') else { break };
        let name = &rest[open + 1..open + close];
        if !name.is_empty() {
            out.push((base + open + 1, name));
        }
        base += open + close + 1;
        rest = &rest[open + close + 1..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = concat!(
        "openapi: 3.1.0\n",
        "info:\n",
        "  title: BillingApi\n",
        "paths:\n",
        "  /invoices/{invoiceId}:\n",
        "    get:\n",
        "      operationId: getInvoice\n",
        "      parameters:\n",
        "        - name: invoiceId\n",
        "          in: path\n",
        "      responses:\n",
        "        \"200\":\n",
        "          content:\n",
        "            application/json:\n",
        "              schema:\n",
        "                $ref: \"#/components/schemas/InvoiceSummary\"\n",
        "components:\n",
        "  schemas:\n",
        "    PlanTier:\n",
        "      type: string\n",
        "      enum: [trial, standard]\n",
        "    InvoiceSummary:\n",
        "      required: [invoiceId]\n",
        "      properties:\n",
        "        invoiceId:\n",
        "          type: string\n",
        "        planTier:\n",
        "          $ref: \"#/components/schemas/PlanTier\"\n"
    );

    fn candidates(source: &str) -> Vec<Candidate> {
        OpenApiParser.structural_candidates(source, "openapi")
    }

    fn of_type(cands: &[Candidate], t: EntityType) -> Vec<&str> {
        let mut v: Vec<&str> = cands
            .iter()
            .filter(|c| c.entity_type == t)
            .map(|c| c.real_name.as_str())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    #[test]
    fn recognised_by_content_not_extension() {
        assert!(OpenApiParser.can_handle(Path::new("api.yaml"), SPEC));
        assert!(OpenApiParser.can_handle(Path::new("api.json"), r#"{"openapi": "3.1.0"}"#));
        assert!(
            !OpenApiParser.can_handle(Path::new("compose.yml"), "services:\n  web:\n    image: nginx\n"),
            "ordinary YAML is not a specification"
        );
    }

    #[test]
    fn every_span_points_at_the_name_it_claims() {
        for candidate in candidates(SPEC) {
            assert_eq!(
                &SPEC[candidate.byte_start..candidate.byte_end],
                candidate.real_name,
                "span mismatch for {:?}",
                candidate.real_name
            );
        }
    }

    #[test]
    fn schema_names_and_their_properties_are_found() {
        let found = candidates(SPEC);
        assert!(of_type(&found, EntityType::Dto).contains(&"InvoiceSummary"));
        assert!(of_type(&found, EntityType::Column).contains(&"invoiceId"));
        assert!(of_type(&found, EntityType::Column).contains(&"planTier"));
    }

    #[test]
    fn a_schema_with_an_enum_is_typed_as_one() {
        // Only affects the alias prefix, but a spec whose enums are called
        // DTO_… reads badly.
        let found = candidates(SPEC);
        assert!(of_type(&found, EntityType::Enum).contains(&"PlanTier"));
        assert!(!of_type(&found, EntityType::Dto).contains(&"PlanTier"));
    }

    #[test]
    fn operation_ids_are_endpoints() {
        // Alongside the literal path segments, which are endpoints too.
        assert_eq!(
            of_type(&candidates(SPEC), EntityType::Endpoint),
            vec!["getInvoice", "invoices"]
        );
    }

    #[test]
    fn a_ref_names_only_its_target() {
        // The pointer `#/components/schemas/` is structure. Aliasing the whole
        // string would produce a `$ref` that resolves to nothing.
        let found = candidates(SPEC);
        let refs: Vec<&Candidate> = found
            .iter()
            .filter(|c| c.kind == OccurrenceKind::Reference && c.real_name == "InvoiceSummary")
            .collect();
        assert_eq!(refs.len(), 1);
        assert_eq!(&SPEC[refs[0].byte_start..refs[0].byte_end], "InvoiceSummary");
    }

    #[test]
    fn a_required_entry_is_the_same_field_named_again() {
        // `required: [invoiceId]` still holding the real name after the
        // property was aliased leaves it in the twin and invalidates the schema.
        let found = candidates(SPEC);
        let occurrences = found.iter().filter(|c| c.real_name == "invoiceId").count();
        assert!(
            occurrences >= 3,
            "property, required, parameter, path template: got {occurrences}"
        );
    }

    #[test]
    fn a_literal_path_segment_is_an_endpoint() {
        // `/invoices` names the resource, and in a project whose table is
        // `invoice` it says the table name out loud.
        let found = candidates(SPEC);
        assert!(
            found
                .iter()
                .any(|c| c.real_name == "invoices" && c.entity_type == EntityType::Endpoint),
            "the literal segment was not detected"
        );
    }

    #[test]
    fn slashes_and_braces_are_never_part_of_a_name() {
        assert_eq!(literal_segments("/invoices/{invoiceId}"), vec![(1, "invoices")]);
        assert_eq!(literal_segments("/a/b/{c}"), vec![(1, "a"), (3, "b")]);
        assert!(literal_segments("/{only}").is_empty());
    }

    #[test]
    fn a_path_template_parameter_is_found() {
        // `/invoices/{invoiceId}` carries a field name in the URL.
        let found = candidates(SPEC);
        let in_template = found
            .iter()
            .find(|c| c.real_name == "invoiceId" && SPEC[..c.byte_start].ends_with("/invoices/{"));
        assert!(in_template.is_some(), "the braced parameter was not detected");
    }

    #[test]
    fn structural_keys_are_never_entities() {
        let found = candidates(SPEC);
        let names: Vec<&str> = found.iter().map(|c| c.real_name.as_str()).collect();
        for structural in [
            "openapi",
            "info",
            "paths",
            "components",
            "schemas",
            "properties",
            "type",
            "responses",
        ] {
            assert!(!names.contains(&structural), "{structural} was treated as a name");
        }
    }

    #[test]
    fn candidates_never_overlap() {
        let found = candidates(SPEC);
        for pair in found.windows(2) {
            assert!(
                pair[0].byte_end <= pair[1].byte_start,
                "overlap: {:?} and {:?}",
                pair[0].real_name,
                pair[1].real_name
            );
        }
    }

    #[test]
    fn structural_counts_track_specification_shape() {
        let counts = OpenApiParser.structural_counts(SPEC).expect("parses");
        assert_eq!(counts.get("schemas"), 2);
        assert_eq!(counts.get("paths"), 1);
        assert_eq!(counts.get("operations"), 1);
    }

    #[test]
    fn braced_parameters_are_located_correctly() {
        assert_eq!(braced_parameters("/invoices/{invoiceId}"), vec![(11, "invoiceId")]);
        assert_eq!(braced_parameters("/a/{one}/b/{two}"), vec![(4, "one"), (12, "two")]);
        assert!(braced_parameters("/plain/path").is_empty());
    }
}
