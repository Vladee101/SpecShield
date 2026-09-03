//! SQL — SDD §4.2, Implementation Plan M3.
//!
//! A schema is the densest source of proprietary identifiers in a project:
//! table names, column names, enum types, index names. Prose leaks diffusely;
//! a schema is nothing but names.
//!
//! # Why the AST drives detection but not the edits
//!
//! `sqlparser` gives a real AST with semantic roles — this `Ident` is a table
//! name, that one is a column of table T. That is what we need, because
//! `customer_id` in three tables is three identities (Design Review B1), and
//! only the AST knows which is which.
//!
//! Edits still come from byte ranges, never from re-serializing the AST. A
//! round-tripped `sqlparser` AST loses comments and normalizes whitespace and
//! keyword casing, which would fail `restore(sanitize(x)) == x` on the first
//! file. Positions come from `Ident::span`, converted to byte offsets here.
//!
//! # What is detected
//!
//! | Construct | Entity | Scope |
//! |---|---|---|
//! | `CREATE TABLE t` | Table | `sql::t` |
//! | column `c` in table `t` | Column | `sql::t.c` |
//! | `CREATE TYPE e AS ENUM` | Enum | `sql::e` |
//! | `CREATE INDEX i` | Index | `sql::i` |
//! | references to any of the above | the same identity | — |
//!
//! References matter as much as declarations: `REFERENCES customer_subscription
//! (subscription_id)` names the table again, and a twin that aliases the
//! declaration but not the reference leaks the name and fails to compile.

use std::path::Path;

use specshield_core::edit::Edit;
use specshield_core::model::{EntityType, OccurrenceKind};
use specshield_core::parser::{AliasMap, ArtifactParser, Candidate, Document, ParseError, Parsed, StructuralCounts};
use sqlparser::ast::{
    ColumnDef, ColumnOption, DataType, Ident, ObjectName, ObjectNamePart, Statement, TableConstraint,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser as SqlAstParser;

use crate::text::plan_from_candidates;

const EXTENSIONS: &[&str] = &["sql", "ddl"];

#[derive(Debug, Default, Clone, Copy)]
pub struct SqlParser;

/// Byte-offset lookup for `sqlparser`'s line/column spans.
///
/// `Location` is 1-based and counts *characters*, not bytes, so a schema with a
/// non-ASCII comment would shift every offset after it if this used raw
/// arithmetic.
struct LineIndex {
    /// Byte offset of the start of each line.
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(source: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(source.match_indices('\n').map(|(i, _)| i + 1));
        Self { starts }
    }

    /// Byte offset of a 1-based line and column, or `None` if out of range.
    fn offset(&self, source: &str, line: u64, column: u64) -> Option<usize> {
        let line_start = *self.starts.get(usize::try_from(line).ok()?.checked_sub(1)?)?;
        let rest = source.get(line_start..)?;
        let column = usize::try_from(column).ok()?.checked_sub(1)?;
        rest.char_indices()
            .nth(column)
            .map(|(i, _)| line_start + i)
            .or(Some(line_start + rest.len()))
    }
}

impl ArtifactParser for SqlParser {
    fn name(&self) -> &'static str {
        "sql"
    }

    fn can_handle(&self, path: &Path, _content: &str) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXTENSIONS.contains(&e.to_lowercase().as_str()))
    }

    fn parse<'a>(&self, doc: &'a Document) -> Result<Parsed<'a>, ParseError> {
        let statements = statements(&doc.content).map_err(|detail| ParseError::Failed {
            parser: "sql",
            path: doc.path.clone(),
            detail,
        })?;
        Ok(Parsed {
            document: doc,
            tree: Box::new(statements),
        })
    }

    fn extract(&self, parsed: &Parsed<'_>) -> Vec<Candidate> {
        self.structural_candidates(&parsed.document.content, &crate::text::scope_of(parsed))
    }

    fn plan_edits(&self, parsed: &Parsed<'_>, aliases: &AliasMap) -> Vec<Edit> {
        plan_from_candidates(&self.extract(parsed), aliases)
    }

    fn structural_candidates(&self, source: &str, _scope: &str) -> Vec<Candidate> {
        let Ok(statements) = statements(source) else {
            // SDD §16: a parse failure is never fatal. The file is left for the
            // prose scan, and the caller reports that no structure was read.
            return Vec::new();
        };
        let index = LineIndex::new(source);
        let mut out = Vec::new();
        for statement in &statements {
            walk(statement, source, &index, &mut out);
        }
        out.sort_by_key(|c| c.byte_start);
        out.dedup_by_key(|c| c.byte_start);
        out
    }

    /// A schema's structure is its object counts — SDD §7.2.
    ///
    /// Renaming identifiers must not add or remove a table, a column, or a
    /// statement. If it does, the alias pass has rewritten something it should
    /// not have and the twin is abandoned.
    fn fingerprints(&self) -> bool {
        true
    }

    fn structural_counts(&self, source: &str) -> Option<StructuralCounts> {
        let statements = statements(source).ok()?;
        let mut tables = 0;
        let mut columns = 0;
        let mut constraints = 0;
        let mut indexes = 0;
        let mut types = 0;

        for statement in &statements {
            match statement {
                Statement::CreateTable(create) => {
                    tables += 1;
                    columns += create.columns.len();
                    constraints += create.constraints.len();
                }
                Statement::CreateIndex(_) => indexes += 1,
                Statement::CreateType { .. } => types += 1,
                _ => {}
            }
        }

        Some(
            StructuralCounts::new()
                .with("statements", statements.len())
                .with("tables", tables)
                .with("columns", columns)
                .with("constraints", constraints)
                .with("indexes", indexes)
                .with("types", types),
        )
    }
}

fn statements(source: &str) -> Result<Vec<Statement>, String> {
    SqlAstParser::parse_sql(&GenericDialect {}, source).map_err(|e| e.to_string())
}

/// Emit a candidate for one identifier, if its span resolves to real bytes.
fn push(
    ident: &Ident,
    entity_type: EntityType,
    scope: String,
    source: &str,
    index: &LineIndex,
    out: &mut Vec<Candidate>,
) {
    let span = ident.span;
    let (Some(start), Some(end)) = (
        index.offset(source, span.start.line, span.start.column),
        index.offset(source, span.end.line, span.end.column),
    ) else {
        return;
    };
    if start >= end || end > source.len() || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return;
    }
    // A quoted identifier's span includes the quotes; the name does not.
    let (start, end) = if ident.quote_style.is_some() && end - start >= 2 {
        (start + 1, end - 1)
    } else {
        (start, end)
    };
    if source.get(start..end) != Some(ident.value.as_str()) {
        // Span and value disagree — skip rather than alias the wrong bytes.
        return;
    }

    out.push(Candidate {
        real_name: ident.value.clone(),
        entity_type,
        scope_path: scope,
        byte_start: start,
        byte_end: end,
        kind: OccurrenceKind::Declaration,
        // The AST said what this is. That is stronger evidence than any
        // heuristic the prose scan can offer.
        confidence: 1.0,
    });
}

fn object_name_parts(name: &ObjectName) -> Vec<&Ident> {
    name.0
        .iter()
        .filter_map(|part| match part {
            ObjectNamePart::Identifier(ident) => Some(ident),
            // A function-valued name part is not an identifier we can alias.
            ObjectNamePart::Function(_) => None,
        })
        .collect()
}

/// The unqualified name of an object, for scoping.
fn tail_name(name: &ObjectName) -> String {
    object_name_parts(name)
        .last()
        .map_or_else(String::new, |i| i.value.clone())
}

fn walk(statement: &Statement, source: &str, index: &LineIndex, out: &mut Vec<Candidate>) {
    match statement {
        Statement::CreateTable(create) => {
            let table = tail_name(&create.name);
            for ident in object_name_parts(&create.name) {
                push(ident, EntityType::Table, format!("sql::{table}"), source, index, out);
            }
            for column in &create.columns {
                walk_column(column, &table, source, index, out);
            }
            for constraint in &create.constraints {
                walk_constraint(constraint, source, index, out);
            }
        }

        Statement::CreateIndex(create) => {
            if let Some(name) = &create.name {
                let index_name = tail_name(name);
                for ident in object_name_parts(name) {
                    push(
                        ident,
                        EntityType::Index,
                        format!("sql::{index_name}"),
                        source,
                        index,
                        out,
                    );
                }
            }
            let table = tail_name(&create.table_name);
            for ident in object_name_parts(&create.table_name) {
                push(ident, EntityType::Table, format!("sql::{table}"), source, index, out);
            }
            // Indexed columns belong to the table being indexed, not to
            // whichever table happened to declare that column name first.
            for column in &create.columns {
                for ident in column_expr_idents(&column.column.expr) {
                    push(
                        ident,
                        EntityType::Column,
                        format!("sql::{table}.{}", ident.value),
                        source,
                        index,
                        out,
                    );
                }
            }
        }

        Statement::CreateType { name, .. } => {
            let type_name = tail_name(name);
            for ident in object_name_parts(name) {
                push(ident, EntityType::Enum, format!("sql::{type_name}"), source, index, out);
            }
        }

        _ => {}
    }
}

fn walk_column(column: &ColumnDef, table: &str, source: &str, index: &LineIndex, out: &mut Vec<Candidate>) {
    push(
        &column.name,
        EntityType::Column,
        format!("sql::{table}.{}", column.name.value),
        source,
        index,
        out,
    );

    // `tier plan_tier` references a user-defined type. Aliasing the type
    // declaration but not this reference produces a schema that no longer
    // resolves.
    if let DataType::Custom(name, _) = &column.data_type {
        let type_name = tail_name(name);
        for ident in object_name_parts(name) {
            push(ident, EntityType::Enum, format!("sql::{type_name}"), source, index, out);
        }
    }

    for option in &column.options {
        if let ColumnOption::ForeignKey(fk) = &option.option {
            walk_reference(&fk.foreign_table, &fk.referred_columns, source, index, out);
        }
    }
}

fn walk_constraint(constraint: &TableConstraint, source: &str, index: &LineIndex, out: &mut Vec<Candidate>) {
    if let TableConstraint::ForeignKey(fk) = constraint {
        // The constraint may also name the local columns it covers, but those
        // are already emitted from the column definitions.
        walk_reference(&fk.foreign_table, &fk.referred_columns, source, index, out);
    }
}

/// A `REFERENCES t (c)` clause names the table and its columns again.
fn walk_reference(
    foreign_table: &ObjectName,
    referred_columns: &[Ident],
    source: &str,
    index: &LineIndex,
    out: &mut Vec<Candidate>,
) {
    let table = tail_name(foreign_table);
    for ident in object_name_parts(foreign_table) {
        push(ident, EntityType::Table, format!("sql::{table}"), source, index, out);
    }
    for ident in referred_columns {
        push(
            ident,
            EntityType::Column,
            format!("sql::{table}.{}", ident.value),
            source,
            index,
            out,
        );
    }
}

/// Identifiers inside an indexed-column expression. Only bare identifiers are
/// entities; a functional index over an expression is left alone.
fn column_expr_idents(expr: &sqlparser::ast::Expr) -> Vec<&Ident> {
    match expr {
        sqlparser::ast::Expr::Identifier(ident) => vec![ident],
        sqlparser::ast::Expr::CompoundIdentifier(parts) => parts.iter().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = concat!(
        "-- Vantor billing schema.\n",
        "CREATE TYPE plan_tier AS ENUM ('trial', 'standard');\n",
        "\n",
        "CREATE TABLE customer_subscription (\n",
        "    subscription_id UUID PRIMARY KEY,\n",
        "    customer_id     UUID NOT NULL,\n",
        "    tier            plan_tier NOT NULL\n",
        ");\n",
        "\n",
        "CREATE INDEX idx_subscription_customer\n",
        "    ON customer_subscription (customer_id);\n",
        "\n",
        "CREATE TABLE invoice (\n",
        "    invoice_id      UUID PRIMARY KEY,\n",
        "    customer_id     UUID NOT NULL,\n",
        "    subscription_id UUID NOT NULL REFERENCES customer_subscription (subscription_id)\n",
        ");\n"
    );

    fn candidates(source: &str) -> Vec<Candidate> {
        SqlParser.structural_candidates(source, "sql")
    }

    fn named<'a>(cands: &'a [Candidate], name: &str) -> Vec<&'a Candidate> {
        cands.iter().filter(|c| c.real_name == name).collect()
    }

    #[test]
    fn claims_sql_extensions_only() {
        let p = SqlParser;
        assert!(p.can_handle(Path::new("schema.sql"), ""));
        assert!(p.can_handle(Path::new("MIGRATION.SQL"), ""));
        assert!(!p.can_handle(Path::new("notes.md"), ""));
    }

    #[test]
    fn every_span_points_at_the_name_it_claims() {
        // The whole design rests on byte offsets being right. If this fails,
        // sanitize aliases the wrong bytes.
        for candidate in candidates(SCHEMA) {
            assert_eq!(
                &SCHEMA[candidate.byte_start..candidate.byte_end],
                candidate.real_name,
                "span mismatch for {:?}",
                candidate.real_name
            );
        }
    }

    #[test]
    fn finds_tables_columns_enums_and_indexes() {
        let found = candidates(SCHEMA);
        let types: Vec<_> = [
            "customer_subscription",
            "customer_id",
            "plan_tier",
            "idx_subscription_customer",
        ]
        .iter()
        .map(|n| named(&found, n).first().map(|c| c.entity_type))
        .collect();
        assert_eq!(
            types,
            vec![
                Some(EntityType::Table),
                Some(EntityType::Column),
                Some(EntityType::Enum),
                Some(EntityType::Index),
            ]
        );
    }

    #[test]
    fn the_same_column_name_in_two_tables_is_two_identities() {
        // Design Review B1, in the format where it bites hardest.
        let found = candidates(SCHEMA);
        let scopes: std::collections::BTreeSet<&str> = named(&found, "customer_id")
            .iter()
            .map(|c| c.scope_path.as_str())
            .collect();
        assert!(scopes.contains("sql::customer_subscription.customer_id"), "{scopes:?}");
        assert!(scopes.contains("sql::invoice.customer_id"), "{scopes:?}");
    }

    #[test]
    fn references_are_found_not_just_declarations() {
        // `REFERENCES customer_subscription (subscription_id)` names both
        // again. Aliasing only the declaration leaks the name and breaks the
        // schema.
        let found = candidates(SCHEMA);
        assert!(
            named(&found, "customer_subscription").len() >= 3,
            "declaration, index ON, and REFERENCES: got {}",
            named(&found, "customer_subscription").len()
        );
    }

    #[test]
    fn a_type_reference_in_a_column_is_found() {
        let found = candidates(SCHEMA);
        assert_eq!(named(&found, "plan_tier").len(), 2, "declaration and the column's type");
    }

    #[test]
    fn candidates_never_overlap() {
        let found = candidates(SCHEMA);
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
    fn unparseable_sql_yields_nothing_rather_than_guesses() {
        // SDD §16: a parse failure is not fatal, and it is not an excuse to
        // fall back to pattern-matching identifiers out of broken SQL.
        assert!(candidates("CREATE TABLE (((").is_empty());
    }

    #[test]
    fn structural_counts_track_schema_shape() {
        let counts = SqlParser.structural_counts(SCHEMA).expect("parses");
        assert_eq!(counts.get("tables"), 2);
        assert_eq!(counts.get("types"), 1);
        assert_eq!(counts.get("indexes"), 1);
        assert_eq!(counts.get("columns"), 6);
    }

    #[test]
    fn a_dropped_column_is_caught_by_the_structural_check() {
        let before = SqlParser.structural_counts(SCHEMA).unwrap();
        let after = SqlParser
            .structural_counts(&SCHEMA.replace("    customer_id     UUID NOT NULL,\n", ""))
            .unwrap();
        let diffs = before.differences(&after);
        assert!(diffs.iter().any(|(kind, _, _)| *kind == "columns"), "{diffs:?}");
    }

    #[test]
    fn unparseable_sql_has_no_structural_counts() {
        assert!(SqlParser.structural_counts("CREATE TABLE (((").is_none());
    }

    #[test]
    fn quoted_identifiers_resolve_to_the_name_without_quotes() {
        let source = "CREATE TABLE \"customer subscription\" (\"customer id\" UUID);\n";
        for candidate in candidates(source) {
            assert_eq!(&source[candidate.byte_start..candidate.byte_end], candidate.real_name);
        }
    }
}
