//! TypeScript and JavaScript — SDD §4.2, Implementation Plan M4.
//!
//! # What Tree-sitter can and cannot do here
//!
//! Tree-sitter produces a concrete syntax tree with **no name resolution, no
//! scope analysis, and no types**. The M0 spike measured what that costs
//! (`spikes/M0-tree-sitter-rename.md`) and found a sharp split:
//!
//! | Construct | Result |
//! |---|---|
//! | Classes, interfaces, enums, type aliases, imports | resolved, including across files and under shadowing |
//! | **Object properties and interface members** | **unresolvable** — 25 of 47 property-position identifiers |
//!
//! Deciding whether `x.customerId` refers to `CustomerSubscription.customerId`
//! requires the type of `x`. Nothing lexical recovers it.
//!
//! # The property rule
//!
//! Properties are therefore scoped **globally**: every property-position
//! identifier matching a known member name gets the same alias project-wide,
//! whichever type declares it.
//!
//! - The twin stays consistent — declaration, object-literal key, and member
//!   access all become the same new name, so it still parses.
//! - Restoration stays unambiguous: one name, one alias.
//! - The cost is a bounded leak. Two unrelated interfaces that both have
//!   `customerId` receive the same alias, disclosing that they share a field
//!   name — not what the field is.
//!
//! Exact per-type renaming needs a type checker and is V1.1.
//!
//! # Comments and strings are the prose
//!
//! This is the format [`prose_regions`] exists for. `// Meridian Freight runs on
//! the Enterprise tier` is prose inside code, and the highest-value leak in the
//! corpus fixture; the surrounding code is not prose and must not be scanned by
//! heuristics that would alias `Promise` or `async`.
//!
//! [`prose_regions`]: ArtifactParser::prose_regions

use std::collections::{HashMap, HashSet};
use std::path::Path;

use specshield_core::detect::classify_pascal;
use specshield_core::edit::Edit;
use specshield_core::model::{EntityType, OccurrenceKind};
use specshield_core::parser::{
    AliasMap, ArtifactParser, Candidate, Document, ParseError, Parsed, ProjectContext, StructuralCounts, fold_name,
};
use specshield_core::paths::{is_entity_segment, segment_identity};
use tree_sitter::{Node, Parser as TsParser, Tree};

use crate::text::plan_from_candidates;

const EXTENSIONS: &[&str] = &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];

/// Scope shared by every property in the project — see the module docs.
const PROPERTY_SCOPE: &str = "ts::property";

#[derive(Debug, Default, Clone, Copy)]
pub struct TypeScriptParser;

/// Parse under one of the two grammars `tree-sitter-typescript` ships.
///
/// They are genuinely different languages, not a superset and a subset. `<T>x`
/// is a type assertion in TypeScript and the start of a JSX element in TSX;
/// neither grammar accepts both readings, which is why `tsc` picks by file
/// extension and why there are two grammars at all.
fn parse_with(source: &str, jsx: bool) -> Option<Tree> {
    let language = if jsx {
        tree_sitter_typescript::LANGUAGE_TSX
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT
    };
    let mut parser = TsParser::new();
    parser.set_language(&language.into()).ok()?;
    parser.parse(source, None)
}

/// Parse as TypeScript, and fall back to TSX when that fails.
///
/// **This is the P3-4 defect.** Only the TypeScript grammar was ever used, and
/// it cannot read JSX: one `return <div>{x}</div>` was enough to make the tree
/// error, which made `structural_candidates_in` return nothing and
/// `structural_counts` return `None`. Every `.tsx` file in a React project
/// therefore went to the model **completely unaliased**, and — because a `None`
/// fingerprint was read as "this parser has no structure to compare" rather
/// than "this parser could not read your file" — was reported as *verified
/// clean*. Found by running the pipeline over a real Vite/React repository, in
/// which 15 of 20 TypeScript files were `.tsx`.
///
/// Order matters and is not arbitrary. TypeScript first, because `<T>x` parses
/// cleanly there and is an error under TSX, so a `.ts` file using type
/// assertions must not be handed to the JSX grammar. A file that parses cleanly
/// as TypeScript contains no JSX by definition, so the two grammars agree on it
/// and the fallback never fires.
///
/// Trying rather than switching on the extension is deliberate: `EXTENSIONS`
/// already claims `.js`, and JSX in a `.js` file is ordinary in React projects.
/// An extension is a hint about a file; whether the grammar accepts it is a
/// fact about the file.
fn parse_tree(source: &str) -> Option<Tree> {
    let typescript = parse_with(source, false);
    if typescript.as_ref().is_some_and(|t| !t.root_node().has_error()) {
        return typescript;
    }
    let tsx = parse_with(source, true);
    if tsx.as_ref().is_some_and(|t| !t.root_node().has_error()) {
        return tsx;
    }
    // Neither grammar is happy. Hand back the TypeScript tree so the callers'
    // existing `has_error` guards see a genuinely broken file and leave it
    // alone, rather than seeing nothing at all.
    typescript.or(tsx)
}

impl ArtifactParser for TypeScriptParser {
    fn name(&self) -> &'static str {
        "typescript"
    }

    fn can_handle(&self, path: &Path, _content: &str) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXTENSIONS.contains(&e.to_lowercase().as_str()))
    }

    fn parse<'a>(&self, doc: &'a Document) -> Result<Parsed<'a>, ParseError> {
        let tree = parse_tree(&doc.content).ok_or_else(|| ParseError::Failed {
            parser: "typescript",
            path: doc.path.clone(),
            detail: "tree-sitter returned no tree".to_owned(),
        })?;
        Ok(Parsed {
            document: doc,
            tree: Box::new(tree),
        })
    }

    fn extract(&self, parsed: &Parsed<'_>) -> Vec<Candidate> {
        self.structural_candidates(&parsed.document.content, &crate::text::scope_of(parsed))
    }

    fn plan_edits(&self, parsed: &Parsed<'_>, aliases: &AliasMap) -> Vec<Edit> {
        plan_from_candidates(&self.extract(parsed), aliases)
    }

    fn structural_candidates(&self, source: &str, scope: &str) -> Vec<Candidate> {
        self.structural_candidates_in(source, scope, &ProjectContext::default())
    }

    fn structural_candidates_in(&self, source: &str, scope: &str, context: &ProjectContext) -> Vec<Candidate> {
        let Some(tree) = parse_tree(source) else {
            return Vec::new();
        };
        // A file with syntax errors is left alone rather than pattern-matched:
        // SDD §16 says a parse failure preserves the original.
        if tree.root_node().has_error() {
            return Vec::new();
        }

        let mut collector = Collector {
            source,
            scope: scope.to_owned(),
            declared: HashMap::new(),
            // Borrowed, not copied. The project's names are seeded from the
            // vault and number in the thousands; cloning them into a per-file
            // set is quadratic in the size of the project.
            context,
            properties: HashSet::new(),
            pending_paths: Vec::new(),
            out: Vec::new(),
        };
        collector.walk_declarations(tree.root_node());
        collector.resolve_paths();
        collector.walk_references(tree.root_node());

        let mut out = std::mem::take(&mut collector.out);
        out.sort_by_key(|c| c.byte_start);
        out.dedup_by_key(|c| c.byte_start);
        out
    }

    /// Comments and string literals — SDD §4.4's prose scan, confined.
    fn prose_regions(&self, source: &str) -> Option<Vec<(usize, usize)>> {
        let tree = parse_tree(source)?;
        let mut regions = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "comment" | "string_fragment" | "template_string") {
                regions.push((node.start_byte(), node.end_byte()));
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        Some(regions)
    }

    /// Declaration and reference counts — SDD §7.2.
    ///
    /// The check the M0 spike validated: renaming must not change how many
    /// identifiers a file has. It catches catastrophic breakage, not subtle
    /// wrongness — an alias substituted for the wrong symbol keeps the count.
    /// The verification gate is what protects the export; this protects the file.
    fn fingerprints(&self) -> bool {
        true
    }

    fn structural_counts(&self, source: &str) -> Option<StructuralCounts> {
        let tree = parse_tree(source)?;
        if tree.root_node().has_error() {
            return None;
        }
        let mut counts = HashMap::new();
        tally(tree.root_node(), &mut counts);
        Some(
            StructuralCounts::new()
                .with("identifiers", counts.get("identifier").copied().unwrap_or(0))
                .with("type_identifiers", counts.get("type_identifier").copied().unwrap_or(0))
                .with("properties", counts.get("property_identifier").copied().unwrap_or(0))
                .with("classes", counts.get("class_declaration").copied().unwrap_or(0))
                .with("interfaces", counts.get("interface_declaration").copied().unwrap_or(0))
                .with("enums", counts.get("enum_declaration").copied().unwrap_or(0))
                .with("imports", counts.get("import_statement").copied().unwrap_or(0)),
        )
    }
}

fn tally(node: Node<'_>, counts: &mut HashMap<&'static str, usize>) {
    for kind in [
        "identifier",
        "type_identifier",
        "property_identifier",
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "import_statement",
    ] {
        if node.kind() == kind {
            *counts.entry(kind).or_default() += 1;
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        tally(child, counts);
    }
}

/// Module identity for scoping: the file path without its extension.
///
/// A declaration in `src/domain/plan-tier.ts` and an import of
/// `../domain/plan-tier` from `src/services/x.ts` must produce the same scope,
/// or the same symbol gets two aliases and the twin stops compiling. Both
/// normalize to `src/domain/plan-tier`.
fn module_id(path: &str) -> String {
    let path = path.replace('\\', "/");
    match path.rsplit_once('.') {
        Some((stem, ext)) if !ext.contains('/') => stem.to_owned(),
        _ => path,
    }
}

/// Resolve an import specifier against the importing file's module id.
///
/// Lexical only — no filesystem access and no module graph. That is enough for
/// relative specifiers, which is how a project refers to itself. A bare
/// specifier (`react`, `@scope/pkg`) is a dependency, not a project module, and
/// is left alone.
fn resolve_import(from_module: &str, specifier: &str) -> Option<String> {
    if !specifier.starts_with('.') {
        return None;
    }
    let mut parts: Vec<&str> = from_module.split('/').collect();
    parts.pop(); // the importing file itself

    for segment in specifier.split('/') {
        match segment {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    Some(module_id(&parts.join("/")))
}

struct Collector<'a> {
    source: &'a str,
    scope: String,
    /// Declared name -> the identity it belongs to. Used so a reference gets the
    /// same entity type and scope as its declaration.
    declared: HashMap<String, (EntityType, String)>,
    /// What the project knows, from the vault. Consulted alongside `properties`
    /// so a file that only *uses* a member still recognises it — the M0 spike's
    /// global-property rule needs project-wide knowledge to mean anything.
    context: &'a ProjectContext,
    /// Property names declared in this file.
    properties: HashSet<String>,
    /// Import segments, held until declarations are complete. An import sits at
    /// the top of the file, so deciding about it in place would ask whether a
    /// name is declared before the walk has seen the declaration.
    pending_paths: Vec<(String, usize)>,
    out: Vec<Candidate>,
}

impl Collector<'_> {
    /// A member of this file, or one the project learned elsewhere.
    fn knows_member(&self, name: &str) -> bool {
        self.properties.contains(name) || self.context.is_member(name)
    }

    fn text(&self, node: Node<'_>) -> &str {
        &self.source[node.byte_range()]
    }

    fn push(&mut self, node: Node<'_>, entity_type: EntityType, scope: String, kind: OccurrenceKind) {
        let name = self.text(node).to_owned();
        self.out.push(Candidate {
            real_name: name,
            entity_type,
            scope_path: scope,
            byte_start: node.start_byte(),
            byte_end: node.end_byte(),
            kind,
            confidence: 1.0,
        });
    }

    /// Pass 1: every declaration, so references can be resolved against them.
    fn walk_declarations(&mut self, node: Node<'_>) {
        match node.kind() {
            // Classes and functions alike: a named unit of behaviour. The
            // suffix rule in `declare` refines it — a `SubscriptionCreated`
            // function is an Event exactly as the class would be.
            //
            // Functions were missed until P3-4 pointed the parser at a real
            // React project, where the components *are* functions: 63 of them
            // went unaliased while the vault learned their names from the
            // filenames and the imports, blocking every export. The corpus
            // generator only ever emitted classes and interfaces.
            //
            // `function_signature` is the ambient form (`declare function f():
            // void`) that a `.d.ts` file is made of.
            "class_declaration"
            | "abstract_class_declaration"
            | "function_declaration"
            | "generator_function_declaration"
            | "function_signature" => {
                self.declare(node, EntityType::Service);
            }
            "interface_declaration" => {
                self.declare(node, EntityType::Dto);
                if let Some(body) = node.child_by_field_name("body") {
                    self.declare_members(body);
                }
            }
            "enum_declaration" => {
                self.declare(node, EntityType::Enum);
            }
            "type_alias_declaration" => {
                self.declare(node, EntityType::Dto);
            }
            "import_statement" => {
                self.import_bindings(node);
                self.import_paths(node);
            }
            _ => {}
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.walk_declarations(child);
        }
    }

    /// Record a named declaration, letting the suffix pick the entity type so a
    /// TypeScript `SubscriptionCreated` is an Event exactly as a prose mention
    /// of it would be.
    fn declare(&mut self, node: Node<'_>, default_type: EntityType) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = self.text(name_node).to_owned();
        let entity_type = classify_pascal(&name).unwrap_or(default_type);
        let scope = format!("{}::{name}", module_id(&self.scope));

        self.declared.insert(name, (entity_type, scope.clone()));
        self.push(name_node, entity_type, scope, OccurrenceKind::Declaration);
    }

    /// Interface members. Scoped globally — see the module docs.
    fn declare_members(&mut self, body: Node<'_>) {
        let mut cursor = body.walk();
        for member in body.named_children(&mut cursor) {
            if member.kind() != "property_signature" {
                continue;
            }
            let Some(name_node) = member.child_by_field_name("name") else {
                continue;
            };
            let name = self.text(name_node).to_owned();
            self.properties.insert(name);
            self.push(
                name_node,
                EntityType::Column,
                PROPERTY_SCOPE.to_owned(),
                OccurrenceKind::Declaration,
            );
        }
    }

    /// Names an import brings into this file.
    ///
    /// These are not declared here, but they *are* used here, and they must
    /// carry the alias of the module that declares them — otherwise the import
    /// and the declaration get different aliases and the twin does not compile.
    /// The scope is resolved from the specifier rather than from a module graph,
    /// which is enough for the relative imports a project uses to refer to
    /// itself.
    fn import_bindings(&mut self, node: Node<'_>) {
        let Some(source_node) = node.child_by_field_name("source") else {
            return;
        };
        let specifier: String = self.text(source_node).trim_matches(['"', '\'', '`']).to_owned();
        let Some(target) = resolve_import(&module_id(&self.scope), &specifier) else {
            return; // a dependency, not a project module
        };

        let mut stack = vec![node];
        let mut bindings = Vec::new();
        while let Some(current) = stack.pop() {
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                if matches!(child.kind(), "import_specifier" | "namespace_import") {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        bindings.push((name_node, self.text(name_node).to_owned()));
                    }
                } else {
                    stack.push(child);
                }
            }
        }

        for (name_node, name) in bindings {
            let entity_type = classify_pascal(&name).unwrap_or(EntityType::Dto);
            let scope = format!("{target}::{name}");
            self.declared.insert(name, (entity_type, scope.clone()));
            self.push(name_node, entity_type, scope, OccurrenceKind::Reference);
        }
    }

    /// Path segments inside an import specifier.
    ///
    /// `from "../domain/customer-subscription"` names a file, and the file is
    /// named after the type it holds. Aliasing the type and leaving the path
    /// leaves the name in the twin.
    fn import_paths(&mut self, node: Node<'_>) {
        let Some(source_node) = node.child_by_field_name("source") else {
            return;
        };
        // Copied out: borrowing `self.source` here would conflict with pushing
        // into `self.out` below.
        let specifier: String = self.text(source_node).trim_matches(['"', '\'', '`']).to_owned();
        // The span includes the quotes; the specifier does not.
        let inner_start = source_node.start_byte() + 1;

        // Only the last segment. A file is named after the type it holds, so
        // `customer-subscription` is derived from `CustomerSubscription` and
        // leaks it. The directories above it — `domain`, `dto`, `services`, `src`
        // — are architectural convention, universal across projects, and
        // aliasing them makes every import unreadable for nothing.
        //
        // A genuinely proprietary directory name is what the dictionary is for.
        let Some(last) = specifier.rsplit('/').next() else {
            return;
        };
        if last.is_empty() || last == "." || last == ".." {
            return;
        }
        // The whole component. A specifier carries no module extension — that is
        // what the resolver adds — so `create-subscription.dto` *is* the name,
        // and it has to be, because the export names the file the same way. A
        // parser that stopped at the first dot gave the file one alias and this
        // import another.
        let stem = last;
        let offset = specifier.len() - last.len();
        self.pending_paths.push((stem.to_owned(), inner_start + offset));
    }

    /// Decide which import segments are entities, once the file's declarations
    /// are known.
    ///
    /// The rule itself lives in [`specshield_core::paths`], because the export
    /// applies it to the file tree as well. If the two ever disagreed, a file
    /// would be written under one name and imported under another and the twin
    /// would stop resolving.
    ///
    /// The one thing added here is the file's own declarations: `thing18.ts`
    /// holding `Thing18` is recognisable from inside the file, before the
    /// project has learned anything.
    fn resolve_paths(&mut self) {
        let declared: HashSet<String> = self.declared.keys().map(|n| fold_name(n)).collect();

        for (stem, start) in std::mem::take(&mut self.pending_paths) {
            if !is_entity_segment(&stem, self.context) && !declared.contains(&fold_name(&stem)) {
                continue;
            }

            let key = segment_identity(&stem);
            self.out.push(Candidate {
                byte_start: start,
                byte_end: start + stem.len(),
                real_name: stem,
                entity_type: key.entity_type,
                // Project-wide: the file and every import of it are one name for
                // one thing (SDD §5). Scoping this per importing file gave two
                // importers two different aliases for the same module, and the
                // file itself could then only be written under one of them.
                scope_path: key.scope_path,
                kind: OccurrenceKind::Path,
                confidence: 1.0,
            });
        }
    }

    /// Pass 2: references to anything pass 1 declared.
    fn walk_references(&mut self, node: Node<'_>) {
        let kind = node.kind();

        if matches!(kind, "identifier" | "type_identifier") && !is_declaration_site(node) {
            let name = self.text(node).to_owned();
            if let Some((entity_type, scope)) = self.declared.get(&name).cloned() {
                self.push(node, entity_type, scope, OccurrenceKind::Reference);
            }
        }

        // A plain identifier that carries a member's name — `findByCustomer(
        // customerId: string)` — says that member out loud even though it is a
        // parameter binding, not a property position. Declaration sites are
        // included for that reason. The alias is derived from the name, so every
        // occurrence of the binding moves together and the code stays
        // consistent; restore maps the alias back to the one name either way.
        if kind == "identifier" {
            let name = self.text(node).to_owned();
            if self.knows_member(&name) && !self.declared.contains_key(&name) {
                self.push(
                    node,
                    EntityType::Column,
                    PROPERTY_SCOPE.to_owned(),
                    OccurrenceKind::Reference,
                );
            }
        }

        // Property positions: object-literal keys and member accesses. Matched
        // by name against the file's declared members, which is the global rule.
        if matches!(kind, "property_identifier" | "shorthand_property_identifier") {
            let name = self.text(node).to_owned();
            if self.knows_member(&name) {
                self.push(
                    node,
                    EntityType::Column,
                    PROPERTY_SCOPE.to_owned(),
                    OccurrenceKind::Reference,
                );
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.walk_references(child);
        }
    }
}

/// Positions where an identifier binds a name rather than referring to one.
fn is_declaration_site(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let is_name_field = parent.child_by_field_name("name").is_some_and(|n| n.id() == node.id());

    match parent.kind() {
        "class_declaration"
        | "abstract_class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "type_alias_declaration" => is_name_field,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = concat!(
        "import { CustomerSubscription } from \"../domain/customer-subscription\";\n",
        "import { PlanTier } from \"./plan-tier\";\n",
        "\n",
        "/** Owns the CustomerSubscription lifecycle for Vantor. */\n",
        "export interface CreateSubscriptionDto {\n",
        "  customerId: string;\n",
        "  planTier: PlanTier;\n",
        "}\n",
        "\n",
        "export class SubscriptionService {\n",
        "  create(dto: CreateSubscriptionDto): CustomerSubscription {\n",
        "    return { customerId: dto.customerId, planTier: dto.planTier } as CustomerSubscription;\n",
        "  }\n",
        "}\n"
    );

    fn candidates(source: &str) -> Vec<Candidate> {
        TypeScriptParser.structural_candidates(source, "src/x.ts")
    }

    fn named<'a>(c: &'a [Candidate], name: &str) -> Vec<&'a Candidate> {
        c.iter().filter(|c| c.real_name == name).collect()
    }

    #[test]
    fn claims_typescript_and_javascript() {
        let p = TypeScriptParser;
        assert!(p.can_handle(Path::new("a.ts"), ""));
        assert!(p.can_handle(Path::new("a.tsx"), ""));
        assert!(p.can_handle(Path::new("a.mjs"), ""));
        assert!(!p.can_handle(Path::new("a.rs"), ""));
    }

    #[test]
    fn every_span_points_at_the_name_it_claims() {
        for candidate in candidates(SOURCE) {
            assert_eq!(
                &SOURCE[candidate.byte_start..candidate.byte_end],
                candidate.real_name,
                "span mismatch for {:?}",
                candidate.real_name
            );
        }
    }

    #[test]
    fn a_module_id_drops_the_extension_so_scopes_match_across_files() {
        assert_eq!(module_id("src/domain/plan-tier.ts"), "src/domain/plan-tier");
        assert_eq!(
            module_id("src/dto/create-subscription.dto.ts"),
            "src/dto/create-subscription.dto"
        );
        assert_eq!(module_id("noext"), "noext");
    }

    #[test]
    fn an_import_resolves_to_the_declaring_module() {
        // The declaration in src/domain/plan-tier.ts and this import must land
        // on the same scope, or the symbol gets two aliases.
        assert_eq!(
            resolve_import("src/services/subscription.service", "../domain/plan-tier"),
            Some("src/domain/plan-tier".to_owned())
        );
        assert_eq!(
            resolve_import("src/domain/customer-subscription", "./plan-tier"),
            Some("src/domain/plan-tier".to_owned())
        );
        assert_eq!(
            resolve_import("src/x", "react"),
            None,
            "a dependency is not a project module"
        );
    }

    #[test]
    fn an_imported_type_is_scoped_to_the_module_that_declares_it() {
        let found = candidates(SOURCE);
        let plan_tier = named(&found, "PlanTier");
        assert!(!plan_tier.is_empty(), "an imported type is still an entity");
        assert!(
            plan_tier.iter().all(|c| c.scope_path == "src/plan-tier::PlanTier"),
            "{:?}",
            plan_tier.iter().map(|c| &c.scope_path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn declarations_are_typed_by_suffix() {
        let found = candidates(SOURCE);
        let kind = |n: &str| named(&found, n).first().map(|c| c.entity_type);
        assert_eq!(kind("SubscriptionService"), Some(EntityType::Service));
        assert_eq!(kind("CreateSubscriptionDto"), Some(EntityType::Dto));
        assert_eq!(kind("PlanTier"), Some(EntityType::Enum));
    }

    #[test]
    fn references_resolve_to_their_declaration() {
        // `CustomerSubscription` is imported and used three times. Aliasing only
        // one of them leaves the name in the twin and breaks the file.
        let found = candidates(SOURCE);
        assert!(
            named(&found, "CreateSubscriptionDto").len() >= 2,
            "declaration and parameter type: got {}",
            named(&found, "CreateSubscriptionDto").len()
        );
    }

    #[test]
    fn properties_are_found_at_declaration_and_use() {
        // Declaration, object-literal key, and member access — the global rule.
        let found = candidates(SOURCE);
        assert!(
            named(&found, "customerId").len() >= 3,
            "got {}",
            named(&found, "customerId").len()
        );
    }

    #[test]
    fn every_property_occurrence_shares_one_scope() {
        // The M0 spike's MVP rule: without types, per-type scoping is not
        // available, so properties are global and consistent.
        let found = candidates(SOURCE);
        let scopes: HashSet<&str> = named(&found, "customerId")
            .iter()
            .map(|c| c.scope_path.as_str())
            .collect();
        assert_eq!(scopes.len(), 1, "{scopes:?}");
    }

    #[test]
    fn import_paths_are_path_segments_without_extension_or_quotes() {
        let found = candidates(SOURCE);
        let segments: Vec<&str> = found
            .iter()
            .filter(|c| c.entity_type == EntityType::PathSegment)
            .map(|c| c.real_name.as_str())
            .collect();
        assert!(segments.contains(&"customer-subscription"), "{segments:?}");
        assert!(segments.contains(&"plan-tier"), "{segments:?}");
        assert!(!segments.contains(&".."), "relative markers are structure");
        assert!(
            !segments.contains(&"domain"),
            "architectural directory names are convention, not proprietary: {segments:?}"
        );
    }

    #[test]
    fn prose_reuses_the_identity_the_parser_resolved() {
        // The doc comment and the type reference are one name, so the twin must
        // show the model one alias — not two for the same thing.
        let source = "import { CustomerSubscription } from \"../domain/x\";
/** Owns the CustomerSubscription lifecycle. */
export class S {}
";
        let mut g = specshield_core::sanitize::Graph::new(
            specshield_core::alias::ProjectKey::from_bytes([7u8; 32]),
            specshield_core::alias::AliasStyle::Opaque,
        );
        // Confirmed: a DTO is not aliased on its own any more (PRD §4.1), and
        // the property under test is that one name yields one alias — which
        // only has something to say when the name is aliased at all.
        let d = specshield_core::detect::Detector::new()
            .with_confirmed_term("CustomerSubscription", specshield_core::model::EntityType::Dto);
        let parser = crate::for_document(std::path::Path::new("s.ts"), source).unwrap();
        let out = specshield_core::sanitize::sanitize(
            source,
            "s.ts",
            &d,
            &mut g,
            Some(parser.as_ref()),
            &specshield_core::parser::ProjectContext::default(),
        )
        .unwrap();

        let aliases: std::collections::BTreeSet<&str> = out
            .applied
            .iter()
            .filter(|a| a.real_name == "CustomerSubscription")
            .map(|a| a.alias.as_str())
            .collect();
        assert_eq!(aliases.len(), 1, "one name, one alias: {aliases:?}");
    }

    #[test]
    fn a_parameter_named_after_a_member_is_aliased() {
        let source = "interface S {
  customerId: string;
}
interface R {
  find(customerId: string): void;
}
";
        let found = candidates(source);
        let hits = found.iter().filter(|c| c.real_name == "customerId").count();
        assert!(hits >= 2, "the parameter must move with the member: {found:#?}");
    }

    #[test]
    fn a_module_named_after_a_type_it_declares_is_a_path_segment() {
        // The dominant TypeScript convention: `thing18.ts` holds `Thing18`. The
        // gate folds case and separators, so it reads the import string as the
        // type's name — the parser has to agree, or the export never passes.
        let source = "import { Thing18 } from \"../mod00/thing18\";
export const x: Thing18 = 1;
";
        let found = candidates(source);
        let segments: Vec<&str> = found
            .iter()
            .filter(|c| c.entity_type == EntityType::PathSegment)
            .map(|c| c.real_name.as_str())
            .collect();
        assert_eq!(segments, vec!["thing18"], "{found:#?}");
    }

    #[test]
    fn a_single_word_module_name_is_not_a_path_segment() {
        // `subscription.repository.ts` reduces to `subscription`, which is also
        // a local variable in half the codebase. Aliasing it blocks the export
        // on every ordinary use.
        let source = "import { X } from \"../repositories/subscription.repository\";
const subscription = 1;
";
        let found = candidates(source);
        let segments: Vec<&str> = found
            .iter()
            .filter(|c| c.entity_type == EntityType::PathSegment)
            .map(|c| c.real_name.as_str())
            .collect();
        assert!(segments.is_empty(), "{segments:?}");
    }

    #[test]
    fn comments_and_strings_are_the_prose_regions() {
        let regions = TypeScriptParser.prose_regions(SOURCE).expect("parses");
        let covers = |needle: &str| {
            let at = SOURCE.find(needle).expect("present");
            regions.iter().any(|(s, e)| *s <= at && at < *e)
        };
        assert!(covers("Vantor"), "a name in a comment must be scannable");
        assert!(!covers("export class"), "code must not be");
    }

    #[test]
    fn a_file_with_syntax_errors_yields_nothing() {
        // SDD §16: preserve the original rather than pattern-match broken code.
        assert!(candidates("class {{{ broken").is_empty());
        assert!(TypeScriptParser.structural_counts("class {{{ broken").is_none());
    }

    #[test]
    fn candidates_never_overlap() {
        for pair in candidates(SOURCE).windows(2) {
            assert!(
                pair[0].byte_end <= pair[1].byte_start,
                "overlap: {:?} and {:?}",
                pair[0].real_name,
                pair[1].real_name
            );
        }
    }

    #[test]
    fn jsx_is_parsed_rather_than_silently_skipped() {
        // The P3-4 defect. Only the TypeScript grammar was ever used and it
        // cannot read JSX, so one `return <div>...</div>` made the tree error,
        // `structural_candidates_in` return nothing, and `structural_counts`
        // return `None` — which the caller read as "this parser has no
        // structure to compare". Every `.tsx` file in a React project went to
        // the model unaliased under the words "verified clean".
        let source = concat!(
            "export interface Stage {
",
            "  name: string;
",
            "}
",
            "export function JourneyMap({ stage }: { stage: Stage }) {
",
            "  return <div className=\"row\">{stage.name}</div>;
",
            "}
",
        );

        let found = TypeScriptParser.structural_candidates(source, "src/journey.tsx");
        let names: Vec<&str> = found.iter().map(|c| c.real_name.as_str()).collect();
        assert!(names.contains(&"Stage"), "the interface must be seen: {names:?}");
        assert!(names.contains(&"JourneyMap"), "and the component: {names:?}");

        assert!(
            TypeScriptParser.structural_counts(source).is_some(),
            "a file the parser can read must have a fingerprint, or §7.2 cannot check it"
        );
    }

    #[test]
    fn a_type_assertion_still_parses_as_typescript() {
        // The other half of the same decision. `<T>x` is a type assertion in
        // TypeScript and an unclosed JSX tag in TSX, so the TypeScript grammar
        // has to be tried first — trying TSX first would break every `.ts` file
        // that uses the older assertion syntax.
        let source = "export interface Stage { name: string }
const s = <Stage>value;
";
        assert!(
            TypeScriptParser.structural_counts(source).is_some(),
            "a type assertion is valid TypeScript and must not need the JSX grammar"
        );
    }

    #[test]
    fn a_function_declaration_is_an_entity() {
        // In a React codebase the components are functions, not classes. The
        // corpus generator only emitted classes and interfaces, so this went
        // unnoticed until the parser met a real project.
        let found = TypeScriptParser.structural_candidates(
            "export function submitOrder(id: string): void {}
",
            "src/orders.ts",
        );
        assert!(
            found.iter().any(|c| c.real_name == "submitOrder"),
            "an exported function is the user's name as much as a class is"
        );
    }

    #[test]
    fn an_ambient_declaration_is_an_entity() {
        // `.d.ts` files are made of these, and P3-4 named them as untested.
        let found = TypeScriptParser.structural_candidates(
            "declare function trackEvent(name: string): void;
",
            "src/globals.d.ts",
        );
        assert!(
            found.iter().any(|c| c.real_name == "trackEvent"),
            "an ambient function signature declares a name too"
        );
    }

    #[test]
    fn structural_counts_track_symbol_shape() {
        let counts = TypeScriptParser.structural_counts(SOURCE).expect("parses");
        assert_eq!(counts.get("interfaces"), 1);
        assert_eq!(counts.get("classes"), 1);
        assert_eq!(counts.get("imports"), 2);
        assert!(counts.get("identifiers") > 0);
    }

    #[test]
    fn a_dropped_declaration_is_caught() {
        let before = TypeScriptParser.structural_counts(SOURCE).unwrap();
        let after = TypeScriptParser
            .structural_counts(&SOURCE.replace("  planTier: PlanTier;\n", ""))
            .unwrap();
        assert!(!before.differences(&after).is_empty());
    }

    #[test]
    fn a_shadowed_binding_is_not_mistaken_for_a_declaration() {
        // The case the M0 spike proved Tree-sitter handles: three bindings of
        // one name at three scopes. None of them is a declared *type*, so none
        // should be claimed.
        let source = concat!(
            "const subscription = \"module\";\n",
            "export function render(subscription: string): string {\n",
            "  { const subscription = inner(); return subscription; }\n",
            "}\n"
        );
        let found = candidates(source);
        assert!(
            named(&found, "subscription").is_empty(),
            "local bindings are not entities: {:?}",
            named(&found, "subscription")
        );
    }
}
