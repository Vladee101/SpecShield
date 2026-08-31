//! M0 spike — can Tree-sitter plus heuristic scoping rename TypeScript correctly?
//!
//! Decides Implementation Plan D-4 and the SDD §7.2 guarantee. Tree-sitter has
//! no name resolution: it produces a concrete syntax tree with no symbol
//! binding, no scope analysis, no types. This spike builds the cheapest
//! plausible substitute — a lexical scope stack plus a module-level
//! import/export graph — and measures where it holds and where it breaks.
//!
//! Run: `cargo run -p spike-ts-rename -- corpus/ts-service/input corpus/adversarial/input`
//!
//! This is spike code. It is deliberately not the production implementation:
//! it exists to produce a verdict, and it reports its own failures rather than
//! papering over them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tree_sitter::{Node, Parser, Tree};

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeclKind {
    Class,
    Interface,
    Enum,
    Function,
    TypeAlias,
    Variable,
    Parameter,
    Import,
    EnumMember,
    Property,
}

impl DeclKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Interface => "interface",
            Self::Enum => "enum",
            Self::Function => "function",
            Self::TypeAlias => "type",
            Self::Variable => "variable",
            Self::Parameter => "parameter",
            Self::Import => "import",
            Self::EnumMember => "enum member",
            Self::Property => "property",
        }
    }
}

#[derive(Debug)]
struct Decl {
    name: String,
    kind: DeclKind,
    scope: usize,
    byte_start: usize,
    byte_end: usize,
    line: usize,
    exported: bool,
}

#[derive(Debug)]
struct Scope {
    parent: Option<usize>,
    /// name -> decl index. A later declaration of the same name in the same
    /// scope shadows the earlier one, which is what `shadowed.ts` probes.
    names: HashMap<String, usize>,
}

#[derive(Debug)]
struct Reference {
    name: String,
    byte_start: usize,
    byte_end: usize,
    line: usize,
    scope: usize,
    resolved: Option<usize>,
}

#[derive(Debug)]
struct Module {
    path: PathBuf,
    source: String,
    tree: Tree,
    scopes: Vec<Scope>,
    decls: Vec<Decl>,
    refs: Vec<Reference>,
    /// import specifier -> module source string, for the cross-file graph.
    imports: HashMap<String, String>,
    /// tree-sitter node id -> scope id, so pass 2 recovers the scope numbering
    /// pass 1 assigned.
    scope_cache: HashMap<usize, usize>,
}

// ---------------------------------------------------------------------------
// Scope construction
// ---------------------------------------------------------------------------

/// Node kinds that open a new lexical scope.
fn opens_scope(kind: &str) -> bool {
    matches!(
        kind,
        "program"
            | "statement_block"
            | "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "class_body"
            | "for_statement"
            | "for_in_statement"
            | "catch_clause"
    )
}

fn analyze(path: &Path, source: String, parser: &mut Parser) -> Result<Module> {
    let tree = parser
        .parse(&source, None)
        .with_context(|| format!("tree-sitter returned no tree for {}", path.display()))?;

    let mut module = Module {
        path: path.to_path_buf(),
        source,
        tree,
        scopes: vec![Scope {
            parent: None,
            names: HashMap::new(),
        }],
        decls: Vec::new(),
        refs: Vec::new(),
        imports: HashMap::new(),
        scope_cache: HashMap::new(),
    };

    // `Node` borrows its tree, and both passes need `&mut module`. A cloned
    // handle (tree-sitter trees are reference-counted) keeps the borrows apart.
    let walked = module.tree.clone();
    let root = walked.root_node();

    // Pass 1: declarations. Done before references so hoisting works — a
    // function used above its declaration still resolves.
    collect_decls(root, 0, &mut module);

    // Pass 2: references, resolved against the scope chain.
    collect_refs(root, 0, &mut module);
    resolve(&mut module);

    Ok(module)
}

fn line_of(source: &str, byte: usize) -> usize {
    source[..byte].matches('\n').count() + 1
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn is_exported(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "export_statement" {
            return true;
        }
        if parent.kind() == "program" {
            return false;
        }
        current = parent;
    }
    false
}

fn declare(module: &mut Module, scope: usize, name_node: Node<'_>, kind: DeclKind, decl_node: Node<'_>) {
    let name = text(name_node, &module.source).to_owned();
    let line = line_of(&module.source, name_node.start_byte());
    let index = module.decls.len();
    module.decls.push(Decl {
        name: name.clone(),
        kind,
        scope,
        byte_start: name_node.start_byte(),
        byte_end: name_node.end_byte(),
        line,
        exported: is_exported(decl_node),
    });
    module.scopes[scope].names.insert(name, index);
}

fn child_scope(module: &mut Module, parent: usize) -> usize {
    module.scopes.push(Scope {
        parent: Some(parent),
        names: HashMap::new(),
    });
    module.scopes.len() - 1
}

#[allow(clippy::too_many_lines)]
fn collect_decls(node: Node<'_>, scope: usize, module: &mut Module) {
    let inner = if opens_scope(node.kind()) && node.kind() != "program" {
        next_scope_for(module, scope, node)
    } else {
        scope
    };

    match node.kind() {
        "class_declaration" | "abstract_class_declaration" => {
            if let Some(name) = node.child_by_field_name("name") {
                declare(module, scope, name, DeclKind::Class, node);
            }
        }
        "interface_declaration" => {
            if let Some(name) = node.child_by_field_name("name") {
                declare(module, scope, name, DeclKind::Interface, node);
            }
        }
        "enum_declaration" => {
            if let Some(name) = node.child_by_field_name("name") {
                declare(module, scope, name, DeclKind::Enum, node);
            }
            // Enum members live in the enum's own namespace, reached only via
            // `Enum.Member`. Recorded so they are not counted as unresolved.
            if let Some(body) = node.child_by_field_name("body") {
                let mut cursor = body.walk();
                for member in body.named_children(&mut cursor) {
                    if let Some(name) = member.child_by_field_name("name") {
                        declare(module, inner, name, DeclKind::EnumMember, member);
                    } else if member.kind() == "property_identifier" {
                        declare(module, inner, member, DeclKind::EnumMember, member);
                    }
                }
            }
        }
        "function_declaration" | "generator_function_declaration" => {
            if let Some(name) = node.child_by_field_name("name") {
                // The function's own name belongs to the *enclosing* scope.
                declare(module, scope, name, DeclKind::Function, node);
            }
        }
        "interface_body" | "object_type" => {
            let mut cursor = node.walk();
            for member in node.named_children(&mut cursor) {
                if member.kind() == "property_signature"
                    && let Some(name) = member.child_by_field_name("name")
                {
                    declare(module, inner, name, DeclKind::Property, member);
                }
            }
        }
        "type_alias_declaration" => {
            if let Some(name) = node.child_by_field_name("name") {
                declare(module, scope, name, DeclKind::TypeAlias, node);
            }
        }
        "variable_declarator" => {
            if let Some(name) = node.child_by_field_name("name")
                && name.kind() == "identifier"
            {
                declare(module, scope, name, DeclKind::Variable, node);
            }
        }
        "required_parameter" | "optional_parameter" => {
            if let Some(pattern) = node.child_by_field_name("pattern")
                && pattern.kind() == "identifier"
            {
                declare(module, inner, pattern, DeclKind::Parameter, node);
            }
        }
        "import_statement" => {
            let source_text = node
                .child_by_field_name("source")
                .map(|s| text(s, &module.source).trim_matches(['"', '\'']).to_owned())
                .unwrap_or_default();
            let mut stack = vec![node];
            while let Some(current) = stack.pop() {
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    if child.kind() == "import_specifier" || child.kind() == "namespace_import" {
                        let bound = child
                            .child_by_field_name("alias")
                            .or_else(|| child.child_by_field_name("name"));
                        if let Some(name) = bound {
                            declare(module, scope, name, DeclKind::Import, node);
                            module
                                .imports
                                .insert(text(name, &module.source).to_owned(), source_text.clone());
                        }
                    } else {
                        stack.push(child);
                    }
                }
            }
            return; // do not descend again
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_decls(child, inner, module);
    }
}

/// Positions where an identifier is a binding site or a property name, not a
/// reference to resolve.
fn is_declaration_site(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let is_named_field = |field: &str| parent.child_by_field_name(field).is_some_and(|n| n.id() == node.id());

    match parent.kind() {
        "class_declaration"
        | "abstract_class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "function_declaration"
        | "generator_function_declaration"
        | "type_alias_declaration"
        | "variable_declarator" => is_named_field("name"),
        "required_parameter" | "optional_parameter" => is_named_field("pattern"),
        "import_specifier" | "namespace_import" => true,
        _ => false,
    }
}

fn collect_refs(node: Node<'_>, scope: usize, module: &mut Module) {
    let inner = if opens_scope(node.kind()) && node.kind() != "program" {
        // Scopes were allocated in order during pass 1; recompute the same way.
        next_scope_for(module, scope, node)
    } else {
        scope
    };

    if matches!(node.kind(), "identifier" | "type_identifier") && !is_declaration_site(node) {
        let name = text(node, &module.source).to_owned();
        module.refs.push(Reference {
            name,
            byte_start: node.start_byte(),
            byte_end: node.end_byte(),
            line: line_of(&module.source, node.start_byte()),
            scope: inner,
            resolved: None,
        });
    }

    // `obj.property` — the property side is not a lexically scoped name.
    if node.kind() == "member_expression" {
        if let Some(object) = node.child_by_field_name("object") {
            collect_refs(object, inner, module);
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_refs(child, inner, module);
    }
}

/// Scope ids are assigned by pass 1 in traversal order. Pass 2 walks the same
/// tree in the same order, so it can recover the mapping by counting.
///
/// This is exactly the kind of fragility that makes the production
/// implementation want a real resolver — noted in the report.
fn next_scope_for(module: &mut Module, parent: usize, node: Node<'_>) -> usize {
    let key = node.id();
    if let Some(&existing) = module.scope_cache.get(&key) {
        return existing;
    }
    let created = child_scope(module, parent);
    module.scope_cache.insert(key, created);
    created
}

fn resolve(module: &mut Module) {
    let mut resolved_indices = Vec::with_capacity(module.refs.len());
    for reference in &module.refs {
        let mut scope = Some(reference.scope);
        let mut found = None;
        while let Some(current) = scope {
            if let Some(&decl) = module.scopes[current].names.get(&reference.name) {
                found = Some(decl);
                break;
            }
            scope = module.scopes[current].parent;
        }
        resolved_indices.push(found);
    }
    for (reference, decl) in module.refs.iter_mut().zip(resolved_indices) {
        reference.resolved = decl;
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// Globals a real implementation would load from lib.dom.d.ts and friends.
/// Unresolved references to these are expected, not failures.
const AMBIENT: &[&str] = &[
    "console",
    "crypto",
    "Promise",
    "Date",
    "Error",
    "String",
    "Number",
    "Boolean",
    "Object",
    "Array",
    "Math",
    "JSON",
    "Map",
    "Set",
    "undefined",
    "null",
    "window",
    "document",
    "process",
    "require",
    "module",
    "globalThis",
    "Symbol",
    "BigInt",
    "RegExp",
    "void",
];

fn main() -> Result<()> {
    let roots: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if roots.is_empty() {
        eprintln!("usage: spike-ts-rename <dir> [<dir>...]");
        std::process::exit(2);
    }

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())?;

    let mut files = Vec::new();
    for root in &roots {
        collect_ts_files(root, &mut files);
    }
    files.sort();

    let mut modules = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path)?;
        modules.push(analyze(path, source, &mut parser)?);
    }

    report(&modules, &mut parser);
    Ok(())
}

fn collect_ts_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_ts_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "ts" || e == "tsx") {
            out.push(path);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn report(modules: &[Module], parser: &mut Parser) {
    println!("# M0 spike — Tree-sitter TypeScript rename\n");
    println!("Files analysed: {}\n", modules.len());

    let mut total_refs = 0usize;
    let mut resolved = 0usize;
    let mut ambient = 0usize;
    let mut cross_file_candidates = 0usize;
    let mut genuinely_unresolved: Vec<(String, String, usize)> = Vec::new();

    let exports: HashMap<String, HashSet<String>> = modules
        .iter()
        .map(|m| {
            let names = m.decls.iter().filter(|d| d.exported).map(|d| d.name.clone()).collect();
            (m.path.to_string_lossy().replace('\\', "/"), names)
        })
        .collect();

    println!("## Per-file resolution\n");
    println!("| File | Decls | Refs | Resolved | Ambient | Unresolved |");
    println!("|---|---:|---:|---:|---:|---:|");

    for module in modules {
        let mut file_resolved = 0;
        let mut file_ambient = 0;
        let mut file_unresolved = 0;

        for reference in &module.refs {
            total_refs += 1;
            if reference.resolved.is_some() {
                resolved += 1;
                file_resolved += 1;
                if module.imports.contains_key(&reference.name) {
                    cross_file_candidates += 1;
                }
            } else if AMBIENT.contains(&reference.name.as_str()) {
                ambient += 1;
                file_ambient += 1;
            } else {
                file_unresolved += 1;
                genuinely_unresolved.push((
                    module.path.to_string_lossy().replace('\\', "/"),
                    reference.name.clone(),
                    reference.line,
                ));
            }
        }

        println!(
            "| `{}` | {} | {} | {} | {} | {} |",
            short(&module.path),
            module.decls.len(),
            module.refs.len(),
            file_resolved,
            file_ambient,
            file_unresolved
        );
    }

    let denominator = total_refs - ambient;
    #[allow(clippy::cast_precision_loss)]
    let rate = if denominator == 0 {
        1.0
    } else {
        resolved as f64 / denominator as f64
    };

    println!(
        "\n**Resolution rate: {:.1}%** ({resolved}/{denominator} non-ambient references)\n",
        rate * 100.0
    );
    println!("Cross-file references resolved through the import graph: {cross_file_candidates}\n");

    if !genuinely_unresolved.is_empty() {
        println!("## Unresolved references\n");
        println!("| File | Name | Line |");
        println!("|---|---|---:|");
        for (file, name, line) in &genuinely_unresolved {
            println!("| `{}` | `{name}` | {line} |", file.rsplit('/').next().unwrap_or(file));
        }
        println!();
    }

    // ------------------------------------------------------------------
    // The decisive test: shadowing.
    // ------------------------------------------------------------------
    println!("## Shadowing (the case Tree-sitter cannot decide alone)\n");
    let mut shadow_findings = Vec::new();
    for module in modules {
        let mut by_name: BTreeMap<&str, Vec<&Decl>> = BTreeMap::new();
        for decl in &module.decls {
            by_name.entry(decl.name.as_str()).or_default().push(decl);
        }
        for (name, decls) in by_name {
            if decls.len() > 1 {
                let scopes: HashSet<usize> = decls.iter().map(|d| d.scope).collect();
                shadow_findings.push((
                    short(&module.path),
                    name.to_owned(),
                    decls.len(),
                    scopes.len(),
                    decls
                        .iter()
                        .map(|d| format!("{} L{}", d.kind.label(), d.line))
                        .collect::<Vec<_>>(),
                ));
            }
        }
    }
    if shadow_findings.is_empty() {
        println!("No shadowed bindings in the analysed set.\n");
    } else {
        println!("| File | Name | Bindings | Distinct scopes | Sites |");
        println!("|---|---|---:|---:|---|");
        for (file, name, count, scopes, sites) in &shadow_findings {
            println!("| `{file}` | `{name}` | {count} | {scopes} | {} |", sites.join("; "));
        }
        println!();
    }

    // ------------------------------------------------------------------
    // Rename + the SDD §7.2 verification pass.
    // ------------------------------------------------------------------
    println!("## Rename and verify (SDD §7.2 guarantee)\n");
    println!("| File | Target | Sites | Twin parses | Counts match |");
    println!("|---|---|---:|---|---|");

    let targets = [
        "CustomerSubscription",
        "SubscriptionService",
        "CreateSubscriptionDto",
        "PlanTier",
        "Status",
        "subscription",
    ];

    let mut rename_failures = 0;
    for module in modules {
        for target in targets {
            let Some(decl_index) = module
                .decls
                .iter()
                .position(|d| d.name == target && d.kind != DeclKind::EnumMember)
            else {
                continue;
            };

            let mut edits: Vec<(usize, usize)> = module
                .refs
                .iter()
                .filter(|r| r.resolved == Some(decl_index))
                .map(|r| (r.byte_start, r.byte_end))
                .collect();
            let decl = &module.decls[decl_index];
            edits.push((decl.byte_start, decl.byte_end));
            edits.sort_unstable();
            edits.dedup();

            let replacement = format!("SERVICE_{}", &"H7K2Q3"[..6]);
            let mut twin = module.source.clone();
            for (start, end) in edits.iter().rev() {
                twin.replace_range(*start..*end, &replacement);
            }

            let twin_tree = parser.parse(&twin, None);
            let twin_parses = twin_tree.as_ref().is_some_and(|t| !t.root_node().has_error());
            let original_ok = !module.tree.root_node().has_error();
            let counts_match = twin_tree.as_ref().is_some_and(|t| {
                count_kind(t.root_node(), "identifier") + count_kind(t.root_node(), "type_identifier")
                    == count_kind(module.tree.root_node(), "identifier")
                        + count_kind(module.tree.root_node(), "type_identifier")
            });

            if !twin_parses || !counts_match {
                rename_failures += 1;
            }

            println!(
                "| `{}` | `{target}` | {} | {} | {} |",
                short(&module.path),
                edits.len(),
                if twin_parses {
                    "yes"
                } else if original_ok {
                    "**NO**"
                } else {
                    "n/a (original has errors)"
                },
                if counts_match { "yes" } else { "**NO**" }
            );
        }
    }

    // ------------------------------------------------------------------
    // The blind spot: property references.
    // ------------------------------------------------------------------
    println!("## Property references — what lexical scoping cannot see\n");

    let known_properties: HashSet<&str> = modules
        .iter()
        .flat_map(|m| m.decls.iter())
        .filter(|d| d.kind == DeclKind::Property)
        .map(|d| d.name.as_str())
        .collect();

    let mut property_sites: Vec<(String, String, usize)> = Vec::new();
    let mut property_total = 0usize;
    for module in modules {
        let mut stack = vec![module.tree.root_node()];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "property_identifier" | "shorthand_property_identifier") {
                property_total += 1;
                let name = text(node, &module.source);
                if known_properties.contains(name) && !is_declaration_site(node) {
                    property_sites.push((
                        short(&module.path),
                        name.to_owned(),
                        line_of(&module.source, node.start_byte()),
                    ));
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }

    println!("Interface and type members declared: {}", known_properties.len());
    println!("Identifiers in property position: {property_total}");
    println!(
        "Of those, matching a declared member by name: **{}**\n",
        property_sites.len()
    );
    println!("None of these can be resolved by lexical scoping. Deciding whether");
    println!("`x.customerId` refers to `CustomerSubscription.customerId` requires");
    println!("knowing the type of `x`, which Tree-sitter does not compute.\n");

    if !property_sites.is_empty() {
        println!("| File | Property | Line |");
        println!("|---|---|---:|");
        for (file, name, line) in &property_sites {
            println!("| `{file}` | `{name}` | {line} |");
        }
        println!();
    }

    println!("\n## Verdict inputs\n");
    println!("- resolution rate: {:.1}%", rate * 100.0);
    println!("- unresolved (non-ambient): {}", genuinely_unresolved.len());
    println!("- shadowed bindings found: {}", shadow_findings.len());
    println!("- rename verification failures: {rename_failures}");
    println!(
        "- property references needing type information: {}",
        property_sites.len()
    );
    println!(
        "- modules with parse errors: {}",
        modules.iter().filter(|m| m.tree.root_node().has_error()).count()
    );
    println!(
        "- exported names discovered: {}",
        exports.values().map(HashSet::len).sum::<usize>()
    );
}

fn count_kind(node: Node<'_>, kind: &str) -> usize {
    let mut total = usize::from(node.kind() == kind);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        total += count_kind(child, kind);
    }
    total
}

fn short(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    s.rsplit("input/").next().unwrap_or(&s).to_owned()
}
