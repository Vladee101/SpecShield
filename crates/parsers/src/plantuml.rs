//! `PlantUML` — PRD FR-2.
//!
//! # Why a diagram is worth claiming
//!
//! A sequence diagram is the densest identity per byte in a repository. Ten
//! lines of `participant "Stripe" as payments`, `actor "Jane Okafor"`, and
//! `node "api.vantor-freight.com"` name the company, the people, the vendors
//! and the hosts, with almost no prose around them to dilute it.
//!
//! Without a parser a `.puml` file is not claimed at all: it falls past every
//! entry in the registry, `for_document` returns `None`, and the file reaches
//! the twin having been read with no structural knowledge and checked against
//! no fingerprint.
//!
//! # Why there is no AST here
//!
//! No `PlantUML` grammar is published for Rust, and this does not need one.
//! `PlantUML` is a line-oriented DSL: a declaration is a keyword, a name, an
//! optional `as` alias and an optional `{ … }` body, all on one line. That is
//! readable with a handful of anchored patterns, and reading it that way keeps
//! byte offsets exact — the property the whole pipeline rests on.
//!
//! What the parser buys over falling through to [`TextParser`]:
//!
//! - **Declarations get their real type and scope.** `class CustomerSubscription`
//!   is a DTO in this file, not a proper-noun-shaped guess.
//! - **The display name is separated from the alias.** In
//!   `participant "Stripe API" as payments`, the quoted half is what a reader
//!   sees and what leaks; `payments` is the diagram's own shorthand.
//! - **A fingerprint.** Aliasing must not add or remove a diagram block, a
//!   declaration, or an arrow, and must never leave a brace unclosed — all of
//!   which a replacement containing a brace or a newline would do.
//!
//! [`TextParser`]: crate::text::TextParser

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use specshield_core::detect::Detector;
use specshield_core::edit::Edit;
use specshield_core::model::{EntityType, OccurrenceKind};
use specshield_core::parser::{AliasMap, ArtifactParser, Candidate, Document, ParseError, Parsed, StructuralCounts};

use crate::text::plan_from_candidates;

const EXTENSIONS: &[&str] = &["puml", "plantuml", "pu", "iuml", "wsd"];

/// Declaration keywords, and what the thing they declare is.
///
/// Every one of these is *structure* under PRD §7 — a diagram describes what
/// was built — so none is aliased by default. What they do is give a name its
/// type and its scope, so `specshield term` can promote it and so the prose
/// scan does not classify it by guessing at its capitals.
///
/// The identity in a diagram comes from the names themselves: a participant
/// called `Stripe`, a node called `api.vantor-freight.com`, an actor called
/// `Jane Okafor`. Those are found by the detector's own rules, not by the
/// keyword in front of them.
///
/// Longest first, because the alternation is tried in order and `abstract
/// class` must not lose to `class`.
const DECLARATIONS: &[(&str, EntityType)] = &[
    // ---- Class diagrams.
    ("abstract class", EntityType::Dto),
    ("annotation", EntityType::Interface),
    ("participant", EntityType::Service),
    ("collections", EntityType::Service),
    ("rectangle", EntityType::Service),
    ("component", EntityType::Service),
    ("interface", EntityType::Interface),
    ("namespace", EntityType::PathSegment),
    ("protocol", EntityType::Interface),
    ("boundary", EntityType::Service),
    ("database", EntityType::Table),
    ("abstract", EntityType::Dto),
    ("artifact", EntityType::Service),
    ("usecase", EntityType::Endpoint),
    ("storage", EntityType::Service),
    ("control", EntityType::Service),
    ("package", EntityType::PathSegment),
    ("folder", EntityType::PathSegment),
    ("object", EntityType::Dto),
    ("struct", EntityType::Dto),
    ("entity", EntityType::Dto),
    ("actor", EntityType::Service),
    ("queue", EntityType::Event),
    ("frame", EntityType::Service),
    ("cloud", EntityType::Service),
    ("agent", EntityType::Service),
    ("class", EntityType::Dto),
    ("card", EntityType::Service),
    ("node", EntityType::Service),
    ("enum", EntityType::Enum),
];

/// One declaration line: `<keyword> <name or "quoted name"> [as <alias>]`.
///
/// The keyword alternation is built from [`DECLARATIONS`] so the two cannot
/// drift. Group 1 is the keyword, 2 the quoted display name, 3 the bare name,
/// 4 a quoted `as` alias, 5 a bare one.
static DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    let keywords = DECLARATIONS
        .iter()
        .map(|(word, _)| regex::escape(word).replace(' ', "[ \\t]+"))
        .collect::<Vec<_>>()
        .join("|");
    let name = "\"([^\"\\n]+)\"|([A-Za-z_][A-Za-z0-9_.\\-]*)";
    let alias = "\"([^\"\\n]+)\"|([A-Za-z_][A-Za-z0-9_.\\-]*)";
    Regex::new(&format!(
        "(?m)^[ \\t]*({keywords})[ \\t]+(?:{name})(?:[ \\t]+as[ \\t]+(?:{alias}))?"
    ))
    .expect("valid regex")
});

/// A member inside a `{ … }` body: `+customerId: UUID`, `-chargeInvoice()`.
///
/// The visibility marker is optional because plenty of diagrams omit it, and
/// the trailing `(` is what separates a method from a field.
static MEMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*[+\-#~]?[ \t]*(?:\{[a-z]+\})?[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*(\()?")
        .expect("valid regex")
});

/// An arrow between two things, in `PlantUML`'s many spellings: `->`, `-->`,
/// `..>`, `<|--`, `*--`, `o--`, `-[#red]->`.
static ARROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:<\|?|\*|o)?(?:-{1,2}|\.{1,2})(?:\[[^\]\n]*\])?(?:-{0,2}|\.{0,2})(?:\|?>|\*|o)?")
        .expect("valid regex")
});

/// Lines that are the renderer being configured rather than the user's model.
///
/// Skipped entirely by [`ArtifactParser::prose_regions`]. A `skinparam` value
/// is a colour, a `!include` is a build path, and `hide empty members` is a
/// rendering switch; aliasing any of them breaks the diagram and hides nothing.
const RENDERER_DIRECTIVES: &[&str] = &[
    "!",
    "skinparam",
    "skin ",
    "hide ",
    "show ",
    "scale ",
    "autonumber",
    "allowmixing",
    "allow_mixing",
    "mainframe",
    "top to bottom",
    "left to right",
];

/// Directives whose *argument* is the user's own text.
///
/// The keyword is skipped and the rest of the line is prose. `@startuml Vantor
/// billing` names the company in the first line of the file, and `title`,
/// `caption`, `header` and `footer` are all things a reader sees. Excluding
/// these lines wholesale — which is what the first version of this parser did
/// — left the organization sitting in line 1 of the twin, past a gate that had
/// nothing to say about it.
const TITLED_DIRECTIVES: &[&str] = &["@start", "@end", "title", "caption", "header", "footer", "legend"];

#[derive(Debug, Default, Clone, Copy)]
pub struct PlantUmlParser;

/// What a parse found, kept behind [`Parsed::tree`].
#[derive(Debug, Default)]
pub struct Diagram {
    /// `(byte_offset, keyword, name)` for each declaration, in document order.
    pub declarations: Vec<(usize, &'static str, String)>,
}

impl ArtifactParser for PlantUmlParser {
    fn name(&self) -> &'static str {
        "plantuml"
    }

    /// By extension, or by the `@startuml` that opens every diagram.
    ///
    /// Content as well as path, for the same reason OpenAPI needs it: diagrams
    /// are routinely committed as `.txt`, and one that falls through to the
    /// text parser goes out with no fingerprint behind it.
    fn can_handle(&self, path: &Path, content: &str) -> bool {
        let by_extension = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXTENSIONS.contains(&e.to_lowercase().as_str()));
        by_extension || content.trim_start().starts_with("@start")
    }

    fn parse<'a>(&self, doc: &'a Document) -> Result<Parsed<'a>, ParseError> {
        Ok(Parsed {
            document: doc,
            tree: Box::new(diagram(&doc.content)),
        })
    }

    fn extract(&self, parsed: &Parsed<'_>) -> Vec<Candidate> {
        let scope = crate::text::scope_of(parsed);
        let mut found = self.structural_candidates(&parsed.document.content, &scope);
        found.extend(Detector::new().scan_text(&parsed.document.content, &scope, OccurrenceKind::Reference));
        found
    }

    fn plan_edits(&self, parsed: &Parsed<'_>, aliases: &AliasMap) -> Vec<Edit> {
        plan_from_candidates(&self.extract(parsed), aliases)
    }

    fn structural_candidates(&self, source: &str, scope: &str) -> Vec<Candidate> {
        let mut found = Vec::new();

        for caps in DECLARATION.captures_iter(source) {
            let keyword = normalize(caps.get(1).map_or("", |m| m.as_str()));
            let Some((_, entity_type)) = DECLARATIONS.iter().find(|(word, _)| *word == keyword) else {
                continue;
            };
            // The display name — quoted or bare — is what a reader sees and
            // what leaks. The `as` alias is the diagram's own shorthand, and it
            // is claimed too: renaming one without the other breaks every arrow
            // that refers to it.
            for group in [2, 3, 4, 5] {
                let Some(m) = caps.get(group) else { continue };
                // `actor "Jane Okafor"` names a person; `actor Ops` names a
                // role. See [`PERSON_SHAPED`].
                let entity_type = if keyword == "actor" && PERSON_SHAPED.is_match(m.as_str()) {
                    EntityType::Person
                } else {
                    *entity_type
                };
                found.push(Candidate {
                    real_name: m.as_str().to_owned(),
                    entity_type,
                    scope_path: format!("{scope}::{}", m.as_str()),
                    byte_start: m.start(),
                    byte_end: m.end(),
                    kind: OccurrenceKind::Declaration,
                    confidence: 1.0,
                });
            }
        }

        for (start, end, owner) in bodies(source) {
            for caps in MEMBER.captures_iter(&source[start..end]) {
                let Some(m) = caps.get(1) else { continue };
                let entity_type = if caps.get(2).is_some() {
                    EntityType::Endpoint
                } else {
                    EntityType::Column
                };
                found.push(Candidate {
                    real_name: m.as_str().to_owned(),
                    entity_type,
                    scope_path: format!("{scope}::{owner}.{}", m.as_str()),
                    byte_start: start + m.start(),
                    byte_end: start + m.end(),
                    kind: OccurrenceKind::Declaration,
                    confidence: 1.0,
                });
            }
        }

        found.sort_by_key(|c| c.byte_start);
        found.dedup_by_key(|c| (c.byte_start, c.byte_end));
        found
    }

    /// Everything except the lines that configure the renderer.
    ///
    /// A diagram is mostly names and labels, so the eligible region is nearly
    /// the whole file.
    fn prose_regions(&self, source: &str) -> Option<Vec<(usize, usize)>> {
        let mut regions = Vec::new();
        let mut offset = 0;
        for line in source.split_inclusive('\n') {
            let indent = line.len() - line.trim_start().len();
            let lower = line.trim_start().to_lowercase();

            if RENDERER_DIRECTIVES.iter().any(|p| lower.starts_with(p)) {
                offset += line.len();
                continue;
            }
            let skip = if TITLED_DIRECTIVES.iter().any(|p| lower.starts_with(p)) {
                // Past the keyword and no further: the argument is prose.
                indent + lower.find(char::is_whitespace).unwrap_or(lower.len())
            } else {
                0
            };
            if skip < line.len() {
                regions.push((offset + skip, offset + line.len()));
            }
            offset += line.len();
        }
        Some(regions)
    }

    /// A diagram's structure is its blocks, its declarations, and its arrows.
    ///
    /// Each is reachable by a plausible bug. An alias containing a newline
    /// splits a declaration in two and loses one; one containing a brace opens
    /// a body that never closes, and `PlantUML` renders nothing from there on;
    /// one containing `-` or `>` invents an arrow between two participants that
    /// were never connected — a diagram that is *wrong* rather than broken,
    /// which is the worst outcome available here.
    fn fingerprints(&self) -> bool {
        true
    }

    fn structural_counts(&self, source: &str) -> Option<StructuralCounts> {
        let starts = count_prefix(source, "@start");
        // A file with no diagram in it is not one this parser can vouch for.
        // Returning counts anyway would report `Verification::Passed` for
        // something never read — the failure mode SDD §7.2 exists to stop.
        if starts == 0 {
            return None;
        }

        let mut counts = StructuralCounts::new()
            .with("diagrams", starts)
            .with("diagram_ends", count_prefix(source, "@end"))
            .with("declarations", DECLARATION.find_iter(source).count())
            .with("arrows", arrows(source))
            .with("open_braces", source.matches('{').count())
            .with("close_braces", source.matches('}').count())
            .with("notes", count_prefix(source, "note "))
            .with("lines", source.lines().count());

        for (keyword, _) in DECLARATIONS {
            counts = counts.with(
                keyword,
                DECLARATION
                    .captures_iter(source)
                    .filter(|c| normalize(c.get(1).map_or("", |m| m.as_str())) == *keyword)
                    .count(),
            );
        }
        Some(counts)
    }
}

/// A name shaped like a person's — two or three capitalised words.
///
/// The `actor` keyword is a person marker in the same sense as a `Contact:`
/// line, and in the same sense it is not enough on its own. Most actors are
/// roles: `actor Ops`, `actor Customer`, `actor Admin`. Typing all of them as
/// `Person` aliased `Ops` in its declaration while every arrow in the diagram
/// went on referring to it by name, which is a diagram that no longer renders
/// — and it hid nothing, because a role is not a person.
///
/// So the keyword narrows *where* to look and this narrows *what counts*, which
/// is the same division of labour `PERSON_LINE` makes in the detector.
static PERSON_SHAPED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][a-z]+(?:[ 	]+[A-Z][a-z]+){1,2}$").expect("valid regex"));

/// Collapse the whitespace inside a two-word keyword, so `abstract   class` and
/// `abstract class` are the same entry in [`DECLARATIONS`].
fn normalize(keyword: &str) -> String {
    keyword.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Arrows, counted only on lines that can hold one.
///
/// Declaration lines and `{ … }` bodies are excluded, because a member written
/// `+rate: -1` would otherwise count as an arrow and make the fingerprint
/// depend on field values rather than on shape.
fn arrows(source: &str) -> usize {
    let bodies = bodies(source);
    let mut offset = 0;
    let mut total = 0;
    for line in source.split_inclusive('\n') {
        let inside = bodies.iter().any(|(s, e, _)| offset >= *s && offset < *e);
        if !inside && DECLARATION.find(line).is_none() {
            total += ARROW.find_iter(line).filter(|m| m.as_str().len() >= 2).count();
        }
        offset += line.len();
    }
    total
}

fn count_prefix(source: &str, prefix: &str) -> usize {
    source
        .lines()
        .filter(|l| l.trim_start().to_lowercase().starts_with(prefix))
        .count()
}

/// Byte ranges of each `{ … }` body, with the name of the thing that owns it.
///
/// Brace-counted rather than matched with a pattern: a nested brace inside a
/// note or a stereotype would close the body early and attribute every member
/// after it to nothing.
fn bodies(source: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    for caps in DECLARATION.captures_iter(source) {
        let whole = caps.get(0).expect("group 0 always matches");
        let owner = caps
            .get(2)
            .or_else(|| caps.get(3))
            .map_or_else(String::new, |m| m.as_str().to_owned());
        let rest = &source[whole.end()..];
        let Some(open) = rest.find('{') else { continue };
        // Only a brace on the declaration's own line opens its body.
        if rest[..open].contains('\n') {
            continue;
        }
        let start = whole.end() + open + 1;
        let mut depth = 1usize;
        for (i, ch) in source[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if i > 0 {
                            out.push((start, start + i, owner));
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn diagram(source: &str) -> Diagram {
    let declarations = DECLARATION
        .captures_iter(source)
        .filter_map(|caps| {
            let keyword = normalize(caps.get(1)?.as_str());
            let (word, _) = DECLARATIONS.iter().find(|(w, _)| *w == keyword)?;
            let name = caps.get(2).or_else(|| caps.get(3))?;
            Some((name.start(), *word, name.as_str().to_owned()))
        })
        .collect();
    Diagram { declarations }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIAGRAM: &str = "@startuml Vantor billing
skinparam backgroundColor #FEFEFE
!theme plain

actor \"Jane Okafor\" as Ops
participant BillingService
participant \"Stripe\" as payments
database customer_subscription
node \"api.vantor-freight.com\" as edge

Ops -> BillingService: chargeInvoice()
BillingService -> payments: capture()
payments --> BillingService: declined

class CustomerSubscription {
  +customerId: UUID
  +chargeInvoice(): void
}

CustomerSubscription --> PaymentGateway
@enduml
";

    fn named(source: &str, name: &str) -> Option<Candidate> {
        PlantUmlParser
            .structural_candidates(source, "d.puml")
            .into_iter()
            .find(|c| c.real_name == name)
    }

    #[test]
    fn claims_diagrams_by_extension_and_by_content() {
        let p = PlantUmlParser;
        assert!(p.can_handle(Path::new("flow.puml"), ""));
        assert!(p.can_handle(Path::new("FLOW.PlantUML"), ""));
        // Committed as `.txt`, which happens constantly. Falling through to the
        // text parser would mean no fingerprint and no structural candidates.
        assert!(p.can_handle(
            Path::new("flow.txt"),
            "@startuml
class A
@enduml"
        ));
        assert!(!p.can_handle(Path::new("notes.txt"), "just prose"));
    }

    #[test]
    fn a_declaration_carries_its_type_and_its_own_scope() {
        assert_eq!(
            named(DIAGRAM, "CustomerSubscription").unwrap().entity_type,
            EntityType::Dto
        );
        assert_eq!(
            named(DIAGRAM, "BillingService").unwrap().entity_type,
            EntityType::Service
        );
        assert_eq!(
            named(DIAGRAM, "customer_subscription").unwrap().entity_type,
            EntityType::Table
        );
        assert_eq!(
            named(DIAGRAM, "CustomerSubscription").unwrap().scope_path,
            "d.puml::CustomerSubscription"
        );
    }

    #[test]
    fn the_display_name_and_the_alias_are_both_claimed() {
        // `participant \"Stripe\" as payments` is two names for one thing. The
        // quoted half is what leaks; the alias is what every arrow refers to,
        // and leaving it unclaimed is how a rename breaks a diagram.
        assert!(named(DIAGRAM, "Stripe").is_some());
        assert!(named(DIAGRAM, "payments").is_some());
    }

    #[test]
    fn members_are_fields_or_methods_scoped_to_their_owner() {
        let field = named(DIAGRAM, "customerId").expect("a field");
        assert_eq!(field.entity_type, EntityType::Column);
        assert_eq!(field.scope_path, "d.puml::CustomerSubscription.customerId");

        // The trailing parenthesis is the only thing that separates the two.
        let method = named(DIAGRAM, "chargeInvoice").expect("a method");
        assert_eq!(method.entity_type, EntityType::Endpoint);
    }

    #[test]
    fn an_actor_is_a_role_unless_the_name_is_a_person_s() {
        // Typing every actor as `Person` aliased `Ops` in its declaration while
        // every arrow went on saying `Ops`, which is a diagram that no longer
        // renders — and it hid nothing, because a role is not a person.
        assert_eq!(named(DIAGRAM, "Jane Okafor").unwrap().entity_type, EntityType::Person);
        assert_eq!(named(DIAGRAM, "Ops").unwrap().entity_type, EntityType::Service);
    }

    #[test]
    fn a_title_is_the_user_s_text_and_a_skinparam_is_not() {
        let regions = PlantUmlParser.prose_regions(DIAGRAM).expect("regions");
        let covered = |needle: &str| {
            let at = DIAGRAM.find(needle).expect(needle);
            regions.iter().any(|(s, e)| at >= *s && at + needle.len() <= *e)
        };
        // `@startuml Vantor billing` names the company in line 1. Skipping the
        // whole line left it in the twin.
        assert!(covered("Vantor billing"), "a diagram title is prose");
        assert!(
            !covered("backgroundColor"),
            "a skinparam is the renderer, not the model"
        );
        assert!(!covered("theme plain"), "a preprocessor line is a build path");
        assert!(covered("Jane Okafor"));
    }

    #[test]
    fn the_fingerprint_counts_what_a_bad_alias_would_break() {
        let counts = PlantUmlParser.structural_counts(DIAGRAM).expect("a fingerprint");
        assert_eq!(counts.get("diagrams"), 1);
        assert_eq!(counts.get("diagram_ends"), 1);
        assert_eq!(counts.get("participant"), 2);
        assert_eq!(counts.get("class"), 1);
        assert_eq!(counts.get("open_braces"), counts.get("close_braces"));
        assert!(counts.get("arrows") >= 4, "{:?}", counts.get("arrows"));
    }

    #[test]
    fn a_replacement_that_invents_an_arrow_changes_the_fingerprint() {
        // The worst outcome available here: not a diagram that fails to render,
        // but one that renders and is wrong.
        let broken = DIAGRAM.replace("BillingService: chargeInvoice()", "BillingService -> edge");
        let before = PlantUmlParser.structural_counts(DIAGRAM).unwrap();
        let after = PlantUmlParser.structural_counts(&broken).unwrap();
        assert!(!before.differences(&after).is_empty());
    }

    #[test]
    fn a_file_with_no_diagram_in_it_has_no_fingerprint() {
        // `None` rather than an empty set of counts. Counting nothing and
        // comparing it against nothing reports `Verification::Passed` for a
        // file that was never read — SDD §7.2.
        assert!(
            PlantUmlParser
                .structural_counts(
                    "class A { }
"
                )
                .is_none()
        );
    }
}
