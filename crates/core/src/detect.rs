//! Identity Extractor — SDD §4.4.
//!
//! Three sources, in descending confidence:
//!
//! 1. **Dictionary** — terms the user has confirmed. Always detected, always
//!    exact. This is how prose organization names get found: `Vantor` is not
//!    recognisable as a company by any rule, but once named it is found
//!    everywhere, forever (PRD FR-10).
//! 2. **Rules** — structural patterns with high precision: `SCREAMING_SNAKE`
//!    environment variables, dotted hostnames, PascalCase compounds with a
//!    known category suffix.
//! 3. **Suggestions** — low-confidence candidates surfaced for review and never
//!    applied silently.
//!
//! Precision matters as much as recall (PRD §5). A detector that flags every
//! capitalized word is not "safe": it makes the twin unreadable and measurably
//! degrades the AI output generated from it, which is the whole point of the
//! exercise.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::{EntityType, OccurrenceKind};
use crate::parser::Candidate;

/// Framework, language, and vendor names that are never proprietary. Detecting
/// one counts as a false positive against the precision target.
///
/// Shipped as a default; the user's allowlist extends it (PRD FR-10).
pub const STOP_LIST: &[&str] = &[
    // Languages and runtimes
    "TypeScript",
    "JavaScript",
    "Rust",
    "Python",
    "Java",
    "Kotlin",
    "Node",
    "Deno",
    "Bun",
    // Frameworks and libraries
    "React",
    "Angular",
    "Vue",
    "Svelte",
    "Express",
    "Fastify",
    "NestJS",
    "Next",
    "Remix",
    "Django",
    "Rails",
    "Spring",
    "Jest",
    "Vitest",
    "Mocha",
    "Cypress",
    "Playwright",
    "Prisma",
    "TypeORM",
    "Sequelize",
    // Data stores
    "Postgres",
    "PostgreSQL",
    "MySQL",
    "SQLite",
    "MongoDB",
    "Redis",
    "Elasticsearch",
    "Kafka",
    "RabbitMQ",
    // Clouds and infrastructure
    "AWS",
    "Azure",
    "GCP",
    "Kubernetes",
    "Docker",
    "Terraform",
    "Nginx",
    "Linux",
    "Windows",
    "macOS",
    // Formats and protocols
    "OpenAPI",
    "JSON",
    "YAML",
    "XML",
    "HTML",
    "CSS",
    "HTTP",
    "HTTPS",
    "REST",
    "GraphQL",
    "gRPC",
    "OAuth",
    "JWT",
    "UUID",
    "SQL",
    "API",
    "SDK",
    "CLI",
    "URL",
    "URI",
    // Common types that are not entities
    "Promise",
    "Date",
    "Error",
    "String",
    "Number",
    "Boolean",
    "Object",
    "Array",
    "Map",
    "Set",
    "Record",
];

/// Suffixes that make a PascalCase compound recognisable as a specific kind of
/// software entity. This is what keeps rule-based detection precise: a bare
/// capitalized word is a suggestion, `SubscriptionService` is a detection.
const TYPED_SUFFIXES: &[(&str, EntityType)] = &[
    ("Service", EntityType::Service),
    ("Controller", EntityType::Service),
    ("Repository", EntityType::Interface),
    ("Repo", EntityType::Interface),
    ("Api", EntityType::Api),
    ("API", EntityType::Api),
    ("Client", EntityType::Api),
    ("Dto", EntityType::Dto),
    ("DTO", EntityType::Dto),
    ("Request", EntityType::Dto),
    ("Response", EntityType::Dto),
    ("Payload", EntityType::Dto),
    ("Entity", EntityType::Dto),
    ("Model", EntityType::Dto),
    ("Tier", EntityType::Enum),
    ("Status", EntityType::Enum),
    ("Kind", EntityType::Enum),
    ("Type", EntityType::Enum),
    ("Created", EntityType::Event),
    ("Updated", EntityType::Event),
    ("Deleted", EntityType::Event),
    ("Issued", EntityType::Event),
    ("Cancelled", EntityType::Event),
    ("Event", EntityType::Event),
];

static PASCAL_COMPOUND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+\b").expect("valid regex"));

static SCREAMING_SNAKE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b").expect("valid regex"));

static HOSTNAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*){2,}\b").expect("valid regex"));

static CAPITALIZED_PHRASE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})*\b").expect("valid regex"));

/// Words that begin sentences constantly and would otherwise dominate the
/// organization suggestions.
const SENTENCE_STARTERS: &[&str] = &[
    "The", "This", "That", "These", "Those", "There", "Then", "They", "Their", "When", "Where", "What", "Which",
    "While", "With", "Without", "Every", "Each", "Some", "Any", "All", "Both", "Either", "Neither", "For", "From",
    "Into", "Only", "Also", "But", "And", "Not", "Card", "Data", "Run", "External", "Multi", "Clients", "Version",
    "Status",
];

/// How the candidate was found. Drives whether it is applied automatically or
/// queued for review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// User-confirmed term. Applied.
    Dictionary,
    /// Structural rule. Applied.
    Rule,
    /// Heuristic. **Never applied without review** (PRD FR-10).
    Suggestion,
}

/// Detector configuration for one project.
#[derive(Debug, Default)]
pub struct Detector {
    /// Confirmed terms, with their type. The primary mechanism for prose
    /// entities that no rule can recognise.
    dictionary: Vec<(String, EntityType)>,
    /// Terms that must never be aliased, beyond [`STOP_LIST`].
    allowlist: HashSet<String>,
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a user-confirmed term.
    #[must_use]
    pub fn with_term(mut self, name: impl Into<String>, entity_type: EntityType) -> Self {
        self.dictionary.push((name.into(), entity_type));
        // Longest first, so `Meridian Freight` is matched before `Meridian`.
        self.dictionary.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
        self
    }

    #[must_use]
    pub fn with_allowed(mut self, term: impl Into<String>) -> Self {
        self.allowlist.insert(term.into());
        self
    }

    fn is_allowed(&self, term: &str) -> bool {
        self.allowlist.contains(term) || STOP_LIST.contains(&term)
    }

    /// Detect entities in plain prose or a comment body.
    ///
    /// `scope` is the identity scope for everything found here — `project` for
    /// Markdown, since prose has no module structure.
    pub fn scan_text(&self, text: &str, scope: &str, kind: OccurrenceKind) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = Vec::new();
        let mut claimed: Vec<(usize, usize)> = Vec::new();

        let push = |cand: Candidate, claimed: &mut Vec<(usize, usize)>, found: &mut Vec<Candidate>| {
            if claimed.iter().any(|(s, e)| cand.byte_start < *e && *s < cand.byte_end) {
                return;
            }
            claimed.push((cand.byte_start, cand.byte_end));
            found.push(cand);
        };

        // 0. Claim everything that is already output of this pipeline, so it
        //    cannot be detected as an entity and aliased a second time.
        //
        //    Without this, `Vantor` -> `ORG_625J2V` on the first pass, and the
        //    alias then matches the SCREAMING_SNAKE rule on the second, giving
        //    `ENV_2386BV`. Restore would return the intermediate alias instead
        //    of the real name — silent data loss. Found by the idempotence
        //    property test, not by anything we thought to write by hand.
        claimed.extend(protected_regions(text));

        // 1. Dictionary — highest confidence, claims spans first.
        for (term, entity_type) in &self.dictionary {
            for (start, end) in whole_token_spans(text, term) {
                push(
                    Candidate {
                        real_name: term.clone(),
                        entity_type: *entity_type,
                        scope_path: scope.to_owned(),
                        byte_start: start,
                        byte_end: end,
                        kind,
                        confidence: 1.0,
                    },
                    &mut claimed,
                    &mut found,
                );
            }
        }

        // 2. Rules.
        for m in SCREAMING_SNAKE.find_iter(text) {
            if self.is_allowed(m.as_str()) {
                continue;
            }
            push(
                Self::candidate(m.as_str(), EntityType::EnvVar, scope, m.start(), m.end(), kind, 0.9),
                &mut claimed,
                &mut found,
            );
        }

        for m in HOSTNAME.find_iter(text) {
            push(
                Self::candidate(m.as_str(), EntityType::Host, scope, m.start(), m.end(), kind, 0.9),
                &mut claimed,
                &mut found,
            );
        }

        for m in PASCAL_COMPOUND.find_iter(text) {
            let word = m.as_str();
            if self.is_allowed(word) {
                continue;
            }
            let Some(entity_type) = classify_pascal(word) else {
                continue;
            };
            push(
                Self::candidate(word, entity_type, scope, m.start(), m.end(), kind, 0.85),
                &mut claimed,
                &mut found,
            );
        }

        // 3. Suggestions — proper-noun-shaped phrases. Never auto-applied.
        for m in CAPITALIZED_PHRASE.find_iter(text) {
            let phrase = m.as_str();
            if self.is_allowed(phrase) || is_sentence_noise(phrase, text, m.start()) {
                continue;
            }
            push(
                Self::candidate(phrase, EntityType::Organization, scope, m.start(), m.end(), kind, 0.35),
                &mut claimed,
                &mut found,
            );
        }

        // 4. Prose variants of everything found so far.
        //
        // A heading reading "## Plan tiers" is the entity `PlanTier` written
        // out in prose, and it leaks the name just as surely. The verification
        // gate already expands real names into case variants (SDD §8), so
        // without this pass the gate blocks exports for names the detector was
        // never able to find — which is exactly what happened the first time
        // this pipeline ran on the corpus PRD.
        //
        // Each variant is interned under its *exact surface text*, not under
        // the canonical name. That keeps restoration byte-for-byte lossless:
        // `Plan tiers` restores to `Plan tiers`, never to `PlanTier`. The cost
        // is that one concept can hold two identities and therefore two
        // aliases, so a model sees them as unrelated. Linking surface forms to
        // a shared concept is a post-MVP refinement.
        let known: Vec<(String, EntityType)> = found
            .iter()
            .filter(|c| c.confidence >= 0.8)
            .map(|c| (c.real_name.clone(), c.entity_type))
            .chain(self.dictionary.iter().cloned())
            .collect();

        for (name, entity_type) in known {
            for variant in crate::verify::case_variants(&name) {
                if variant == name || variant.len() < 4 || self.is_allowed(&variant) {
                    continue;
                }
                // Case-insensitively, because the gate matches that way too
                // (`ascii_case_insensitive` in SDD §8). A case-sensitive pass
                // here finds `plan tiers` but not the `Plan tiers` actually in
                // the heading, and the gate then blocks on it.
                for (start, end) in whole_token_spans_ci(text, &variant) {
                    push(
                        Candidate {
                            // The exact surface text, so restore is lossless.
                            real_name: text[start..end].to_owned(),
                            entity_type,
                            scope_path: scope.to_owned(),
                            byte_start: start,
                            byte_end: end,
                            kind,
                            confidence: 0.82,
                        },
                        &mut claimed,
                        &mut found,
                    );
                }
            }
        }

        found.sort_by_key(|c| c.byte_start);
        found
    }

    #[allow(clippy::too_many_arguments)]
    fn candidate(
        name: &str,
        entity_type: EntityType,
        scope: &str,
        start: usize,
        end: usize,
        kind: OccurrenceKind,
        confidence: f32,
    ) -> Candidate {
        Candidate {
            real_name: name.to_owned(),
            entity_type,
            scope_path: scope.to_owned(),
            byte_start: start,
            byte_end: end,
            kind,
            confidence,
        }
    }
}

/// Classify a PascalCase compound by its suffix. Returns `None` when no suffix
/// matches — an unclassifiable compound is a suggestion, not a detection.
fn classify_pascal(word: &str) -> Option<EntityType> {
    // Longest suffix wins, so `SubscriptionCreated` is an Event rather than
    // being caught by a shorter suffix elsewhere in the table.
    TYPED_SUFFIXES
        .iter()
        .filter(|(suffix, _)| word.len() > suffix.len() && word.ends_with(suffix))
        .max_by_key(|(suffix, _)| suffix.len())
        .map(|(_, entity_type)| *entity_type)
}

/// Is this capitalized phrase just a sentence opening?
fn is_sentence_noise(phrase: &str, text: &str, start: usize) -> bool {
    let first = phrase.split_whitespace().next().unwrap_or(phrase);
    if SENTENCE_STARTERS.contains(&first) {
        return true;
    }
    // A single capitalized word directly after a sentence boundary is far more
    // likely to be ordinary prose than a proper noun.
    if !phrase.contains(char::is_whitespace) {
        let preceding = text[..start].trim_end();
        if preceding.is_empty() || preceding.ends_with(['.', '!', '?', '\n', '#', '-', '*', '|']) {
            return true;
        }
    }
    false
}

/// Whole-token byte spans, so `invoice` does not match inside `invoice_id`.
pub fn whole_token_spans(text: &str, needle: &str) -> Vec<(usize, usize)> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut spans = Vec::new();
    let mut start = 0;
    while let Some(offset) = text[start..].find(needle) {
        let found = start + offset;
        let end = found + needle.len();
        let before = text[..found].chars().next_back();
        let after = text[end..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if boundary(before) && boundary(after) {
            spans.push((found, end));
        }
        start = found + 1;
    }
    spans
}

/// Spans that must never be re-detected: aliases this pipeline already emitted,
/// and redaction markers.
///
/// Sanitization has to be idempotent. A twin is a perfectly ordinary document,
/// and users will sanitize one — by re-running a project, by importing a twin,
/// or by pointing the tool at its own output.
fn protected_regions(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();

    // Redaction markers, `<<REDACTED:type>>`, including the delimiters.
    let mut from = 0;
    while let Some(offset) = text[from..].find(crate::secrets::REDACTION_PREFIX) {
        let start = from + offset;
        let end = text[start..].find(">>").map_or(text.len(), |e| start + e + 2);
        spans.push((start, end));
        from = end;
    }

    // Alias-shaped tokens. Matching on the whole token means a typed alias
    // (`PrimaryService_H7K2Q3`) protects its `PrimaryService` prefix too, which
    // the PascalCase rule would otherwise claim.
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            if crate::alias::is_alias_shaped(&text[start..i]) {
                spans.push((start, i));
            }
        } else {
            i += 1;
        }
    }

    spans
}

/// Whole-token spans, matched case-insensitively.
///
/// Returns spans rather than text so the caller can take the *original* bytes:
/// aliasing must record what was actually written, or restoration stops being
/// byte-for-byte lossless.
pub fn whole_token_spans_ci(text: &str, needle: &str) -> Vec<(usize, usize)> {
    if needle.is_empty() {
        return Vec::new();
    }
    let haystack = text.to_lowercase();
    let needle_lower = needle.to_lowercase();
    // Lowercasing can change byte length for non-ASCII, which would invalidate
    // the offsets. Fall back to the exact matcher in that case.
    if haystack.len() != text.len() || needle_lower.len() != needle.len() {
        return whole_token_spans(text, needle);
    }

    let mut spans = Vec::new();
    let mut start = 0;
    while let Some(offset) = haystack[start..].find(&needle_lower) {
        let found = start + offset;
        let end = found + needle_lower.len();
        let before = text[..found].chars().next_back();
        let after = text[end..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if boundary(before) && boundary(after) {
            spans.push((found, end));
        }
        start = found + 1;
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> Detector {
        Detector::new()
            .with_term("Vantor", EntityType::Organization)
            .with_term("Meridian Freight", EntityType::Organization)
            .with_term("Paylane", EntityType::Organization)
    }

    fn names(candidates: &[Candidate]) -> Vec<&str> {
        candidates.iter().map(|c| c.real_name.as_str()).collect()
    }

    #[test]
    fn dictionary_terms_are_found_everywhere() {
        let found = detector().scan_text(
            "Vantor bills Meridian Freight through Paylane.",
            "project",
            OccurrenceKind::Comment,
        );
        assert!(names(&found).contains(&"Vantor"));
        assert!(names(&found).contains(&"Meridian Freight"));
        assert!(names(&found).contains(&"Paylane"));
    }

    #[test]
    fn longer_dictionary_terms_win() {
        // `Meridian Freight` must not be split into `Meridian` plus a stray
        // suggestion for `Freight`.
        let found = detector().scan_text(
            "Meridian Freight is the largest account.",
            "project",
            OccurrenceKind::Comment,
        );
        assert!(names(&found).contains(&"Meridian Freight"));
        assert!(!names(&found).contains(&"Meridian"));
    }

    #[test]
    fn pascal_compounds_classify_by_suffix() {
        let d = Detector::new();
        let found = d.scan_text(
            "SubscriptionService publishes SubscriptionCreated and calls BillingApi with CreateSubscriptionDto.",
            "project",
            OccurrenceKind::Comment,
        );
        let by_name = |n: &str| found.iter().find(|c| c.real_name == n).map(|c| c.entity_type);
        assert_eq!(by_name("SubscriptionService"), Some(EntityType::Service));
        assert_eq!(by_name("SubscriptionCreated"), Some(EntityType::Event));
        assert_eq!(by_name("BillingApi"), Some(EntityType::Api));
        assert_eq!(by_name("CreateSubscriptionDto"), Some(EntityType::Dto));
    }

    #[test]
    fn env_vars_and_hosts_are_detected() {
        let d = Detector::new();
        let found = d.scan_text(
            "Set VANTOR_BILLING_URL to reach billing.vantor.internal today.",
            "project",
            OccurrenceKind::Comment,
        );
        let by_name = |n: &str| found.iter().find(|c| c.real_name == n).map(|c| c.entity_type);
        assert_eq!(by_name("VANTOR_BILLING_URL"), Some(EntityType::EnvVar));
        assert_eq!(by_name("billing.vantor.internal"), Some(EntityType::Host));
    }

    #[test]
    fn stop_list_terms_are_never_detected() {
        let d = Detector::new();
        let found = d.scan_text(
            "Data lives in Postgres. The console is React and TypeScript.",
            "project",
            OccurrenceKind::Comment,
        );
        for framework in ["Postgres", "React", "TypeScript"] {
            assert!(!names(&found).contains(&framework), "{framework} should be stop-listed");
        }
    }

    #[test]
    fn user_allowlist_extends_the_stop_list() {
        let d = Detector::new().with_allowed("InternalTool");
        let found = d.scan_text("InternalToolService is fine.", "project", OccurrenceKind::Comment);
        // The compound is still detected; the bare allowlisted term is not.
        assert!(!names(&found).contains(&"InternalTool"));
    }

    #[test]
    fn sentence_openings_are_not_suggested_as_organizations() {
        let d = Detector::new();
        let found = d.scan_text(
            "The platform is fast. Every invoice is checked. This matters.",
            "project",
            OccurrenceKind::Comment,
        );
        assert!(found.is_empty(), "got spurious candidates: {:?}", names(&found));
    }

    #[test]
    fn candidates_never_overlap() {
        let found = detector().scan_text(
            "Vantor runs SubscriptionService behind billing.vantor.internal.",
            "project",
            OccurrenceKind::Comment,
        );
        for pair in found.windows(2) {
            assert!(
                pair[0].byte_end <= pair[1].byte_start,
                "overlapping candidates: {:?} and {:?}",
                pair[0].real_name,
                pair[1].real_name
            );
        }
    }

    #[test]
    fn spans_point_at_the_detected_text() {
        let text = "Vantor bills through Paylane.";
        for candidate in detector().scan_text(text, "project", OccurrenceKind::Comment) {
            assert_eq!(&text[candidate.byte_start..candidate.byte_end], candidate.real_name);
        }
    }

    #[test]
    fn suggestions_are_marked_low_confidence() {
        let d = Detector::new();
        let found = d.scan_text(
            "We partner with Northwind Logistics here.",
            "project",
            OccurrenceKind::Comment,
        );
        let suggestion = found.iter().find(|c| c.entity_type == EntityType::Organization);
        assert!(suggestion.is_some_and(|c| c.confidence < 0.5));
    }

    #[test]
    fn whole_token_matching_ignores_substrings() {
        assert!(whole_token_spans("invoice_id", "invoice").is_empty());
        assert_eq!(whole_token_spans("the invoice here", "invoice"), vec![(4, 11)]);
    }
}
