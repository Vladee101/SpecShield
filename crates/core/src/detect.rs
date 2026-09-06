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
    // Environment variables every project has. Universal, never proprietary,
    // and aliasing them makes a config file unreadable for no gain.
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "PORT",
    "HOST",
    "DEBUG",
    "LOG_LEVEL",
    "NODE_ENV",
    "RUST_LOG",
    "TZ",
    "LANG",
    "CI",
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

/// A line that names a person out loud — `@author Jane Okafor`, `Contact: Jane
/// Okafor`, a `Reviewed-by:` trailer. Group 1 is the name.
///
/// Built from [`crate::vendors::PERSON_MARKERS`] so the list stays in one place
/// and reads as data rather than as a pattern.
static PERSON_LINE: LazyLock<Regex> = LazyLock::new(|| {
    let markers = crate::vendors::PERSON_MARKERS
        .iter()
        .map(|m| regex::escape(m))
        .collect::<Vec<_>>()
        .join("|");
    // One to three capitalised words after the marker, **on the same line**.
    // Three because `Jane Anne Okafor` happens; four starts matching sentences.
    //
    // Spaces and tabs rather than `\s`, because `\s` matches a newline and a
    // name is not allowed to run into the next line. It did: a `Contact:` line
    // followed by a `Reviewed-by:` line matched across the break as one person,
    // and replacing that span ate the newline — which §7.2 caught as
    // `lines: 4 -> 3` and abandoned the whole file's aliasing.
    Regex::new(&format!(
        r"(?i)(?:^|[\s*/#@\-])(?:{markers})[ \t]*[:=@]?[ \t]+((?-i:[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){{1,2}}))"
    ))
    .expect("valid regex")
});

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
    /// Terms the user has named with `specshield term` — PRD FR-10.
    ///
    /// Separate from the dictionary, which is also seeded from every identity
    /// already in the vault. Only the ones a person typed override
    /// [`crate::words::is_identifying`]: `account` is an ordinary word until
    /// someone says it is their table, and then it is theirs forever.
    confirmed: HashSet<String>,
    /// One automaton over the whole dictionary, built on first use.
    ///
    /// The dictionary is not a handful of user terms any more: it is seeded
    /// from the vault, so a repo-scale project puts tens of thousands of names
    /// in it. Scanning each term across each file separately made a 1,000-file
    /// export run for over ten minutes. Aho-Corasick makes it one pass over the
    /// text regardless of how many names the project knows — the same reason
    /// the export gate uses it (SDD §8).
    matcher: std::sync::OnceLock<aho_corasick::AhoCorasick>,
    /// The dictionary's case variants, as one case-insensitive automaton.
    ///
    /// The variant pass used to scan the text once per variant. At project
    /// scale that is tens of thousands of substring searches per file, and it
    /// was the single slowest thing in a repo-wide export — 115 ms per file at
    /// 5,000 known names, against 2 ms at 100.
    variants: std::sync::OnceLock<(aho_corasick::AhoCorasick, Vec<EntityType>)>,
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a user-confirmed term.
    #[must_use]
    pub fn with_term(mut self, name: impl Into<String>, entity_type: EntityType) -> Self {
        self.dictionary.push((name.into(), entity_type));
        // Deliberately not sorted here. `Meridian Freight` still wins over
        // `Meridian` — leftmost-longest is the automaton's match semantics —
        // and re-sorting on every insertion turned seeding 24,000 vault names
        // into the slowest part of an export.
        self.matcher.take();
        self.variants.take();
        self
    }

    /// The case-variant automaton over the dictionary, built once.
    ///
    /// Variants of names found in *this* document are handled separately: there
    /// are a handful of them and they change per file.
    fn variant_matcher(&self) -> &(aho_corasick::AhoCorasick, Vec<EntityType>) {
        self.variants.get_or_init(|| {
            let mut patterns: Vec<String> = Vec::new();
            let mut types: Vec<EntityType> = Vec::new();
            for (term, entity_type) in &self.dictionary {
                // An allowlisted term contributes no variants either. Filtering
                // only by the variant's own text let `invoice` through as
                // `Invoice`, which the case-insensitive automaton then matched
                // against the very word the user had just excluded.
                if self.is_allowed(term) {
                    continue;
                }
                for variant in crate::verify::case_variants(term) {
                    if variant == *term || variant.len() < 4 || self.is_allowed(&variant) {
                        continue;
                    }
                    patterns.push(variant);
                    types.push(*entity_type);
                }
            }
            let automaton = aho_corasick::AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                // The gate matches this way too (SDD §8). A case-sensitive pass
                // finds `plan tiers` but not the `Plan tiers` in the heading,
                // and the gate then blocks on it.
                .ascii_case_insensitive(true)
                .build(&patterns)
                .expect("variant automaton");
            (automaton, types)
        })
    }

    /// Known commercial services, built once — PRD §7 and [`crate::vendors`].
    ///
    /// Case-insensitive, because `stripe.charges.create()` names the company as
    /// surely as `Stripe` does in a sentence.
    fn vendor_matcher() -> &'static (aho_corasick::AhoCorasick, Vec<EntityType>) {
        static MATCHER: std::sync::OnceLock<(aho_corasick::AhoCorasick, Vec<EntityType>)> = std::sync::OnceLock::new();
        MATCHER.get_or_init(|| {
            let automaton = aho_corasick::AhoCorasick::builder()
                // `Checkout.com` must not lose to `Checkout` if both are ever
                // listed, and `Plaid.com` must not be shadowed by a shorter
                // entry.
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .ascii_case_insensitive(true)
                .build(crate::vendors::VENDORS.iter().map(|(name, _)| *name))
                .expect("vendor automaton");
            let types = crate::vendors::VENDORS.iter().map(|(_, t)| *t).collect();
            (automaton, types)
        })
    }

    /// The dictionary automaton, built once.
    fn matcher(&self) -> &aho_corasick::AhoCorasick {
        self.matcher.get_or_init(|| {
            aho_corasick::AhoCorasick::builder()
                // Longest wins, so `Meridian Freight` is never shadowed by
                // `Meridian`. This is what the old length sort was for.
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .build(self.dictionary.iter().map(|(term, _)| term))
                .expect("dictionary automaton")
        })
    }

    #[must_use]
    pub fn with_allowed(mut self, term: impl Into<String>) -> Self {
        self.allowlist.insert(term.into());
        self
    }

    /// Record a term as user-confirmed as well as adding it — PRD FR-10.
    ///
    /// The difference from [`Detector::with_term`] is authority, not matching.
    /// Both find the name; only this one says a person chose it, which is what
    /// lets an ordinary word like `account` be aliased when it really is the
    /// name of a table.
    #[must_use]
    pub fn with_confirmed_term(mut self, term: impl Into<String>, entity_type: EntityType) -> Self {
        let term = term.into();
        self.confirmed.insert(term.clone());
        self.with_term(term, entity_type)
    }

    /// Did a person name this? Case-insensitive, matching the allowlist and the
    /// gate.
    #[must_use]
    pub fn is_confirmed(&self, term: &str) -> bool {
        self.confirmed.iter().any(|c| c.eq_ignore_ascii_case(term))
    }

    /// Should this name be aliased at all? — PRD §4.
    ///
    /// Three questions in order, and the order is the product:
    ///
    /// 1. **Did a person name it?** Then it is theirs, whatever it is. This is
    ///    how a service or a table gets hidden when it really does need to be.
    /// 2. **Does it say who you are?** Only [`EntityType::is_identity`] types —
    ///    your organization, its products and brands, the hosts it runs on, the
    ///    vendors it pays, and the people who work on it — are aliased on their
    ///    own. What you *built* stays legible, because a model that cannot read
    ///    your architecture cannot help you extend it.
    /// 3. **Is it identifying at all?** A host called `localhost` or an org
    ///    called `admin` is a word, not an identity — see [`crate::words`].
    #[must_use]
    pub fn should_alias(&self, name: &str, entity_type: EntityType) -> bool {
        if self.is_confirmed(name) {
            return true;
        }
        entity_type.is_identity() && crate::words::is_identifying(name)
    }

    /// Case-insensitively, matching the export gate — see
    /// [`crate::verify::LeakScanner::with_allowlist`]. The two have to agree:
    /// a term the gate exempts but the detector still aliases is only a
    /// cosmetic waste, but a term the detector leaves alone and the gate still
    /// blocks is a deadlock with no way out.
    fn is_allowed(&self, term: &str) -> bool {
        STOP_LIST.contains(&term) || self.allowlist.iter().any(|a| a.eq_ignore_ascii_case(term))
    }

    /// Detect entities in plain prose or a comment body.
    ///
    /// `scope` is the identity scope for everything found here — `project` for
    /// Markdown, since prose has no module structure.
    #[allow(clippy::too_many_lines)]
    pub fn scan_text(&self, text: &str, scope: &str, kind: OccurrenceKind) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = Vec::new();
        let mut claimed: Vec<(usize, usize)> = Vec::new();

        // An identity is refused only by another identity. A *structural* claim
        // must not suppress one, because the structural name is usually the
        // thing wrapped around it: the `VANTOR_BILLING_URL` rule matched the
        // whole env var, claimed the span, and hid the `VANTOR` inside it — so
        // the company name went into the twin under a name the product does not
        // alias any more. Found by the round-trip property test, on the input
        // `Vantor VANTOR_BILLING_URL`.
        //
        // The two candidates then overlap, which is fine: only one of them is
        // aliased, and `sanitize` drops the loser before planning edits.
        let push = |cand: Candidate, claimed: &mut Vec<(usize, usize)>, found: &mut Vec<Candidate>| {
            let hits = |spans: &[(usize, usize)]| spans.iter().any(|(s, e)| cand.byte_start < *e && *s < cand.byte_end);
            if cand.entity_type.is_identity() {
                let identities: Vec<(usize, usize)> = found
                    .iter()
                    .filter(|c| c.entity_type.is_identity())
                    .map(|c| (c.byte_start, c.byte_end))
                    .collect();
                // Output of this pipeline is still off limits, or an alias gets
                // aliased again.
                if hits(&identities) || hits(&protected_regions(text)) {
                    return;
                }
            } else if hits(claimed) {
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
        if !self.dictionary.is_empty() {
            for m in self.matcher().find_iter(text) {
                let (term, entity_type) = &self.dictionary[m.pattern().as_usize()];
                // The automaton matches substrings. A structural name is a whole
                // token — `plan` inside `planning` is not the term. An identity
                // is also caught inside a compound, because that is where a
                // company name usually sits: `VantorBillingService`.
                let bounded = if entity_type.is_identity() {
                    is_subword(text, m.start(), m.end())
                } else {
                    is_whole_token(text, m.start(), m.end())
                };
                if !bounded {
                    continue;
                }

                // The allowlist wins over the dictionary — PRD FR-10 says the
                // user may mark *any* term never-alias, with no carve-out for
                // terms they added themselves.
                //
                // It did not, and the omission was invisible: `specshield allow`
                // reported success and the term kept being aliased. A user who
                // adds `invoice` as a table and then decides the word in prose
                // is a false positive has said something more specific and more
                // recent, and it has to be honoured.
                if self.is_allowed(term) {
                    continue;
                }

                push(
                    Candidate {
                        real_name: term.clone(),
                        entity_type: *entity_type,
                        scope_path: scope.to_owned(),
                        byte_start: m.start(),
                        byte_end: m.end(),
                        kind,
                        confidence: 1.0,
                    },
                    &mut claimed,
                    &mut found,
                );
            }
        }

        // 2. Commercial services — PRD §7. The only identity category besides
        //     hostnames that can be found without being told, because unlike
        //     `Vantor` these names are the same in every company that uses them.
        {
            let (automaton, types) = Self::vendor_matcher();
            for m in automaton.find_iter(text) {
                let name = &text[m.start()..m.end()];
                if self.is_allowed(name) {
                    continue;
                }
                push(
                    Candidate {
                        // The exact surface text, so `stripe` restores to
                        // `stripe` and `Stripe` to `Stripe`.
                        real_name: name.to_owned(),
                        entity_type: types[m.pattern().as_usize()],
                        scope_path: scope.to_owned(),
                        byte_start: m.start(),
                        byte_end: m.end(),
                        kind,
                        confidence: 0.95,
                    },
                    &mut claimed,
                    &mut found,
                );
            }
        }

        // 3. People, where a line says so out loud — PRD FR-3.
        for caps in PERSON_LINE.captures_iter(text) {
            let Some(name) = caps.get(1) else { continue };
            if self.is_allowed(name.as_str()) {
                continue;
            }
            push(
                Self::candidate(
                    name.as_str(),
                    EntityType::Person,
                    scope,
                    name.start(),
                    name.end(),
                    kind,
                    0.9,
                ),
                &mut claimed,
                &mut found,
            );
        }

        // 4. Shape rules. Lower confidence than anything above, and last
        //    because a known company name must beat a guess about dots and
        //    capitals: `stripe.charges.create` matches the hostname shape
        //    exactly, and claiming it there would hide the vendor inside it.
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
            // `3.1.0` and `2.4.0` match the dotted-segment shape exactly. A
            // hostname's last segment is a TLD-like word, never digits — the
            // openapi fixtures are full of version strings and every one of
            // them was being aliased as a host.
            let looks_like_a_host = m
                .as_str()
                .rsplit('.')
                .next()
                .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()));
            if !looks_like_a_host {
                continue;
            }
            push(
                Self::candidate(m.as_str(), EntityType::Domain, scope, m.start(), m.end(), kind, 0.9),
                &mut claimed,
                &mut found,
            );
        }

        for m in PASCAL_COMPOUND.find_iter(text) {
            let word = m.as_str();
            if self.is_allowed(word) {
                continue;
            }
            // An unclassifiable compound is still an entity — `CustomerSubscription`
            // is every bit as proprietary as `SubscriptionService`, it just has
            // no suffix telling us what kind of thing it is.
            //
            // Guessing the *type* is safe in a way guessing the *name* is not:
            // the type only picks the alias prefix, so a wrong guess makes the
            // twin marginally less readable. Failing to detect the name at all
            // leaks it. The stop-list is what keeps `HttpClient` and `ArrayList`
            // out.
            let (entity_type, confidence) = classify_pascal(word).map_or((EntityType::Dto, 0.8), |t| (t, 0.85));
            push(
                Self::candidate(word, entity_type, scope, m.start(), m.end(), kind, confidence),
                &mut claimed,
                &mut found,
            );
        }

        // 5. Suggestions — proper-noun-shaped phrases. Never auto-applied.
        for m in CAPITALIZED_PHRASE.find_iter(text) {
            let phrase = m.as_str();
            if self.is_allowed(phrase) || is_sentence_noise(phrase, text, m.start()) {
                continue;
            }
            // `Contact: Jane Okafor` — the marker is evidence that a person
            // follows, so suggesting the marker itself as an organization is
            // noise the user has to dismiss on every file that has a contact
            // line. The name it introduces was already taken in pass 3.
            if crate::vendors::PERSON_MARKERS
                .iter()
                .any(|marker| marker.eq_ignore_ascii_case(phrase))
            {
                continue;
            }
            push(
                Self::candidate(phrase, EntityType::Organization, scope, m.start(), m.end(), kind, 0.35),
                &mut claimed,
                &mut found,
            );
        }

        // 6. Prose variants of everything found so far.
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
        if !self.dictionary.is_empty() {
            let (automaton, types) = self.variant_matcher();
            for m in automaton.find_iter(text) {
                // An identity is caught inside the compound that wraps it, so
                // `VantorBillingService` becomes `<org>BillingService` — the
                // company hidden, the architecture still readable. That is the
                // whole shape of the product (PRD §4.1), and it only applies to
                // identity types: hunting for a *structural* name inside every
                // identifier would be noise, and those are not aliased anyway.
                let entity_type = types[m.pattern().as_usize()];
                let bounded = if entity_type.is_identity() {
                    is_subword(text, m.start(), m.end())
                } else {
                    is_whole_token(text, m.start(), m.end())
                };
                if !bounded {
                    continue;
                }
                push(
                    Candidate {
                        // The exact surface text, so restore is lossless.
                        real_name: text[m.start()..m.end()].to_owned(),
                        entity_type,
                        scope_path: scope.to_owned(),
                        byte_start: m.start(),
                        byte_end: m.end(),
                        kind,
                        confidence: 0.82,
                    },
                    &mut claimed,
                    &mut found,
                );
            }
        }

        // Names found in *this* document, whose variants no precomputed
        // automaton could hold.
        let known: Vec<(String, EntityType)> = found
            .iter()
            .filter(|c| c.confidence >= 0.8)
            .map(|c| (c.real_name.clone(), c.entity_type))
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

/// Classify a `PascalCase` compound by its suffix. Returns `None` when no suffix
/// matches — an unclassifiable compound is a suggestion, not a detection.
///
/// Shared with the language parsers: a TypeScript `interface SubscriptionCreated`
/// is an Event for the same reason a prose mention of it is, and having two
/// tables of suffixes would let them disagree.
pub fn classify_pascal(word: &str) -> Option<EntityType> {
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
/// Is `text[start..end]` bounded by something that is not part of a name?
///
/// `_` counts as part of a name, which is what lets the gate see `customer_id`
/// inside `old_customer_id_v2`.
#[must_use]
pub fn is_whole_token(text: &str, start: usize, end: usize) -> bool {
    let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
    boundary(text[..start].chars().next_back()) && boundary(text[end..].chars().next())
}

/// Does `[start, end)` sit on the boundaries of a *word within an identifier*?
///
/// Looser than [`is_whole_token`], and deliberately: an identity has to be
/// caught inside the compound that wraps it. `VantorBillingService` and
/// `vantor_invoice` both say who you are, and a rule that only fires on the bare
/// token `Vantor` misses the two forms it actually appears in — which, once the
/// product stopped aliasing what you *built*, became the only forms that matter.
///
/// A boundary is the start or end of the text, a non-alphanumeric character, or
/// a camelCase hump. The hump test is what keeps this from being a substring
/// match: `api` inside `rapid` starts mid-word with no case change and is
/// refused, while the `Vantor` of `getVantorClient` is not.
#[must_use]
pub fn is_subword(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let matched_first = text[start..end].chars().next();
    let after = text[end..].chars().next();

    let opens = match (before, matched_first) {
        (None, _) => true,
        (Some(b), _) if !b.is_alphanumeric() => true,
        // `getVantor` — a capital after something that is not one.
        (Some(b), Some(f)) => f.is_uppercase() && !b.is_uppercase(),
        _ => false,
    };
    let closes = match after {
        None => true,
        Some(a) => !a.is_alphanumeric() || a.is_uppercase(),
    };
    opens && closes
}

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
mod scale {
    use super::*;

    /// The detector's cost must not grow with the size of the project.
    ///
    /// It did, twice: once per dictionary term and once per case variant of
    /// each term, both scanning the whole text. Seeding the dictionary from the
    /// vault turned that into 15,000 substring searches per file and a
    /// 1,000-file export into a ten-minute one. The ratio below is generous —
    /// the regression it guards was roughly a hundredfold.
    #[test]
    fn scan_cost_does_not_grow_with_the_dictionary() {
        let text = "export class Service0 { method0(): number { return 1; } }\n".repeat(150);

        let time_with = |n: usize| {
            let mut d = Detector::new();
            for i in 0..n {
                d = d.with_term(format!("Name{i}Thing"), EntityType::Dto);
            }
            // Both automatons are built on first use; the build is once per
            // project, not per file, so it is not what this measures.
            let _ = d.scan_text(&text, "s", OccurrenceKind::Reference);

            let start = std::time::Instant::now();
            for _ in 0..20 {
                let _ = d.scan_text(&text, "s", OccurrenceKind::Reference);
            }
            start.elapsed()
        };

        let small = time_with(100);
        let large = time_with(5000);
        assert!(
            large < small * 15 + std::time::Duration::from_millis(50),
            "50x the names should not cost meaningfully more per file: {small:?} -> {large:?}"
        );
    }
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
    fn version_strings_are_not_hostnames() {
        let d = Detector::new();
        for version in ["openapi: 3.1.0", "version: 2.4.0", "1.0.0"] {
            let found = d.scan_text(version, "project", OccurrenceKind::Reference);
            assert!(
                found.iter().all(|c| c.entity_type != EntityType::Domain),
                "{version} detected as a host: {:?}",
                names(&found)
            );
        }
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
        assert_eq!(by_name("billing.vantor.internal"), Some(EntityType::Domain));
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

    #[test]
    fn the_allowlist_beats_a_dictionary_term() {
        // PRD FR-10: the user may mark *any* term never-alias, including one
        // they added themselves. `specshield allow` reported success and the
        // term kept being aliased.
        let d = Detector::new()
            .with_term("invoice", EntityType::Table)
            .with_allowed("invoice");

        let found = d.scan_text("The invoice table.", "doc", OccurrenceKind::Reference);
        assert!(found.iter().all(|c| c.real_name != "invoice"), "{found:#?}");
    }
}

#[cfg(test)]
mod identity_detection {
    use super::*;

    fn scan(text: &str) -> Vec<Candidate> {
        Detector::new().scan_text(text, "project", OccurrenceKind::Reference)
    }

    fn typed(text: &str, name: &str) -> Option<EntityType> {
        scan(text)
            .into_iter()
            .find(|c| c.real_name == name)
            .map(|c| c.entity_type)
    }

    #[test]
    fn a_payment_provider_is_found_without_being_named() {
        // PRD §8's worked example. `Stripe` is not a name the user has to type
        // first, because unlike `Vantor` it means the same thing everywhere.
        assert_eq!(
            typed("BillingService charges Stripe.", "Stripe"),
            Some(EntityType::PaymentProvider)
        );
    }

    #[test]
    fn a_vendor_is_found_in_the_case_the_code_uses() {
        // `stripe.charges.create()` names the company as surely as a sentence
        // does, and the surface text is kept so restore is byte-exact.
        let found = scan("await stripe.charges.create(payload);");
        assert!(
            found
                .iter()
                .any(|c| c.real_name == "stripe" && c.entity_type == EntityType::PaymentProvider),
            "{:?}",
            names(&found)
        );
    }

    #[test]
    fn an_integration_partner_is_found_too() {
        assert_eq!(
            typed("Notifications go out via Twilio.", "Twilio"),
            Some(EntityType::Partner)
        );
        assert_eq!(typed("Tokens are issued by Auth0.", "Auth0"), Some(EntityType::Partner));
    }

    #[test]
    fn tooling_is_still_never_aliased() {
        // The line between VENDORS and STOP_LIST: do you have an account with
        // them? Everyone uses React and Postgres, and hiding them costs the
        // model context for no disclosure at all.
        let found = scan("A React front end talks to Postgres through Prisma.");
        for tool in ["React", "Postgres", "Prisma"] {
            assert!(!names(&found).contains(&tool), "{tool} must not be an entity");
        }
    }

    #[test]
    fn allowing_a_vendor_stops_it_being_aliased() {
        // A team that does not mind saying which processor they use says so
        // once, and the escape hatch has to reach the built-in table too.
        let d = Detector::new().with_allowed("Stripe");
        let found = d.scan_text("BillingService charges Stripe.", "project", OccurrenceKind::Reference);
        assert!(!names(&found).contains(&"Stripe"));
    }

    #[test]
    fn a_person_is_found_where_a_line_says_so() {
        for text in [
            " * @author Jane Okafor",
            "Contact: Jane Okafor",
            "Owner: Jane Okafor",
            "Reviewed-by: Jane Okafor",
            "# Maintainer: Jane Okafor",
        ] {
            assert_eq!(
                typed(text, "Jane Okafor"),
                Some(EntityType::Person),
                "no person found in {text:?}"
            );
        }
    }

    #[test]
    fn a_person_with_three_names_is_found_whole() {
        assert_eq!(
            typed("@author Maria de Souza Lima", "Maria de Souza"),
            None,
            "a lowercase particle ends the name rather than joining it"
        );
        assert_eq!(
            typed("@author Jane Anne Okafor", "Jane Anne Okafor"),
            Some(EntityType::Person)
        );
    }

    #[test]
    fn prose_that_merely_capitalises_is_not_a_person() {
        // The marker is what makes this precise. Without one, every capitalised
        // pair in a specification would be a person, and a PRD is full of them.
        let found = scan("The Billing Service handles Gold Business Subscription renewals.");
        assert!(
            !found.iter().any(|c| c.entity_type == EntityType::Person),
            "{:?}",
            found.iter().map(|c| (&c.real_name, c.entity_type)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_capitalised_phrase_is_still_only_a_suggestion() {
        // How an unguessable product or brand gets found: surfaced for review,
        // never applied. `specshield term` is what promotes it.
        let found = scan("Acme Bank offers Gold Business Subscription.");
        let phrase = found
            .iter()
            .find(|c| c.real_name == "Gold Business Subscription")
            .expect("surfaced for review");
        assert!(
            phrase.confidence < crate::sanitize::AUTO_APPLY_CONFIDENCE,
            "a guess at a product name must never be applied on its own"
        );
    }

    #[test]
    fn the_marker_word_itself_is_not_suggested() {
        // `Contact` is capitalised, three letters, and starts a line, so the
        // proper-noun pass surfaced it on every file with a contact line. It is
        // evidence that a person follows, never a name in its own right.
        let found = scan(
            "Contact: Jane Okafor
",
        );
        assert!(
            !names(&found).contains(&"Contact"),
            "a person marker is not an organization: {:?}",
            names(&found)
        );
    }

    fn names(candidates: &[Candidate]) -> Vec<&str> {
        candidates.iter().map(|c| c.real_name.as_str()).collect()
    }
}

#[cfg(test)]
mod person_lines {
    use super::*;

    #[test]
    fn a_person_name_never_runs_into_the_next_line() {
        // `\s` matches a newline, so `Contact: Jane Okafor` followed by
        // `Reviewed-by: ...` matched `Jane Okafor\nReviewed` as one person.
        // Replacing that span ate the line break, §7.2 saw `lines: 4 -> 3`, and
        // the whole file's aliasing was abandoned — so two working detectors
        // produced a completely unaliased twin.
        let text = "# Billing integration\n\nContact: Jane Okafor\nReviewed-by: Samuel Adeyemi\n";
        let found = Detector::new().scan_text(text, "p", OccurrenceKind::Reference);

        let people: Vec<&str> = found
            .iter()
            .filter(|c| c.entity_type == EntityType::Person)
            .map(|c| c.real_name.as_str())
            .collect();
        assert_eq!(people, vec!["Jane Okafor", "Samuel Adeyemi"]);

        for candidate in &found {
            assert!(
                !candidate.real_name.contains('\n'),
                "{:?} spans a line break",
                candidate.real_name
            );
        }
    }
}
