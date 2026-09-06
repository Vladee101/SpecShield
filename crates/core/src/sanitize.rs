//! Semantic Twin Generator — SDD §7.
//!
//! The pipeline, in order (SDD §3):
//!
//! 1. **Secrets first** (§4.3). One-way, and it runs before identity extraction
//!    so a credential is never admitted to the graph as a "name".
//! 2. **Detect** identities (§4.4).
//! 3. **Assign** aliases, reusing existing ones (§6).
//! 4. **Plan** edits over byte ranges, validate non-overlap (§4.2.1).
//! 5. **Apply**, then **verify** (§7.2).
//!
//! The guarantee is *not* "the twin compiles" — unachievable without a type
//! checker (SDD §4.2.2). It is: **the twin parses, and its declaration and
//! reference counts match the original.** Where that cannot be met, the file is
//! emitted unaliased and reported, per SDD §16 — never in a broken state.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::alias;
use crate::detect::Detector;
use crate::edit::{Edit, apply};
use crate::model::{EntityType, IdentityKey, IdentityNode, Origin, Status};
use crate::parser::{ArtifactParser, Candidate, ProjectContext};
use crate::secrets;

/// The identity graph as it stands during a sanitize run.
///
/// Alias assignment is idempotent: an identity keeps the alias it was first
/// given, for the life of the project (SDD §6.5, enforced by `ux_alias`).
///
/// **The graph is the allocator.** Numbers are handed out per entity type in
/// first-seen order — PRD §13 — which makes this type stateful in a way HMAC
/// derivation was not. The state is not stored separately: every number this
/// project has issued is already in the aliases it has issued, so
/// [`Graph::restore_node`] rebuilds the counters as it loads the vault. There is
/// no counter column to drift out of step with the rows it describes.
#[derive(Debug, Default)]
pub struct Graph {
    by_identity: HashMap<IdentityKey, Uuid>,
    nodes: HashMap<Uuid, IdentityNode>,
    aliases: HashMap<String, Uuid>,
    /// Highest number issued per type. `ORG_004` means `next` holds 5 for
    /// organizations, whether that row was written a second ago or last year.
    next: HashMap<EntityType, u32>,
    /// Identities the user has confirmed as one concept — SDD §5. Members share
    /// an alias *number*; nothing is ever merged without confirmation.
    concepts: HashMap<IdentityKey, String>,
    /// The number each confirmed concept settled on, so `DB_TABLE_007` and
    /// `DTO_007` are visibly the same thing.
    concept_numbers: HashMap<String, u32>,
}

impl Graph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a confirmed unification — SDD §5.
    ///
    /// Members keep their own identity, scope, and real name; they share an
    /// alias suffix so the twin shows the relationship. Confirming after a twin
    /// has been shared changes those aliases, which orphans it — the same
    /// hazard as a re-key (SDD §9.5).
    pub fn confirm_concept(&mut self, members: &[IdentityKey], concept: &str) {
        for member in members {
            self.concepts.insert(member.clone(), concept.to_owned());
            // A member already loaded from the vault fixes the concept's number,
            // so a later member joins the alias that is already in twins rather
            // than starting a second one.
            if let Some(uuid) = self.by_identity.get(member)
                && let Some(node) = self.nodes.get(uuid)
                && let Some((_, number)) = alias::parse(&node.alias)
            {
                self.concept_numbers.entry(concept.to_owned()).or_insert(number);
            }
        }
    }

    /// Concepts confirmed so far, for persistence.
    pub fn concepts(&self) -> impl Iterator<Item = (&IdentityKey, &String)> {
        self.concepts.iter()
    }

    /// Look up or create the identity for `key`, returning its node.
    pub fn intern(&mut self, key: &IdentityKey, origin: Origin) -> &IdentityNode {
        if let Some(uuid) = self.by_identity.get(key) {
            return &self.nodes[uuid];
        }

        let alias = self.allocate(key);

        let uuid = Uuid::new_v4();
        self.aliases.insert(alias.clone(), uuid);
        self.by_identity.insert(key.clone(), uuid);
        self.nodes.insert(
            uuid,
            IdentityNode {
                uuid,
                key: key.clone(),
                alias,
                origin,
                status: Status::Active,
            },
        );
        &self.nodes[&uuid]
    }

    /// The next free alias for this identity — PRD §13.
    ///
    /// A confirmed concept takes the number its first member took, so the twin
    /// shows the relationship (SDD §5). Where that number is already spoken for
    /// within *this* type — possible, because the counters are per type and a
    /// concept crosses them — the counter wins and the concept simply does not
    /// get to share. A duplicate alias would make restore ambiguous, which is
    /// the one failure with no safe recovery (SDD §10.4).
    fn allocate(&mut self, key: &IdentityKey) -> String {
        let entity_type = key.entity_type;
        let concept = self.concepts.get(key).cloned();

        if let Some(concept) = &concept
            && let Some(number) = self.concept_numbers.get(concept).copied()
        {
            let shared = alias::format_alias(entity_type, number);
            if !self.aliases.contains_key(&shared) {
                return shared;
            }
        }

        let number = self.next.entry(entity_type).or_insert(1);
        let mut alias = alias::format_alias(entity_type, *number);
        // The counter cannot collide on its own; it can still meet a number a
        // concept claimed for this type earlier.
        while self.aliases.contains_key(&alias) {
            *number += 1;
            alias = alias::format_alias(entity_type, *number);
        }
        let issued = *number;
        *number += 1;

        if let Some(concept) = concept {
            self.concept_numbers.entry(concept).or_insert(issued);
        }
        alias
    }

    /// Reinstate a node loaded from the vault, preserving its stored UUID and
    /// alias.
    ///
    /// Aliases must survive across sessions unchanged (SDD §6.5). The stored
    /// value always wins, and loading it is also how the allocator learns what
    /// this project has already issued — there is no separate counter to load,
    /// and therefore none to get out of step.
    pub fn restore_node(&mut self, key: &IdentityKey, uuid: &str, alias: &str, origin: Origin, status: Status) -> bool {
        let Ok(uuid) = uuid.parse::<Uuid>() else {
            return false;
        };
        if let Some((entity_type, number)) = alias::parse(alias) {
            let next = self.next.entry(entity_type).or_insert(1);
            *next = (*next).max(number + 1);
        }
        self.aliases.insert(alias.to_owned(), uuid);
        self.by_identity.insert(key.clone(), uuid);
        self.nodes.insert(
            uuid,
            IdentityNode {
                uuid,
                key: key.clone(),
                alias: alias.to_owned(),
                origin,
                status,
            },
        );
        true
    }

    pub fn nodes(&self) -> impl Iterator<Item = &IdentityNode> {
        self.nodes.values()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// `(alias, real_name)` pairs for the restore vocabulary.
    pub fn vocabulary(&self) -> Vec<(String, String)> {
        self.nodes
            .values()
            .map(|n| (n.alias.clone(), n.key.real_name.clone()))
            .collect()
    }

    /// Every real name known to the vault, for the verification gate (SDD §8).
    pub fn real_names(&self) -> Vec<String> {
        self.nodes.values().map(|n| n.key.real_name.clone()).collect()
    }
}

/// Result of sanitizing one document.
///
/// **Every byte offset in here indexes `source`, the text the caller passed
/// in** — not the twin and not the redacted intermediate the alias pass
/// actually ran over. Those three texts have different lengths whenever a
/// secret was found, and an offset that means "somewhere in a string nobody
/// holds" is worse than no offset at all.
#[derive(Debug)]
pub struct Sanitized {
    pub twin: String,
    /// Identities applied, in document order.
    pub applied: Vec<Applied>,
    pub secrets: Vec<secrets::Finding>,
    /// Candidates below the confidence floor: surfaced for review, not applied
    /// (PRD FR-10).
    pub suggestions: Vec<Candidate>,
    /// What the SDD §7.2 pass concluded. When this says aliasing was abandoned,
    /// `twin` is the unaliased original and `applied` is empty.
    pub verification: Verification,
}

#[derive(Debug, Clone)]
pub struct Applied {
    pub uuid: Uuid,
    pub alias: String,
    pub real_name: String,
    pub byte_start: usize,
    pub byte_end: usize,
    /// What sort of position this was — the `occurrences.kind` column of
    /// SDD §9.1. Carried through from the candidate rather than recomputed: the
    /// parser knew whether this was a declaration and nothing downstream does.
    pub kind: crate::model::OccurrenceKind,
}

/// Candidates at or above this confidence are applied automatically; below it
/// they are suggestions requiring review.
pub const AUTO_APPLY_CONFIDENCE: f32 = 0.8;

#[derive(Debug, thiserror::Error)]
pub enum SanitizeError {
    #[error("planned edits are invalid: {0}")]
    Edits(#[from] crate::edit::EditError),
}

/// Outcome of the SDD §7.2 verification pass.
///
/// A twin that fails verification is never returned. The file is emitted
/// unaliased instead, per SDD §16 — a broken artifact is worse than an
/// unprocessed one, and silently emitting one is worse than both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// The twin has the same structure as the original.
    Passed,

    /// The parser has no structure to compare. Reported rather than treated as
    /// a pass: Markdown prose and plain text genuinely have nothing to check,
    /// and the caller deserves to know that "verified" did not happen here.
    Unsupported { parser: &'static str },

    /// The parser claimed this file and could not read it.
    ///
    /// Distinct from [`Self::Unsupported`], and much worse. A parser that
    /// cannot parse the original produced no structural candidates either, so
    /// the twin is the original with at most a few prose substitutions — and
    /// nothing checked it. Folded into `Unsupported`, as it was until P3-4,
    /// this reads as "nothing to check here" and a user is told their untouched
    /// source is verified clean.
    OriginalDidNotParse { parser: &'static str },

    /// No parser was supplied. The caller chose not to verify.
    NotAttempted,

    /// The twin no longer parses. Aliasing was abandoned.
    TwinDidNotParse { parser: &'static str },

    /// The twin parses but its shape changed. Aliasing was abandoned, and the
    /// differing counts are reported so the parser bug is findable.
    StructureChanged {
        parser: &'static str,
        differences: Vec<(&'static str, usize, usize)>,
    },
}

impl Verification {
    /// Did aliasing survive? False means the returned twin is the unaliased
    /// (but still secret-redacted) original.
    ///
    /// `OriginalDidNotParse` is true here on purpose: there is nothing to
    /// abandon. The parser contributed no candidates, so whatever was applied
    /// came from the prose scan and discarding it would make the twin *less*
    /// sanitized. What that case needs is to be reported, not reverted.
    pub const fn aliases_applied(&self) -> bool {
        matches!(
            self,
            Self::Passed | Self::Unsupported { .. } | Self::NotAttempted | Self::OriginalDidNotParse { .. }
        )
    }

    /// Did a structural check actually run and succeed?
    pub const fn structurally_verified(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Sanitize one document — SDD §7.
///
/// `parser` supplies the structural fingerprint for the §7.2 verification pass.
/// Passing `None` is allowed and is reported as [`Verification::NotAttempted`]
/// — it is never silently equivalent to passing.
pub fn sanitize(
    source: &str,
    scope: &str,
    detector: &Detector,
    graph: &mut Graph,
    parser: Option<&dyn ArtifactParser>,
    context: &ProjectContext,
) -> Result<Sanitized, SanitizeError> {
    // 1. Secrets, before anything else looks at the text.
    let findings = secrets::scan(source);
    let redacted = secrets::redact(source, &findings);

    // 2. Detect against the redacted text, so a credential can never be
    //    admitted to the identity graph as though it were a name.
    //
    //    Two sources, in that order of authority. The parser reads the format's
    //    own syntax and knows that `customer_id` in one table is a different
    //    identity from `customer_id` in another; the prose scan then covers
    //    comments and free text, which no grammar describes. Structural
    //    candidates claim their spans first, so a name the AST has already
    //    classified is never reclassified by a heuristic.
    let structural = parser.map_or_else(Vec::new, |p| p.structural_candidates_in(&redacted, scope, context));
    let mut candidates = structural;
    let claimed = claims(&candidates);

    // Some formats confine prose to specific regions — YAML values, and later
    // TypeScript comments and string literals. Outside them the text is the
    // format's own vocabulary, and detecting there produces confident nonsense.
    let regions = parser.and_then(|p| p.prose_regions(&redacted));

    // What the parser resolved this name to *in this document*. A doc comment
    // saying `CustomerSubscription` means the type imported three lines above
    // it; minting a document-scoped identity for the prose mention hands the
    // model two aliases for one name, and the connection the real source made is
    // the whole point of the twin.
    //
    // Structural evidence in the same document, or nothing. Two files that each
    // mention `Status` in prose and neither of which declares it are two
    // identities — Design Review B1 — and prose cannot say which was meant.
    let mut resolved: HashMap<String, Option<IdentityKey>> = HashMap::new();
    for candidate in &candidates {
        let key = IdentityKey::new(&candidate.scope_path, candidate.entity_type, &candidate.real_name);
        resolved
            .entry(candidate.real_name.clone())
            .and_modify(|slot| {
                if slot.as_ref() != Some(&key) {
                    // Ambiguous within the document; prose keeps its own scope.
                    *slot = None;
                }
            })
            .or_insert(Some(key));
    }

    let mut from_prose: HashSet<usize> = HashSet::new();
    for candidate in detector.scan_text(&redacted, scope, crate::model::OccurrenceKind::Reference) {
        let overlaps = suppressed(&candidate, &claimed);
        let in_prose = regions.as_ref().is_none_or(|regions| {
            regions
                .iter()
                .any(|(s, e)| candidate.byte_start >= *s && candidate.byte_end <= *e)
        });
        if !overlaps && in_prose {
            from_prose.insert(candidate.byte_start);
            candidates.push(candidate);
        }
    }
    candidates.sort_by_key(|c| c.byte_start);

    // Two bars, and the second one is the product. Confidence says the detector
    // is sure *what* this is; `should_alias` says it is worth hiding — which for
    // anything but an organization or a host means the user asked for it by
    // name (PRD §4.1).
    //
    // Everything else becomes a suggestion rather than disappearing, so
    // `specshield scan` still lists it and `specshield term` is one command
    // away. The detector's work is not wasted; it just no longer decides.
    let (confident, mut suggestions): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|c| c.confidence >= AUTO_APPLY_CONFIDENCE && detector.should_alias(&c.real_name, c.entity_type));

    let confident = identity_wins(confident);

    // 3-4. Intern each identity and plan an edit for it.
    let mut edits: Vec<Edit> = Vec::with_capacity(confident.len());
    let mut applied = Vec::with_capacity(confident.len());

    for candidate in &confident {
        // A name the parser resolved keeps that identity, even where prose is
        // how this file happens to mention it.
        let key = from_prose
            .contains(&candidate.byte_start)
            .then(|| resolved.get(&candidate.real_name).cloned().flatten())
            .flatten()
            // ...unless the two disagree about what *kind* of name it is. The
            // resolution exists to unify a prose mention with the declaration it
            // refers to, which is only meaningful when both are talking about
            // the same category of thing.
            //
            // A `PlantUML` parser calls `Stripe` a participant and the vendor
            // table calls it a payment provider. Taking the parser's key there
            // does not merge two mentions of one thing — it files an identity
            // under a structural alias, and the twin says `SERVICE_001` where it
            // means `PAYMENT_PROVIDER_001`. Identity wins the classification for
            // the same reason it wins the span above.
            .filter(|key| key.entity_type.is_identity() == candidate.entity_type.is_identity())
            .unwrap_or_else(|| IdentityKey::new(&candidate.scope_path, candidate.entity_type, &candidate.real_name));
        let node = graph.intern(&key, Origin::Detected);
        let (uuid, alias) = (node.uuid, node.alias.clone());

        edits.push(Edit::new(
            candidate.byte_start,
            candidate.byte_end,
            alias.clone(),
            Some(uuid),
        ));
        applied.push(Applied {
            uuid,
            alias,
            real_name: candidate.real_name.clone(),
            byte_start: candidate.byte_start,
            byte_end: candidate.byte_end,
            kind: candidate.kind,
        });
    }

    // A suggestion at a span that was aliased anyway is noise. It happens
    // whenever two passes read one name differently and identity won: the
    // structural reading lost the span but was still sitting in the review
    // queue, so `specshield sanitize` listed `Stripe` as something to confirm
    // immediately after replacing it.
    suggestions.retain(|s| {
        !applied
            .iter()
            .any(|hit| s.byte_start < hit.byte_end && hit.byte_start < s.byte_end)
    });

    // 5. Apply. `apply` validates non-overlap and char boundaries, so a bad
    //    plan fails here rather than producing a corrupt twin.
    let twin = apply(&redacted, &mut edits)?;

    // 6. Verify — SDD §7.2. The guarantee is not "the twin compiles", which is
    //    unachievable without a type checker (SDD §4.2.2). It is: the twin
    //    parses, and its structure matches the original.
    let verification = verify_structure(parser, &redacted, &twin);

    // Back into the caller's coordinates. A no-op when nothing was redacted,
    // which is the overwhelmingly common case.
    if !findings.is_empty() {
        for hit in &mut applied {
            hit.byte_start = secrets::source_offset(&findings, hit.byte_start);
            hit.byte_end = secrets::source_offset(&findings, hit.byte_end);
        }
        for candidate in &mut suggestions {
            candidate.byte_start = secrets::source_offset(&findings, candidate.byte_start);
            candidate.byte_end = secrets::source_offset(&findings, candidate.byte_end);
        }
    }

    if verification.aliases_applied() {
        Ok(Sanitized {
            twin,
            applied,
            secrets: findings,
            suggestions,
            verification,
        })
    } else {
        // Abandon aliasing, keep redaction. Secrets are one-way and must not be
        // reinstated just because the alias pass was rejected.
        //
        // The identities stay interned: aliases are derived deterministically,
        // so a later successful run produces exactly the same ones, and
        // discarding them would not undo anything a caller has already
        // persisted.
        Ok(Sanitized {
            twin: redacted,
            applied: Vec::new(),
            secrets: findings,
            suggestions,
            verification,
        })
    }
}

/// Drop candidates that overlap one already accepted, identity first.
///
/// Two can now cover the same bytes: `VANTOR_BILLING_URL` as an env var and the
/// `VANTOR` inside it as an organization. Only one can be edited, and it is the
/// identity — hiding who you are is the point, and the env var name is not
/// aliased at all unless the user asked for it by name.
/// Spans a parser has already read, with the *class* of each — identity or
/// structure. See [`suppressed`].
#[must_use]
pub fn claims(candidates: &[Candidate]) -> Vec<(usize, usize, bool)> {
    candidates
        .iter()
        .map(|c| (c.byte_start, c.byte_end, c.entity_type.is_identity()))
        .collect()
}

/// Does a structural claim hide this prose candidate?
///
/// A structural claim says what a name *is for*. It does not say what kind of
/// name it is, and it never suppresses an identity — whether the identity sits
/// inside it (`acme` in the module path `./acme-billing`) or covers it exactly.
///
/// The exact-cover case is the one that cost a diagram. A `PlantUML` parser reads
/// `participant "Stripe" as payments` and is right that Stripe is a
/// participant; the vendor table is right that it is a payment provider.
/// Letting the parser win did not file the name under the parser's type —
/// structure is not aliased, so it dropped the name from consideration
/// entirely, left the vendor in the twin, and taught every prose mention of
/// `Stripe` in the same file that it was a service. Three wrong answers from one
/// rule.
///
/// Structure still wins over structure: two readings of one span where neither
/// is identity is a real disagreement, and there the parser read the grammar
/// while the prose pass guessed.
///
/// Public because the corpus grader merges the same two sources and must merge
/// them the same way. It had its own copy of this rule, and the copy went stale
/// the day this one changed — reporting three vendors as missed that the
/// pipeline aliases correctly.
#[must_use]
pub fn suppressed(candidate: &Candidate, claimed: &[(usize, usize, bool)]) -> bool {
    claimed.iter().any(|(start, end, claim_is_identity)| {
        let intersects = candidate.byte_start < *end && *start < candidate.byte_end;
        // The one thing that gets through a claim it overlaps.
        let pierces = candidate.entity_type.is_identity() && !*claim_is_identity;
        intersects && !pierces
    })
}

fn identity_wins(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut accepted: Vec<(usize, usize)> = Vec::new();
    let mut out = candidates;
    out.sort_by_key(|c| (c.byte_start, !c.entity_type.is_identity()));
    out.retain(|c| {
        if accepted.iter().any(|(s, e)| c.byte_start < *e && *s < c.byte_end) {
            return false;
        }
        accepted.push((c.byte_start, c.byte_end));
        true
    });
    out
}

/// Compare the structure of `before` and `after` — SDD §7.2.
fn verify_structure(parser: Option<&dyn ArtifactParser>, before: &str, after: &str) -> Verification {
    let Some(parser) = parser else {
        return Verification::NotAttempted;
    };
    let name = parser.name();

    let Some(original) = parser.structural_counts(before) else {
        // A parser with no fingerprint has nothing to say about shape. One that
        // has a fingerprint and produced none could not read the file it
        // claimed, which is a different thing entirely.
        return if parser.fingerprints() {
            Verification::OriginalDidNotParse { parser: name }
        } else {
            Verification::Unsupported { parser: name }
        };
    };
    // `None` here means the twin no longer parses, while the original did.
    let Some(twin) = parser.structural_counts(after) else {
        return Verification::TwinDidNotParse { parser: name };
    };

    let differences = original.differences(&twin);
    if differences.is_empty() {
        Verification::Passed
    } else {
        Verification::StructureChanged {
            parser: name,
            differences,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EntityType;
    use crate::restore::{Vocabulary, restore};
    use crate::verify::LeakScanner;

    fn graph() -> Graph {
        Graph::new()
    }

    fn detector() -> Detector {
        Detector::new()
            .with_term("Vantor", EntityType::Organization)
            .with_term("Meridian Freight", EntityType::Organization)
    }

    #[test]
    fn reported_offsets_index_the_caller_s_source_not_the_redacted_text() {
        // The alias pass runs over text in which the secret has already been
        // replaced by a marker of a different length. Everything after that
        // point is displaced, so an offset taken straight from that pass points
        // into the wrong part of the file — and only ever in files that held a
        // secret, which is where being wrong costs the most.
        let source = "key = ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa and then Vantor ships it.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();

        assert_eq!(out.secrets.len(), 1, "the token must have been found");
        let hit = out.applied.iter().find(|a| a.real_name == "Vantor").expect("Vantor");
        assert_eq!(
            &source[hit.byte_start..hit.byte_end],
            "Vantor",
            "the reported span must slice the caller's own text"
        );
    }

    #[test]
    fn an_offset_before_a_secret_is_unmoved() {
        let source = "Vantor uses key = ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa here.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();

        let hit = out.applied.iter().find(|a| a.real_name == "Vantor").expect("Vantor");
        assert_eq!(hit.byte_start, 0);
        assert_eq!(&source[hit.byte_start..hit.byte_end], "Vantor");
    }

    #[test]
    fn offsets_survive_several_secrets_of_differing_lengths() {
        let source = concat!(
            "a = ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
",
            "b = AKIAIOSFODNN7EXAMPLE
",
            "Vantor is last.
",
        );
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();

        assert_eq!(out.secrets.len(), 2, "both credentials must have been found");
        let hit = out.applied.iter().find(|a| a.real_name == "Vantor").expect("Vantor");
        assert_eq!(&source[hit.byte_start..hit.byte_end], "Vantor");
    }

    #[test]
    fn a_parser_that_cannot_read_the_file_is_not_reported_as_unsupported() {
        // The difference between "plain text has no shape to compare" and "I
        // claimed this file and could not read it". Folding the second into the
        // first tells a user their untouched source was verified clean, which
        // is exactly how every `.tsx` file in a React project could have been
        // sent to a model in the clear.
        struct Broken;
        impl crate::parser::ArtifactParser for Broken {
            fn name(&self) -> &'static str {
                "broken"
            }
            fn can_handle(&self, _: &std::path::Path, _: &str) -> bool {
                true
            }
            fn parse<'a>(
                &self,
                _: &'a crate::parser::Document,
            ) -> Result<crate::parser::Parsed<'a>, crate::parser::ParseError> {
                unreachable!("not exercised")
            }
            fn extract(&self, _: &crate::parser::Parsed<'_>) -> Vec<Candidate> {
                Vec::new()
            }
            fn plan_edits(&self, _: &crate::parser::Parsed<'_>, _: &crate::parser::AliasMap) -> Vec<Edit> {
                Vec::new()
            }
            fn structural_candidates(&self, _: &str, _: &str) -> Vec<Candidate> {
                Vec::new()
            }
            // Claims a fingerprint and never produces one: a parser that cannot
            // read what it claimed.
            fn fingerprints(&self) -> bool {
                true
            }
        }

        let mut g = graph();
        let out = sanitize(
            "anything",
            "project",
            &detector(),
            &mut g,
            Some(&Broken),
            &ProjectContext::default(),
        )
        .unwrap();
        assert_eq!(out.verification, Verification::OriginalDidNotParse { parser: "broken" });
        assert!(
            !out.verification.structurally_verified(),
            "nothing was verified and nothing may claim it was"
        );
    }

    #[test]
    fn round_trip_is_lossless() {
        // The core invariant, PRD §5.
        let source = "Vantor bills Meridian Freight through SubscriptionService.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();

        let restored = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
        assert_eq!(restored.text, source);
    }

    #[test]
    fn the_twin_contains_no_real_names() {
        let source = "Vantor runs SubscriptionService for Meridian Freight.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();

        let scanner = LeakScanner::new(g.real_names());
        assert!(scanner.scan(&out.twin).is_clean(), "twin leaked: {}", out.twin);
    }

    #[test]
    fn aliases_are_stable_across_documents() {
        let mut g = graph();
        let a = sanitize(
            "Vantor here",
            "project",
            &detector(),
            &mut g,
            None,
            &ProjectContext::default(),
        )
        .unwrap();
        let b = sanitize(
            "and Vantor there",
            "project",
            &detector(),
            &mut g,
            None,
            &ProjectContext::default(),
        )
        .unwrap();

        assert_eq!(a.applied[0].alias, b.applied[0].alias);
        assert_eq!(g.len(), 1, "one identity, not two");
    }

    #[test]
    fn distinct_scopes_get_distinct_aliases() {
        let mut g = graph();
        // Confirmed, because `Status` is an ordinary word and is not aliased
        // otherwise (PRD §4). Naming it is exactly how a user says "this one is
        // mine" — and the B1 property under test is about scope, not about
        // which names qualify.
        let d = Detector::new().with_confirmed_term("Status", EntityType::Enum);
        let a = sanitize("Status", "mod/a", &d, &mut g, None, &ProjectContext::default()).unwrap();
        let b = sanitize("Status", "mod/b", &d, &mut g, None, &ProjectContext::default()).unwrap();

        assert_ne!(a.applied[0].alias, b.applied[0].alias, "Design Review B1");
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn what_you_built_stays_readable() {
        // The product, in one assertion. An agent asked to extend this code has
        // to be able to read it; a twin in which the domain model is opaque
        // tells it nothing to build on.
        let mut g = graph();
        let d = Detector::new()
            .with_term("Vantor", EntityType::Organization)
            .with_term("CustomerSubscription", EntityType::Dto)
            .with_term("chargeInvoice", EntityType::Service);
        let source = "Vantor bills through CustomerSubscription and chargeInvoice.";
        let out = sanitize(source, "project", &d, &mut g, None, &ProjectContext::default()).unwrap();

        assert!(out.twin.contains("CustomerSubscription"), "{}", out.twin);
        assert!(out.twin.contains("chargeInvoice"), "{}", out.twin);
        assert!(!out.twin.contains("Vantor"), "who you are still goes: {}", out.twin);
    }

    #[test]
    fn an_identity_inside_a_compound_is_replaced_in_place() {
        // The half that makes the claim true. `VantorBillingService` says who
        // you are *and* what you built; aliasing the whole token would hide the
        // architecture, and aliasing none of it would publish the company.
        let mut g = graph();
        let d = Detector::new().with_term("Vantor", EntityType::Organization);
        let source = "class VantorBillingService {}
const vantor_invoice = 1;
";
        let out = sanitize(source, "project", &d, &mut g, None, &ProjectContext::default()).unwrap();

        assert!(!out.twin.contains("Vantor"), "{}", out.twin);
        assert!(!out.twin.contains("vantor"), "{}", out.twin);
        assert!(out.twin.contains("BillingService"), "the shape survives: {}", out.twin);
        assert!(out.twin.contains("_invoice"), "so does this one: {}", out.twin);

        // And it comes back, or hiding it was worse than useless.
        let restored = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
        assert_eq!(restored.text, source);
    }

    #[test]
    fn a_word_inside_a_word_is_not_an_identity() {
        // The rule that keeps the pass above from being a substring match: a
        // match has to start at a word boundary or a camelCase hump.
        let mut g = graph();
        let d = Detector::new().with_term("Vantor", EntityType::Organization);
        let out = sanitize("advantorous", "project", &d, &mut g, None, &ProjectContext::default()).unwrap();
        assert_eq!(out.twin, "advantorous");
    }

    #[test]
    fn a_structural_name_the_user_confirms_is_still_aliased() {
        // The escape hatch has to reach the structural side too, or a team with
        // a genuinely secret internal service has no way to hide it.
        let mut g = graph();
        let d = Detector::new().with_confirmed_term("CustomerSubscription", EntityType::Dto);
        let out = sanitize(
            "the CustomerSubscription model",
            "project",
            &d,
            &mut g,
            None,
            &ProjectContext::default(),
        )
        .unwrap();
        assert!(!out.twin.contains("CustomerSubscription"), "{}", out.twin);
    }

    #[test]
    fn an_ordinary_word_is_a_suggestion_rather_than_an_alias() {
        // The relaxation. `status` is a real declaration and the detector is
        // certain of it — and aliasing it makes the twin worse for no gain,
        // because the word says nothing about who wrote it.
        let mut g = graph();
        let d = Detector::new().with_term("status", EntityType::Column);
        let out = sanitize(
            "the status field",
            "mod/a",
            &d,
            &mut g,
            None,
            &ProjectContext::default(),
        )
        .unwrap();

        assert!(out.applied.is_empty(), "an ordinary word is not aliased");
        assert!(
            out.suggestions.iter().any(|c| c.real_name == "status"),
            "but it is still surfaced, so `specshield term` is one command away"
        );
        assert_eq!(out.twin, "the status field");
    }

    #[test]
    fn naming_an_ordinary_word_makes_it_an_identity() {
        // The other half: the escape hatch has to actually work, or the rule
        // above is a wall rather than a default.
        let mut g = graph();
        let d = Detector::new().with_confirmed_term("status", EntityType::Column);
        let out = sanitize(
            "the status field",
            "mod/a",
            &d,
            &mut g,
            None,
            &ProjectContext::default(),
        )
        .unwrap();

        assert_eq!(out.applied.len(), 1, "a name the user typed is theirs");
        assert_ne!(out.twin, "the status field");
    }

    #[test]
    fn secrets_are_redacted_before_detection_and_never_interned() {
        let source = "api_key = \"sk_live_abcdefghijklmnopqrstuvwx\"\nVantor owns it.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();

        assert!(!out.twin.contains("sk_live_abcdefghijklmnopqrstuvwx"));
        assert!(out.twin.contains("<<REDACTED:"));
        assert_eq!(out.secrets.len(), 1);
        // The credential must not have become an identity.
        assert!(
            g.nodes().all(|n| !n.key.real_name.contains("sk_live")),
            "a secret was interned as an identity"
        );
    }

    #[test]
    fn a_redacted_secret_does_not_come_back_on_restore() {
        let source = "token = \"sk_live_abcdefghijklmnopqrstuvwx\"";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();
        let restored = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
        assert!(!restored.text.contains("sk_live_abcdefghijklmnopqrstuvwx"));
    }

    #[test]
    fn low_confidence_candidates_are_suggested_not_applied() {
        let mut g = graph();
        let out = sanitize(
            "We also work with Northwind Logistics on this.",
            "project",
            &Detector::new(),
            &mut g,
            None,
            &ProjectContext::default(),
        )
        .unwrap();

        assert!(out.applied.is_empty(), "suggestions must not be applied");
        assert!(!out.suggestions.is_empty(), "should have been surfaced for review");
        assert!(out.twin.contains("Northwind Logistics"));
    }

    #[test]
    fn formatting_is_preserved_exactly() {
        let source = "# Heading\n\n- Vantor\n- Other\n\n```ts\nconst x = 1;\n```\n";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();
        let restored = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
        assert_eq!(restored.text, source, "byte-for-byte, whitespace included");
    }

    #[test]
    fn empty_input_round_trips() {
        let mut g = graph();
        let out = sanitize("", "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();
        assert_eq!(out.twin, "");
    }

    // -- SDD §7.2 verification pass -----------------------------------------

    /// A parser that reports whatever structure the test tells it to, so the
    /// pass can be exercised without a real language.
    #[derive(Debug)]
    struct FakeParser {
        /// Counts keyed by the text passed in, so `before` and `after` can be
        /// made to disagree.
        after_headings: Option<usize>,
    }

    impl crate::parser::ArtifactParser for FakeParser {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn can_handle(&self, _: &std::path::Path, _: &str) -> bool {
            true
        }
        fn parse<'a>(
            &self,
            _: &'a crate::parser::Document,
        ) -> Result<crate::parser::Parsed<'a>, crate::parser::ParseError> {
            unreachable!("verification never parses through this path")
        }
        fn extract(&self, _: &crate::parser::Parsed<'_>) -> Vec<Candidate> {
            Vec::new()
        }
        fn plan_edits(&self, _: &crate::parser::Parsed<'_>, _: &crate::parser::AliasMap) -> Vec<Edit> {
            Vec::new()
        }
        fn structural_counts(&self, source: &str) -> Option<crate::parser::StructuralCounts> {
            // The original always reports 1; the twin reports whatever the test
            // asked for, or nothing at all to simulate a parse failure.
            if source.contains("ORG_") || source.contains("SERVICE_") {
                return self
                    .after_headings
                    .map(|n| crate::parser::StructuralCounts::new().with("headings", n));
            }
            Some(crate::parser::StructuralCounts::new().with("headings", 1))
        }
    }

    #[test]
    fn a_matching_structure_passes_and_keeps_the_aliases() {
        let mut g = graph();
        let parser = FakeParser {
            after_headings: Some(1),
        };
        let out = sanitize(
            "Vantor",
            "project",
            &detector(),
            &mut g,
            Some(&parser),
            &ProjectContext::default(),
        )
        .unwrap();

        assert_eq!(out.verification, Verification::Passed);
        assert!(out.verification.structurally_verified());
        assert_eq!(out.applied.len(), 1);
        assert!(out.twin.contains("ORG_"));
    }

    #[test]
    fn a_changed_structure_abandons_aliasing_rather_than_emitting_a_broken_twin() {
        // SDD §16: a broken artifact is worse than an unprocessed one.
        let mut g = graph();
        let parser = FakeParser {
            after_headings: Some(4),
        };
        let out = sanitize(
            "Vantor",
            "project",
            &detector(),
            &mut g,
            Some(&parser),
            &ProjectContext::default(),
        )
        .unwrap();

        assert!(matches!(out.verification, Verification::StructureChanged { .. }));
        assert!(!out.verification.aliases_applied());
        assert!(out.applied.is_empty(), "no alias may be reported as applied");
        assert_eq!(out.twin, "Vantor", "the unaliased original is returned");
    }

    #[test]
    fn a_twin_that_no_longer_parses_abandons_aliasing() {
        let mut g = graph();
        let parser = FakeParser { after_headings: None };
        let out = sanitize(
            "Vantor",
            "project",
            &detector(),
            &mut g,
            Some(&parser),
            &ProjectContext::default(),
        )
        .unwrap();

        assert!(matches!(out.verification, Verification::TwinDidNotParse { .. }));
        assert_eq!(out.twin, "Vantor");
    }

    #[test]
    fn abandoning_aliasing_still_keeps_secrets_redacted() {
        // Redaction is one-way. Rejecting the alias pass must not reinstate a
        // credential — that would turn a verification failure into a leak.
        let mut g = graph();
        let parser = FakeParser {
            after_headings: Some(9),
        };
        let source = "token = \"sk_live_abcdefghijklmnopqrstuvwx\"
Vantor owns it.";
        let out = sanitize(
            source,
            "project",
            &detector(),
            &mut g,
            Some(&parser),
            &ProjectContext::default(),
        )
        .unwrap();

        assert!(!out.verification.aliases_applied());
        assert!(!out.twin.contains("sk_live_abcdefghijklmnopqrstuvwx"), "{}", out.twin);
        assert!(out.twin.contains("<<REDACTED:"));
    }

    #[test]
    fn no_parser_is_reported_as_not_attempted_never_as_a_pass() {
        let mut g = graph();
        let out = sanitize(
            "Vantor",
            "project",
            &detector(),
            &mut g,
            None,
            &ProjectContext::default(),
        )
        .unwrap();

        assert_eq!(out.verification, Verification::NotAttempted);
        assert!(!out.verification.structurally_verified(), "must not read as verified");
        assert!(out.verification.aliases_applied(), "but aliasing still happens");
    }

    // -- SDD §5 cross-artifact unification -----------------------------------

    #[test]
    fn a_confirmed_concept_shares_an_alias_suffix_across_artifacts() {
        // The point of the feature: a model reading the twin should see that
        // the SQL table and the OpenAPI schema are the same thing.
        let mut g = graph();
        let table = IdentityKey::new("sql::customer_subscription", EntityType::Table, "customer_subscription");
        let dto = IdentityKey::new(
            "#/components/schemas/CustomerSubscription",
            EntityType::Dto,
            "CustomerSubscription",
        );
        g.confirm_concept(&[table.clone(), dto.clone()], "customersubscription");

        let table_alias = g.intern(&table, Origin::Detected).alias.clone();
        let dto_alias = g.intern(&dto, Origin::Detected).alias.clone();

        assert_ne!(table_alias, dto_alias, "distinct aliases keep restore unambiguous");
        let suffix = |a: &str| a.rsplit('_').next().unwrap_or_default().to_owned();
        assert_eq!(suffix(&table_alias), suffix(&dto_alias), "{table_alias} vs {dto_alias}");
        assert!(table_alias.starts_with("DB_TABLE_"));
        assert!(dto_alias.starts_with("DTO_"));
    }

    #[test]
    fn unified_identities_still_restore_to_their_own_surface_form() {
        // The reason one shared alias is impossible: SQL needs
        // `customer_subscription` back and TypeScript needs
        // `CustomerSubscription`.
        use crate::restore::{Vocabulary, restore};
        let mut g = graph();
        let table = IdentityKey::new("sql::customer_subscription", EntityType::Table, "customer_subscription");
        let dto = IdentityKey::new("ts::CustomerSubscription", EntityType::Dto, "CustomerSubscription");
        g.confirm_concept(&[table.clone(), dto.clone()], "customersubscription");

        let table_alias = g.intern(&table, Origin::Detected).alias.clone();
        let dto_alias = g.intern(&dto, Origin::Detected).alias.clone();

        let vocabulary = Vocabulary::new(g.vocabulary());
        assert_eq!(restore(&table_alias, &vocabulary).text, "customer_subscription");
        assert_eq!(restore(&dto_alias, &vocabulary).text, "CustomerSubscription");
    }

    #[test]
    fn confirming_a_concept_does_not_merge_identities() {
        let mut g = graph();
        let table = IdentityKey::new("sql::invoice", EntityType::Table, "invoice");
        let dto = IdentityKey::new("ts::Invoice", EntityType::Dto, "Invoice");
        g.confirm_concept(&[table.clone(), dto.clone()], "invoice");
        g.intern(&table, Origin::Detected);
        g.intern(&dto, Origin::Detected);
        assert_eq!(g.len(), 2, "two identities, one concept");
    }

    #[test]
    fn an_unconfirmed_match_changes_nothing() {
        // Proposals are inert. Nothing unifies until someone says so, and two
        // identities stay two identities with two aliases.
        //
        // This used to assert that their alias *suffixes* differed, which no
        // longer says anything: counters are per type (PRD §13 shows `ORG_001`
        // and `PRODUCT_001` side by side), so the first of any two kinds both
        // land on 001 whether or not they are one concept. Sharing a number is
        // still what unification *does* — it is no longer evidence that it
        // happened.
        let mut g = graph();
        let table = IdentityKey::new("sql::invoice", EntityType::Table, "invoice");
        let dto = IdentityKey::new("ts::Invoice", EntityType::Dto, "Invoice");
        let a = g.intern(&table, Origin::Detected).alias.clone();
        let b = g.intern(&dto, Origin::Detected).alias.clone();

        assert_ne!(a, b, "two identities never share one alias");
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn stop_listed_terms_survive_into_the_twin() {
        let mut g = graph();
        let out = sanitize(
            "Built with React and Postgres.",
            "project",
            &detector(),
            &mut g,
            None,
            &ProjectContext::default(),
        )
        .unwrap();
        assert!(out.twin.contains("React"));
        assert!(out.twin.contains("Postgres"));
    }
}
