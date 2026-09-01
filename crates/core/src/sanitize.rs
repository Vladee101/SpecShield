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

use std::collections::HashMap;

use uuid::Uuid;

use crate::alias::{AliasStyle, ProjectKey, derive_in_concept};
use crate::detect::Detector;
use crate::edit::{Edit, apply};
use crate::model::{IdentityKey, IdentityNode, Origin, Status};
use crate::parser::{ArtifactParser, Candidate};
use crate::secrets;

/// The identity graph as it stands during a sanitize run.
///
/// Alias assignment is idempotent: the same identity always receives the same
/// alias, and a collision is resolved by a deterministic disambiguator so two
/// distinct identities can never share one (SDD §6.1, enforced by `ux_alias`).
#[derive(Debug)]
pub struct Graph {
    key: ProjectKey,
    style: AliasStyle,
    by_identity: HashMap<IdentityKey, Uuid>,
    nodes: HashMap<Uuid, IdentityNode>,
    aliases: HashMap<String, Uuid>,
    /// Identities the user has confirmed as one concept — SDD §5. Members share
    /// an alias suffix; nothing is ever merged without confirmation.
    concepts: HashMap<IdentityKey, String>,
}

impl Graph {
    pub fn new(key: ProjectKey, style: AliasStyle) -> Self {
        Self {
            key,
            style,
            by_identity: HashMap::new(),
            nodes: HashMap::new(),
            aliases: HashMap::new(),
            concepts: HashMap::new(),
        }
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

        // Derive, then walk disambiguators until the alias is free. In practice
        // the first attempt always succeeds; the loop exists so a collision is
        // impossible rather than merely unlikely.
        let concept = self.concepts.get(key).cloned();
        let mut disambiguator = None;
        let alias = loop {
            let candidate = derive_in_concept(&self.key, key, self.style, disambiguator, concept.as_deref());
            if !self.aliases.contains_key(&candidate) {
                break candidate;
            }
            disambiguator = Some(disambiguator.unwrap_or(1) + 1);
        };

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

    /// Reinstate a node loaded from the vault, preserving its stored UUID and
    /// alias.
    ///
    /// Aliases must survive across sessions unchanged (SDD §6.5): re-deriving
    /// them would be equivalent for the same project key, but a vault written by
    /// an older grammar would silently re-alias everything, orphaning every twin
    /// already sent to a model. The stored value always wins.
    pub fn restore_node(&mut self, key: &IdentityKey, uuid: &str, alias: &str, origin: Origin, status: Status) -> bool {
        let Ok(uuid) = uuid.parse::<Uuid>() else {
            return false;
        };
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
    pub const fn aliases_applied(&self) -> bool {
        matches!(self, Self::Passed | Self::Unsupported { .. } | Self::NotAttempted)
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
    let structural = parser.map_or_else(Vec::new, |p| p.structural_candidates(&redacted, scope));
    let mut candidates = structural;
    let claimed: Vec<(usize, usize)> = candidates.iter().map(|c| (c.byte_start, c.byte_end)).collect();

    // Some formats confine prose to specific regions — YAML values, and later
    // TypeScript comments and string literals. Outside them the text is the
    // format's own vocabulary, and detecting there produces confident nonsense.
    let regions = parser.and_then(|p| p.prose_regions(&redacted));

    for candidate in detector.scan_text(&redacted, scope, crate::model::OccurrenceKind::Reference) {
        let overlaps = claimed
            .iter()
            .any(|(s, e)| candidate.byte_start < *e && *s < candidate.byte_end);
        let in_prose = regions.as_ref().is_none_or(|regions| {
            regions
                .iter()
                .any(|(s, e)| candidate.byte_start >= *s && candidate.byte_end <= *e)
        });
        if !overlaps && in_prose {
            candidates.push(candidate);
        }
    }
    candidates.sort_by_key(|c| c.byte_start);

    let (confident, suggestions): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|c| c.confidence >= AUTO_APPLY_CONFIDENCE);

    // 3-4. Intern each identity and plan an edit for it.
    let mut edits: Vec<Edit> = Vec::with_capacity(confident.len());
    let mut applied = Vec::with_capacity(confident.len());

    for candidate in &confident {
        let key = IdentityKey::new(&candidate.scope_path, candidate.entity_type, &candidate.real_name);
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
        });
    }

    // 5. Apply. `apply` validates non-overlap and char boundaries, so a bad
    //    plan fails here rather than producing a corrupt twin.
    let twin = apply(&redacted, &mut edits)?;

    // 6. Verify — SDD §7.2. The guarantee is not "the twin compiles", which is
    //    unachievable without a type checker (SDD §4.2.2). It is: the twin
    //    parses, and its structure matches the original.
    let verification = verify_structure(parser, &redacted, &twin);

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

/// Compare the structure of `before` and `after` — SDD §7.2.
fn verify_structure(parser: Option<&dyn ArtifactParser>, before: &str, after: &str) -> Verification {
    let Some(parser) = parser else {
        return Verification::NotAttempted;
    };
    let name = parser.name();

    let Some(original) = parser.structural_counts(before) else {
        return Verification::Unsupported { parser: name };
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
        Graph::new(ProjectKey::from_bytes([42; 32]), AliasStyle::Opaque)
    }

    fn detector() -> Detector {
        Detector::new()
            .with_term("Vantor", EntityType::Organization)
            .with_term("Meridian Freight", EntityType::Organization)
    }

    #[test]
    fn round_trip_is_lossless() {
        // The core invariant, PRD §5.
        let source = "Vantor bills Meridian Freight through SubscriptionService.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None).unwrap();

        let restored = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
        assert_eq!(restored.text, source);
    }

    #[test]
    fn the_twin_contains_no_real_names() {
        let source = "Vantor runs SubscriptionService for Meridian Freight.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None).unwrap();

        let scanner = LeakScanner::new(g.real_names());
        assert!(scanner.scan(&out.twin).is_clean(), "twin leaked: {}", out.twin);
    }

    #[test]
    fn aliases_are_stable_across_documents() {
        let mut g = graph();
        let a = sanitize("Vantor here", "project", &detector(), &mut g, None).unwrap();
        let b = sanitize("and Vantor there", "project", &detector(), &mut g, None).unwrap();

        assert_eq!(a.applied[0].alias, b.applied[0].alias);
        assert_eq!(g.len(), 1, "one identity, not two");
    }

    #[test]
    fn distinct_scopes_get_distinct_aliases() {
        let mut g = graph();
        let d = Detector::new().with_term("Status", EntityType::Enum);
        let a = sanitize("Status", "mod/a", &d, &mut g, None).unwrap();
        let b = sanitize("Status", "mod/b", &d, &mut g, None).unwrap();

        assert_ne!(a.applied[0].alias, b.applied[0].alias, "Design Review B1");
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn secrets_are_redacted_before_detection_and_never_interned() {
        let source = "api_key = \"sk_live_abcdefghijklmnopqrstuvwx\"\nVantor owns it.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g, None).unwrap();

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
        let out = sanitize(source, "project", &detector(), &mut g, None).unwrap();
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
        let out = sanitize(source, "project", &detector(), &mut g, None).unwrap();
        let restored = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
        assert_eq!(restored.text, source, "byte-for-byte, whitespace included");
    }

    #[test]
    fn empty_input_round_trips() {
        let mut g = graph();
        let out = sanitize("", "project", &detector(), &mut g, None).unwrap();
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
        let out = sanitize("Vantor", "project", &detector(), &mut g, Some(&parser)).unwrap();

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
        let out = sanitize("Vantor", "project", &detector(), &mut g, Some(&parser)).unwrap();

        assert!(matches!(out.verification, Verification::StructureChanged { .. }));
        assert!(!out.verification.aliases_applied());
        assert!(out.applied.is_empty(), "no alias may be reported as applied");
        assert_eq!(out.twin, "Vantor", "the unaliased original is returned");
    }

    #[test]
    fn a_twin_that_no_longer_parses_abandons_aliasing() {
        let mut g = graph();
        let parser = FakeParser { after_headings: None };
        let out = sanitize("Vantor", "project", &detector(), &mut g, Some(&parser)).unwrap();

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
        let out = sanitize(source, "project", &detector(), &mut g, Some(&parser)).unwrap();

        assert!(!out.verification.aliases_applied());
        assert!(!out.twin.contains("sk_live_abcdefghijklmnopqrstuvwx"), "{}", out.twin);
        assert!(out.twin.contains("<<REDACTED:"));
    }

    #[test]
    fn no_parser_is_reported_as_not_attempted_never_as_a_pass() {
        let mut g = graph();
        let out = sanitize("Vantor", "project", &detector(), &mut g, None).unwrap();

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
        // Proposals are inert. Nothing unifies until someone says so.
        let mut g = graph();
        let table = IdentityKey::new("sql::invoice", EntityType::Table, "invoice");
        let dto = IdentityKey::new("ts::Invoice", EntityType::Dto, "Invoice");
        let a = g.intern(&table, Origin::Detected).alias.clone();
        let b = g.intern(&dto, Origin::Detected).alias.clone();
        let suffix = |s: &str| s.rsplit('_').next().unwrap_or_default().to_owned();
        assert_ne!(suffix(&a), suffix(&b));
    }

    #[test]
    fn stop_listed_terms_survive_into_the_twin() {
        let mut g = graph();
        let out = sanitize("Built with React and Postgres.", "project", &detector(), &mut g, None).unwrap();
        assert!(out.twin.contains("React"));
        assert!(out.twin.contains("Postgres"));
    }
}
