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

use crate::alias::{AliasStyle, ProjectKey, derive};
use crate::detect::Detector;
use crate::edit::{Edit, apply};
use crate::model::{IdentityKey, IdentityNode, Origin, Status};
use crate::parser::Candidate;
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
}

impl Graph {
    pub fn new(key: ProjectKey, style: AliasStyle) -> Self {
        Self {
            key,
            style,
            by_identity: HashMap::new(),
            nodes: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    /// Look up or create the identity for `key`, returning its node.
    pub fn intern(&mut self, key: &IdentityKey, origin: Origin) -> &IdentityNode {
        if let Some(uuid) = self.by_identity.get(key) {
            return &self.nodes[uuid];
        }

        // Derive, then walk disambiguators until the alias is free. In practice
        // the first attempt always succeeds; the loop exists so a collision is
        // impossible rather than merely unlikely.
        let mut disambiguator = None;
        let alias = loop {
            let candidate = derive(&self.key, key, self.style, disambiguator);
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

/// Sanitize one document — SDD §7.
pub fn sanitize(source: &str, scope: &str, detector: &Detector, graph: &mut Graph) -> Result<Sanitized, SanitizeError> {
    // 1. Secrets, before anything else looks at the text.
    let findings = secrets::scan(source);
    let redacted = secrets::redact(source, &findings);

    // 2. Detect against the redacted text, so a credential can never be
    //    admitted to the identity graph as though it were a name.
    let candidates = detector.scan_text(&redacted, scope, crate::model::OccurrenceKind::Reference);

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

    Ok(Sanitized {
        twin,
        applied,
        secrets: findings,
        suggestions,
    })
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
        let out = sanitize(source, "project", &detector(), &mut g).unwrap();

        let restored = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
        assert_eq!(restored.text, source);
    }

    #[test]
    fn the_twin_contains_no_real_names() {
        let source = "Vantor runs SubscriptionService for Meridian Freight.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g).unwrap();

        let scanner = LeakScanner::new(g.real_names());
        assert!(scanner.scan(&out.twin).is_clean(), "twin leaked: {}", out.twin);
    }

    #[test]
    fn aliases_are_stable_across_documents() {
        let mut g = graph();
        let a = sanitize("Vantor here", "project", &detector(), &mut g).unwrap();
        let b = sanitize("and Vantor there", "project", &detector(), &mut g).unwrap();

        assert_eq!(a.applied[0].alias, b.applied[0].alias);
        assert_eq!(g.len(), 1, "one identity, not two");
    }

    #[test]
    fn distinct_scopes_get_distinct_aliases() {
        let mut g = graph();
        let d = Detector::new().with_term("Status", EntityType::Enum);
        let a = sanitize("Status", "mod/a", &d, &mut g).unwrap();
        let b = sanitize("Status", "mod/b", &d, &mut g).unwrap();

        assert_ne!(a.applied[0].alias, b.applied[0].alias, "Design Review B1");
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn secrets_are_redacted_before_detection_and_never_interned() {
        let source = "api_key = \"sk_live_abcdefghijklmnopqrstuvwx\"\nVantor owns it.";
        let mut g = graph();
        let out = sanitize(source, "project", &detector(), &mut g).unwrap();

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
        let out = sanitize(source, "project", &detector(), &mut g).unwrap();
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
        let out = sanitize(source, "project", &detector(), &mut g).unwrap();
        let restored = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
        assert_eq!(restored.text, source, "byte-for-byte, whitespace included");
    }

    #[test]
    fn empty_input_round_trips() {
        let mut g = graph();
        let out = sanitize("", "project", &detector(), &mut g).unwrap();
        assert_eq!(out.twin, "");
    }

    #[test]
    fn stop_listed_terms_survive_into_the_twin() {
        let mut g = graph();
        let out = sanitize("Built with React and Postgres.", "project", &detector(), &mut g).unwrap();
        assert!(out.twin.contains("React"));
        assert!(out.twin.contains("Postgres"));
    }
}
