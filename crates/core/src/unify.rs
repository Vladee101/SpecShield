//! Cross-artifact unification — SDD §5.
//!
//! The SQL table `customer_subscription`, the OpenAPI schema
//! `CustomerSubscription`, and the TypeScript DTO of the same name are one
//! concept. A twin that gives them three unrelated aliases hands the model three
//! unrelated things and loses the structure the graph exists to preserve.
//!
//! # Where the specification is not implementable as written
//!
//! SDD §5 says they "must resolve to **one** identity carrying **one** alias".
//! One alias cannot work, and the reason is the core invariant.
//!
//! `identities.alias` is UNIQUE, so one alias maps to one real name. If
//! `customer_subscription` and `CustomerSubscription` share an alias, restoring
//! that token has one answer — but the SQL file needs `customer_subscription`
//! and the TypeScript file needs `CustomerSubscription`. Whichever is stored,
//! one of the two files comes back wrong, and `restore(sanitize(x)) == x` fails.
//!
//! **What is implemented instead: one concept, one alias *suffix*, per-artifact
//! prefix.**
//!
//! | Artifact | Real name | Alias |
//! |---|---|---|
//! | SQL | `customer_subscription` | `DB_TABLE_H7K2Q3` |
//! | OpenAPI | `CustomerSubscription` | `DTO_H7K2Q3` |
//! | TypeScript | `CustomerSubscription` | `DTO_H7K2Q3` |
//!
//! The shared suffix makes the relationship visible — a model reading the twin
//! sees the same connection it would see between `customer_subscription` and
//! `CustomerSubscription` in the real project, which is exactly the naming
//! convention it was trained on. Restoration stays unambiguous because the
//! aliases are still distinct, and the grammar is unchanged.
//!
//! # Nothing is unified automatically
//!
//! SDD §5 says unification is "confirmable by the user", and the reason is in
//! `corpus/adversarial`: three unrelated `Status` enums in three modules. A
//! matcher that merged on name would collapse them, which is Design Review B1
//! reintroduced by the back door.
//!
//! So a name match alone is never enough. A proposal requires a **compatible
//! pair of different kinds** — Table with DTO, Service with API — because the
//! differing kind is the evidence that these are one thing seen from two sides.
//! Three enums with one name and one kind is a name collision, and this module
//! says so rather than guessing.

use std::collections::BTreeMap;

use crate::model::{EntityType, IdentityKey};

/// Normalized form used to compare names across naming conventions.
///
/// `customer_subscription`, `CustomerSubscription`, and `customer-subscription`
/// all reduce to `customersubscription`.
pub fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Kinds that can name the same concept in different artifacts.
///
/// Deliberately narrow. A Column and a Column are not a pair — `customer_id`
/// appears in a dozen tables, and merging on name is the mistake this module
/// exists to avoid.
fn is_compatible_pair(a: EntityType, b: EntityType) -> bool {
    use EntityType::{Api, Dto, Enum, Event, Interface, Service, Table};
    let pair = (a.min(b), a.max(b));
    matches!(
        pair,
        (Table, Dto | Interface | Enum) | (Dto, Interface | Enum) | (Service, Api | Event)
    )
}

/// Kinds eligible for unification at all.
///
/// Members — columns, properties, endpoints — are excluded. They are scoped to
/// a parent, and matching them across artifacts by name would merge
/// `invoice.customer_id` with `customer_subscription.customer_id`.
fn is_unifiable(entity_type: EntityType) -> bool {
    matches!(
        entity_type,
        EntityType::Table
            | EntityType::Dto
            | EntityType::Interface
            | EntityType::Enum
            | EntityType::Service
            | EntityType::Api
            | EntityType::Event
    )
}

/// Why a proposal was made, so the user can judge it rather than trust it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// The names normalize to the same string and the kinds form a compatible
    /// pair. This is the strong case.
    CompatibleKinds { kinds: Vec<EntityType> },
}

/// A suggested unification. **Never applied without confirmation.**
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    /// The normalized name shared by every member. Used as the concept id when
    /// the proposal is confirmed.
    pub concept: String,
    /// The identities this would link, in a stable order.
    pub members: Vec<IdentityKey>,
    pub evidence: Evidence,
    /// 0.0–1.0. Below 1.0 means something about the match is ambiguous and the
    /// reason is in [`Proposal::caveat`].
    pub confidence: f32,
    /// What makes this uncertain, if anything.
    pub caveat: Option<String>,
}

impl Proposal {
    /// The distinct entity kinds involved.
    pub fn kinds(&self) -> Vec<EntityType> {
        let mut kinds: Vec<EntityType> = self.members.iter().map(|m| m.entity_type).collect();
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    }
}

/// Find identities that look like one concept seen from several artifacts.
///
/// Returns proposals only. Applying one is [`crate::sanitize::Graph::confirm_concept`],
/// and that is a deliberate act.
pub fn propose(identities: &[IdentityKey]) -> Vec<Proposal> {
    let mut groups: BTreeMap<String, Vec<&IdentityKey>> = BTreeMap::new();
    for key in identities.iter().filter(|k| is_unifiable(k.entity_type)) {
        groups.entry(normalize(&key.real_name)).or_default().push(key);
    }

    let mut proposals = Vec::new();
    for (concept, members) in groups {
        if members.len() < 2 {
            continue;
        }

        let mut kinds: Vec<EntityType> = members.iter().map(|m| m.entity_type).collect();
        kinds.sort_unstable();
        kinds.dedup();

        // One kind means one name used repeatedly, not one concept seen twice.
        // This is the `Status` case: three enums in three modules, unrelated.
        if kinds.len() < 2 {
            continue;
        }

        // Every kind present must pair with some other kind present. A stray
        // `Host` sharing a name with a `Service` is a coincidence.
        let all_pair = kinds
            .iter()
            .all(|a| kinds.iter().any(|b| a != b && is_compatible_pair(*a, *b)));
        if !all_pair {
            continue;
        }

        // If one kind appears more than once, which member the others
        // correspond to is not determined. Still worth proposing — the user can
        // see it — but not at full confidence.
        let duplicated: Vec<EntityType> = kinds
            .iter()
            .copied()
            .filter(|k| members.iter().filter(|m| m.entity_type == *k).count() > 1)
            .collect();

        let (confidence, caveat) = if duplicated.is_empty() {
            (1.0, None)
        } else {
            (
                0.5,
                Some(format!(
                    "{} appears more than once under this name, so which member the others \
                     correspond to is not determined by the name alone",
                    duplicated
                        .iter()
                        .map(|k| k.prefix().to_owned())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            )
        };

        let mut members: Vec<IdentityKey> = members.into_iter().cloned().collect();
        members.sort();

        proposals.push(Proposal {
            concept,
            members,
            evidence: Evidence::CompatibleKinds { kinds },
            confidence,
            caveat,
        });
    }

    proposals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(scope: &str, entity_type: EntityType, name: &str) -> IdentityKey {
        IdentityKey::new(scope, entity_type, name)
    }

    #[test]
    fn normalization_crosses_naming_conventions() {
        for name in [
            "customer_subscription",
            "CustomerSubscription",
            "customer-subscription",
            "customerSubscription",
            "CUSTOMER_SUBSCRIPTION",
        ] {
            assert_eq!(normalize(name), "customersubscription", "{name}");
        }
    }

    #[test]
    fn the_sdd_example_is_proposed() {
        // SQL table, OpenAPI schema, TypeScript DTO — one concept.
        let identities = vec![
            key("sql::customer_subscription", EntityType::Table, "customer_subscription"),
            key(
                "#/components/schemas/CustomerSubscription",
                EntityType::Dto,
                "CustomerSubscription",
            ),
            key(
                "src/domain/customer-subscription.ts::CustomerSubscription",
                EntityType::Interface,
                "CustomerSubscription",
            ),
        ];
        let proposals = propose(&identities);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].concept, "customersubscription");
        assert_eq!(proposals[0].members.len(), 3);
    }

    #[test]
    fn three_unrelated_enums_with_one_name_are_not_proposed() {
        // corpus/adversarial. Merging these is Design Review B1 reintroduced,
        // and a name match is not evidence of anything.
        let identities = vec![
            key("modules/order-status.ts::Status", EntityType::Enum, "Status"),
            key("modules/payment-status.ts::Status", EntityType::Enum, "Status"),
            key("modules/invoice-status.ts::Status", EntityType::Enum, "Status"),
        ];
        assert!(
            propose(&identities).is_empty(),
            "one kind is a collision, not a concept"
        );
    }

    #[test]
    fn columns_are_never_unified_across_artifacts() {
        // `customer_id` is in a dozen tables. Matching members by name would
        // merge them all.
        let identities = vec![
            key("sql::invoice.customer_id", EntityType::Column, "customer_id"),
            key(
                "#/components/schemas/CustomerSubscription.customerId",
                EntityType::Column,
                "customerId",
            ),
        ];
        assert!(propose(&identities).is_empty());
    }

    #[test]
    fn a_service_and_its_api_are_proposed() {
        let identities = vec![
            key("project", EntityType::Service, "BillingService"),
            key("#/info/title", EntityType::Api, "BillingService"),
        ];
        assert_eq!(propose(&identities).len(), 1);
    }

    #[test]
    fn incompatible_kinds_sharing_a_name_are_not_proposed() {
        // A host and a service with the same string is a coincidence.
        let identities = vec![
            key("project", EntityType::Service, "billing"),
            key("project", EntityType::Domain, "billing"),
        ];
        assert!(propose(&identities).is_empty());
    }

    #[test]
    fn an_ambiguous_match_is_proposed_but_flagged() {
        // Two tables and one DTO: which table the DTO mirrors is not something
        // the name can tell us. Worth showing the user; not worth asserting.
        let identities = vec![
            key("sql::a.subscription", EntityType::Table, "subscription"),
            key("sql::b.subscription", EntityType::Table, "subscription"),
            key("#/components/schemas/Subscription", EntityType::Dto, "Subscription"),
        ];
        let proposals = propose(&identities);
        assert_eq!(proposals.len(), 1);
        assert!(proposals[0].confidence < 1.0);
        assert!(proposals[0].caveat.is_some());
    }

    #[test]
    fn a_lone_identity_is_not_a_concept() {
        let identities = vec![key("sql::invoice", EntityType::Table, "invoice")];
        assert!(propose(&identities).is_empty());
    }

    #[test]
    fn proposals_are_deterministic() {
        let identities = vec![
            key("#/components/schemas/Invoice", EntityType::Dto, "Invoice"),
            key("sql::invoice", EntityType::Table, "invoice"),
        ];
        assert_eq!(propose(&identities), propose(&identities));
    }
}
