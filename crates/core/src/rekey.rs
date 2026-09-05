//! Alias re-derivation — PRD FR-11, SDD §9.5. **M6.**
//!
//! Two callers need this and it must not drift between them: the command line
//! and the desktop application both re-key, and an alias derived one way in one
//! surface and another way in the other would mean a twin produced by one could
//! not be restored by the other.
//!
//! Storage stays with the caller. This module is given identities and hands back
//! the aliases they should now carry, which also makes the part worth testing —
//! collision handling and ordering — testable without a vault.
//!
//! # Why order matters
//!
//! Numbers are handed out in sequence, so *which* identity gets `ORG_001`
//! depends on which is processed first. Sorting by UUID before allocating makes
//! that stable: renumbering the same vault twice produces the same answer.

use std::collections::HashSet;

use std::collections::HashMap;

use crate::alias;
use crate::model::{EntityType, IdentityKey};

/// One identity as storage holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rekeyed {
    /// Row identity, and the sort key that makes collision handling stable.
    pub uuid: String,
    pub key: IdentityKey,
    /// The alias on the way in; the newly derived one on the way out.
    pub alias: String,
    /// The confirmed concept this identity belongs to, if any — SDD §5.
    pub concept: Option<String>,
}

/// Renumber every alias, in place. Returns how many actually changed.
///
/// **This is now a renumbering, not a re-derivation, and the difference is
/// visible to the user.** Aliases used to be a pure function of the project key
/// and the identity, so re-keying under the *same* key changed nothing and under
/// a new one changed everything. Numbers are allocated instead (PRD §13), so
/// there is no key to change: this hands out `_001`, `_002`, … from scratch in
/// UUID order, and the answer differs from what a project is carrying whenever
/// identities were added or removed since.
///
/// It is still what a re-key is for — orphaning every twin already shared —
/// and it is still the thing `unify --confirm` needs, because a concept only
/// takes effect when its members are renumbered onto a shared number.
///
/// The returned count is what a caller warns on: telling a user that "0 aliases
/// changed" after confirming a concept is how the inert `unify --confirm` bug
/// went unnoticed.
pub fn rederive(identities: &mut [Rekeyed]) -> usize {
    identities.sort_by(|a, b| a.uuid.cmp(&b.uuid));

    let mut used: HashSet<String> = HashSet::new();
    let mut next: HashMap<EntityType, u32> = HashMap::new();
    let mut concept_numbers: HashMap<String, u32> = HashMap::new();
    let mut changed = 0;

    for identity in identities.iter_mut() {
        let entity_type = identity.key.entity_type;

        // A concept's members share a number where the type allows it — SDD §5.
        let shared = identity
            .concept
            .as_ref()
            .and_then(|c| concept_numbers.get(c).copied())
            .map(|n| alias::format_alias(entity_type, n))
            .filter(|a| !used.contains(a));

        let alias = shared.unwrap_or_else(|| {
            let number = next.entry(entity_type).or_insert(1);
            let mut candidate = alias::format_alias(entity_type, *number);
            while used.contains(&candidate) {
                *number += 1;
                candidate = alias::format_alias(entity_type, *number);
            }
            *number += 1;
            candidate
        });

        if let Some(concept) = identity.concept.clone()
            && let Some((_, number)) = alias::parse(&alias)
        {
            concept_numbers.entry(concept).or_insert(number);
        }
        used.insert(alias.clone());

        if alias != identity.alias {
            changed += 1;
            identity.alias = alias;
        }
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EntityType;

    fn identity(uuid: &str, scope: &str, name: &str) -> Rekeyed {
        Rekeyed {
            uuid: uuid.to_owned(),
            key: IdentityKey::new(scope, EntityType::Organization, name),
            alias: String::new(),
            concept: None,
        }
    }

    #[test]
    fn renumbering_is_stable_the_second_time() {
        let mut identities = vec![identity("a", "mod/a", "Vantor"), identity("b", "mod/b", "Paylane")];

        assert_eq!(rederive(&mut identities), 2);
        let after_first: Vec<String> = identities.iter().map(|i| i.alias.clone()).collect();
        assert_eq!(after_first, vec!["ORG_001".to_owned(), "ORG_002".to_owned()]);

        assert_eq!(rederive(&mut identities), 0, "nothing moved, so nothing is reported");
        let after_second: Vec<String> = identities.iter().map(|i| i.alias.clone()).collect();
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn removing_an_identity_moves_the_ones_after_it() {
        // The consequence of counting rather than deriving, and the reason a
        // re-key still orphans twins: an alias is a position in a sequence, so
        // deleting an earlier identity shifts every later one.
        let mut identities = vec![
            identity("a", "mod/a", "Vantor"),
            identity("b", "mod/b", "Paylane"),
            identity("c", "mod/c", "Meridian"),
        ];
        rederive(&mut identities);
        assert_eq!(identities[2].alias, "ORG_003");

        identities.remove(1);
        assert_eq!(rederive(&mut identities), 1);
        assert_eq!(identities[1].alias, "ORG_002");
    }

    #[test]
    fn numbers_are_per_type() {
        // PRD §13 shows `ORG_001` and `PRODUCT_001` side by side: the counters
        // are independent, and the first of each kind is 001.
        let mut identities = vec![
            Rekeyed {
                uuid: "a".to_owned(),
                key: IdentityKey::new("p", EntityType::Organization, "Vantor"),
                alias: String::new(),
                concept: None,
            },
            Rekeyed {
                uuid: "b".to_owned(),
                key: IdentityKey::new("p", EntityType::Product, "Gold Business Subscription"),
                alias: String::new(),
                concept: None,
            },
        ];
        rederive(&mut identities);
        assert_eq!(identities[0].alias, "ORG_001");
        assert_eq!(identities[1].alias, "PRODUCT_001");
    }

    #[test]
    fn a_concept_shares_its_number_across_types() {
        // SDD §5. `DB_TABLE_001` and `DTO_001` are visibly the same thing to a
        // reader and to a model, and they still restore unambiguously because
        // the prefixes differ.
        let mut identities = vec![
            Rekeyed {
                uuid: "a".to_owned(),
                key: IdentityKey::new("db", EntityType::Table, "customer_subscription"),
                alias: String::new(),
                concept: Some("customersubscription".to_owned()),
            },
            Rekeyed {
                uuid: "b".to_owned(),
                key: IdentityKey::new("api", EntityType::Dto, "CustomerSubscription"),
                alias: String::new(),
                concept: Some("customersubscription".to_owned()),
            },
        ];
        rederive(&mut identities);

        let numbers: Vec<u32> = identities
            .iter()
            .map(|i| crate::alias::parse(&i.alias).expect("an alias").1)
            .collect();
        assert_eq!(numbers[0], numbers[1], "one concept, one number: {identities:?}");
    }

    #[test]
    fn no_two_identities_share_an_alias() {
        // The one failure with no safe recovery: a shared alias makes restore
        // ambiguous (SDD §10.4).
        let mut identities: Vec<Rekeyed> = (0..200)
            .map(|i| identity(&format!("{i:04}"), "mod/a", &format!("Company{i}")))
            .collect();

        rederive(&mut identities);

        let unique: HashSet<&str> = identities.iter().map(|i| i.alias.as_str()).collect();
        assert_eq!(unique.len(), identities.len());
    }

    #[test]
    fn the_outcome_does_not_depend_on_the_order_they_arrive_in() {
        // Which identity gets `ORG_001` must not depend on the order storage
        // happened to return them, or renumbering the same vault twice would
        // give two answers.
        let forwards_source = vec![
            identity("a", "mod/a", "Vantor"),
            identity("b", "mod/b", "Paylane"),
            identity("c", "mod/c", "Meridian"),
        ];
        let mut forwards = forwards_source.clone();
        let mut backwards: Vec<Rekeyed> = forwards_source.iter().rev().cloned().collect();

        rederive(&mut forwards);
        rederive(&mut backwards);

        assert_eq!(forwards, backwards);
    }
}
