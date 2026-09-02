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
//! Two identities can derive the same alias. The loser takes a deterministic
//! `_2` suffix, so *which* one loses depends on which is processed first. Sorting
//! by UUID before deriving makes that stable: re-keying the same vault twice
//! produces the same answer, and two machines agree without coordinating.

use std::collections::HashSet;

use crate::alias::{AliasStyle, ProjectKey, derive_in_concept};
use crate::model::IdentityKey;

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

/// Re-derive every alias, in place. Returns how many actually changed.
///
/// Derivation is deterministic, so an identity whose scope, type, name, and
/// concept are unchanged keeps exactly the alias it had — under the *same*
/// project key. Under a new one, everything moves.
///
/// The returned count is what a caller warns on: telling a user that "0 aliases
/// changed" after confirming a concept is how the inert `unify --confirm` bug
/// went unnoticed.
pub fn rederive(project_key: &ProjectKey, style: AliasStyle, identities: &mut [Rekeyed]) -> usize {
    identities.sort_by(|a, b| a.uuid.cmp(&b.uuid));

    let mut used: HashSet<String> = HashSet::new();
    let mut changed = 0;

    for identity in identities.iter_mut() {
        let mut disambiguator = None;
        let alias = loop {
            let candidate = derive_in_concept(
                project_key,
                &identity.key,
                style,
                disambiguator,
                identity.concept.as_deref(),
            );
            if used.insert(candidate.clone()) {
                break candidate;
            }
            disambiguator = Some(disambiguator.unwrap_or(1) + 1);
        };

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
            key: IdentityKey::new(scope, EntityType::Service, name),
            alias: String::new(),
            concept: None,
        }
    }

    #[test]
    fn re_deriving_under_the_same_key_changes_nothing_the_second_time() {
        let key = ProjectKey::from_bytes([4; 32]);
        let mut identities = vec![
            identity("a", "mod/a", "CustomerService"),
            identity("b", "mod/b", "BillingService"),
        ];

        assert_eq!(rederive(&key, AliasStyle::Opaque, &mut identities), 2);
        let after_first: Vec<String> = identities.iter().map(|i| i.alias.clone()).collect();

        assert_eq!(rederive(&key, AliasStyle::Opaque, &mut identities), 0);
        let after_second: Vec<String> = identities.iter().map(|i| i.alias.clone()).collect();
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn a_new_project_key_moves_every_alias() {
        // FR-11's whole purpose: an over-shared twin stops resolving.
        let mut identities = vec![identity("a", "mod/a", "CustomerService")];
        rederive(&ProjectKey::from_bytes([4; 32]), AliasStyle::Opaque, &mut identities);
        let before = identities[0].alias.clone();

        let changed = rederive(&ProjectKey::from_bytes([5; 32]), AliasStyle::Opaque, &mut identities);
        assert_eq!(changed, 1);
        assert_ne!(identities[0].alias, before);
    }

    #[test]
    fn no_two_identities_share_an_alias() {
        // The one failure with no safe recovery: a shared alias makes restore
        // ambiguous (SDD §10.4).
        let key = ProjectKey::from_bytes([4; 32]);
        let mut identities: Vec<Rekeyed> = (0..200)
            .map(|i| identity(&format!("{i:04}"), "mod/a", &format!("Service{i}")))
            .collect();

        rederive(&key, AliasStyle::Opaque, &mut identities);

        let unique: HashSet<&str> = identities.iter().map(|i| i.alias.as_str()).collect();
        assert_eq!(unique.len(), identities.len());
    }

    #[test]
    fn the_outcome_does_not_depend_on_the_order_they_arrive_in() {
        // Two identities can derive the same alias; the loser takes a `_2`.
        // Which one loses must not depend on the order storage happened to
        // return them, or two machines would disagree.
        let key = ProjectKey::from_bytes([4; 32]);
        let mut forwards = vec![
            identity("a", "mod/a", "CustomerService"),
            identity("b", "mod/b", "BillingService"),
            identity("c", "mod/c", "InvoiceService"),
        ];
        let mut backwards: Vec<Rekeyed> = forwards.iter().rev().cloned().collect();

        rederive(&key, AliasStyle::Opaque, &mut forwards);
        rederive(&key, AliasStyle::Opaque, &mut backwards);

        assert_eq!(forwards, backwards);
    }

    #[test]
    fn a_confirmed_concept_moves_its_members_and_nothing_else() {
        // SDD §5: members of one concept share an alias suffix. Confirming a
        // concept must move exactly those, which is what the caller reports.
        let key = ProjectKey::from_bytes([4; 32]);
        let mut identities = vec![
            identity("a", "mod/a", "CustomerService"),
            identity("b", "mod/b", "BillingService"),
        ];
        rederive(&key, AliasStyle::Opaque, &mut identities);
        let untouched = identities[1].alias.clone();

        identities[0].concept = Some("customerservice".to_owned());
        let changed = rederive(&key, AliasStyle::Opaque, &mut identities);

        assert_eq!(changed, 1, "only the confirmed member moves");
        assert_eq!(identities[1].alias, untouched);
    }

    #[test]
    fn an_empty_project_is_not_an_error() {
        let mut nothing: Vec<Rekeyed> = Vec::new();
        assert_eq!(
            rederive(&ProjectKey::from_bytes([4; 32]), AliasStyle::Opaque, &mut nothing),
            0
        );
    }
}
