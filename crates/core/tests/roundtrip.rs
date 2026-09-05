//! The core invariant, as a property — PRD §5, Implementation Plan M1.
//!
//! `restore(sanitize(x)) == x` byte-for-byte, for arbitrary text. Unit tests
//! cover the cases we thought of; this covers the ones we did not.

use proptest::prelude::*;
use specshield_core::detect::Detector;
use specshield_core::model::EntityType;
use specshield_core::parser::ProjectContext;
use specshield_core::restore::{Vocabulary, restore};
use specshield_core::sanitize::{Graph, sanitize};
use specshield_core::verify::LeakScanner;

fn graph() -> Graph {
    Graph::new()
}

fn detector() -> Detector {
    Detector::new()
        .with_term("Vantor", EntityType::Organization)
        .with_term("Meridian Freight", EntityType::Organization)
        .with_term("Paylane", EntityType::Organization)
}

/// Text built from fragments that actually exercise the pipeline: entity names,
/// prose, punctuation, markdown structure, and Unicode.
fn document() -> impl Strategy<Value = String> {
    let fragment = prop_oneof![
        Just("Vantor".to_owned()),
        Just("Meridian Freight".to_owned()),
        Just("SubscriptionService".to_owned()),
        Just("CreateSubscriptionDto".to_owned()),
        Just("PlanTier".to_owned()),
        Just("SubscriptionCreated".to_owned()),
        Just("billing.vantor.internal".to_owned()),
        Just("VANTOR_BILLING_URL".to_owned()),
        Just("plan tiers".to_owned()),
        Just("the subscription service".to_owned()),
        Just("React".to_owned()),
        Just("Postgres".to_owned()),
        Just("MAX_RETRIES".to_owned()),
        Just("# Heading".to_owned()),
        Just("\n\n".to_owned()),
        Just("  ".to_owned()),
        Just("\t".to_owned()),
        Just("- item".to_owned()),
        Just("```ts".to_owned()),
        Just("émigré — naïve".to_owned()),
        Just("日本語".to_owned()),
        Just(".".to_owned()),
        Just(", ".to_owned()),
        "[a-zA-Z0-9 ]{0,20}",
    ];
    proptest::collection::vec(fragment, 0..24).prop_map(|parts| parts.join(" "))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// The invariant.
    #[test]
    fn restore_undoes_sanitize(source in document()) {
        {
            let mut g = graph();
            let out = sanitize(&source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();
            let back = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
            prop_assert_eq!(&back.text, &source);
        }
    }

    /// A verified twin never contains a name the vault knows. This is the
    /// promise the product is built on (SDD §8).
    #[test]
    fn the_twin_never_contains_a_known_real_name(source in document()) {
        let mut g = graph();
        let out = sanitize(&source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();
        let scanner = LeakScanner::new(g.real_names());
        prop_assert!(scanner.scan(&out.twin).is_clean(), "leaked: {:?}", out.twin);
    }

    /// Sanitizing twice must not double-alias: the second pass sees aliases,
    /// not names, and must leave them alone.
    #[test]
    fn sanitize_is_idempotent(source in document()) {
        let mut g = graph();
        let once = sanitize(&source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();
        let twice = sanitize(&once.twin, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();
        prop_assert_eq!(&twice.twin, &once.twin);
    }

    /// Restoring text with no aliases in it changes nothing.
    #[test]
    fn restore_is_a_no_op_without_aliases(source in document()) {
        let g = graph();
        let out = restore(&source, &Vocabulary::new(g.vocabulary()));
        prop_assert_eq!(&out.text, &source);
    }

    /// Every alias in a twin resolves. An alias that restore cannot resolve is
    /// a silent data-loss bug — PRD §5 allows zero of them.
    #[test]
    fn every_applied_alias_resolves(source in document()) {
        let mut g = graph();
        let out = sanitize(&source, "project", &detector(), &mut g, None, &ProjectContext::default()).unwrap();
        let back = restore(&out.twin, &Vocabulary::new(g.vocabulary()));
        prop_assert!(
            back.unresolved.is_empty(),
            "unresolved after our own sanitize: {:?}",
            back.unresolved
        );
        prop_assert_eq!(back.restored.len(), out.applied.len());
    }
}
