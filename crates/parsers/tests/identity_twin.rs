//! A markdown file full of identity, end to end — PRD §7, FR-3.
//!
//! The unit tests cover each detector pass on its own. This one covers the
//! thing that actually broke: every pass worked, one of them produced a span
//! containing a line break, the SDD §7.2 structural check saw the twin lose a
//! line, and the whole file's aliasing was abandoned. Nine correct detections
//! and a completely unaliased twin, reported as "verified clean".
//!
//! So the assertion here is not "the detector found X". It is "the twin that
//! reaches the model has the identity replaced and the structure intact".

use specshield_core::detect::Detector;
use specshield_core::parser::ProjectContext;
use specshield_core::sanitize::{Graph, sanitize};

const NOTES: &str = "\
# Billing integration

Contact: Jane Okafor
Reviewed-by: Samuel Adeyemi

BillingService charges Stripe and falls back to Adyen.
Notifications go through Twilio; tokens come from Auth0.
Errors land in Sentry, metrics in Datadog.

A React front end talks to Postgres via Prisma.
";

fn twin(source: &str) -> specshield_core::sanitize::Sanitized {
    let path = std::path::Path::new("notes.md");
    let parser = specshield_parsers::for_document(path, source).expect("markdown parser");
    sanitize(
        source,
        "notes.md",
        &Detector::new(),
        &mut Graph::new(),
        Some(parser.as_ref()),
        &ProjectContext::new(Vec::new(), Vec::new()),
    )
    .expect("sanitize")
}

#[test]
fn identity_leaves_and_structure_stays() {
    let out = twin(NOTES);

    assert!(
        out.verification.aliases_applied(),
        "aliasing was abandoned: {:?}",
        out.verification
    );
    assert_eq!(
        out.twin.lines().count(),
        NOTES.lines().count(),
        "the twin must have the same shape as the source"
    );

    // Who we deal with: gone.
    for identity in [
        "Jane Okafor",
        "Samuel Adeyemi",
        "Stripe",
        "Adyen",
        "Twilio",
        "Auth0",
        "Sentry",
        "Datadog",
    ] {
        assert!(
            !out.twin.contains(identity),
            "{identity} survived into the twin:\n{}",
            out.twin
        );
    }

    // What we built, and what we built it with: kept. An agent that cannot read
    // the architecture cannot help extend it (PRD §4.1).
    for structure in ["BillingService", "React", "Postgres", "Prisma"] {
        assert!(
            out.twin.contains(structure),
            "{structure} was aliased away and should not have been:\n{}",
            out.twin
        );
    }
}

#[test]
fn the_twin_restores_byte_for_byte() {
    let out = twin(NOTES);
    let vocabulary = specshield_core::restore::Vocabulary::new(
        out.applied.iter().map(|hit| (hit.alias.clone(), hit.real_name.clone())),
    );
    assert_eq!(specshield_core::restore::restore(&out.twin, &vocabulary).text, NOTES);
}

/// The same file the corpus grades, as a diagram rather than as prose.
const DIAGRAM: &str = "@startuml Vantor billing
skinparam backgroundColor #FEFEFE

actor \"Jane Okafor\" as Ops
participant BillingService
participant \"Stripe\" as payments
node \"api.vantor-freight.com\" as edge

Ops -> BillingService: chargeInvoice()
BillingService -> payments: capture()
edge --> BillingService

class CustomerSubscription {
  +customerId: UUID
}
@enduml
";

fn diagram_twin(source: &str) -> specshield_core::sanitize::Sanitized {
    let path = std::path::Path::new("flow.puml");
    let parser = specshield_parsers::for_document(path, source).expect("plantuml parser");
    assert_eq!(parser.name(), "plantuml");
    sanitize(
        source,
        "flow.puml",
        &Detector::new().with_term("Vantor", specshield_core::model::EntityType::Organization),
        &mut Graph::new(),
        Some(parser.as_ref()),
        &ProjectContext::new(Vec::new(), Vec::new()),
    )
    .expect("sanitize")
}

#[test]
fn a_diagram_loses_its_identity_and_still_renders() {
    // Three things at once, and the third is the one only an end-to-end test
    // sees: the identity goes, the architecture stays, and every name an arrow
    // refers to still exists. A twin where `actor \"Jane Okafor\" as Ops` became
    // `actor \"PERSON_001\" as PERSON_002` while `Ops -> BillingService` was left
    // alone is a diagram that no longer renders, and nothing else catches it.
    let out = diagram_twin(DIAGRAM);

    assert!(
        out.verification.aliases_applied(),
        "aliasing was abandoned: {:?}",
        out.verification
    );

    for identity in ["Vantor", "Jane Okafor", "Stripe", "api.vantor-freight.com"] {
        assert!(!out.twin.contains(identity), "{identity} survived:\n{}", out.twin);
    }
    for structure in ["BillingService", "CustomerSubscription", "customerId", "chargeInvoice"] {
        assert!(
            out.twin.contains(structure),
            "{structure} was aliased away:\n{}",
            out.twin
        );
    }

    // Every bare token on an arrow line must still name something declared.
    let declared: Vec<&str> = out
        .twin
        .lines()
        .filter_map(|line| line.rsplit(" as ").next().filter(|_| line.contains(" as ")))
        .collect();
    for shorthand in ["Ops", "payments", "edge"] {
        assert!(
            declared.contains(&shorthand),
            "the arrows still say {shorthand:?}, but nothing declares it: {declared:?}\n{}",
            out.twin
        );
    }
}

#[test]
fn the_diagram_restores_byte_for_byte() {
    let out = diagram_twin(DIAGRAM);
    let vocabulary = specshield_core::restore::Vocabulary::new(
        out.applied.iter().map(|hit| (hit.alias.clone(), hit.real_name.clone())),
    );
    assert_eq!(specshield_core::restore::restore(&out.twin, &vocabulary).text, DIAGRAM);
}
