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
