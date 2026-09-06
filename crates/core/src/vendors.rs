//! Commercial services, and the people named in a codebase — PRD §7, FR-3.
//!
//! Two categories that can be found without being told, unlike the rest of the
//! identity model. `Vantor` is unguessable and needs `specshield term`; `Stripe`
//! and `@author Jane Okafor` are not.
//!
//! # Where the line falls between this and [`crate::detect::STOP_LIST`]
//!
//! Both hold third-party names, and they are treated as opposites. The question
//! is **do you have an account with them?**
//!
//! - `React`, `Postgres`, `Kubernetes` — tooling. Everybody uses them, they say
//!   nothing about your business, and aliasing them makes a twin unreadable for
//!   no gain. Those live in `STOP_LIST` and are never aliased.
//! - `Stripe`, `Twilio`, `Auth0` — a commercial relationship. Which processor
//!   takes your money, who sends your messages, and who holds your identities
//!   are facts about your company, and PRD §7 lists partners and payment
//!   providers among the things to neutralize.
//!
//! `AWS`, `Azure` and `GCP` sit on the tooling side by judgement rather than by
//! rule: you do have an account, but so does everyone, and the disclosure is
//! close to nil.
//!
//! # The cost, which is real
//!
//! These match case-insensitively, so `stripe` in a CSS file is a false
//! positive. Several are ordinary English words in other contexts. That trade
//! is the same one the whole detector makes — over-aliasing is recoverable with
//! `specshield allow`, under-aliasing is not — but names that are *usually* the
//! ordinary word rather than the company are deliberately absent below.
//! `Square`, `Wise`, `Affirm`, `Plaid`, `Block`, `Segment`, `Snowflake`,
//! `Amplitude`, `Paddle`, `Clerk` and `Intercom` are all real vendors and none of
//! them is here; a team that uses one names it once with `specshield term`.
//!
//! `Stripe` is the exception that proves the rule. It is an ordinary word too,
//! and it stays because in a software project the lowercase `stripe` is
//! overwhelmingly the company — and because PRD §8's worked example turns on it.
//! `Segment` was in this table for one commit and matched the phrase "the final
//! segment" in the corpus, which is how the rule above came to be written down.

use crate::model::EntityType;

/// Services a company transacts with, by the name they appear under in code and
/// documents.
///
/// Deliberately a fixed table rather than a downloaded list: it has to be
/// reviewable in a diff and identical on every machine, and a detector that
/// changes what it finds when a feed updates is not one anybody can test.
pub const VENDORS: &[(&str, EntityType)] = &[
    // ---- Payment and financial infrastructure.
    ("Stripe", EntityType::PaymentProvider),
    ("Adyen", EntityType::PaymentProvider),
    ("Braintree", EntityType::PaymentProvider),
    ("PayPal", EntityType::PaymentProvider),
    ("Klarna", EntityType::PaymentProvider),
    ("Mollie", EntityType::PaymentProvider),
    ("GoCardless", EntityType::PaymentProvider),
    ("Razorpay", EntityType::PaymentProvider),
    ("Worldpay", EntityType::PaymentProvider),
    ("Checkout.com", EntityType::PaymentProvider),
    ("Payoneer", EntityType::PaymentProvider),
    ("Skrill", EntityType::PaymentProvider),
    ("Nuvei", EntityType::PaymentProvider),
    ("BlueSnap", EntityType::PaymentProvider),
    ("Recurly", EntityType::PaymentProvider),
    ("Chargebee", EntityType::PaymentProvider),
    ("Zuora", EntityType::PaymentProvider),
    ("Marqeta", EntityType::PaymentProvider),
    ("Afterpay", EntityType::PaymentProvider),
    ("Authorize.Net", EntityType::PaymentProvider),
    // ---- Identity and access.
    ("Auth0", EntityType::Partner),
    ("Okta", EntityType::Partner),
    ("Keycloak", EntityType::Partner),
    ("OneLogin", EntityType::Partner),
    ("WorkOS", EntityType::Partner),
    // ---- Messaging and delivery.
    ("Twilio", EntityType::Partner),
    ("SendGrid", EntityType::Partner),
    ("Mailgun", EntityType::Partner),
    ("Postmark", EntityType::Partner),
    ("Mailchimp", EntityType::Partner),
    ("Vonage", EntityType::Partner),
    ("MessageBird", EntityType::Partner),
    // ---- Observability and operations.
    ("Datadog", EntityType::Partner),
    ("Sentry", EntityType::Partner),
    ("PagerDuty", EntityType::Partner),
    ("Grafana", EntityType::Partner),
    ("Splunk", EntityType::Partner),
    ("LaunchDarkly", EntityType::Partner),
    // ---- Data, analytics, and content.
    ("Databricks", EntityType::Partner),
    ("Mixpanel", EntityType::Partner),
    ("Algolia", EntityType::Partner),
    ("Contentful", EntityType::Partner),
    ("Cloudinary", EntityType::Partner),
    // ---- Business systems.
    ("Salesforce", EntityType::Partner),
    ("HubSpot", EntityType::Partner),
    ("Zendesk", EntityType::Partner),
    ("NetSuite", EntityType::Partner),
    ("Shopify", EntityType::Partner),
    ("Xero", EntityType::Partner),
];

/// Contexts that name a person — PRD FR-3, `PERSON_001`.
///
/// Marker-driven on purpose. A rule that treated every capitalised pair of words
/// as a person would alias half the prose in a specification, and the
/// `CAPITALIZED_PHRASE` suggestion pass already surfaces those for review at low
/// confidence. What is matched here is the small set of places a codebase says
/// *this is a person* out loud: a `JSDoc` `@author`, a `Contact:` line, a
/// `Reviewed-by:` trailer.
///
/// High precision and deliberately low recall. A name that appears only in
/// running prose is found the way every other unguessable name is: the user
/// types it once.
pub const PERSON_MARKERS: &[&str] = &[
    "author",
    "authors",
    "contact",
    "owner",
    "owners",
    "maintainer",
    "maintainers",
    "assignee",
    "reviewer",
    "reviewed-by",
    "reviewed by",
    "written-by",
    "written by",
    "reported-by",
    "reported by",
    "signed-off-by",
    "co-authored-by",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_vendor_is_also_stop_listed() {
        // The two tables mean opposite things. A name in both would be aliased
        // or not depending on which pass ran first, which is the kind of
        // ambiguity nobody would find by reading.
        let stopped: HashSet<String> = crate::detect::STOP_LIST.iter().map(|s| s.to_lowercase()).collect();
        for (vendor, _) in VENDORS {
            assert!(
                !stopped.contains(&vendor.to_lowercase()),
                "{vendor} is in both VENDORS and STOP_LIST"
            );
        }
    }

    #[test]
    fn every_vendor_is_an_identity_type() {
        // A vendor filed under a structural type would be found and then not
        // aliased, which is the worst of both.
        for (vendor, entity_type) in VENDORS {
            assert!(entity_type.is_identity(), "{vendor} must be an identity type");
        }
    }

    #[test]
    fn vendors_are_unique_and_long_enough_to_match_on() {
        let mut seen = HashSet::new();
        for (vendor, _) in VENDORS {
            assert!(seen.insert(vendor.to_lowercase()), "{vendor} appears twice");
            assert!(vendor.len() >= 4, "{vendor} is too short to match safely");
        }
    }

    #[test]
    fn the_ordinary_word_vendors_are_deliberately_absent() {
        // Documented in the module header, and asserted so nobody adds one back
        // without reading why. Each is a real company whose name is a word
        // people use far more often about something else.
        let names: HashSet<String> = VENDORS.iter().map(|(v, _)| v.to_lowercase()).collect();
        for absent in [
            "square",
            "wise",
            "affirm",
            "plaid",
            "block",
            "brex",
            "ramp",
            "segment",
            "snowflake",
            "amplitude",
            "paddle",
            "clerk",
            "intercom",
        ] {
            assert!(
                !names.contains(absent),
                "{absent} is an ordinary word — see the module docs"
            );
        }
    }
}
