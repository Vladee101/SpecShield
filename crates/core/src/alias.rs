//! Alias allocation, grammar, and drift-tolerant matching — SDD §6, PRD §13.
//!
//! An alias is a prefix, an underscore, and a zero-padded number: `ORG_001`,
//! `PRODUCT_001`, `PAYMENT_PROVIDER_001`. Numbers are allocated per type on
//! first sight and stored in the vault, so an identity keeps its alias for the
//! life of the project however many times it is rescanned and whatever order the
//! files are walked in.
//!
//! **This replaced HMAC derivation, and the trade is worth writing down.**
//! Design Review A6 chose `ORG_H7K2Q3` — derived from a project key — precisely
//! to avoid a central allocator: two developers on the same repository derive
//! identical aliases with no coordination, whereas counters diverge the moment
//! two people scan independently, and a twin one of them produced then restores
//! to the wrong names in the other's vault.
//!
//! That concern is real and is now **out of scope rather than solved**: PRD §15
//! puts team collaboration outside the MVP and §16 excludes multi-user projects.
//! What the counter buys is the thing §13 asks for and A6 cost — a twin a person
//! can read. `ORG_001 offers PRODUCT_001` is a sentence; `ORG_H7K2Q3 offers
//! DTO_8WFF40` is a puzzle, and the model reads it as one too. If shared vaults
//! ever come back, this decision comes back with them.
//!
//! **The grammar is frozen.** Every alias in every vault depends on it, so a
//! change here is a vault migration — see `PRAGMA user_version` in SDD §9.3.

use crate::model::EntityType;

/// Digits in an allocated alias. Zero-padded, so `ORG_007` sorts beside
/// `ORG_011` and the column width in a review table does not jump.
///
/// Not a limit: the thousandth organization in a project is `ORG_1000`, and the
/// grammar reads any run of digits.
const NUMBER_WIDTH: usize = 3;

/// Regex form of the grammar, for the prompt envelope handed to the model
/// (SDD §11). Deliberately looser than [`is_alias_shaped`]: a model does not
/// need the prefix list explained to it, and a looser pattern makes it more
/// likely to leave a drifted token recognisable.
pub const ENVELOPE_PATTERN: &str = r"^[A-Z][A-Z0-9_]*_[0-9]{3,}$";

/// The alias for `entity_type` numbered `number` — PRD §13.
///
/// A formatter, not an allocator. Which number an identity gets is decided by
/// [`crate::sanitize::Graph`], which is the only place that knows what a project
/// has already issued.
#[must_use]
pub fn format_alias(entity_type: EntityType, number: u32) -> String {
    format!("{}_{number:0NUMBER_WIDTH$}", entity_type.prefix())
}

/// The type and number a token names, if it is an alias this build could have
/// issued.
///
/// Matched against the known prefixes rather than a shape, which is what makes
/// the grammar precise instead of heuristic: `MAX_RETRIES` and `HTTP_200` are
/// not aliases and never were, but the old `[A-Z][A-Za-z0-9_]*_[A-Z0-9]{3,8}`
/// rule had to carry a "contains a digit" clause to say so. `HTTP` is simply not
/// a prefix.
///
/// The longest matching prefix wins, so `ENV_VAR_004` is an env var and not the
/// environment `ENV` followed by nonsense.
#[must_use]
pub fn parse(token: &str) -> Option<(EntityType, u32)> {
    let mut best: Option<(EntityType, u32)> = None;

    for entity_type in EntityType::ALL {
        let prefix = entity_type.prefix();
        let Some(rest) = token.strip_prefix(prefix).and_then(|r| r.strip_prefix('_')) else {
            continue;
        };
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(number) = rest.parse::<u32>() else {
            continue;
        };
        if best.is_none_or(|(current, _)| prefix.len() > current.prefix().len()) {
            best = Some((entity_type, number));
        }
    }
    best
}

/// Does this token look like an alias? — SDD §6.3.
///
/// ```text
/// alias  := prefix "_" number
/// prefix := one of the fourteen in `EntityType::prefix`
/// number := [0-9]+
/// ```
///
/// Used by the restore engine to decide what is worth looking up, and to
/// classify unknown alias-shaped tokens as unresolved identities (SDD §12)
/// rather than silently ignoring them.
#[must_use]
pub fn is_alias_shaped(token: &str) -> bool {
    parse(token).is_some()
}

/// Canonical form for drift-tolerant matching — SDD §6.4.
///
/// Models mangle placeholders: `Service014`, `service_014`, `SERVICE-014`,
/// `SERVICE_14`, `SERVICE_014s`. Comparing canonical forms collapses all of
/// those onto one another.
///
/// Steps 1–4 of SDD §6.4 are implemented here. Step 5 (affix stripping, which
/// applies only when the remainder matches an existing alias exactly) belongs
/// to the matcher rather than the normalizer, and lands with the restore engine
/// in M1.
pub fn canonical(token: &str) -> String {
    // 1–2. Uppercase, drop everything that is not alphanumeric.
    let mut out: String = token
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();

    // 4. A trailing plural `S`, but only after a digit — so `SERVICE_014s`
    //    normalizes while a genuine name ending in S is left alone.
    if out.len() > 1 && out.ends_with('S') && out[..out.len() - 1].ends_with(|c: char| c.is_ascii_digit()) {
        out.pop();
    }

    // 3. Strip leading zeros within each digit run: SERVICE014 -> SERVICE14.
    strip_leading_zeros(&out)
}

fn strip_leading_zeros(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if !c.is_ascii_digit() {
            out.push(c);
            continue;
        }
        let mut run = String::from(c);
        while let Some(&next) = chars.peek() {
            if next.is_ascii_digit() {
                run.push(next);
                chars.next();
            } else {
                break;
            }
        }
        let trimmed = run.trim_start_matches('0');
        out.push_str(if trimmed.is_empty() { "0" } else { trimmed });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_alias_is_a_prefix_and_a_padded_number() {
        // PRD §13, verbatim. The zero padding is what keeps a review table from
        // jumping a column width between the ninth and the tenth organization.
        assert_eq!(format_alias(EntityType::Organization, 1), "ORG_001");
        assert_eq!(format_alias(EntityType::Product, 1), "PRODUCT_001");
        assert_eq!(format_alias(EntityType::PaymentProvider, 1), "PAYMENT_PROVIDER_001");
        assert_eq!(format_alias(EntityType::Domain, 42), "DOMAIN_042");
    }

    #[test]
    fn padding_is_a_minimum_and_not_a_ceiling() {
        // A project with a thousand organizations is unusual, not unsupported.
        assert_eq!(format_alias(EntityType::Organization, 1000), "ORG_1000");
    }

    #[test]
    fn every_alias_this_build_can_issue_parses_back() {
        // The round trip the restore engine depends on. A type whose prefix
        // cannot be read back is a type whose aliases nobody can resolve.
        for entity_type in EntityType::ALL {
            for number in [1, 7, 99, 100, 12345] {
                let alias = format_alias(entity_type, number);
                assert_eq!(
                    parse(&alias),
                    Some((entity_type, number)),
                    "{alias} must read back as what wrote it"
                );
                assert!(is_alias_shaped(&alias));
            }
        }
    }

    #[test]
    fn the_longest_matching_prefix_wins() {
        // `ENV_VAR` and `ENV` are both prefixes, and one is a prefix of the
        // other. Without the longest-match rule an env var would read as an
        // environment followed by nonsense, and restore would hand back the
        // wrong name.
        assert_eq!(parse("ENV_VAR_004"), Some((EntityType::EnvVar, 4)));
        assert_eq!(parse("ENV_004"), Some((EntityType::Environment, 4)));
    }

    #[test]
    fn ordinary_constants_are_not_aliases() {
        // Matching against the known prefixes is what makes this precise rather
        // than heuristic. The old shape rule needed a "contains a digit" clause
        // to keep `MAX_RETRIES` out; `MAX` is simply not a prefix.
        for token in [
            "MAX_RETRIES",
            "HTTP_200",
            "ORG",
            "ORG_",
            "ORG_00A",
            "_001",
            "org_001",
            "ORGANIZATION_001",
            "",
        ] {
            assert!(!is_alias_shaped(token), "{token} is not an alias");
        }
    }

    #[test]
    fn an_alias_from_the_old_grammar_is_not_recognised() {
        // Deliberate, and the reason schema v5 renumbers rather than tolerating
        // both. Two grammars in one vault would leave the allocator unable to
        // tell which numbers are taken.
        assert!(!is_alias_shaped("ORG_H7K2Q3"));
        assert!(!is_alias_shaped("PrimaryService_H7K2Q3"));
    }

    #[test]
    fn canonical_collapses_the_ways_a_model_mangles_an_alias() {
        let target = canonical("ORG_001");
        for drifted in ["org_001", "Org-001", "ORG001", "ORG_1", "ORG_001s"] {
            assert_eq!(canonical(drifted), target, "{drifted} must normalize onto ORG_001");
        }
    }

    #[test]
    fn canonical_keeps_distinct_aliases_distinct() {
        assert_ne!(canonical("ORG_001"), canonical("ORG_002"));
        assert_ne!(canonical("ORG_001"), canonical("PRODUCT_001"));
        // A trailing S is only dropped after a digit, so a name that genuinely
        // ends in one survives.
        assert_ne!(canonical("PARTNERS_001"), canonical("PARTNER_001"));
    }

    #[test]
    fn the_envelope_pattern_describes_what_is_issued() {
        // The model is handed this regex (SDD §11). If it does not match a real
        // alias, the instruction is worse than none.
        let re = regex::Regex::new(ENVELOPE_PATTERN).expect("valid pattern");
        for entity_type in EntityType::ALL {
            let alias = format_alias(entity_type, 7);
            assert!(re.is_match(&alias), "{alias} must match the envelope pattern");
        }
        assert!(!re.is_match("MAX_RETRIES"));
    }
}
