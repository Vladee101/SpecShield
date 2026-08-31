//! Alias derivation, grammar, and drift-tolerant matching — SDD §6.
//!
//! Aliases are HMAC-derived rather than sequence-allocated. Sequence allocation
//! needs a central allocator: two developers on the same repository would
//! produce different aliases for the same entity, giving divergent twins and
//! cross-machine restore failures (Design Review A6). HMAC derivation needs only
//! a shared project key.
//!
//! **The grammar in this module is frozen.** Every alias in every vault depends
//! on it, so a change here is a vault migration — see `PRAGMA user_version` in
//! SDD §9.3.

use std::sync::LazyLock;

use data_encoding::{Encoding, Specification};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::model::IdentityKey;

type HmacSha256 = Hmac<Sha256>;

/// Number of base32 characters taken from the HMAC — the `suffix` production.
const SUFFIX_LEN: usize = 6;

/// Crockford base32: excludes I, L, O, and U so a suffix cannot be misread as
/// a digit or accidentally spell a word.
static CROCKFORD: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    spec.encoding().expect("Crockford alphabet is exactly 32 symbols")
});

/// Regex form of the grammar, for the prompt envelope handed to the model
/// (SDD §11). It is deliberately looser than [`is_alias_shaped`]: a model does
/// not need the digit rule explained to it, and a looser pattern makes it more
/// likely to leave a drifted token recognisable.
pub const ENVELOPE_PATTERN: &str = r"^[A-Z][A-Za-z0-9_]*_[A-Z0-9]{3,8}$";

/// Per-project HMAC key. Two machines holding the same key derive identical
/// aliases with no coordination.
///
/// Not `Debug`-printable and not `Clone`: it is key material.
pub struct ProjectKey([u8; 32]);

impl ProjectKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ProjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProjectKey(<redacted>)")
    }
}

// TODO(M1): `impl Drop for ProjectKey` with `zeroize`, once the vault crate
// owns key lifecycle (SDD §9.4).

/// Alias readability, traded against protection — SDD §6.2.
///
/// Fixed at project creation; changing it requires a re-key (SDD §9.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasStyle {
    /// `SERVICE_H7K2Q3` — maximum protection, weakest AI output quality.
    Opaque,
    /// `PrimaryService_H7K2Q3` — retains a generic category, hides the subject.
    #[default]
    Typed,
    /// `AuroraService` — most readable, weakest protection.
    Pseudonymous,
}

/// Derive the alias for an identity — SDD §6.1.
///
/// Deterministic in `(key, identity, style)`: the same inputs always produce the
/// same alias, on any machine. `disambiguator` is `None` for the common case and
/// `Some(n)` when the caller has hit a collision against the vault's `ux_alias`
/// index, yielding `SERVICE_H7K2Q3_2`.
pub fn derive(key: &ProjectKey, identity: &IdentityKey, style: AliasStyle, disambiguator: Option<u32>) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(identity.hmac_input().as_bytes());
    let digest = mac.finalize().into_bytes();

    let encoded = CROCKFORD.encode(&digest);
    let suffix = digit_bearing_window(&encoded);
    let entity_type = identity.entity_type;

    let stem = match style {
        AliasStyle::Opaque => format!("{}_{suffix}", entity_type.prefix()),
        AliasStyle::Typed => format!("{}{}_{suffix}", qualifier(suffix), entity_type.category()),
        AliasStyle::Pseudonymous => format!("{}{}", pseudonym(suffix), entity_type.category()),
    };

    match disambiguator {
        Some(n) => format!("{stem}_{n}"),
        None => stem,
    }
}

/// First `SUFFIX_LEN`-character window of the encoded digest containing at least
/// one digit.
///
/// The digit is what separates an alias from an ordinary `SCREAMING_SNAKE`
/// constant: without it, `MAX_RETRIES` parses as a perfectly good alias and
/// every constant in the model's output would be reported as an unresolved
/// identity. Roughly 11% of raw windows are all-letters, so scanning forward
/// costs nothing and keeps derivation deterministic.
fn digit_bearing_window(encoded: &str) -> &str {
    let bytes = encoded.as_bytes();
    for start in 0..=bytes.len().saturating_sub(SUFFIX_LEN) {
        let window = &encoded[start..start + SUFFIX_LEN];
        if window.bytes().any(|b| b.is_ascii_digit()) {
            return window;
        }
    }
    // A 52-character base32 digest with no digit anywhere is not reachable in
    // practice, but the fallback keeps the function total.
    &encoded[..SUFFIX_LEN]
}

/// Deterministic generic qualifier for [`AliasStyle::Typed`].
///
/// Deliberately drawn from a bland, non-identifying word list: the point of
/// typed mode is to give the model *a* category hint without disclosing the
/// subject.
fn qualifier(suffix: &str) -> &'static str {
    const WORDS: [&str; 8] = [
        "Primary",
        "Secondary",
        "Internal",
        "External",
        "Upstream",
        "Downstream",
        "Shared",
        "Core",
    ];
    WORDS[pick(suffix, WORDS.len())]
}

/// Deterministic neutral name for [`AliasStyle::Pseudonymous`].
fn pseudonym(suffix: &str) -> &'static str {
    const NAMES: [&str; 12] = [
        "Aurora", "Basalt", "Cobalt", "Dahlia", "Ember", "Fjord", "Garnet", "Harbor", "Indigo", "Juniper", "Kestrel",
        "Lumen",
    ];
    NAMES[pick(suffix, NAMES.len())]
}

/// Stable index into a word list, derived from the already-hashed suffix.
fn pick(suffix: &str, len: usize) -> usize {
    suffix.bytes().fold(0_usize, |acc, b| acc.wrapping_add(b as usize)) % len
}

/// Does this token look like an alias? — SDD §6.3.
///
/// ```text
/// alias  := prefix "_" suffix [ "_" disambiguator ]
/// prefix := [A-Z] [A-Za-z0-9_]*        // underscores allowed: DB_TABLE
/// suffix := [A-Z0-9]{3,8}              // must contain at least one digit
/// disambiguator := [0-9]+
/// ```
///
/// Hand-parsed rather than regex-matched because the digit rule and the
/// rightmost-underscore split are both awkward to express as one pattern, and
/// this is on the hot path of every restore.
///
/// Used by the restore engine to decide what is worth looking up, and to
/// classify unknown alias-shaped tokens as unresolved identities (SDD §12)
/// rather than silently ignoring them.
pub fn is_alias_shaped(token: &str) -> bool {
    let stem = strip_disambiguator(token);

    let Some((prefix, suffix)) = stem.rsplit_once('_') else {
        return false;
    };

    prefix_is_valid(prefix) && suffix_is_valid(suffix)
}

/// Remove a trailing `_<digits>` collision suffix, but only when what precedes
/// it is itself a plausible `prefix_suffix` pair — otherwise `SERVICE_014`
/// would have its own suffix stripped.
fn strip_disambiguator(token: &str) -> &str {
    match token.rsplit_once('_') {
        Some((stem, tail)) if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) && stem.contains('_') => {
            stem
        }
        _ => token,
    }
}

fn prefix_is_valid(prefix: &str) -> bool {
    let mut chars = prefix.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase()) && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn suffix_is_valid(suffix: &str) -> bool {
    (3..=8).contains(&suffix.len())
        && suffix.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && suffix.bytes().any(|b| b.is_ascii_digit())
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
    use crate::model::EntityType;

    fn key() -> ProjectKey {
        ProjectKey::from_bytes([7; 32])
    }

    fn ident(name: &str) -> IdentityKey {
        IdentityKey::new("src/services", EntityType::Service, name)
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive(&key(), &ident("CustomerService"), AliasStyle::Opaque, None);
        let b = derive(&key(), &ident("CustomerService"), AliasStyle::Opaque, None);
        assert_eq!(a, b);
    }

    #[test]
    fn different_scopes_yield_different_aliases() {
        // The Design Review B1 case: same name, different module.
        let a = IdentityKey::new("mod/a", EntityType::Enum, "Status");
        let b = IdentityKey::new("mod/b", EntityType::Enum, "Status");
        assert_ne!(
            derive(&key(), &a, AliasStyle::Opaque, None),
            derive(&key(), &b, AliasStyle::Opaque, None)
        );
    }

    #[test]
    fn different_project_keys_yield_different_aliases() {
        let other = ProjectKey::from_bytes([9; 32]);
        assert_ne!(
            derive(&key(), &ident("CustomerService"), AliasStyle::Opaque, None),
            derive(&other, &ident("CustomerService"), AliasStyle::Opaque, None)
        );
    }

    #[test]
    fn every_machine_readable_style_and_type_produces_a_grammatical_alias() {
        for t in EntityType::ALL {
            for style in [AliasStyle::Opaque, AliasStyle::Typed] {
                let id = IdentityKey::new("scope", t, "Thing");
                let alias = derive(&key(), &id, style, None);
                assert!(is_alias_shaped(&alias), "{style:?}/{t:?} produced {alias}");
            }
        }
    }

    #[test]
    fn pseudonymous_style_is_intentionally_outside_the_machine_grammar() {
        // It trades matchability for readability; restore resolves it by exact
        // vault lookup rather than by shape.
        let alias = derive(&key(), &ident("A"), AliasStyle::Pseudonymous, None);
        assert!(!is_alias_shaped(&alias), "{alias}");
    }

    #[test]
    fn disambiguator_is_grammatical() {
        let alias = derive(&key(), &ident("A"), AliasStyle::Opaque, Some(2));
        assert!(alias.ends_with("_2"), "{alias}");
        assert!(is_alias_shaped(&alias), "{alias}");
    }

    #[test]
    fn underscored_prefixes_are_grammatical() {
        // DB_TABLE is a prefix in SDD §4.4, so the prefix production must admit
        // underscores.
        assert!(is_alias_shaped("DB_TABLE_H7K2Q3"));
    }

    #[test]
    fn screaming_snake_constants_are_not_mistaken_for_aliases() {
        // Without the digit rule every constant in AI output would be reported
        // as an unresolved identity, drowning the real ones.
        for token in ["MAX_RETRIES", "DEFAULT_TIMEOUT", "HTTP_OK", "API_BASE_URL"] {
            assert!(!is_alias_shaped(token), "{token} should not look like an alias");
        }
    }

    #[test]
    fn alias_shape_rejects_ordinary_identifiers() {
        for token in [
            "customerService",
            "CustomerService",
            "SERVICE",
            "_014",
            "SERVICE_",
            "lower_case_1",
        ] {
            assert!(!is_alias_shaped(token), "{token} should not look like an alias");
        }
    }

    #[test]
    fn canonical_collapses_observed_model_drift() {
        let want = canonical("SERVICE_014");
        for drifted in [
            "Service014",
            "service_014",
            "SERVICE-014",
            "Service_014",
            "SERVICE_14",
            "SERVICE_014s",
            "`SERVICE_014`",
        ] {
            assert_eq!(canonical(drifted), want, "{drifted} should canonicalize to {want}");
        }
    }

    #[test]
    fn canonical_keeps_distinct_aliases_distinct() {
        assert_ne!(canonical("SERVICE_014"), canonical("SERVICE_015"));
        assert_ne!(canonical("SERVICE_014"), canonical("DTO_014"));
    }

    #[test]
    fn canonical_does_not_strip_a_meaningful_trailing_s() {
        assert_eq!(canonical("STATUS"), "STATUS");
    }
}
