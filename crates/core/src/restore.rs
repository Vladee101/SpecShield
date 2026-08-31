//! Restore Engine — SDD §10.
//!
//! Deliberately **lexical, not AST-based**. What returns from a model is often
//! a fragment, a unified diff, Markdown with prose interleaved, or code with
//! syntax errors; an AST-first restore fails on all of those. Restore is a scan
//! over a closed alias vocabulary, which is exactly what makes it robust
//! (Design Review B2).
//!
//! Matching order (SDD §10.3):
//!
//! 1. exact alias hit → replace silently
//! 2. canonical hit → replace **and flag** as fuzzy
//! 3. affix-stripped canonical hit → replace **and flag**
//! 4. alias-shaped but unknown → unresolved identity, left untouched
//! 5. `<<REDACTED:*>>` markers → never restored

use std::collections::HashMap;

use crate::alias::{canonical, is_alias_shaped};
use crate::edit::Edit;
use crate::secrets::REDACTION_PREFIX;

/// How an alias was matched. Surfaced in the diff so the user can review every
/// non-exact substitution (SDD §13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// Byte-identical to a known alias.
    Exact,
    /// Matched only after normalization — the model drifted the token.
    Canonical,
    /// Matched after stripping a suffix the model appended, e.g.
    /// `SERVICE_H7K2Q3Impl`. SDD §6.4 step 5.
    AffixStripped,
}

impl MatchKind {
    /// Exact matches are applied silently; everything else is reported.
    pub const fn needs_review(self) -> bool {
        !matches!(self, Self::Exact)
    }
}

/// One alias replaced during a restore.
#[derive(Debug, Clone)]
pub struct Restored {
    pub alias: String,
    /// The token actually present in the input, which may differ from `alias`.
    pub found: String,
    pub real_name: String,
    pub match_kind: MatchKind,
    pub byte_start: usize,
    pub byte_end: usize,
    pub line: usize,
}

/// An alias-shaped token with no matching identity — SDD §12.
///
/// Never guessed at: silent inference here would write a wrong name into the
/// user's real repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    pub token: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub line: usize,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub text: String,
    pub restored: Vec<Restored>,
    pub unresolved: Vec<Unresolved>,
    /// Redaction markers left in place, counted so the UI can explain why the
    /// output still contains them.
    pub redactions_preserved: usize,
}

impl Outcome {
    /// Substitutions a human must look at before the patch is applied.
    pub fn needs_review(&self) -> Vec<&Restored> {
        self.restored.iter().filter(|r| r.match_kind.needs_review()).collect()
    }
}

/// Suffixes a model appends to an alias while otherwise preserving it. Stripped
/// only when the remainder matches a known alias exactly — which is why this
/// belongs to the matcher and not to [`canonical`].
const APPENDED_AFFIXES: &[&str] = &[
    "Impl",
    "Implementation",
    "Service",
    "Class",
    "Type",
    "Interface",
    "Dto",
    "Model",
    "Base",
    "Abstract",
    "Default",
    "New",
    "V2",
    "Ext",
];

/// The alias vocabulary a restore runs against.
#[derive(Debug, Default)]
pub struct Vocabulary {
    exact: HashMap<String, String>,
    canonical: HashMap<String, String>,
}

impl Vocabulary {
    /// Build from `(alias, real_name)` pairs.
    ///
    /// A canonical form shared by two aliases is dropped from the fuzzy index
    /// rather than resolved arbitrarily: guessing between two identities is the
    /// one failure mode with no safe recovery. Exact matching still works for
    /// both.
    pub fn new<I, A, R>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (A, R)>,
        A: Into<String>,
        R: Into<String>,
    {
        let mut exact = HashMap::new();
        let mut canonical_map: HashMap<String, Option<String>> = HashMap::new();

        for (alias, real) in pairs {
            let alias = alias.into();
            let real = real.into();
            let key = canonical(&alias);
            canonical_map
                .entry(key)
                .and_modify(|slot| {
                    if slot.as_deref() != Some(real.as_str()) {
                        *slot = None; // ambiguous
                    }
                })
                .or_insert_with(|| Some(real.clone()));
            exact.insert(alias, real);
        }

        Self {
            exact,
            canonical: canonical_map
                .into_iter()
                .filter_map(|(k, v)| v.map(|real| (k, real)))
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }

    /// Resolve one token. Returns the real name and how it was matched.
    fn resolve(&self, token: &str) -> Option<(&str, MatchKind)> {
        if let Some(real) = self.exact.get(token) {
            return Some((real, MatchKind::Exact));
        }
        if let Some(real) = self.canonical.get(&canonical(token)) {
            return Some((real, MatchKind::Canonical));
        }
        for affix in APPENDED_AFFIXES {
            if let Some(stem) = token.strip_suffix(affix)
                && !stem.is_empty()
                && let Some(real) = self.exact.get(stem).or_else(|| self.canonical.get(&canonical(stem)))
            {
                return Some((real, MatchKind::AffixStripped));
            }
        }
        None
    }
}

/// Restore aliases in AI output back to real identifiers — SDD §10.3.
pub fn restore(input: &str, vocabulary: &Vocabulary) -> Outcome {
    let mut edits: Vec<Edit> = Vec::new();
    let mut outcome = Outcome::default();

    for (start, end) in token_spans(input) {
        let token = &input[start..end];

        if let Some((real, match_kind)) = vocabulary.resolve(token) {
            outcome.restored.push(Restored {
                alias: token.to_owned(),
                found: token.to_owned(),
                real_name: real.to_owned(),
                match_kind,
                byte_start: start,
                byte_end: end,
                line: line_of(input, start),
            });
            edits.push(Edit::new(start, end, real, None));
        } else if is_alias_shaped(token) {
            outcome.unresolved.push(Unresolved {
                token: token.to_owned(),
                byte_start: start,
                byte_end: end,
                line: line_of(input, start),
            });
        }
    }

    outcome.redactions_preserved = input.matches(REDACTION_PREFIX).count();

    // Token spans never overlap, so this cannot fail.
    outcome.text = crate::edit::apply(input, &mut edits).unwrap_or_else(|_| input.to_owned());
    outcome
}

/// Identifier-shaped spans. Deliberately generous — it costs nothing to look up
/// a token that turns out to be ordinary code, and missing one is a failed
/// restore.
fn token_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_token_byte(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            spans.push((start, i));
        } else {
            i += 1;
        }
    }
    spans
}

const fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn line_of(text: &str, byte: usize) -> usize {
    text[..byte].matches('\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vocab() -> Vocabulary {
        Vocabulary::new([
            ("SERVICE_H7K2Q3", "CustomerSubscriptionService"),
            ("DTO_M4X2Q7", "CreateSubscriptionDto"),
            ("DB_TABLE_K9P3Q2", "customer_subscription"),
        ])
    }

    #[test]
    fn exact_aliases_restore_silently() {
        let out = restore("const dto = new DTO_M4X2Q7();", &vocab());
        assert_eq!(out.text, "const dto = new CreateSubscriptionDto();");
        assert_eq!(out.restored.len(), 1);
        assert_eq!(out.restored[0].match_kind, MatchKind::Exact);
        assert!(out.needs_review().is_empty());
    }

    #[test]
    fn drifted_aliases_restore_but_are_flagged() {
        // The model lowercased it.
        let out = restore("const dto = new dto_m4x2q7();", &vocab());
        assert_eq!(out.text, "const dto = new CreateSubscriptionDto();");
        assert_eq!(out.restored[0].match_kind, MatchKind::Canonical);
        assert_eq!(out.needs_review().len(), 1);
    }

    #[test]
    fn appended_affixes_are_stripped_and_flagged() {
        // SDD §6.4 step 5 — the case the M0 spike proved is load-bearing.
        let out = restore("class SERVICE_H7K2Q3Impl {}", &vocab());
        assert_eq!(out.text, "class CustomerSubscriptionService {}");
        assert_eq!(out.restored[0].match_kind, MatchKind::AffixStripped);
        assert_eq!(out.needs_review().len(), 1);
    }

    #[test]
    fn unknown_alias_shaped_tokens_are_reported_never_guessed() {
        let out = restore("class SERVICE_999 extends Base {}", &vocab());
        assert_eq!(out.text, "class SERVICE_999 extends Base {}", "must be left untouched");
        assert_eq!(out.unresolved.len(), 1);
        assert_eq!(out.unresolved[0].token, "SERVICE_999");
    }

    #[test]
    fn ordinary_code_is_untouched_and_not_reported() {
        let input = "const MAX_RETRIES = 5;\nfor (const item of items) { console.log(item); }";
        let out = restore(input, &vocab());
        assert_eq!(out.text, input);
        assert!(out.restored.is_empty());
        assert!(out.unresolved.is_empty(), "got {:?}", out.unresolved);
    }

    #[test]
    fn redaction_markers_are_never_restored() {
        let input = "const key = \"<<REDACTED:api_key>>\";";
        let out = restore(input, &vocab());
        assert_eq!(out.text, input);
        assert_eq!(out.redactions_preserved, 1);
    }

    #[test]
    fn works_on_a_fragment_with_prose_and_fences() {
        // The realistic shape of a model response.
        let input = "Here's the updated file:\n\n```ts\nclass SERVICE_H7K2Q3 {}\n```\n\nI added retries.";
        let out = restore(input, &vocab());
        assert!(out.text.contains("class CustomerSubscriptionService {}"));
        assert!(out.text.starts_with("Here's the updated file:"));
    }

    #[test]
    fn works_on_a_unified_diff() {
        let input = "@@ -1,3 +1,4 @@\n-class SERVICE_H7K2Q3 {}\n+class SERVICE_H7K2Q3 {\n+  retry() {}\n+}";
        let out = restore(input, &vocab());
        assert_eq!(out.restored.len(), 2);
        assert!(out.text.contains("-class CustomerSubscriptionService {}"));
    }

    #[test]
    fn aliases_inside_strings_and_comments_are_restored() {
        let input = "// see SERVICE_H7K2Q3\nconst url = \"/api/DTO_M4X2Q7\";";
        let out = restore(input, &vocab());
        assert!(out.text.contains("// see CustomerSubscriptionService"));
        assert!(out.text.contains("/api/CreateSubscriptionDto"));
    }

    #[test]
    fn ambiguous_canonical_forms_are_not_guessed() {
        // Two aliases that canonicalize identically: exact matching still
        // works, fuzzy matching must refuse rather than pick one.
        let v = Vocabulary::new([("SERVICE_014", "Alpha"), ("SERVICE_14", "Beta")]);
        assert_eq!(restore("SERVICE_014", &v).text, "Alpha");
        assert_eq!(restore("SERVICE_14", &v).text, "Beta");

        let out = restore("service-014", &v);
        assert_eq!(out.text, "service-014", "ambiguous drift must not be resolved");
    }

    #[test]
    fn multiple_occurrences_all_restore() {
        let out = restore("SERVICE_H7K2Q3 calls SERVICE_H7K2Q3 twice", &vocab());
        assert_eq!(out.restored.len(), 2);
        assert_eq!(
            out.text,
            "CustomerSubscriptionService calls CustomerSubscriptionService twice"
        );
    }

    #[test]
    fn reports_line_numbers() {
        let out = restore("line one\nline two\nSERVICE_H7K2Q3", &vocab());
        assert_eq!(out.restored[0].line, 3);
    }
}
