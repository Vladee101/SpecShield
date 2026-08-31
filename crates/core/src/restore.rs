//! Restore Engine — SDD §10. **M1.**
//!
//! Deliberately **lexical, not AST-based**. What returns from a model is often
//! a fragment, a unified diff, Markdown with prose interleaved, or code with
//! syntax errors; an AST-first restore fails on all of those. Restore is a scan
//! over a closed alias vocabulary, which is exactly what makes it robust
//! (Design Review B2).
//!
//! Matching order (SDD §10.3):
//!
//! 1. exact alias hit -> replace silently
//! 2. canonical hit ([`crate::alias::canonical`]) -> replace **and flag**
//! 3. alias-shaped but unknown -> unresolved identity, leave untouched
//! 4. `<<REDACTED:*>>` markers -> never restored

/// How an alias was matched. Surfaced in the diff so the user can review every
/// non-exact substitution (SDD §13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Exact,
    /// Matched only after normalization — the model drifted the token.
    Canonical,
}

// TODO(M1): tokenizer, matcher, unresolved-identity collection.
