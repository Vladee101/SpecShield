//! Secret Detector — SDD §4.3. **M1.**
//!
//! Runs *before* identity extraction. Secrets are redacted one-way and are
//! never restored: round-tripping a live credential back into AI-generated code
//! would be both meaningless and dangerous (Design Review A2).
//!
//! This is a different operation from pseudonymization and must never share a
//! code path with it. Secrets are never written to the vault as plaintext —
//! only `HMAC(project_key, match)`, for idempotency across rescans.

/// Marker substituted for a detected secret. Deliberately not alias-shaped, so
/// the restore engine can never resolve it.
pub const REDACTION_PREFIX: &str = "<<REDACTED:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Blocks export until acknowledged (SDD §8 step 3).
    High,
    /// Surfaced for review.
    Low,
}

// TODO(M1): regex rule pack (cloud keys, OAuth tokens, JWTs, PEM blocks,
// connection strings, bearer tokens, emails), Shannon-entropy heuristic over
// string literals, and an allowlist for placeholder values such as
// `your-api-key-here`.
