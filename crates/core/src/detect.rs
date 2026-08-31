//! Identity Extractor — SDD §4.4. **M1.**
//!
//! Combines AST traversal, SQL schema inspection, OpenAPI traversal, a rule
//! engine, a custom dictionary, and a prose scan over comments, string
//! literals, and Markdown body text — which is where most narrative leakage
//! lives (Design Review D5).
//!
//! Precision matters as much as recall here (PRD §5): false positives make the
//! twin unreadable and degrade the AI output generated from it.

// TODO(M1): rule engine, shipped stop-list of framework and vendor names
// (React, Express, Postgres, AWS, ...), user allowlist, confidence scoring.
