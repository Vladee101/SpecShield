//! Format parsers — SDD §4.2.
//!
//! Every parser implements [`specshield_core::parser::ArtifactParser`] and emits
//! byte-range edits. Adding a language means adding a module here; nothing else
//! in the pipeline changes.
//!
//! | Format | Parser | Milestone |
//! |---|---|---|
//! | Markdown, plain text | markdown AST with source offsets | M1 |
//! | SQL | `sqlparser` | M3 |
//! | JSON, YAML | CST-preserving | M3 |
//! | OpenAPI | semantic layer over the YAML/JSON CST | M3 |
//! | TypeScript / JavaScript | Tree-sitter + heuristic scoping | M4 |
//!
//! Two deliberate library choices, both from the design review:
//!
//! - **Not `serde_yaml`** (archived 2024), and not a `serde_json` round-trip:
//!   deserializing to a value model and re-serializing destroys comments and key
//!   order, which SDD §4.2 requires preserving.
//! - **Tree-sitter has no name resolution.** Correct renaming needs to know which
//!   declaration each reference binds to. MVP uses heuristic scoping and the
//!   weaker parse-and-count guarantee of SDD §7.2; an exact rename via the
//!   TypeScript compiler API is V1.1.

// TODO(M1): markdown, text
// TODO(M3): sql, json, yaml, openapi
// TODO(M4): typescript
