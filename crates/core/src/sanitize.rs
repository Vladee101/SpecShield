//! Semantic Twin Generator — SDD §7. **M1.**
//!
//! Drives parsers to plan edits, then applies them via [`crate::edit::apply`].
//!
//! The guarantee is *not* "the twin compiles" — unachievable without a type
//! checker (SDD §4.2.2). It is: **the twin parses, and its declaration and
//! reference counts match the original.** On mismatch the transformation for
//! that file is rejected and the file is emitted unaliased, per SDD §16.

// TODO(M1): plan/verify/apply pipeline, plus the post-sanitize re-parse and
// node-count comparison (SDD §7.2).
