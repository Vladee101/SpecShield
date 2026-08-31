//! Diff Engine — SDD §13. **M5.**
//!
//! Compares Original / Twin / AI-Twin and presents the restored result,
//! highlighting additions, deletions, and modifications. Fuzzy-restored aliases,
//! unresolved identities, and redaction markers are called out inline.
//!
//! Staleness (SDD §13.1) is checked here: if `files.checksum` no longer matches
//! the real file, restoring would silently revert intervening edits, so patch
//! application is blocked until a rescan.

// TODO(M5): three-way diff over `similar`, formatting-noise suppression.
