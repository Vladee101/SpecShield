//! Project indexing — SDD §4.1, §13.1. **M4.**
//!
//! Gitignore-aware walking via `ignore`, BLAKE3 checksums, `rayon` parse
//! parallelism, and incremental rescan.
//!
//! Checksums are not bookkeeping: they drive staleness detection. Restoring AI
//! output produced from a stale twin silently reverts intervening edits, so a
//! checksum mismatch blocks patch application until a rescan (SDD §13.1).

// TODO(M4): walker, checksums, incremental rescan
