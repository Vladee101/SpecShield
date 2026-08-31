//! Encrypted mapping vault — SDD §9. **M1.**
//!
//! SQLite + SQLCipher via `rusqlite`. The schema is in SDD §9.1, which is
//! authoritative; `schema.sql` in this crate must match it.
//!
//! Three things here are easy to get wrong and expensive to fix later:
//!
//! - **Migrations from day one** (SDD §9.3). `PRAGMA user_version` drives a
//!   runner that exists before the first release; retrofitting migrations onto
//!   an encrypted store is painful, and the alias grammar is part of the
//!   versioned contract.
//! - **Key storage** (SDD §9.4). The vault key lives in the OS credential store,
//!   never on disk beside the database — otherwise SQLCipher protects against
//!   exactly one thing: the `.db` being copied alone.
//! - **Batched writes** (SDD §9.2). One transaction per file. Row-by-row inserts
//!   across a full index will not meet the 30 s target.

// TODO(M1): connection, schema, migrate, key
