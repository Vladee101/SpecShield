//! Git integration — SDD §14. **M5.**
//!
//! SpecShield never writes directly to `main`. It generates a unified diff with
//! `similar`, dry-runs it, applies it onto a dedicated branch, and lets the user
//! commit normally.
//!
//! Patch application shells out to the user's `git`: libgit2 has no usable
//! `git apply` equivalent (Design Review C3). Where `git` is unavailable, patch
//! mode is disabled and restored files are written instead — never a silent
//! overwrite.

// TODO(M5): patch generation, `git apply --check` dry run, branch guard, undo
