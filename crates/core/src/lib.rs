//! SpecShield core: the headless engine.
//!
//! This crate holds all logic and has no I/O side effects, no database, and no
//! Tauri dependency — see `Implementation Plan` §0. The desktop shell and the
//! CLI are both thin drivers over this API.
//!
//! Module map (SDD §3):
//!
//! | Module | SDD |
//! |---|---|
//! | [`model`] | §5 Identity Graph |
//! | [`alias`] | §6 Alias Generation |
//! | [`edit`] | §4.2.1 Edit lists |
//! | [`parser`] | §4.2.1 Parser contract |
//! | [`secrets`] | §4.3 Secret Detector |
//! | [`detect`] | §4.4 Identity Extractor |
//! | [`sanitize`] | §7 Semantic Twin Generator |
//! | [`verify`] | §8 Export Verification Gate |
//! | [`restore`] | §10 Restore Engine |
//! | [`unify`] | §5 Cross-artifact unification |
//! | [`diff`] | §13 Diff Engine |

pub mod alias;
pub mod detect;
pub mod diff;
pub mod edit;
pub mod model;
pub mod parser;
pub mod restore;
pub mod sanitize;
pub mod secrets;
pub mod unify;
pub mod verify;

pub use alias::{AliasStyle, ProjectKey};
pub use edit::{Edit, EditError};
pub use model::{EntityType, IdentityKey, IdentityNode, Occurrence, OccurrenceKind, Origin, Status};
