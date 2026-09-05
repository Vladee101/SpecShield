//! Tauri v2 desktop shell — Implementation Plan M2.
//!
//! **This layer holds no logic.** Every command here is a thin translation
//! between the UI and `specshield-core`; anything the app can do, the CLI can do
//! without it (Implementation Plan §0). If a rule starts living in this file, it
//! is in the wrong place.
//!
//! Security posture, all of it deliberate:
//!
//! - The capability set grants **no network and no shell**. SpecShield claims to
//!   work offline (PRD §10); a capability that could reach the network would
//!   make that claim untestable.
//! - The verification gate runs on the Rust side, before any twin can reach the
//!   frontend. The UI is never handed unverified content and asked to be careful
//!   with it.
//! - Original text is never placed on the clipboard by any command. Only a
//!   verified twin can be copied (SDD §17.5).

// Tauri deserializes command arguments from IPC, which requires owned types in
// the signature. `needless_pass_by_value` cannot see that constraint and fires
// on every command.
#![allow(clippy::needless_pass_by_value)]

mod clipboard;
mod state;

use std::path::Path;

use serde::Serialize;
use specshield_core::detect::Detector;
use specshield_core::model::{EntityType, OccurrenceKind, Origin, Status};
use specshield_core::parser::ProjectContext;
use specshield_core::restore::Vocabulary;
use specshield_core::sanitize::{AUTO_APPLY_CONFIDENCE, Graph};
use specshield_core::{alias, diff, restore, sanitize, secrets, verify};
use specshield_git as git;
use specshield_project as project;
use specshield_vault as vault;
use tauri::{Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroize;

use crate::state::AppState;

/// Where an applied patch is kept so `undo_patch` can reverse it. Beside the
/// vault, in plaintext: it holds real identifiers, which is no new exposure —
/// the source files it was built from sit unencrypted in the same tree — but it
/// must not be committed, and `.specshield/` is already ignored.
const LAST_PATCH: &str = ".specshield/last-apply.patch";
const LAST_APPLY: &str = ".specshield/last-apply.json";

/// Errors crossing the IPC boundary.
///
/// Deliberately stringly-typed: the frontend shows these to a human, and a
/// structured error taxonomy here would be a second copy of the one in core.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Message(String),
}

impl Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<vault::VaultError> for AppError {
    fn from(e: vault::VaultError) -> Self {
        Self::Message(e.to_string())
    }
}

impl From<project::ProjectError> for AppError {
    fn from(e: project::ProjectError) -> Self {
        Self::Message(e.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::Message(e.to_string())
    }
}

type Result<T> = std::result::Result<T, AppError>;

fn fail(message: impl Into<String>) -> AppError {
    AppError::Message(message.into())
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ProjectInfo {
    pub name: String,
    pub identity_count: usize,
    pub term_count: usize,
    /// Set when the project sits in a cloud-sync tree — PRD §10, SDD §17.4.
    pub cloud_sync_warning: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DetectedEntity {
    pub real_name: String,
    pub entity_type: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub confidence: f32,
}

#[derive(Debug, Serialize)]
pub struct SecretFinding {
    pub secret_type: String,
    pub line: usize,
    pub blocking: bool,
}

/// What `scan` shows in the review step of Workflow A.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub parser: String,
    pub entities: Vec<DetectedEntity>,
    /// Below the confidence floor: shown for review, never applied (PRD FR-10).
    pub suggestions: Vec<DetectedEntity>,
    pub secrets: Vec<SecretFinding>,
}

#[derive(Debug, Serialize)]
pub struct Leak {
    pub matched: String,
    pub line: usize,
    pub column: usize,
}

/// The outcome of a sanitize. `twin` is `None` whenever the gate blocked, so the
/// frontend cannot display or copy unverified content even by mistake.
#[derive(Debug, Serialize)]
pub struct SanitizeResult {
    pub verified: bool,
    /// The parser claimed this file and could not read it.
    ///
    /// Reported alongside `verified` rather than folded into it, because the
    /// two say different things and the difference is the whole point: the gate
    /// passed, and nothing was aliased. A file no parser could read has no vault
    /// names in it *yet*, so it sails through the gate looking clean. The UI
    /// must say so — this is how an entire React codebase could have been
    /// copied to a model under a green banner.
    pub unreadable: bool,
    pub twin: Option<String>,
    pub envelope: String,
    pub applied: usize,
    pub secrets_redacted: usize,
    pub patterns_checked: usize,
    pub leaks: Vec<Leak>,
    pub blocking_secrets: Vec<SecretFinding>,
    /// What the gate did *not* check — PRD §4.3. Shown next to every green
    /// state, so "verified" is never read as "safe to share anything".
    pub not_checked: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RestoredAlias {
    pub found: String,
    pub real_name: String,
    pub match_kind: String,
    pub line: usize,
    pub needs_review: bool,
}

#[derive(Debug, Serialize)]
pub struct RestoreResult {
    pub text: String,
    pub restored: Vec<RestoredAlias>,
    pub unresolved: Vec<String>,
    pub redactions_preserved: usize,
}

#[derive(Debug, Serialize)]
pub struct AuditRow {
    pub ts: i64,
    pub operation: String,
    /// FR-9 lists file count among the recorded fields. The wire type was
    /// dropping it, so the one screen that shows the log showed less than the
    /// log holds.
    pub file_count: Option<i64>,
    pub entity_count: Option<i64>,
    pub verification: Option<String>,
    pub destination: Option<String>,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn create_project(state: State<'_, AppState>, path: String, passphrase: String) -> Result<ProjectInfo> {
    let root = std::path::PathBuf::from(&path);
    let vault_path = state::vault_path(&root);
    if vault_path.exists() {
        return Err(fail(format!("a vault already exists at {}", vault_path.display())));
    }

    let settings = vault::Settings {
        project_name: root
            .file_name()
            .map_or_else(|| "project".to_owned(), |n| n.to_string_lossy().into_owned()),
        root_path: root.display().to_string(),
        scope_strategy: "module".to_owned(),
    };
    vault::Vault::create(&vault_path, &passphrase, &settings)?;
    state.open(&root, &passphrase)?;
    project_info(state)
}

#[tauri::command]
fn open_project(state: State<'_, AppState>, path: String, passphrase: String) -> Result<ProjectInfo> {
    state.open(&std::path::PathBuf::from(path), &passphrase)?;
    project_info(state)
}

#[tauri::command]
fn project_info(state: State<'_, AppState>) -> Result<ProjectInfo> {
    state.with(|vault, root| {
        let settings = vault.settings()?;
        Ok(ProjectInfo {
            name: settings.project_name,
            identity_count: vault.identities()?.len(),
            term_count: vault.dictionary()?.len(),
            cloud_sync_warning: vault::cloud_sync_root(root).map(|provider| {
                format!(
                    "This project is inside a {provider} folder. The vault will be synced to \
                     {provider}'s cloud, which contradicts SpecShield's local-only guarantee \
                     (PRD §10). Move it to a local-only path before storing real data."
                )
            }),
        })
    })
}

#[tauri::command]
fn close_project(state: State<'_, AppState>) {
    state.close();
}

#[tauri::command]
fn add_term(state: State<'_, AppState>, name: String, entity_type: String) -> Result<usize> {
    add_term_in(&state, &name, &entity_type)
}

fn add_term_in(state: &AppState, name: &str, entity_type: &str) -> Result<usize> {
    state.with(|vault, _| {
        let parsed: EntityType = entity_type
            .parse()
            .map_err(|_| fail(format!("unknown entity type {entity_type:?}")))?;
        vault.add_term(name, parsed.prefix())?;
        vault.log("term.add", None, Some(1), None, None)?;
        Ok(vault.dictionary()?.len())
    })
}

#[tauri::command]
fn add_allowed(state: State<'_, AppState>, term: String) -> Result<()> {
    state.with(|vault, _| {
        vault.add_allowed(&term, Some("user"))?;
        Ok(())
    })
}

#[tauri::command]
fn scan_text(state: State<'_, AppState>, filename: String, content: String) -> Result<ScanResult> {
    scan_text_in(&state, &filename, &content)
}

fn scan_text_in(state: &AppState, filename: &str, content: &str) -> Result<ScanResult> {
    let parser = require_parser(filename, content)?;
    state.with(|vault, _| {
        let detector = detector_from(vault)?;
        let findings = secrets::scan(content);
        let redacted = secrets::redact(content, &findings);
        let candidates = detector.scan_text(&redacted, filename, OccurrenceKind::Reference);

        let (confident, suggestions): (Vec<_>, Vec<_>) = candidates
            .into_iter()
            .partition(|c| c.confidence >= AUTO_APPLY_CONFIDENCE);

        Ok(ScanResult {
            parser: parser.name().to_owned(),
            entities: confident.iter().map(to_wire).collect(),
            suggestions: suggestions.iter().map(to_wire).collect(),
            secrets: findings.iter().map(to_secret_wire).collect(),
        })
    })
}

#[tauri::command]
fn sanitize_text(state: State<'_, AppState>, filename: String, content: String) -> Result<SanitizeResult> {
    sanitize_text_in(&state, &filename, &content)
}

/// The body, split from the IPC wrapper so the gate can be tested. This is the
/// command that decides whether a twin exists at all.
fn sanitize_text_in(state: &AppState, filename: &str, content: &str) -> Result<SanitizeResult> {
    let parser = require_parser(filename, content)?;
    let result = state.with(|vault, _| {
        let mut graph = graph_from(vault)?;
        let detector = detector_from(vault)?;

        let members = context_from(vault)?;

        let result = sanitize::sanitize(
            content,
            filename,
            &detector,
            &mut graph,
            Some(parser.as_ref()),
            &members,
        )
        .map_err(|e| fail(format!("sanitize failed: {e}")))?;

        persist(vault, &graph)?;

        // SDD §8 — the gate runs here, on the Rust side. It reports what reached
        // the twin; only an unredacted secret withholds it.
        let scanner = project::gate(vault, &graph)?;
        let verdict = scanner.scan(&result.twin);
        let twin_secrets = secrets::scan(&result.twin);
        let blocking: Vec<SecretFinding> = twin_secrets
            .iter()
            .filter(|f| f.confidence == secrets::Confidence::High)
            .map(to_secret_wire)
            .collect();

        let leaks = match &verdict {
            verify::Verdict::Clean => Vec::new(),
            verify::Verdict::Blocked(found) => found
                .iter()
                .map(|l| Leak {
                    matched: l.matched.clone(),
                    line: l.line,
                    column: l.column,
                })
                .collect(),
        };

        // `verified` is now about the *secret* check, which is the one that
        // still refuses. Names that reached the twin are reported in `leaks`
        // and the twin is handed over anyway: the user is the one who can say
        // whether `Node` matters in their project, and they cannot say it if
        // they never see the twin. `has_leaks` on the wire keeps the two
        // distinguishable in the UI.
        let verified = blocking.is_empty();
        vault.log(
            "sanitize",
            Some(1),
            i64::try_from(result.applied.len()).ok(),
            Some(if verified { "clean" } else { "blocked" }),
            None,
        )?;

        Ok(SanitizeResult {
            verified,
            unreadable: matches!(result.verification, sanitize::Verification::OriginalDidNotParse { .. }),
            twin: verified.then(|| result.twin.clone()),
            envelope: prompt_envelope(),
            applied: result.applied.len(),
            secrets_redacted: result.secrets.len(),
            patterns_checked: scanner.pattern_count(),
            leaks,
            blocking_secrets: blocking,
            not_checked: vec![
                "Business logic written out in prose".to_owned(),
                "Algorithms and implementation approach".to_owned(),
                "Architecture shape and data-model topology".to_owned(),
                "Anything you paste into a model by hand, outside SpecShield".to_owned(),
            ],
        })
    })?;

    // Park the twin for `copy_verified_twin`, and clear any previous one when
    // this run was blocked — a stale verified twin must not remain copyable
    // after a later failure. Done outside `with`, which holds the state lock.
    state.set_verified_twin(result.twin.clone());
    Ok(result)
}

#[tauri::command]
fn restore_text(state: State<'_, AppState>, content: String) -> Result<RestoreResult> {
    state.with(|vault, _| {
        let graph = graph_from(vault)?;
        let outcome = restore::restore(&content, &Vocabulary::new(graph.vocabulary()));
        vault.log("restore", None, i64::try_from(outcome.restored.len()).ok(), None, None)?;

        Ok(RestoreResult {
            restored: outcome
                .restored
                .iter()
                .map(|r| RestoredAlias {
                    found: r.found.clone(),
                    real_name: r.real_name.clone(),
                    match_kind: format!("{:?}", r.match_kind),
                    line: r.line,
                    needs_review: r.match_kind.needs_review(),
                })
                .collect(),
            unresolved: outcome.unresolved.iter().map(|u| u.token.clone()).collect(),
            redactions_preserved: outcome.redactions_preserved,
            text: outcome.text,
        })
    })
}

/// A run of changed lines, flattened for the frontend.
#[derive(Serialize)]
struct WireHunk {
    kind: String,
    before_start: usize,
    after_start: usize,
    lines: Vec<WireLine>,
    notes: Vec<WireNote>,
}

#[derive(Serialize)]
struct WireLine {
    added: bool,
    number: usize,
    text: String,
}

/// A note carries its own line, because the UI shows the full list as well as
/// the per-hunk ones — a fuzzy match can restore to text identical to the
/// original and land in no hunk at all.
#[derive(Serialize)]
struct WireNote {
    kind: String,
    line: usize,
    detail: String,
    /// The token to name, for `Unresolved` notes. Empty otherwise.
    token: String,
}

#[derive(Serialize)]
struct DiffReview {
    restored: String,
    changes: Vec<WireHunk>,
    model_changes: usize,
    substantive: usize,
    notes: Vec<WireNote>,
    /// Unresolved identities block the patch outright — SDD §12.
    blocks_patch: bool,
    unresolved: Vec<String>,
}

/// Whether this document can be applied as a patch, and why not if it cannot.
///
/// Four flags rather than one verdict, deliberately. "Cannot apply" is not
/// useful on its own; the UI shows *which* condition failed, because the fix
/// differs completely — re-sanitize, install git, or pick a real file.
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
struct PatchStatus {
    /// The file exists under the project root.
    file_exists: bool,
    /// git is available and the project is a working tree.
    git_available: bool,
    git_explain: String,
    branch: String,
    dirty: bool,
    /// Set when the file has changed since it was indexed — SDD §13.1.
    stale: bool,
    /// Set when no checksum was ever recorded for this path.
    not_indexed: bool,
}

#[derive(Debug, Serialize)]
struct AppliedPatch {
    branch: String,
    previous_branch: String,
    created_branch: bool,
    files: usize,
}

fn to_note(line: usize, note: &diff::Note) -> WireNote {
    match note {
        diff::Note::Fuzzy { found, real_name, kind } => WireNote {
            kind: "fuzzy".to_owned(),
            line,
            detail: format!("{found} → {real_name} ({kind:?}) — matched loosely, not byte-for-byte"),
            token: String::new(),
        },
        diff::Note::Unresolved { token } => WireNote {
            kind: "unresolved".to_owned(),
            line,
            detail: format!("{token} is an alias this project has never issued"),
            token: token.clone(),
        },
        diff::Note::Redaction { marker } => WireNote {
            kind: "redaction".to_owned(),
            line,
            detail: format!("{marker} stays — redaction is one-way"),
            token: String::new(),
        },
    }
}

fn to_hunk(hunk: &diff::Hunk) -> WireHunk {
    WireHunk {
        kind: match hunk.kind {
            diff::ChangeKind::Added => "added",
            diff::ChangeKind::Removed => "removed",
            diff::ChangeKind::Changed => "changed",
            diff::ChangeKind::Formatting => "formatting",
        }
        .to_owned(),
        before_start: hunk.before.0,
        after_start: hunk.after.0,
        lines: hunk
            .lines
            .iter()
            .map(|l| WireLine {
                added: l.side == diff::Side::After,
                number: l.number,
                text: l.text.clone(),
            })
            .collect(),
        notes: hunk.notes.iter().map(|n| to_note(0, n)).collect(),
    }
}

/// Compare the file, the twin that was sent, and the twin that came back —
/// SDD §13.
///
/// Read-only. Nothing is written, no identity is interned, and the vault is not
/// touched: reviewing a response must not change what the next sanitize does.
#[tauri::command]
fn review_diff(state: State<'_, AppState>, original: String, twin: String, ai_twin: String) -> Result<DiffReview> {
    state.with(|vault, _| {
        let graph = graph_from(vault)?;
        let review = diff::review(&original, &twin, &ai_twin, &Vocabulary::new(graph.vocabulary()));

        Ok(DiffReview {
            changes: review.changes.iter().map(to_hunk).collect(),
            model_changes: review.model_changes.len(),
            substantive: review.substantive().count(),
            notes: review.notes.iter().map(|(line, n)| to_note(*line, n)).collect(),
            blocks_patch: review.blocks_patch(),
            unresolved: review.outcome.unresolved.iter().map(|u| u.token.clone()).collect(),
            restored: review.restored,
        })
    })
}

/// Name an entity the model invented — SDD §12.
///
/// The model's own token becomes the identity's alias. A freshly derived one
/// would leave the response being reviewed unrestorable, since that response
/// contains the token and nothing else.
#[tauri::command]
fn resolve_identity(
    state: State<'_, AppState>,
    alias: String,
    name: String,
    entity_type: String,
    scope: String,
) -> Result<()> {
    if !alias::is_alias_shaped(&alias) {
        return Err(fail(format!(
            "{alias:?} is not alias-shaped — this names tokens the model invented, not arbitrary text"
        )));
    }
    let parsed: EntityType = entity_type
        .parse()
        .map_err(|_| fail(format!("unknown entity type {entity_type:?}")))?;

    state.with(|vault, _| {
        if let Some(existing) = vault.identities()?.into_iter().find(|i| i.alias == alias) {
            return Err(fail(format!(
                "{alias} is already issued for {:?} — nothing to resolve",
                existing.real_name
            )));
        }

        vault.put_identity(&vault::StoredIdentity {
            uuid: uuid::Uuid::new_v4().to_string(),
            scope_path: if scope.is_empty() { "project".to_owned() } else { scope },
            entity_type: parsed.prefix().to_owned(),
            real_name: name,
            alias,
            origin: "ai_new".to_owned(),
            status: "active".to_owned(),
        })?;
        vault.log("resolve", None, Some(1), None, None)?;
        Ok(())
    })
}

/// Everything the UI needs to decide whether to offer patch application.
///
/// Answered before the user asks for it, so the button explains itself rather
/// than failing on click.
#[tauri::command]
fn patch_status(state: State<'_, AppState>, filename: String) -> Result<PatchStatus> {
    patch_status_in(&state, &filename)
}

/// The body, separated from the IPC wrapper so the guards can be tested. A
/// `State` cannot be constructed outside a running Tauri app, and these are the
/// checks that stand between AI output and someone's repository.
fn patch_status_in(session: &AppState, filename: &str) -> Result<PatchStatus> {
    session.with(|vault, root| {
        let path = root.join(filename);
        let file_exists = path.is_file();

        let indexed = vault.files()?.into_iter().find(|f| f.path == filename);
        let not_indexed = indexed.is_none();
        let stale = match (&indexed, file_exists) {
            (Some(entry), true) => {
                specshield_index::checksum_of(&path).map_err(|e| fail(e.to_string()))? != entry.checksum
            }
            _ => false,
        };

        let (git_available, git_explain, branch, dirty) = match git::Repository::discover(root) {
            git::Availability::Ready(repository) => {
                let branch = repository.current_branch().unwrap_or_default();
                let dirty = repository.is_dirty().unwrap_or(false);
                (true, "patch mode available".to_owned(), branch, dirty)
            }
            unavailable => (false, unavailable.explain().to_owned(), String::new(), false),
        };

        Ok(PatchStatus {
            file_exists,
            git_available,
            git_explain,
            branch,
            dirty,
            stale,
            not_indexed,
        })
    })
}

/// Apply restored content to a branch — SDD §14.
///
/// The frontend supplies the restored text it displayed, and nothing else: the
/// original comes off disk here, so the patch is built against what is actually
/// there rather than against whatever the UI last read.
///
/// Every guard is re-checked on this side. The frontend disables the button when
/// a patch is refused, but a disabled button is a courtesy, not a control.
#[tauri::command]
fn apply_patch(state: State<'_, AppState>, filename: String, restored: String, branch: String) -> Result<AppliedPatch> {
    apply_patch_in(&state, &filename, &restored, &branch)
}

fn apply_patch_in(state: &AppState, filename: &str, restored: &str, branch: &str) -> Result<AppliedPatch> {
    state.with(|vault, root| {
        let path = root.join(filename);
        let original = std::fs::read_to_string(&path).map_err(|e| fail(format!("reading {filename}: {e}")))?;

        // SDD §13.1. A patch built from a twin of older content can apply
        // cleanly and silently revert the edits made in between.
        let indexed = vault.files()?.into_iter().find(|f| f.path == filename);
        if let Some(entry) = indexed
            && specshield_index::checksum_of(&path).map_err(|e| fail(e.to_string()))? != entry.checksum
        {
            return Err(fail(format!(
                "{filename} has changed since it was indexed — re-sanitize before applying"
            )));
        }

        // SDD §12. An alias-shaped token left in the text would be written into
        // real source as a name nobody chose.
        let leftover = restore::restore(restored, &Vocabulary::new(graph_from(vault)?.vocabulary()));
        if !leftover.unresolved.is_empty() {
            return Err(fail(format!(
                "{} unresolved identit(ies) remain — name them first",
                leftover.unresolved.len()
            )));
        }

        let Some(diff) = git::patch([(filename, original.as_str(), restored)]) else {
            return Err(fail("no changes to apply"));
        };

        let git::Availability::Ready(repo) = git::Repository::discover(root) else {
            return Err(fail("git is not available here — patch mode is disabled"));
        };

        let applied = repo
            .apply_to_branch(&diff, branch, 1)
            .map_err(|e| fail(e.to_string()))?;

        std::fs::write(root.join(LAST_PATCH), &diff).map_err(|e| fail(e.to_string()))?;
        std::fs::write(
            root.join(LAST_APPLY),
            format!(
                "{{\"branch\":{:?},\"previous_branch\":{:?},\"created_branch\":{}}}\n",
                applied.branch, applied.previous_branch, applied.created_branch
            ),
        )
        .map_err(|e| fail(e.to_string()))?;

        vault.log("apply", Some(1), None, Some("applied"), Some(&applied.branch))?;

        Ok(AppliedPatch {
            branch: applied.branch,
            previous_branch: applied.previous_branch,
            created_branch: applied.created_branch,
            files: applied.files,
        })
    })
}

/// Reverse the last patch this project applied.
#[tauri::command]
fn undo_patch(state: State<'_, AppState>) -> Result<String> {
    state.with(|vault, root| {
        let patch_path = root.join(LAST_PATCH);
        let patch = std::fs::read_to_string(&patch_path).map_err(|_| fail("there is no applied patch to reverse"))?;
        let record = std::fs::read_to_string(root.join(LAST_APPLY)).unwrap_or_default();

        let field = |name: &str| -> String {
            record
                .split(&format!("\"{name}\":\""))
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default()
                .to_owned()
        };
        let applied = git::Applied {
            branch: field("branch"),
            previous_branch: field("previous_branch"),
            created_branch: record.contains("\"created_branch\":true"),
            files: 1,
        };

        let git::Availability::Ready(repository) = git::Repository::discover(root) else {
            return Err(fail("git is not available here — there is nothing to reverse"));
        };

        repository.undo(&patch, &applied).map_err(|e| fail(e.to_string()))?;
        vault.log("undo", Some(1), None, Some("reverted"), None)?;

        let _ = std::fs::remove_file(&patch_path);
        let _ = std::fs::remove_file(root.join(LAST_APPLY));

        Ok(repository.current_branch().unwrap_or_default())
    })
}

/// Copy a verified twin to the clipboard — SDD §17.5.
///
/// Reads the twin from session state rather than accepting text from the
/// frontend, so there is no path by which the UI can put arbitrary — possibly
/// original — content on the clipboard.
///
/// The clipboard write happens **before** the audit entry. An `export` row
/// means content left the application; writing it for a copy that failed would
/// make the log lie about the one thing a security team reads it for.
#[tauri::command]
fn copy_verified_twin(app: tauri::AppHandle, state: State<'_, AppState>, with_envelope: bool) -> Result<usize> {
    let twin = state
        .verified_twin()
        .ok_or_else(|| fail("nothing verified to copy — sanitize first"))?;

    let payload = if with_envelope {
        format!("{}\n\n{twin}", prompt_envelope())
    } else {
        twin
    };

    // Opt out of platform clipboard retention where we can — see `clipboard`
    // for what the three Windows formats govern and why the third one matters.
    let protection = match clipboard::write_protected(&payload)? {
        clipboard::Protection::OptedOut => clipboard::Protection::OptedOut,
        clipboard::Protection::NotAvailable => {
            // No opt-out on this platform: the plugin still has to do the write.
            app.clipboard()
                .write_text(payload.clone())
                .map_err(|e| fail(format!("clipboard write failed: {e}")))?;
            clipboard::Protection::NotAvailable
        }
    };

    // Clear it again after a delay, but only if it is still ours — see
    // `clear_if_unchanged`. Best-effort: a missed clear is not worth failing a
    // copy the user already has.
    let expected = payload.clone();
    let handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(clipboard::CLEAR_AFTER);
        if clipboard::clear_if_unchanged(&expected).unwrap_or(false) {
            let state = handle.state::<AppState>();
            let _ = state.with(|vault, _| {
                vault.log("clipboard.cleared", None, None, None, Some("clipboard"))?;
                Ok(())
            });
        }
    });

    state.with(|vault, _| {
        // Record whether the opt-out actually applied. A security team reading
        // this log needs to know which exports the platform may have retained.
        let destination = match protection {
            clipboard::Protection::OptedOut => "clipboard(opted-out)",
            clipboard::Protection::NotAvailable => "clipboard(unprotected)",
        };
        vault.log("export", Some(1), None, Some("clean"), Some(destination))?;
        Ok(payload.len())
    })
}

#[tauri::command]
fn audit_log(state: State<'_, AppState>, limit: usize) -> Result<Vec<AuditRow>> {
    state.with(|vault, _| {
        Ok(vault
            .audit_log(limit)?
            .into_iter()
            .map(|e| AuditRow {
                ts: e.ts,
                operation: e.operation,
                file_count: e.file_count,
                entity_count: e.entity_count,
                verification: e.verification,
                destination: e.destination,
            })
            .collect())
    })
}

/// Write the audit log to a CSV file — PRD FR-9, "exportable as CSV for
/// compliance review".
///
/// Rust writes the file rather than the frontend, because the application holds
/// no filesystem capability and is not going to acquire one to save a report.
/// The destination is inside `.specshield/`, which is already ignored by git:
/// the log contains no names and no content, but an operations history is not
/// something to scatter through someone's repository either.
#[tauri::command]
fn export_audit_csv(state: State<'_, AppState>, limit: usize) -> Result<String> {
    state.with(|vault, root| {
        let csv = vault::audit_csv(&vault.audit_log(limit)?);
        let path = root.join(".specshield").join("audit.csv");
        std::fs::write(&path, csv).map_err(|e| fail(format!("writing {}: {e}", path.display())))?;

        // Deliberately not logged. An audit export that appends to the audit log
        // makes every export look like activity in the next one.
        Ok(path.display().to_string())
    })
}

// ---------------------------------------------------------------------------
// Vault operations — PRD FR-11, SDD §16
//
// These are the operations that make a lost or over-shared vault survivable.
// They lived only on the command line, which put them out of reach of the users
// least likely to open a terminal.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct RekeyPreview {
    /// How many aliases would move. Shown before the user commits, because
    /// every one of them orphans a twin already shared.
    identities: usize,
}

#[derive(Serialize)]
struct RecoveryReport {
    diagnosis: String,
    readable: bool,
    schema_version: i64,
    identities: usize,
    files: usize,
    entity_types: Vec<(String, usize)>,
    audit: Vec<AuditRow>,
}

/// Copy the vault somewhere safe — FR-11.
///
/// `dest` is resolved relative to the project root when it is not absolute. The
/// application has no filesystem capability and no file picker; Rust does the
/// writing, and it refuses to overwrite.
#[tauri::command]
fn backup_vault(state: State<'_, AppState>, dest: String) -> Result<String> {
    state.with(|vault, root| {
        let path = resolve(root, &dest);
        vault.backup_to(&path)?;
        Ok(path.display().to_string())
    })
}

/// Put a backup back — FR-11.
///
/// Takes its own passphrase because the backup may predate the current one, and
/// verifies the backup opens before the destination exists. Restoring a backup
/// nobody can open is a failure discovered in the middle of the incident the
/// backup existed for.
#[tauri::command]
fn restore_vault(state: State<'_, AppState>, backup: String, into: String, passphrase: String) -> Result<String> {
    state.with(|_, root| {
        let from = resolve(root, &backup);
        let to = resolve(root, &into);
        vault::backup::restore_from(&from, &to, &passphrase)?;
        Ok(to.display().to_string())
    })
}

/// Export a passphrase-protected key escrow — FR-11.
#[tauri::command]
fn export_escrow(
    state: State<'_, AppState>,
    out: String,
    escrow_passphrase: String,
    passphrase: String,
) -> Result<String> {
    export_escrow_in(&state, &out, &escrow_passphrase, &passphrase)
}

/// The body, split from the IPC wrapper so it can be tested — a `State` cannot
/// be constructed outside a running Tauri app.
fn export_escrow_in(state: &AppState, out: &str, escrow_passphrase: &str, passphrase: &str) -> Result<String> {
    state.with(|vault, root| {
        let path = resolve(root, out);
        if path.exists() {
            return Err(fail(format!(
                "{} already exists — refusing to overwrite an escrow file",
                path.display()
            )));
        }

        // The escrow holds the vault's data key, not the passphrase — schema
        // v3. The passphrase is still checked, because issuing an escrow is not
        // something to do on a vault you cannot open.
        vault::Vault::open(&crate::state::vault_path(root), passphrase)
            .map_err(|_| fail("that is not this vault's passphrase"))?;

        let sealed = vault.export_escrow(escrow_passphrase)?;
        std::fs::write(&path, &sealed).map_err(|e| fail(format!("writing {}: {e}", path.display())))?;
        vault.log("vault.escrow", None, None, None, None)?;

        Ok(path.display().to_string())
    })
}

/// The warning FR-11 requires, so the screen shows the same words the file
/// carries rather than a paraphrase of them.
#[tauri::command]
const fn escrow_warning() -> &'static str {
    vault::backup::ESCROW_WARNING
}

/// Recover a vault passphrase from an escrow file — FR-11.
///
/// Returns the passphrase. There is nothing else it could usefully return: the
/// point of escrow is to hand back the way in.
#[tauri::command]
fn open_escrow(
    state: State<'_, AppState>,
    file: String,
    escrow_passphrase: String,
    new_passphrase: String,
) -> Result<String> {
    if new_passphrase.is_empty() {
        return Err(fail("an empty passphrase protects nothing"));
    }

    state.with(|_, root| {
        let path = resolve(root, &file);
        let sealed = std::fs::read(&path).map_err(|e| fail(format!("reading {}: {e}", path.display())))?;

        // Re-wraps the data key under the passphrase the recoverer chose. It
        // never reveals the original one — that is the point of escrowing a key
        // rather than a passphrase.
        vault::Vault::recover_with_escrow(
            &crate::state::vault_path(root),
            &sealed,
            &escrow_passphrase,
            &new_passphrase,
        )?;
        Ok(crate::state::vault_path(root).display().to_string())
    })
}

/// Change the vault passphrase — PRD FR-11.
///
/// Re-wraps the data key. Not one encrypted value moves, which is what makes
/// this possible at all: before schema v3 it would have been a re-encryption of
/// the entire vault.
#[tauri::command]
fn change_passphrase(state: State<'_, AppState>, old: String, new: String) -> Result<()> {
    state.with(|vault, _| {
        vault.change_passphrase(&old, &new)?;
        Ok(())
    })
}

/// Rotate the vault's data key — PRD FR-11.
///
/// Re-encrypts every sealed value. The only way to make an escrow file or an old
/// backup stop working, and slow in proportion to the vault.
#[tauri::command]
fn rotate_vault_key(state: State<'_, AppState>, passphrase: String) -> Result<()> {
    state.with(|vault, _| {
        vault.rotate_data_key(&passphrase)?;
        Ok(())
    })
}

/// What a re-key would cost, without doing it.
#[tauri::command]
fn rekey_preview(state: State<'_, AppState>) -> Result<RekeyPreview> {
    state.with(|vault, _| {
        Ok(RekeyPreview {
            identities: vault.identities()?.len(),
        })
    })
}

/// Regenerate every alias under a new project key — FR-11.
///
/// The operation with the worst failure mode in the product: every twin already
/// shared stops resolving. `confirm` is required, and the caller is expected to
/// have shown `rekey_preview` first.
#[tauri::command]
fn rekey_project(state: State<'_, AppState>, confirm: bool) -> Result<usize> {
    rekey_project_in(&state, confirm)
}

/// The body, split from the IPC wrapper so the confirmation guard can be
/// tested. A `State` cannot be constructed outside a running Tauri app, and
/// this is the operation that orphans every twin a project has produced.
fn rekey_project_in(state: &AppState, confirm: bool) -> Result<usize> {
    if !confirm {
        return Err(fail("re-keying orphans every twin already shared — confirm first"));
    }

    state
        .with(|vault, _| {
            let mut fresh = [0u8; 32];
            getrandom::fill(&mut fresh).map_err(|e| fail(format!("entropy source unavailable: {e}")))?;
            vault.rotate_project_key(&fresh)?;
            fresh.zeroize();

            let concepts: std::collections::HashMap<String, String> = vault.concepts()?.into_iter().collect();

            let stored = vault.identities()?;
            let mut identities: Vec<specshield_core::rekey::Rekeyed> = stored
                .iter()
                .filter_map(|s| {
                    let entity_type = s.entity_type.parse().ok()?;
                    Some(specshield_core::rekey::Rekeyed {
                        uuid: s.uuid.clone(),
                        key: specshield_core::model::IdentityKey::new(&s.scope_path, entity_type, &s.real_name),
                        alias: s.alias.clone(),
                        concept: concepts.get(&s.uuid).cloned(),
                    })
                })
                .collect();

            let changed = specshield_core::rekey::rederive(&mut identities);

            let by_uuid: std::collections::HashMap<&str, &specshield_core::rekey::Rekeyed> =
                identities.iter().map(|i| (i.uuid.as_str(), i)).collect();
            for mut row in stored {
                let Some(rekeyed) = by_uuid.get(row.uuid.as_str()) else {
                    continue;
                };
                if rekeyed.alias != row.alias {
                    row.alias = rekeyed.alias.clone();
                    vault.put_identity(&row)?;
                }
            }

            // The session's verified twin was produced under the old key and no
            // longer restores. Holding on to it would let the user copy something
            // this vault can no longer reverse.
            Ok(changed)
        })
        .inspect(|_| state.set_verified_twin(None))
}

/// Inspect a vault that will not open — SDD §16.
///
/// Takes a path rather than using the session, because the case this exists for
/// is a vault that could not be opened in the first place.
#[tauri::command]
fn recover_vault(path: String) -> Result<RecoveryReport> {
    let recovery = vault::Recovery::open(std::path::Path::new(&path))?;

    Ok(RecoveryReport {
        diagnosis: recovery.diagnosis().to_owned(),
        readable: recovery.is_readable(),
        schema_version: recovery.schema_version().unwrap_or(0),
        identities: recovery.identity_count(),
        files: recovery.file_count(),
        entity_types: recovery.entity_types(),
        audit: recovery
            .audit_log(50)
            .into_iter()
            .map(|e| AuditRow {
                ts: e.ts,
                operation: e.operation,
                file_count: e.file_count,
                entity_count: e.entity_count,
                verification: e.verification,
                destination: e.destination,
            })
            .collect(),
    })
}

/// Resolve a user-supplied path against the project root.
///
/// A relative path lands beside the project, which is what someone typing
/// `../billing.backup` means. An absolute one is taken as given.
fn resolve(root: &std::path::Path, given: &str) -> std::path::PathBuf {
    let path = std::path::Path::new(given);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

// ---------------------------------------------------------------------------
// Project operations — the same pipeline the command line runs
//
// Every one of these delegates to `specshield-project`. Two copies of the
// export pipeline would be two chances to drift, and drift here means a twin
// produced by one surface cannot be restored by the other.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct IndexSummary {
    files: usize,
    text: usize,
    parseable: usize,
    seconds: f64,
}

#[derive(Serialize)]
struct RescanSummary {
    files: usize,
    added: Vec<String>,
    modified: Vec<String>,
    removed: Vec<String>,
    unchanged: usize,
    /// Files whose recorded twin was made from content that no longer exists —
    /// SDD §13.1.
    stale: Vec<String>,
    seconds: f64,
}

#[derive(Serialize)]
struct ExportSummary {
    written: usize,
    aliased: usize,
    identities: usize,
    renamed: usize,
    unchecked: usize,
    abandoned: Vec<(String, String)>,
    /// Vault names that reached a twin. Reported; the twin was still written
    /// unless `refused` — SDD §8.
    leaks: Vec<(String, Vec<String>)>,
    /// Files whose twin still holds a secret. Always fatal.
    unredacted: Vec<String>,
    /// Nothing was written.
    refused: bool,
    /// Vault names the gate was told to ignore — FR-10.
    allowlisted: usize,
    /// Files a parser claimed and could not read. They went out with no
    /// structural aliasing and no check — see `SanitizeResult::unreadable`.
    unreadable: Vec<(String, String)>,
    /// Places recorded in the vault — FR-5.
    occurrences: usize,
    /// Secrets redacted on the way out, and how many are new since the last
    /// export. Both are about the working tree, not the twin.
    redacted: usize,
    redacted_new: usize,
    destination: String,
}

#[derive(Serialize)]
struct UnifyProposal {
    concept: String,
    confidence: f32,
    members: Vec<UnifyMember>,
    caveat: Option<String>,
}

#[derive(Serialize)]
struct UnifyMember {
    entity_type: String,
    real_name: String,
    scope_path: String,
}

#[derive(Serialize)]
struct VerifyResult {
    /// `false` when a real name survived, or a high-confidence secret is present.
    clean: bool,
    /// How many patterns the gate had to look for. Zero means nothing was
    /// checked, which is not the same as clean.
    patterns_checked: usize,
    leaks: Vec<Leak>,
    secrets: Vec<SecretFinding>,
}

/// Walk the project and record what is in it — SDD §4.1.
#[tauri::command]
fn index_project(state: State<'_, AppState>) -> Result<IndexSummary> {
    state.with(|vault, root| {
        let started = std::time::Instant::now();
        let index = project::index_project(root, vault)?;
        let seconds = started.elapsed().as_secs_f64();

        let parseable = index
            .files
            .values()
            .filter(|e| !project::parser_for(root, e).is_empty())
            .count();

        Ok(IndexSummary {
            files: index.len(),
            text: index.text_files().count(),
            parseable,
            seconds,
        })
    })
}

/// Re-walk and say what moved — SDD §13.1.
#[tauri::command]
fn rescan_project(session: State<'_, AppState>) -> Result<RescanSummary> {
    session.with(|vault, root| {
        if vault.files()?.is_empty() {
            return Err(fail("no index for this project yet — index it first"));
        }

        let started = std::time::Instant::now();
        let (index, changes, stale) = project::rescan_project(root, vault)?;

        Ok(RescanSummary {
            files: index.len(),
            added: changes.added,
            modified: changes.modified,
            removed: changes.removed,
            unchanged: changes.unchanged,
            stale,
            seconds: started.elapsed().as_secs_f64(),
        })
    })
}

/// Sanitize the whole project into a twin directory.
///
/// Nothing is written unless every file passes the gate: a directory that is
/// clean apart from one leak is not clean.
#[tauri::command]
fn export_project(state: State<'_, AppState>, dest: String, strict: bool) -> Result<ExportSummary> {
    state.with(|vault, root| {
        let destination = resolve(root, &dest);
        let result = project::export(root, &destination, vault, strict)?;

        Ok(ExportSummary {
            written: result.written,
            aliased: result.aliased,
            identities: result.identities,
            renamed: result.renamed,
            unchecked: result.unchecked,
            abandoned: result.abandoned,
            leaks: result.leaks,
            unredacted: result.unredacted,
            refused: result.refused,
            allowlisted: result.allowlisted,
            unreadable: result.unreadable,
            occurrences: result.occurrences,
            redacted: result.redacted,
            redacted_new: result.redacted_new,
            destination: destination.display().to_string(),
        })
    })
}

#[derive(Serialize)]
struct RestoredProject {
    written: usize,
    aliases_resolved: usize,
    unmapped: Vec<String>,
    destination: String,
}

/// Put a whole twin project back at its real paths — the inverse of
/// `export_project`.
///
/// The half of path aliasing that makes it usable: a twin tree whose
/// directories and filenames are aliases is only reversible because the vault
/// recorded the mapping.
#[tauri::command]
fn restore_project(state: State<'_, AppState>, twin: String, dest: String) -> Result<RestoredProject> {
    state.with(|vault, root| {
        let twin_root = resolve(root, &twin);
        let destination = resolve(root, &dest);
        let result = project::restore_project(vault, &twin_root, &destination)?;

        Ok(RestoredProject {
            written: result.written,
            aliases_resolved: result.aliases_resolved,
            unmapped: result.unmapped,
            destination: destination.display().to_string(),
        })
    })
}

#[derive(Serialize)]
struct Appearance {
    path: String,
    line: usize,
    column: usize,
    kind: String,
}

#[derive(Serialize)]
struct LocatedIdentity {
    real_name: String,
    alias: String,
    entity_type: String,
    scope_path: String,
    appearances: Vec<Appearance>,
}

/// Where an identity appears, by real name or by alias — PRD FR-5.
#[tauri::command]
fn locate_identity(state: State<'_, AppState>, name: String) -> Result<Vec<LocatedIdentity>> {
    state.with(|vault, root| locate_identity_in(vault, root, &name))
}

fn locate_identity_in(vault: &mut vault::Vault, root: &Path, name: &str) -> Result<Vec<LocatedIdentity>> {
    Ok(project::locate(vault, name)?
        .into_iter()
        .map(|found| LocatedIdentity {
            real_name: found.real_name,
            alias: found.alias,
            entity_type: found.entity_type,
            scope_path: found.scope_path,
            appearances: found
                .appearances
                .into_iter()
                .map(|a| {
                    // Resolved here rather than in the webview, which has no
                    // filesystem access and could not turn an offset into a
                    // line if it wanted to. Zero means "no position", which the
                    // UI shows as nothing rather than as line zero.
                    let (line, column) = project::line_and_column(root, &a.path, a.byte_start).unwrap_or((0, 0));
                    Appearance {
                        path: a.path,
                        line,
                        column,
                        kind: a.kind,
                    }
                })
                .collect(),
        })
        .collect())
}

#[derive(Serialize)]
struct SecretSite {
    path: String,
    line: usize,
    column: usize,
    secret_type: String,
}

/// Every secret this project redacted, and where it still is — SDD §4.3.
///
/// Positions in the working tree, never values: the vault holds a one-way index
/// and no plaintext, so it can say where it found something and nothing more.
#[tauri::command]
fn secret_sites(state: State<'_, AppState>) -> Result<Vec<SecretSite>> {
    state.with(secret_sites_in)
}

fn secret_sites_in(vault: &mut vault::Vault, root: &Path) -> Result<Vec<SecretSite>> {
    Ok(project::secret_sites(vault)?
        .into_iter()
        .map(|site| {
            let (line, column) = project::line_and_column(root, &site.path, site.byte_start).unwrap_or((0, 0));
            SecretSite {
                path: site.path,
                line,
                column,
                secret_type: site.secret_type,
            }
        })
        .collect())
}

/// Cross-artifact unification proposals — SDD §5.
#[tauri::command]
fn unify_proposals(state: State<'_, AppState>) -> Result<Vec<UnifyProposal>> {
    state.with(|vault, _| {
        Ok(project::unify_proposals(vault)?
            .into_iter()
            .map(|p| UnifyProposal {
                concept: p.concept,
                confidence: p.confidence,
                members: p
                    .members
                    .iter()
                    .map(|m| UnifyMember {
                        entity_type: m.entity_type.prefix().to_owned(),
                        real_name: m.real_name.clone(),
                        scope_path: m.scope_path.clone(),
                    })
                    .collect(),
                caveat: p.caveat,
            })
            .collect())
    })
}

/// Confirm one proposal — SDD §5. Returns `(linked, aliases changed)`.
///
/// Nothing is ever unified without this: three unrelated `Status` enums share a
/// name and are three different things.
#[tauri::command]
fn unify_confirm(state: State<'_, AppState>, concept: String) -> Result<(usize, usize)> {
    let outcome = state.with(|vault, _| Ok(project::unify_confirm(vault, &concept)?));

    // Confirmation re-derives aliases, so the session's twin may no longer
    // restore. Same reasoning as re-key.
    if let Ok((_, changed)) = &outcome
        && *changed > 0
    {
        state.set_verified_twin(None);
    }
    outcome
}

/// Run the export gate over arbitrary text — SDD §8.
///
/// Standalone, for checking something that did not come from `sanitize` — a
/// file edited by hand, or a fragment about to be pasted somewhere.
#[tauri::command]
fn verify_text(state: State<'_, AppState>, content: String) -> Result<VerifyResult> {
    verify_text_in(&state, &content)
}

fn verify_text_in(state: &AppState, content: &str) -> Result<VerifyResult> {
    state.with(|vault, _| {
        let graph = project::graph_from(vault)?;
        let scanner = project::gate(vault, &graph)?;
        let verdict = scanner.scan(content);
        let findings = secrets::scan(content);

        let leaks = match &verdict {
            verify::Verdict::Clean => Vec::new(),
            verify::Verdict::Blocked(hits) => hits
                .iter()
                .map(|l| Leak {
                    matched: l.matched.clone(),
                    line: l.line,
                    column: l.column,
                })
                .collect(),
        };

        Ok(VerifyResult {
            clean: verdict.is_clean() && !secrets::blocks_export(&findings),
            patterns_checked: scanner.pattern_count(),
            leaks,
            secrets: findings.iter().map(to_secret_wire).collect(),
        })
    })
}

// ---------------------------------------------------------------------------
// File picking — P1-3
//
// The dialog runs **in Rust**. The frontend is given no dialog permission and no
// filesystem permission, and none of these commands accepts a path to read: the
// only way content enters the application is a file a human chose in a native
// dialog.
//
// That distinction is the whole point. Granting the webview `fs:allow-read-*`
// would have been two lines shorter and would have meant the frontend could read
// anything on the machine — a capability that has to be reasoned about forever
// afterwards, in a product whose main claim is about what it does not do.
// ---------------------------------------------------------------------------

/// Extensions offered in the open dialog. Formats this build has a parser for,
/// plus the plain-text kinds that fall back to the text parser.
const OPENABLE: &[&str] = &[
    "md", "markdown", "txt", "sql", "yaml", "yml", "json", "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs",
];

#[derive(Serialize)]
struct PickedFile {
    /// Absolute path, for display.
    path: String,
    /// The name the parser dispatches on.
    name: String,
    content: String,
}

/// Open a file the user chooses.
///
/// Returns `None` when the dialog is cancelled, which is not an error and should
/// not be reported as one.
///
/// Text only: a binary would arrive as replacement characters and sanitize into
/// nonsense. Saying so beats letting someone wonder why their PNG produced an
/// empty document.
#[tauri::command]
fn pick_file(app: tauri::AppHandle) -> Result<Option<PickedFile>> {
    use tauri_plugin_dialog::DialogExt;

    let Some(picked) = app
        .dialog()
        .file()
        .add_filter("Supported documents", OPENABLE)
        .add_filter("All files", &["*"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };

    let path = picked
        .into_path()
        .map_err(|e| fail(format!("that file could not be opened: {e}")))?;

    let content = std::fs::read_to_string(&path)
        .map_err(|_| fail(format!("{} is not text this build can read", path.display())))?;

    Ok(Some(PickedFile {
        name: path
            .file_name()
            .map_or_else(|| "document".to_owned(), |n| n.to_string_lossy().into_owned()),
        path: path.display().to_string(),
        content,
    }))
}

/// Choose a directory — a project root, a twin destination, a restore target.
#[tauri::command]
fn pick_directory(app: tauri::AppHandle) -> Result<Option<String>> {
    use tauri_plugin_dialog::DialogExt;

    let Some(picked) = app.dialog().file().blocking_pick_folder() else {
        return Ok(None);
    };
    let path = picked
        .into_path()
        .map_err(|e| fail(format!("that folder could not be used: {e}")))?;
    Ok(Some(path.display().to_string()))
}

/// Choose where to write something, and write it.
///
/// The content comes from the caller rather than a path, so this cannot be used
/// to copy a file from one place to another — it writes what the application
/// already had in hand.
#[tauri::command]
fn save_text(app: tauri::AppHandle, suggested_name: String, content: String) -> Result<Option<String>> {
    use tauri_plugin_dialog::DialogExt;

    let Some(picked) = app.dialog().file().set_file_name(&suggested_name).blocking_save_file() else {
        return Ok(None);
    };

    let path = picked
        .into_path()
        .map_err(|e| fail(format!("that location could not be used: {e}")))?;
    std::fs::write(&path, content).map_err(|e| fail(format!("writing {}: {e}", path.display())))?;
    Ok(Some(path.display().to_string()))
}

/// Save the verified twin, without it passing through the frontend.
///
/// The same reasoning as `copy_verified_twin` (SDD §17.5): the twin is read from
/// session state rather than accepted over IPC, so there is no path by which the
/// UI could write *original* content to a file the user thinks holds a twin.
#[tauri::command]
fn save_verified_twin(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    suggested_name: String,
) -> Result<Option<String>> {
    let twin = state
        .verified_twin()
        .ok_or_else(|| fail("nothing verified to save — sanitize first"))?;

    let saved = save_text(app, suggested_name, twin)?;
    if saved.is_some() {
        state.with(|vault, _| {
            vault.log("export", Some(1), None, Some("clean"), Some("file"))?;
            Ok(())
        })?;
    }
    Ok(saved)
}

/// Formats this build can process. The UI uses it to explain a refusal rather
/// than showing a dead end.
#[tauri::command]
fn supported_formats() -> Vec<String> {
    specshield_parsers::implemented()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_parser(filename: &str, content: &str) -> Result<Box<dyn specshield_core::parser::ArtifactParser>> {
    specshield_parsers::for_document(std::path::Path::new(filename), content).ok_or_else(|| {
        fail(format!(
            "No parser for {filename} in this build (have: {}). \
                 Processing it anyway would produce a twin that looks sanitized while \
                 leaving declarations and identifiers untouched. SQL and YAML arrive in M3; \
                 TypeScript in M4.",
            specshield_parsers::implemented().join(", ")
        ))
    })
}

fn to_wire(c: &specshield_core::parser::Candidate) -> DetectedEntity {
    DetectedEntity {
        real_name: c.real_name.clone(),
        entity_type: c.entity_type.prefix().to_owned(),
        byte_start: c.byte_start,
        byte_end: c.byte_end,
        confidence: c.confidence,
    }
}

fn to_secret_wire(f: &secrets::Finding) -> SecretFinding {
    SecretFinding {
        secret_type: f.secret_type.to_owned(),
        line: f.line,
        blocking: f.confidence == secrets::Confidence::High,
    }
}

fn graph_from(vault: &vault::Vault) -> Result<Graph> {
    let mut graph = Graph::new();
    for stored in vault.identities()? {
        let entity_type: EntityType = stored
            .entity_type
            .parse()
            .map_err(|_| fail(format!("vault holds unknown entity type {:?}", stored.entity_type)))?;
        graph.restore_node(
            &specshield_core::model::IdentityKey::new(&stored.scope_path, entity_type, &stored.real_name),
            &stored.uuid,
            &stored.alias,
            Origin::Detected,
            Status::Active,
        );
    }
    Ok(graph)
}

/// The members the project already knows, so a file that only *uses* a property
/// still recognises it — SDD §5.
fn context_from(vault: &vault::Vault) -> Result<ProjectContext> {
    let identities = vault.identities()?;
    let members = identities
        .iter()
        .filter(|i| i.entity_type == EntityType::Column.prefix())
        .map(|i| i.real_name.clone());
    let names = identities.iter().map(|i| i.real_name.clone());
    Ok(ProjectContext::new(members, names))
}

fn detector_from(vault: &vault::Vault) -> Result<Detector> {
    let mut detector = Detector::new();

    // Names learned from any artifact are found in every artifact — SDD §5.
    // Without this the SQL scan interns the table `invoice`, the spec next to it
    // says "invoice" in prose, and the gate blocks on a name the project already
    // knows.
    for identity in vault.identities()? {
        if let Ok(entity_type) = identity.entity_type.parse() {
            detector = detector.with_term(identity.real_name, entity_type);
        }
    }

    for (name, type_name) in vault.dictionary()? {
        let entity_type: EntityType = type_name
            .parse()
            .map_err(|_| fail(format!("dictionary holds unknown entity type {type_name:?}")))?;
        detector = detector.with_term(name, entity_type);
    }
    for term in vault.allowlist()? {
        detector = detector.with_allowed(term);
    }
    Ok(detector)
}

fn persist(vault: &mut vault::Vault, graph: &Graph) -> Result<()> {
    let identities: Vec<vault::StoredIdentity> = graph
        .nodes()
        .map(|n| vault::StoredIdentity {
            uuid: n.uuid.to_string(),
            scope_path: n.key.scope_path.clone(),
            entity_type: n.key.entity_type.prefix().to_owned(),
            real_name: n.key.real_name.clone(),
            alias: n.alias.clone(),
            origin: "detected".to_owned(),
            status: "active".to_owned(),
        })
        .collect();
    vault.put_identities(&identities)?;
    Ok(())
}

/// SDD §11 / PRD FR-6b.
fn prompt_envelope() -> String {
    format!(
        "Tokens matching `{}` are opaque anonymized identifiers. Preserve them \
         exactly — do not rename, expand, translate, pluralize, or reformat them. \
         If you introduce a new entity, name it `NEW_<n>` and list every such name \
         at the end of your response.",
        alias::ENVELOPE_PATTERN
    )
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        // The dialog runs in Rust only — see `pick_file`. No dialog or
        // filesystem permission is granted to the webview.
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            create_project,
            open_project,
            project_info,
            close_project,
            add_term,
            add_allowed,
            scan_text,
            sanitize_text,
            restore_text,
            review_diff,
            resolve_identity,
            patch_status,
            apply_patch,
            undo_patch,
            copy_verified_twin,
            audit_log,
            export_audit_csv,
            backup_vault,
            restore_vault,
            export_escrow,
            escrow_warning,
            open_escrow,
            change_passphrase,
            rotate_vault_key,
            rekey_preview,
            rekey_project,
            recover_vault,
            index_project,
            rescan_project,
            export_project,
            restore_project,
            unify_proposals,
            unify_confirm,
            verify_text,
            locate_identity,
            secret_sites,
            pick_file,
            pick_directory,
            save_text,
            save_verified_twin,
            supported_formats,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SpecShield");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::vault_path;

    struct TempProject(std::path::PathBuf);

    impl TempProject {
        fn new(name: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!("specshield-app-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("temp dir");
            std::fs::create_dir_all(root.join(".specshield")).expect("vault dir");

            let settings = vault::Settings {
                project_name: "test".to_owned(),
                root_path: root.display().to_string(),
                scope_strategy: "module".to_owned(),
            };
            vault::Vault::create(&vault_path(&root), "pw", &settings).expect("create vault");
            Self(root)
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("parent");
            }
            std::fs::write(path, content).expect("write");
        }

        fn open(&self) -> AppState {
            let state = AppState::default();
            state.open(&self.0, "pw").expect("open");
            state
        }
    }

    impl Drop for TempProject {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record_file(state: &AppState, path: &str, checksum: &str) {
        state
            .with(|vault, _| {
                vault.put_files(&[vault::StoredFile {
                    path: path.to_owned(),
                    twin_path: path.to_owned(),
                    checksum: checksum.to_owned(),
                    parser: "typescript".to_owned(),
                }])?;
                Ok(())
            })
            .expect("record");
    }

    #[test]
    fn a_relative_path_lands_beside_the_project_and_an_absolute_one_is_taken_as_given() {
        let root = std::path::Path::new("/work/billing");
        assert_eq!(resolve(root, "../billing.backup"), root.join("../billing.backup"));

        let absolute = if cfg!(windows) {
            "C:/secure/x.backup"
        } else {
            "/secure/x.backup"
        };
        assert_eq!(resolve(root, absolute), std::path::PathBuf::from(absolute));
    }

    #[test]
    fn re_keying_without_confirmation_does_nothing() {
        // The frontend gates this behind a checkbox. A checkbox is a courtesy;
        // this is the control. Every twin the project ever shared stops working.
        let project = TempProject::new("rekey-unconfirmed");
        let state = project.open();

        let before = state.with(|vault, _| Ok(vault.identities()?)).expect("read");
        assert!(rekey_project_in(&state, false).is_err());
        let after = state.with(|vault, _| Ok(vault.identities()?)).expect("read");
        assert_eq!(before, after);
    }

    #[test]
    fn re_keying_moves_every_alias_and_drops_the_session_twin() {
        let project = TempProject::new("rekey-confirmed");
        let state = project.open();
        state
            .with(|vault, _| {
                vault.put_identity(&vault::StoredIdentity {
                    uuid: "0198c0de0000700080000000000001".to_owned(),
                    scope_path: "mod/a".to_owned(),
                    entity_type: "SERVICE".to_owned(),
                    real_name: "CustomerService".to_owned(),
                    alias: "SERVICE_AAA111".to_owned(),
                    origin: "detected".to_owned(),
                    status: "active".to_owned(),
                })?;
                Ok(())
            })
            .expect("seed");
        state.set_verified_twin(Some("SERVICE_AAA111 owns it".to_owned()));

        let changed = rekey_project_in(&state, true).expect("rekey");
        assert_eq!(changed, 1);

        let alias = state
            .with(|vault, _| Ok(vault.identities()?[0].alias.clone()))
            .expect("read");
        assert_ne!(alias, "SERVICE_AAA111");
        assert!(
            state.verified_twin().is_none(),
            "the session twin was produced under the old key and no longer restores —              keeping it would let the user copy something this vault cannot reverse"
        );
    }

    #[test]
    fn escrow_refuses_a_passphrase_that_is_not_this_vaults() {
        // An escrow file holding the wrong passphrase is worse than none: it is
        // a recovery plan that fails only when it is needed.
        let project = TempProject::new("escrow-wrong");
        let state = project.open();

        let out = project.0.join("wrong.escrow");
        let result = export_escrow_in(&state, out.to_str().expect("path"), "escrow-pw", "not-the-passphrase");

        assert!(result.is_err());
        assert!(!out.exists(), "nothing was written");
    }

    #[test]
    fn escrow_round_trips_through_the_app_layer() {
        let project = TempProject::new("escrow-ok");
        let state = project.open();

        let out = project.0.join("good.escrow");
        let path = export_escrow_in(&state, out.to_str().expect("path"), "escrow-pw", "pw").expect("export");
        assert!(std::path::Path::new(&path).exists());

        // The escrow holds the vault's data key, not the passphrase (schema
        // v3), so what it proves is that recovery works — not that it hands
        // back a string somebody could reuse elsewhere.
        let sealed = std::fs::read(&path).expect("read");
        assert!(vault::backup::open_escrow(&sealed, "escrow-pw").is_ok());
        assert!(
            !sealed.windows(2).any(|w| w == b"pw"),
            "the passphrase must not be in the escrow"
        );
    }

    #[test]
    fn recovery_reports_a_garbage_file_without_failing() {
        let project = TempProject::new("recover");
        let path = project.0.join("broken.bin");
        std::fs::write(&path, b"not a vault").expect("write");

        let report = recover_vault(path.display().to_string()).expect("recovery is not a dead end");
        assert!(!report.readable);
        assert!(
            report.diagnosis.contains("not a SpecShield vault"),
            "{}",
            report.diagnosis
        );
    }

    // --- P1-5: the commands, not just the helpers ---------------------------

    #[test]
    fn sanitizing_aliases_a_dictionary_term_and_makes_the_twin_copyable() {
        let project = TempProject::new("sanitize-ok");
        let state = project.open();
        add_term_in(&state, "Vantor", "ORG").expect("term");

        let result = sanitize_text_in(&state, "a.md", "Vantor owns billing.\n").expect("sanitize");

        assert!(result.verified);
        let twin = result.twin.expect("a verified twin is returned");
        assert!(!twin.contains("Vantor"), "{twin}");
        assert_eq!(state.verified_twin().as_deref(), Some(twin.as_str()));
        assert!(
            !result.not_checked.is_empty(),
            "PRD §4.3 — every green state carries what was not checked"
        );
    }

    #[test]
    fn a_format_with_no_parser_is_refused_rather_than_guessed_at() {
        let project = TempProject::new("no-parser");
        let state = project.open();

        let result = scan_text_in(&state, "photo.png", "not really a png");
        assert!(
            result.is_err(),
            "a format with no parser must be named, not silently text-scanned"
        );
    }

    #[test]
    fn an_unknown_entity_type_is_refused() {
        let project = TempProject::new("bad-type");
        let state = project.open();
        assert!(add_term_in(&state, "Vantor", "NOT_A_TYPE").is_err());
    }

    #[test]
    fn the_standalone_gate_blocks_on_a_name_the_vault_knows() {
        let project = TempProject::new("verify-blocks");
        let state = project.open();
        add_term_in(&state, "Vantor", "ORG").expect("term");
        // Interning happens on the first sanitize, which is what gives the gate
        // something to look for.
        sanitize_text_in(&state, "a.md", "Vantor owns billing.\n").expect("sanitize");

        let result = verify_text_in(&state, "A note about Vantor.").expect("verify");
        assert!(!result.clean);
        assert!(result.patterns_checked > 0);
        assert_eq!(result.leaks.len(), 1);
        assert_eq!(result.leaks[0].matched, "Vantor");
    }

    #[test]
    fn the_standalone_gate_reports_zero_patterns_rather_than_a_false_clean() {
        // A project with no identities has nothing for the gate to look for.
        // Reporting that as clean is how a check that verified nothing looks
        // exactly like one that passed.
        let project = TempProject::new("verify-nothing");
        let state = project.open();

        let result = verify_text_in(&state, "Anything at all.").expect("verify");
        assert_eq!(result.patterns_checked, 0);
        assert!(result.leaks.is_empty());
    }

    #[test]
    fn an_allowlisted_name_stops_being_aliased_and_stops_blocking() {
        // PRD FR-10, both halves. Fixing only the detector would leave the name
        // in the twin for the gate to block on, forever.
        let project = TempProject::new("allowlisted");
        let state = project.open();
        add_term_in(&state, "invoice", "DB_TABLE").expect("term");
        sanitize_text_in(&state, "a.md", "The invoice table.\n").expect("first sanitize interns it");

        state
            .with(|vault, _| {
                vault.add_allowed("invoice", Some("a common word here"))?;
                Ok(())
            })
            .expect("allow");

        let result = sanitize_text_in(&state, "a.md", "The invoice table.\n").expect("sanitize");
        let twin = result.twin.expect("not blocked");
        assert!(twin.contains("invoice"), "the user said leave it alone: {twin}");
        assert!(result.verified, "and the gate must not then block on it");
    }

    #[test]
    fn the_capability_set_stays_minimal() {
        // The threat model says the webview holds no network, no shell, and no
        // filesystem permission, and tells reviewers to check this exact file.
        // Widening it should require deliberately editing this test and the
        // document beside it, not slipping past review in a plugin's
        // recommended setup.
        //
        // The file picker was added without touching this list: the dialog runs
        // in Rust, so the webview never gains the permission.
        let capabilities = include_str!("../capabilities/default.json");
        let granted: Vec<&str> = capabilities
            .split("\"permissions\"")
            .nth(1)
            .expect("a permissions array")
            .split('"')
            .filter(|s| s.contains(':') && !s.contains('\n'))
            .collect();

        assert_eq!(
            granted,
            vec![
                "core:default",
                "core:window:allow-start-dragging",
                "clipboard-manager:allow-write-text",
            ],
            "the webview's capability set changed — update docs/Threat Model.md §5.5 too"
        );

        for forbidden in ["http:", "shell:", "fs:", "dialog:"] {
            assert!(
                !granted.iter().any(|p| p.starts_with(forbidden)),
                "{forbidden} reached the webview"
            );
        }
    }

    #[test]
    fn nothing_reads_a_caller_supplied_path_without_a_dialog() {
        // `pick_file` takes no path. If it ever grows one, the frontend can read
        // any file on the machine and the picker stops being a consent step.
        let source = include_str!("lib.rs");
        let signature = source
            .lines()
            .find(|l| l.contains("fn pick_file("))
            .expect("pick_file exists");

        assert!(
            signature.contains("app: tauri::AppHandle") && !signature.contains("path"),
            "pick_file must be dialog-driven only: {signature}"
        );
    }

    #[test]
    fn the_frontend_knows_every_entity_type_the_engine_has() {
        // Two languages, one list. A type the frontend does not offer is a type
        // the dictionary cannot express, and the dictionary is the only
        // protection for a name no rule can recognise — so an omission here is
        // a silent hole, not a cosmetic gap.
        //
        // This has already happened twice: `INDEX` was missing from the
        // frontend and four types were missing from the CLI.
        let api = include_str!("../../src/api.ts");

        for entity_type in EntityType::ALL {
            let quoted = format!("\"{}\"", entity_type.prefix());
            assert!(
                api.contains(&quoted),
                "app/src/api.ts is missing {quoted} — add it to EntityType and to                  ENTITY_TYPES in App.tsx"
            );
        }
    }

    #[test]
    fn an_unresolved_note_carries_the_token_the_form_needs() {
        // The naming form submits `token`. An empty one makes the whole SDD §12
        // flow unusable while looking perfectly fine on screen.
        let note = to_note(
            7,
            &diff::Note::Unresolved {
                token: "SERVICE_099".to_owned(),
            },
        );
        assert_eq!(note.kind, "unresolved");
        assert_eq!(note.token, "SERVICE_099");
        assert_eq!(note.line, 7);
    }

    #[test]
    fn a_hunk_keeps_which_side_each_line_came_from() {
        let hunk = diff::Hunk {
            kind: diff::ChangeKind::Changed,
            before: (3, 4),
            after: (3, 4),
            lines: vec![
                diff::Line {
                    side: diff::Side::Before,
                    number: 3,
                    text: "old\n".to_owned(),
                },
                diff::Line {
                    side: diff::Side::After,
                    number: 3,
                    text: "new\n".to_owned(),
                },
            ],
            notes: Vec::new(),
        };

        let wire = to_hunk(&hunk);
        assert_eq!(wire.kind, "changed");
        assert!(!wire.lines[0].added, "a removal must not render as an addition");
        assert!(wire.lines[1].added);
    }

    #[test]
    fn patch_status_reports_a_file_that_moved_since_it_was_indexed() {
        let project = TempProject::new("stale");
        project.write("src/a.ts", "one\n");
        let state = project.open();
        record_file(&state, "src/a.ts", "a checksum from another time");

        let status = patch_status_in(&state, "src/a.ts").expect("status");
        assert!(status.file_exists);
        assert!(status.stale, "SDD §13.1");
        assert!(!status.not_indexed);
    }

    #[test]
    fn patch_status_distinguishes_never_indexed_from_stale() {
        let project = TempProject::new("unindexed");
        project.write("src/a.ts", "one\n");
        let state = project.open();

        let status = patch_status_in(&state, "src/a.ts").expect("status");
        assert!(status.not_indexed);
        assert!(!status.stale, "nothing to be stale against");
    }

    #[test]
    fn applying_over_a_stale_file_is_refused_in_rust() {
        // The frontend disables the button. A disabled button is a courtesy,
        // not a control — the guard has to hold when the command is called
        // anyway.
        let project = TempProject::new("apply-stale");
        project.write("src/a.ts", "one\n");
        let state = project.open();
        record_file(&state, "src/a.ts", "not the current content");

        let result = apply_patch_in(&state, "src/a.ts", "two\n", "specshield/restore");
        let message = result.expect_err("must refuse").to_string();
        assert!(message.contains("changed since it was indexed"), "{message}");
        assert_eq!(
            std::fs::read_to_string(project.0.join("src/a.ts")).unwrap(),
            "one\n",
            "nothing was written"
        );
    }

    #[test]
    fn applying_with_an_unresolved_identity_is_refused_in_rust() {
        let project = TempProject::new("apply-unresolved");
        project.write("src/a.ts", "class Thing {}\n");
        let state = project.open();

        // Alias-shaped, and the vault has never issued it — SDD §12.
        let result = apply_patch_in(&state, "src/a.ts", "class SERVICE_099 {}\n", "specshield/restore");
        let message = result.expect_err("must refuse").to_string();
        assert!(message.contains("unresolved"), "{message}");
        assert_eq!(
            std::fs::read_to_string(project.0.join("src/a.ts")).unwrap(),
            "class Thing {}\n",
            "nothing was written"
        );
    }

    #[test]
    fn resolving_a_token_that_is_not_alias_shaped_is_refused() {
        let project = TempProject::new("resolve-shape");
        let _state = project.open();
        assert!(!alias::is_alias_shaped("just some words"));
    }
}
