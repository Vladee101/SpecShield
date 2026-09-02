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

use serde::Serialize;
use specshield_core::detect::Detector;
use specshield_core::model::{EntityType, OccurrenceKind, Origin, Status};
use specshield_core::parser::ProjectContext;
use specshield_core::restore::Vocabulary;
use specshield_core::sanitize::{AUTO_APPLY_CONFIDENCE, Graph};
use specshield_core::{alias, diff, restore, sanitize, secrets, verify};
use specshield_git as git;
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
    pub alias_style: String,
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
    pub entity_count: Option<i64>,
    pub verification: Option<String>,
    pub destination: Option<String>,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn create_project(
    state: State<'_, AppState>,
    path: String,
    passphrase: String,
    alias_style: String,
) -> Result<ProjectInfo> {
    let root = std::path::PathBuf::from(&path);
    let vault_path = state::vault_path(&root);
    if vault_path.exists() {
        return Err(fail(format!("a vault already exists at {}", vault_path.display())));
    }

    let mut project_key = [0u8; 32];
    getrandom::fill(&mut project_key).map_err(|e| fail(format!("entropy unavailable: {e}")))?;

    let settings = vault::Settings {
        project_name: root
            .file_name()
            .map_or_else(|| "project".to_owned(), |n| n.to_string_lossy().into_owned()),
        root_path: root.display().to_string(),
        alias_style: alias_style.to_lowercase(),
        scope_strategy: "module".to_owned(),
        project_key,
    };
    // The vault owns the key now; clear our copy off the stack.
    project_key.zeroize();
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
            // `Settings` clears its key on drop, which makes it non-movable
            // field-by-field. Clone the two strings we need.
            name: settings.project_name.clone(),
            alias_style: settings.alias_style.clone(),
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
    state.with(|vault, _| {
        let parsed: EntityType = entity_type
            .parse()
            .map_err(|_| fail(format!("unknown entity type {entity_type:?}")))?;
        vault.add_term(&name, parsed.prefix())?;
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
    let parser = require_parser(&filename, &content)?;
    state.with(|vault, _| {
        let detector = detector_from(vault)?;
        let findings = secrets::scan(&content);
        let redacted = secrets::redact(&content, &findings);
        let candidates = detector.scan_text(&redacted, &filename, OccurrenceKind::Reference);

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
    let parser = require_parser(&filename, &content)?;
    let result = state.with(|vault, _| {
        let mut graph = graph_from(vault)?;
        let detector = detector_from(vault)?;

        let members = context_from(vault)?;

        let result = sanitize::sanitize(
            &content,
            &filename,
            &detector,
            &mut graph,
            Some(parser.as_ref()),
            &members,
        )
        .map_err(|e| fail(format!("sanitize failed: {e}")))?;

        persist(vault, &graph)?;

        // SDD §8 — the gate runs here, on the Rust side. The frontend is never
        // handed unverified content.
        let scanner = verify::LeakScanner::new(graph.real_names());
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

        let verified = leaks.is_empty() && blocking.is_empty();
        vault.log(
            "sanitize",
            Some(1),
            i64::try_from(result.applied.len()).ok(),
            Some(if verified { "clean" } else { "blocked" }),
            None,
        )?;

        Ok(SanitizeResult {
            verified,
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
                entity_count: e.entity_count,
                verification: e.verification,
                destination: e.destination,
            })
            .collect())
    })
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
    let settings = vault.settings()?;
    let style = match settings.alias_style.as_str() {
        "opaque" => alias::AliasStyle::Opaque,
        "pseudonymous" => alias::AliasStyle::Pseudonymous,
        _ => alias::AliasStyle::Typed,
    };
    let mut settings = settings;
    let mut graph = Graph::new(alias::ProjectKey::take_bytes(&mut settings.project_key), style);
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
                alias_style: "opaque".to_owned(),
                scope_strategy: "module".to_owned(),
                project_key: [1; 32],
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
