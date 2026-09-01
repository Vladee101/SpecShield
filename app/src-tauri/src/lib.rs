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

mod state;

use serde::Serialize;
use specshield_core::detect::Detector;
use specshield_core::model::{EntityType, OccurrenceKind, Origin, Status};
use specshield_core::restore::Vocabulary;
use specshield_core::sanitize::{AUTO_APPLY_CONFIDENCE, Graph};
use specshield_core::{alias, restore, sanitize, secrets, verify};
use specshield_vault as vault;
use tauri::State;
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::state::AppState;

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
            alias_style: settings.alias_style,
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

        let result = sanitize::sanitize(&content, &filename, &detector, &mut graph, Some(parser.as_ref()))
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

    // TODO(M2): mark the payload with `ExcludeClipboardContentFromMonitorProcessing`
    // and `CanIncludeInClipboardHistory=false` on Windows, and clear it after a
    // configurable timeout. Tauri's clipboard plugin does not expose clipboard
    // formats, so this needs a small platform shim — tracked, not forgotten,
    // because Cloud Clipboard syncs history to the user's Microsoft account
    // (Design Review A5). Until then, PRD §10's clipboard claim is unmet.
    app.clipboard()
        .write_text(payload.clone())
        .map_err(|e| fail(format!("clipboard write failed: {e}")))?;

    state.with(|vault, _| {
        vault.log("export", Some(1), None, Some("clean"), Some("clipboard"))?;
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
    let mut graph = Graph::new(alias::ProjectKey::from_bytes(settings.project_key), style);
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

fn detector_from(vault: &vault::Vault) -> Result<Detector> {
    let mut detector = Detector::new();
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
            copy_verified_twin,
            audit_log,
            supported_formats,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SpecShield");
}
