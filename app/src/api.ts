/**
 * Typed wrappers over the Tauri commands.
 *
 * This file is the only place the frontend talks to Rust. It holds no logic —
 * the engine decides what is an entity, what is a leak, and what may be
 * exported. The UI's job is to show those answers accurately, never to
 * second-guess them.
 */
import { invoke } from "@tauri-apps/api/core";

/**
 * Every entity type the engine has — `EntityType::prefix()` in
 * `crates/core/src/model.rs`.
 *
 * Kept exhaustive on purpose, and checked by a Rust test that reads this file.
 * A type missing here is a type the dictionary cannot express, and the
 * dictionary is the only protection for a name no rule can recognise.
 */
export type EntityType =
  | "ORG"
  | "SERVICE"
  | "API"
  | "ENDPOINT"
  | "DB_TABLE"
  | "COLUMN"
  | "DTO"
  | "IFACE"
  | "ENUM"
  | "EVENT"
  | "INDEX"
  | "ENV"
  | "HOST"
  | "PATH";

export interface ProjectInfo {
  name: string;
  alias_style: string;
  identity_count: number;
  term_count: number;
  /** Present when the project sits in a cloud-sync tree (PRD §10). */
  cloud_sync_warning: string | null;
}

export interface DetectedEntity {
  real_name: string;
  entity_type: string;
  byte_start: number;
  byte_end: number;
  confidence: number;
}

export interface SecretFinding {
  secret_type: string;
  line: number;
  blocking: boolean;
}

export interface ScanResult {
  parser: string;
  entities: DetectedEntity[];
  suggestions: DetectedEntity[];
  secrets: SecretFinding[];
}

export interface Leak {
  matched: string;
  line: number;
  column: number;
}

export interface SanitizeResult {
  verified: boolean;
  /** Null whenever the gate blocked — there is no unverified twin to show. */
  twin: string | null;
  envelope: string;
  applied: number;
  secrets_redacted: number;
  patterns_checked: number;
  leaks: Leak[];
  blocking_secrets: SecretFinding[];
  not_checked: string[];
}

export interface RestoredAlias {
  found: string;
  real_name: string;
  match_kind: string;
  line: number;
  needs_review: boolean;
}

export interface RestoreResult {
  text: string;
  restored: RestoredAlias[];
  unresolved: string[];
  redactions_preserved: number;
}

/** One changed line. `added` distinguishes the two sides of a hunk. */
export interface DiffLine {
  added: boolean;
  number: number;
  text: string;
}

export interface DiffNote {
  /** "fuzzy" | "unresolved" | "redaction" */
  kind: string;
  line: number;
  detail: string;
  /** The token to name, for unresolved notes. Empty otherwise. */
  token: string;
}

export interface DiffHunk {
  /** "added" | "removed" | "changed" | "formatting" */
  kind: string;
  before_start: number;
  after_start: number;
  lines: DiffLine[];
  notes: DiffNote[];
}

export interface DiffReview {
  restored: string;
  changes: DiffHunk[];
  /** How many edits the model itself made, in twin space. */
  model_changes: number;
  substantive: number;
  /**
   * Every note, including ones that fall inside no hunk. A fuzzy match can
   * restore to text identical to the original — the guess still happened.
   */
  notes: DiffNote[];
  blocks_patch: boolean;
  unresolved: string[];
}

export interface PatchStatus {
  file_exists: boolean;
  git_available: boolean;
  git_explain: string;
  branch: string;
  dirty: boolean;
  /** The file has changed since it was indexed — SDD §13.1. */
  stale: boolean;
  not_indexed: boolean;
}

export interface AppliedPatch {
  branch: string;
  previous_branch: string;
  created_branch: boolean;
  files: number;
}

export interface IndexSummary {
  files: number;
  text: number;
  parseable: number;
  seconds: number;
}

export interface RescanSummary {
  files: number;
  added: string[];
  modified: string[];
  removed: string[];
  unchanged: number;
  /** Files whose recorded twin was made from content that no longer exists. */
  stale: string[];
  seconds: number;
}

export interface ExportSummary {
  written: number;
  aliased: number;
  identities: number;
  renamed: number;
  unchecked: number;
  abandoned: [string, string][];
  /** Non-empty means nothing was written at all. */
  blocked: [string, string[]][];
  /** Vault names the gate was told to ignore — FR-10. */
  allowlisted: number;
  /** Places recorded in the vault — FR-5. */
  occurrences: number;
  /**
   * Secrets redacted on the way out, and how many are new since the last
   * export. Both describe the working tree, not the twin: the twin has a marker
   * where each one was, the file on disk still has the credential.
   */
  redacted: number;
  redacted_new: number;
  destination: string;
}

/** One recorded appearance of an identity — PRD FR-5. */
export interface Appearance {
  path: string;
  /** 0 when the position could not be resolved against the file as it is now. */
  line: number;
  column: number;
  kind: string;
}

export interface LocatedIdentity {
  real_name: string;
  alias: string;
  entity_type: string;
  scope_path: string;
  appearances: Appearance[];
}

/** One secret this project redacted — SDD §4.3. A position, never a value. */
export interface SecretSite {
  path: string;
  line: number;
  column: number;
  secret_type: string;
}

export interface RestoredProject {
  written: number;
  aliases_resolved: number;
  /** Twin paths the vault has no mapping for, written where they stand. */
  unmapped: string[];
  destination: string;
}

export interface UnifyMember {
  entity_type: string;
  real_name: string;
  scope_path: string;
}

export interface UnifyProposal {
  concept: string;
  confidence: number;
  members: UnifyMember[];
  caveat: string | null;
}

export interface VerifyResult {
  clean: boolean;
  /** Zero means nothing was checked, which is not the same as clean. */
  patterns_checked: number;
  leaks: Leak[];
  secrets: SecretFinding[];
}

export interface PickedFile {
  path: string;
  /** The name the parser dispatches on. */
  name: string;
  content: string;
}

export interface RecoveryReport {
  diagnosis: string;
  readable: boolean;
  schema_version: number;
  identities: number;
  files: number;
  entity_types: [string, number][];
  audit: AuditRow[];
}

export interface AuditRow {
  ts: number;
  operation: string;
  file_count: number | null;
  entity_count: number | null;
  verification: string | null;
  destination: string | null;
}

export const api = {
  createProject: (path: string, passphrase: string, aliasStyle: string) =>
    invoke<ProjectInfo>("create_project", { path, passphrase, aliasStyle }),

  openProject: (path: string, passphrase: string) =>
    invoke<ProjectInfo>("open_project", { path, passphrase }),

  projectInfo: () => invoke<ProjectInfo>("project_info"),

  closeProject: () => invoke<void>("close_project"),

  addTerm: (name: string, entityType: EntityType) =>
    invoke<number>("add_term", { name, entityType }),

  addAllowed: (term: string) => invoke<void>("add_allowed", { term }),

  scan: (filename: string, content: string) =>
    invoke<ScanResult>("scan_text", { filename, content }),

  sanitize: (filename: string, content: string) =>
    invoke<SanitizeResult>("sanitize_text", { filename, content }),

  restore: (content: string) => invoke<RestoreResult>("restore_text", { content }),

  reviewDiff: (original: string, twin: string, aiTwin: string) =>
    invoke<DiffReview>("review_diff", { original, twin, aiTwin }),

  resolveIdentity: (alias: string, name: string, entityType: EntityType, scope: string) =>
    invoke<void>("resolve_identity", { alias, name, entityType, scope }),

  patchStatus: (filename: string) => invoke<PatchStatus>("patch_status", { filename }),

  applyPatch: (filename: string, restored: string, branch: string) =>
    invoke<AppliedPatch>("apply_patch", { filename, restored, branch }),

  undoPatch: () => invoke<string>("undo_patch"),

  // --- File picking (P1-3) ------------------------------------------------
  // The dialog runs in Rust. The frontend has no dialog permission and no
  // filesystem permission, and cannot ask for a path it was not given by a
  // human in a native dialog. `null` means the dialog was cancelled, which is
  // not an error.

  pickFile: () => invoke<PickedFile | null>("pick_file"),

  pickDirectory: () => invoke<string | null>("pick_directory"),

  saveText: (suggestedName: string, content: string) =>
    invoke<string | null>("save_text", { suggestedName, content }),

  /** Reads the twin from session state, never from the frontend — SDD §17.5. */
  saveVerifiedTwin: (suggestedName: string) =>
    invoke<string | null>("save_verified_twin", { suggestedName }),

  copyVerifiedTwin: (withEnvelope: boolean) =>
    invoke<number>("copy_verified_twin", { withEnvelope }),

  auditLog: (limit: number) => invoke<AuditRow[]>("audit_log", { limit }),

  /** Writes the CSV on the Rust side and returns where it landed — FR-9. */
  exportAuditCsv: (limit: number) => invoke<string>("export_audit_csv", { limit }),

  // --- FR-11: backup, escrow, re-key -------------------------------------
  // Paths are resolved against the project root on the Rust side; the app has
  // no filesystem capability and does not acquire one to save a file.

  backupVault: (dest: string) => invoke<string>("backup_vault", { dest }),

  restoreVault: (backup: string, into: string, passphrase: string) =>
    invoke<string>("restore_vault", { backup, into, passphrase }),

  exportEscrow: (out: string, escrowPassphrase: string, passphrase: string) =>
    invoke<string>("export_escrow", { out, escrowPassphrase, passphrase }),

  escrowWarning: () => invoke<string>("escrow_warning"),

  openEscrow: (file: string, escrowPassphrase: string) =>
    invoke<string>("open_escrow", { file, escrowPassphrase }),

  rekeyPreview: () => invoke<{ identities: number }>("rekey_preview"),

  rekeyProject: (confirm: boolean) => invoke<number>("rekey_project", { confirm }),

  /** SDD §16. Takes a path: the case this exists for is a vault that would not open. */
  recoverVault: (path: string) => invoke<RecoveryReport>("recover_vault", { path }),

  // --- Project operations, the same pipeline the CLI runs -----------------

  indexProject: () => invoke<IndexSummary>("index_project"),

  rescanProject: () => invoke<RescanSummary>("rescan_project"),

  exportProject: (dest: string) => invoke<ExportSummary>("export_project", { dest }),

  restoreProject: (twin: string, dest: string) =>
    invoke<RestoredProject>("restore_project", { twin, dest }),

  unifyProposals: () => invoke<UnifyProposal[]>("unify_proposals"),

  /** Returns [identities linked, aliases changed]. */
  unifyConfirm: (concept: string) => invoke<[number, number]>("unify_confirm", { concept }),

  verifyText: (content: string) => invoke<VerifyResult>("verify_text", { content }),

  /** Where an identity appears — by real name (case-insensitive) or alias (exact). */
  locateIdentity: (name: string) => invoke<LocatedIdentity[]>("locate_identity", { name }),

  /** Every secret this project redacted, and where it still is. */
  secretSites: () => invoke<SecretSite[]>("secret_sites"),

  supportedFormats: () => invoke<string[]>("supported_formats"),
};
