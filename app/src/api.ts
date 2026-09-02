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

export interface AuditRow {
  ts: number;
  operation: string;
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

  copyVerifiedTwin: (withEnvelope: boolean) =>
    invoke<number>("copy_verified_twin", { withEnvelope }),

  auditLog: (limit: number) => invoke<AuditRow[]>("audit_log", { limit }),

  supportedFormats: () => invoke<string[]>("supported_formats"),
};
