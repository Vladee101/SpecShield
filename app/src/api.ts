/**
 * Typed wrappers over the Tauri commands.
 *
 * This file is the only place the frontend talks to Rust. It holds no logic —
 * the engine decides what is an entity, what is a leak, and what may be
 * exported. The UI's job is to show those answers accurately, never to
 * second-guess them.
 */
import { invoke } from "@tauri-apps/api/core";

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

  copyVerifiedTwin: (withEnvelope: boolean) =>
    invoke<number>("copy_verified_twin", { withEnvelope }),

  auditLog: (limit: number) => invoke<AuditRow[]>("audit_log", { limit }),

  supportedFormats: () => invoke<string[]>("supported_formats"),
};
