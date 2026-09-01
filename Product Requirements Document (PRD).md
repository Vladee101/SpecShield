# Product Requirements Document (PRD)

## SpecShield

**Semantic Gateway for Secure Agentic Software Development**

### Version

v1.1 (MVP)

### Status

Draft

---

## Change Log

### v1.1 — incorporates *Design Review (PRD + SDD)*

| Change | Origin |
|---|---|
| Added §4 Threat Model with explicit protected / not-protected / residual risk | Review A1 |
| Rewrote §5 Success Metrics as measurable recall/precision against a labelled corpus | Review C5 |
| Added FR-3b Secret Detection (one-way redaction, distinct from pseudonymization) | Review A2 |
| Added FR-4b Export Verification Gate | Review A3 |
| Added FR-6b Prompt Envelope Generator | Review B4 |
| Added FR-9 Local Audit Log, FR-10 Manual Entity Control, FR-11 Vault Backup & Rotation, FR-12 Project Ignore Rules | Review D2, D7 |
| Identity is now scoped — `(scope_path, entity_type, real_name)` | Review B1 |
| Aliases are HMAC-derived, not sequence-allocated; three selectable alias styles | Review A6, D1 |
| Added key-management, clipboard, and cloud-sync requirements to §10 NFRs | Review A4, A5 |
| OpenAPI moved into MVP scope, resolving the contradiction between the architect user story and the SDD roadmap | Review E |
| §14 now references the SDD stack table rather than duplicating it | Review E |
| Sections renumbered to accommodate §4; FR IDs are unchanged | — |

---

## 1. Executive Summary

SpecShield is a local-first desktop application that enables software teams to safely use
commercial LLMs (ChatGPT, Codex, Claude, Gemini) without exposing proprietary business
identifiers.

The application creates a **reversible semantic twin** of documentation and source code by
replacing sensitive identifiers with deterministic placeholders. AI agents operate
exclusively on the sanitized twin, while SpecShield restores generated code and
documentation back to the original project terminology with a single click.

Secrets — API keys, tokens, credentials — are handled by a separate, **one-way** redaction
path and are never restored.

Before any content leaves the machine, SpecShield **verifies** the twin against the vault
and blocks export if any real identifier survives.

The product targets organizations whose security policies prohibit uploading internal code
or documentation to cloud LLMs.

---

## 2. Problem Statement

Engineering teams increasingly rely on AI for requirements analysis, architecture, coding,
refactoring, and test generation.

However, many companies prohibit commercial LLM usage because project artifacts contain
confidential information such as:

- customer names
- internal service names
- database schemas
- API endpoints
- business terminology
- infrastructure identifiers

Existing DLP tools focus on personal data rather than software artifacts, making them
unsuitable for modern development workflows.

---

## 3. Goal

Enable secure AI-assisted software development while preserving:

- confidentiality of proprietary identifiers
- architectural meaning
- deterministic restoration
- developer workflow

---

## 4. Threat Model

This section defines what SpecShield protects against, what it does not, and the risk that
remains. It is the basis on which a security team can approve the tool.

### 4.1 Adversaries

| # | Adversary | Capability | In scope |
|---|---|---|---|
| T1 | **LLM provider (honest-but-curious)** | Retains submitted prompts for training, abuse review, or subpoena; staff may read them | **Primary** |
| T2 | **Cloud backup / file sync** | Silently uploads the vault or project tree (OneDrive, Dropbox, Google Drive, iCloud) | **Primary** |
| T3 | **Clipboard history services** | Persists or syncs clipboard contents (e.g. Windows Cloud Clipboard) | **Primary** |
| T4 | **Local malware / stolen device** | Reads files at rest as the user | Partial — vault at rest only |
| T5 | **Insider with legitimate access** | Reads the real project directly | Out of scope |
| T6 | **Nation-state / targeted attacker** | Endpoint compromise, memory scraping | Out of scope |

### 4.2 What SpecShield protects

Proprietary **nouns** — the names by which the organization's intellectual property is
identified:

- organization, product, and brand names
- service, module, and component names
- API names, endpoint paths, and operation IDs
- database table and column names
- DTO, interface, enum, and event names
- environment variable names, hostnames, bucket names
- file and directory names derived from the above

And, separately and irreversibly, **secrets**: API keys, tokens, passwords, connection
strings, private keys, JWTs, email addresses, and customer PII (see FR-3b).

### 4.3 What SpecShield explicitly does not protect

SpecShield replaces identifiers while **deliberately preserving semantics** — that is what
makes the twin useful to an AI. The following therefore still reach the model:

- **Business logic expressed in prose.** `SERVICE_014 charges a 3% commission on ORG_007
  payouts for EU customers above EUR 10k` discloses the rule, the jurisdiction, the fee,
  and the shape of the integration.
- **Algorithms and implementation approach.**
- **Architecture shape and data-model topology** — the number of services, their
  relationships, table cardinality, endpoint structure.
- **Comments and documentation prose** the user chooses to keep (a scan and an optional
  strip-comments mode are provided, but retention is the user's decision).
- **Anything the user pastes into an AI by hand**, outside the tool.
- **Structural re-identification.** A distinctive domain model plus endpoint shapes is
  often sufficient to identify the organization, even with every name replaced.

### 4.4 Residual risk statement

> SpecShield reduces disclosure to a commercial LLM from *"names plus semantics"* to
> *"semantics only"*. It does not make the submission non-confidential. Teams handling
> material where the business logic itself is the secret should not use commercial LLMs
> for that material, with or without SpecShield.

This statement must appear in the product's onboarding and in the security one-pager.

---

## 5. Success Metrics

All metrics are measured by CI against a committed, hand-labelled **golden corpus** of
3–5 synthetic projects (a PRD, an OpenAPI spec, a SQL schema, a TypeScript service, a
mixed repository). Performance metrics are measured on the reference machine defined in
SDD §18.

| Metric | Definition | Target |
|---|---|---|
| Detection recall | Labelled entities correctly detected ÷ total labelled entities | ≥ 0.95 |
| Detection precision | Correct detections ÷ total detections | ≥ 0.90 |
| Restoration correctness | `restore(sanitize(x)) == x` byte-for-byte, all corpus files | 100% |
| Silent restore failures | Aliases neither restored nor reported as unresolved | 0 |
| Leak gate | Vault real-names present in a verified twin | 0 |
| Secret detection | Planted secrets found in the secrets fixture | 100% |
| Secret false positives | Per 10,000 LOC | < 5 |
| Sanitize a 100-page PRD | ~40k words, cold | < 10 s |
| Restore an AI response | ~2k lines pasted | < 3 s |
| Offline functionality | Outbound connections observed under egress block | 0 |

Precision is a first-class target, not a nicety: false positives make the twin unreadable
and measurably degrade the quality of AI output generated from it.

---

## 6. Target Users

### Primary

- System Analysts
- Solution Architects
- Software Developers
- QA Engineers

### Secondary

- Engineering Managers
- Security Teams — served by §4, FR-4b, and FR-9

---

## 7. User Stories

### System Analyst

> As a system analyst, I want to sanitize a PRD before sending it to ChatGPT so that
> confidential business identifiers are never exposed, and I want the tool to prove the
> output is clean before I copy it.

### Developer

> As a developer, I want Codex to generate code using anonymized identifiers and restore
> the result into my real repository automatically, as a reviewable Git patch.

### Architect

> As an architect, I want OpenAPI and SQL schemas anonymized without breaking structural
> relationships, and I want the same entity to carry the same alias across the spec, the
> schema, and the code.

### QA

> As a QA engineer, I want generated test cases restored using real API names and DTOs.

### Security Engineer

> As a security engineer, I want to see what left the machine and when, and I want the
> tool to refuse to export anything containing a known real identifier or a live secret.

---

## 8. Core Concept

Every project has two synchronized representations.

**Real Project**

- PRD
- OpenAPI
- SQL
- Source Code
- Tests

**Semantic Twin**

- ORG_001
- SERVICE_014
- DB_TABLE_008
- DTO_004
- API_002

Only the semantic twin is shared with AI.

### 8.1 Two distinct operations

The product performs two transformations that must never be confused:

| Operation | Direction | Applies to | On restore |
|---|---|---|---|
| **Pseudonymization** | two-way | identifiers — service, DTO, table, column, enum, event, endpoint | replaced back with the real name |
| **Redaction** | **one-way** | secrets — API keys, tokens, passwords, connection strings, private keys, JWTs, PII | **never** restored; the marker remains |

Restoring a live API key into AI-generated code would be both nonsensical and dangerous.
Secrets are therefore never stored as identities and never enter the mapping vault as
plaintext.

### 8.2 Alias styles

Opaque aliases maximize protection but strip the semantic hints models rely on, degrading
generated code and making the twin diff hard to review. Alias style is therefore a
per-project setting:

| Mode | Example | Trade-off |
|---|---|---|
| **Opaque** | `SERVICE_014` | Maximum protection; weakest AI output quality |
| **Typed** *(default)* | `PaymentService_014` | Retains a generic category, hides the subject |
| **Pseudonymous** | `AuroraService` | Most readable; weakest protection |

Typed mode discloses only a category name that is almost always generic, and is a
substantial usability win. It is the default; the choice is fixed at project creation and
changing it requires a re-key (FR-11).

---

## 9. Functional Requirements

### FR-1 Project Creation

The system shall create a local project containing:

- encrypted vault
- identity graph
- project settings — alias style, scope strategy, ignore rules
- custom terminology and allowlist

At creation the system shall warn if the project root or vault path lies inside a known
cloud-sync root, and offer to relocate the vault (see NFR Security).

**Priority:** Must

### FR-2 Import Artifacts

Supported formats (MVP):

| Format | Extensions |
|---|---|
| Markdown | `.md`, `.markdown` |
| Plain text | `.txt` |
| YAML | `.yaml`, `.yml` |
| JSON | `.json` |
| SQL | `.sql` |
| TypeScript / JavaScript | `.ts`, `.tsx`, `.mts`, `.cts`, `.d.ts`, `.js`, `.jsx`, `.mjs`, `.cjs` |
| OpenAPI | OpenAPI 3.x documents in YAML or JSON, recognized by content |

**Priority:** Must

### FR-3 Entity Detection

Automatically identify:

- organizations
- services
- APIs and endpoints
- database tables and columns
- DTOs, interfaces, enums
- events
- environment variable names
- hostnames, URLs, bucket names, account identifiers
- path segments (directory and file names)

Detection covers declarations, references, **comments, string literals, and Markdown
prose**. Each entity receives a deterministic alias.

Example:

- CustomerService → SERVICE_014
- Stripe → ORG_001

Identity is **scoped**, not global. The identity key is the triple
`(scope_path, entity_type, real_name)`, so `customer_id` in two different tables and
`Status` in two different modules are distinct identities with distinct aliases. Scope
resolution granularity is a project setting: `global` | `module` | `strict`.

**Priority:** Must

### FR-3b Secret Detection and Redaction

The system shall scan every imported artifact for secrets **before** identity extraction,
using a regex rule pack plus a Shannon-entropy heuristic.

Matches are replaced with a non-restorable marker of the form `<<REDACTED:TYPE>>`. The
system stores only a salted hash of each match — never the plaintext — for idempotency
across rescans.

High-confidence matches **block export** until the user explicitly acknowledges each one.

**Priority:** Must

### FR-4 Sanitization

Generate a semantic twin preserving:

- syntax
- references
- imports
- relationships
- document structure
- original formatting, comment placement, and key ordering

The twin must remain valid, parseable code and valid documentation. Specifically, the twin
**must parse**, and its declaration and reference counts must match the original. Where a
transformation cannot meet this bar, the affected file is left unaliased and reported,
rather than emitted in a broken state.

**Priority:** Must

### FR-4b Export Verification Gate

No content may leave the application — clipboard, file export, or patch — without passing
verification:

1. Scan the twin for every `real_name` in the vault, including generated case variants
   (camelCase, PascalCase, snake_case, kebab-case, SCREAMING_CASE, spaced, pluralized).
2. Any hit is a **hard block**, reporting file, line, and matched term.
3. Re-run the secret detector over the twin as an independent second pass.
4. On success, display a verified-clean state that names both what was checked and what
   was **not** checked (per §4.3).

Verification is not advisory and cannot be skipped. It may be overridden only by an
explicit per-item acknowledgement, which is recorded in the audit log.

**Priority:** Must

### FR-5 Mapping Vault

Store encrypted mappings locally.

Each identity contains:

- UUID
- scope path
- real name
- alias
- entity type
- origin — detected, manual, or AI-introduced
- status — active, excluded, unresolved

Occurrences (file, byte range, kind) are stored separately and support the diff viewer,
incremental rescan, provenance, and the verification gate.

The vault is versioned and migrated. No cloud synchronization.

**Priority:** Must

### FR-6 Restore Response

The user shall paste AI output and press **Restore**.

The system replaces every known placeholder with its original identifier while preserving
all newly generated content.

Restoration operates lexically over a closed alias vocabulary, so it tolerates code
fragments, unified diffs, Markdown-wrapped responses, and syntactically invalid input.
Alias matching is normalized to survive model drift (`Service014`, `service_014`,
`SERVICE-014`, `SERVICE_014s`). Every non-exact match is restored **and flagged** for
review; every alias-shaped token matching nothing is reported as an unresolved identity.

**Priority:** Must

### FR-6b Prompt Envelope Generator

Alongside the twin, the system shall generate and copy a short instruction preamble
telling the model that placeholders are opaque, must be preserved verbatim, and that new
entities must be named `NEW_<n>` and listed.

Restore reliability depends substantially on the model having been given this instruction.

**Priority:** Should

### FR-7 Twin Diff

Display side-by-side comparison:

- Twin version
- Restored version
- Added
- Modified
- Deleted

Fuzzy-restored aliases and unresolved identities are called out inline. Formatting-only
changes are suppressed where possible.

The system shall detect when the twin is **stale** — the real files have changed since it
was generated — and require an explicit rescan before any patch derived from it is
applied.

**Priority:** Must

### FR-8 Git Integration

Generate restored patches instead of overwriting files.

The system shall:

- generate a unified diff
- dry-run the patch before applying it
- apply only onto a new branch, never onto the current checked-out `main`
- support undo
- degrade gracefully with a clear message when Git is not available

The system shall preserve Git history.

**Priority:** Should

### FR-9 Local Audit Log

The system shall maintain an append-only local log recording: timestamp, project,
operation, file count, entity count, verification result, and export destination
(clipboard, file, or patch).

The log never contains real names or artifact content, and is never transmitted. It is
exportable as CSV for compliance review.

This is distinct from telemetry, which the product does not have.

**Priority:** Should

### FR-10 Manual Entity Control

The user shall be able to add, rename, exclude, and merge entities, and mark any term as
**never alias**.

The system ships with a stop-list of common framework, library, and vendor names (React,
Express, Postgres, AWS, …) that are excluded by default.

False positives are inevitable; without this requirement the twin becomes unreadable.

**Priority:** Must

### FR-11 Vault Backup, Escrow, and Re-Key

The system shall support:

- encrypted vault backup and restore
- passphrase-protected key escrow export, with an explicit warning that key loss is
  unrecoverable
- alias re-keying — regenerating all aliases under a new project key, for use when a twin
  has been over-shared or the alias style is changed

**Priority:** Should

### FR-12 Project Ignore Rules

The system shall respect `.gitignore` and a project-level `.specshieldignore`, and shall
exclude binary files, lockfiles, and vendored dependency trees by default.

**Priority:** Must

---

## 10. Non-Functional Requirements

### Security

- Local-only execution
- AES-256 encrypted vault (SQLCipher)
- **Key management:** the vault key is held in the operating system credential store
  (Windows DPAPI / Credential Manager, macOS Keychain, Linux Secret Service) and never
  written to disk in plaintext. An optional user passphrase derives a key-encryption key
  via Argon2id. All key material is zeroized in memory after use.
- **Cloud-sync detection:** the application warns when the project root or vault path lies
  inside a OneDrive, Dropbox, Google Drive, or iCloud tree, and offers to relocate the
  vault to a local-only path.
- **Clipboard hardening:** on Windows, payloads are marked with the three opt-out
  clipboard formats — `ExcludeClipboardContentFromMonitorProcessing`,
  `CanIncludeInClipboardHistory`, and `CanUploadToCloudClipboard`, the last of which
  governs cross-device sync to the user's Microsoft account. The clipboard is cleared
  after a timeout, and only if it still holds SpecShield's own payload. Original,
  unsanitized content is never placed on the clipboard by any UI affordance.

  These formats are advisory: a cooperating OS and clipboard manager honour them, and one
  that ignores them still captures the text. macOS and Linux opt-outs are not implemented,
  and the audit log records which exports were protected and which were not.
- No telemetry, no analytics, no auto-update network dependency
- No internet required — enforced by a network-capability-free application configuration
  and verified by an egress-blocked test in CI
- No cloud storage

### Performance

Measured on the reference machine defined in SDD §18.

- Startup under 2 seconds
- Cold indexing of a 1,000-file / ~150k-LOC project under 30 seconds
- Incremental rescan under 2 seconds
- Sanitize a 100-page PRD under 10 seconds
- Restore a pasted response under 3 seconds

### Reliability

- Deterministic alias generation — identical input and project key always yield identical
  aliases, on any machine
- Lossless restoration, verified as a property test over the golden corpus
- Atomic restore and patch operations, with undo
- No destructive operations: on parser failure the original file is preserved unmodified

### Usability

- Drag & drop import
- One-click sanitize, verify, and copy
- One-click restore
- No command line required

---

## 11. Identity Graph

Every software artifact belongs to a semantic graph rather than a text dictionary.

Example node:

| Field | Value |
|---|---|
| ID | UUID |
| Scope Path | `src/services/subscription` |
| Alias | SERVICE_014 |
| Real Name | CustomerSubscriptionService |
| Type | Service |
| Origin | detected |
| Status | active |

Relationships:

- Service uses DTO
- Service writes Table
- API exposes Service

The graph guarantees consistent anonymization across documents and code: the SQL table
`customer_subscription`, the OpenAPI schema `CustomerSubscription`, and the TypeScript DTO
resolve to a **single** identity carrying a single alias.

Aliases are globally unique within a project by construction, because alias derivation
includes the scope path. Restoration is therefore never ambiguous, even for a bare code
fragment with no file context.

---

## 12. User Workflow

### Workflow A — PRD to ChatGPT

1. Import PRD
2. Detect entities and secrets
3. Review mappings — accept, rename, exclude, never-alias
4. Sanitize
5. **Verify** — the export gate confirms the twin is clean
6. Copy twin + prompt envelope
7. Paste into ChatGPT
8. Paste response into SpecShield
9. Restore, reviewing any fuzzy matches and unresolved identities

### Workflow B — Agentic Development

1. Import repository
2. Create semantic twin
3. Verify and export the twin project
4. Open twin in Codex
5. AI generates code
6. Review twin diff
7. Resolve unresolved identities
8. Restore, generate patch, dry-run, apply to a branch
9. Commit to Git

---

## 13. Out of Scope (MVP)

- PDF OCR
- DOCX editing
- Java/C# AST
- UML parsing
- Multi-user collaboration and vault merge workflows
- Cloud synchronization

Note: aliases are derived deterministically from a shared project key rather than
allocated from a local counter, so two developers sharing that key produce identical
twins. Collaboration tooling is out of scope; alias compatibility across machines is not.

---

## 14. Technical Architecture

See **SDD §21 Technology Stack** for the authoritative stack table. It is not duplicated
here so the two documents cannot drift.

---

## 15. Risks

| Risk | Mitigation |
|---|---|
| AI renames or reformats placeholders | Prompt envelope (FR-6b), formal alias grammar, normalizing fuzzy matcher, unresolved reporting — never a silent guess |
| Broken imports or references | AST-based transformation with a post-sanitize parse-and-count verification; fall back to leaving the file unaliased |
| Missed entities | Export verification gate (FR-4b), manual review, recall measured in CI |
| False positives make the twin unreadable | Stop-list and allowlist (FR-10), precision target in CI, typed alias style |
| Semantic leakage in prose — unfixable by design | Documented residual risk (§4.4), prose scanning, optional comment stripping |
| Large repositories | Incremental indexing, gitignore-aware walking, parallel parsing |
| TypeScript scope resolution without a type checker | Heuristic scoping validated by spike; limitation stated explicitly; compiler-API sidecar deferred to V1.1 |
| Vault key loss | Key escrow export with explicit warning |
| Vault synced to cloud storage by the user's environment | Startup detection and relocation offer |

---

## 16. MVP Deliverables

### Included

- Local desktop application
- Encrypted project vault with OS-keychain key management
- Scoped identity graph
- Deterministic, machine-independent anonymization
- Secret detection and one-way redaction
- Export verification gate
- Prompt envelope generator
- Bidirectional restoration with fuzzy matching and unresolved reporting
- Twin diff viewer with staleness detection
- Git patch generation
- Local audit log

### Excluded

- IDE plugins
- Cloud accounts
- Team collaboration tooling
- Local LLM inference
- Automatic naming of AI-introduced entities

---

## 17. Product Vision

SpecShield becomes the secure semantic gateway between proprietary software projects and
commercial AI agents, allowing organizations to adopt agentic development without exposing
confidential intellectual property — and to demonstrate, artifact by artifact, that they
did not.
