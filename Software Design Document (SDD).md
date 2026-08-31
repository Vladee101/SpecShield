# Software Design Document (SDD)

## SpecShield

**Semantic Gateway for Secure Agentic Software Development**

Version: 1.1 (MVP)

---

# 0. Change Log

### v1.1 — incorporates *Design Review (PRD + SDD)*

| Change | Origin |
|---|---|
| Identity key is now the triple `(scope_path, entity_type, real_name)` | Review B1 |
| Aliases are HMAC-derived from a project key, not sequence-allocated | Review A6 |
| Formal alias grammar + canonical-form normalizer for LLM drift | Review B3 |
| Sanitize is AST-first; **restore is lexical** — the asymmetry is now explicit | Review B2 |
| "The twin must compile" replaced with the verifiable "must parse, counts must match" | Review C1 |
| New §4.3 Secret Detector — one-way redaction, separate from the identity graph | Review A2 |
| New §8 Export Verification Gate | Review A3 |
| New §11 Prompt Envelope; new §15 Audit Log | Review B4, D2 |
| Vault schema rewritten: project, scope, occurrences, twin paths, redactions, allowlist, migrations | Review B5, B6, E |
| Key management specified: OS credential store + optional Argon2id | Review A4 |
| `serde_yaml` replaced with a CST-preserving parser; libgit2 no longer used to apply patches | Review C2, C3 |
| Performance targets given a reference machine; rendering artifacts fixed | Review C4, E |
| New §19 Test Strategy | Review C5 |
| Sections renumbered | — |

---

# 1. Purpose

This document describes the technical architecture and internal design of SpecShield.

The primary design principle is **lossless bidirectional pseudonymization**: every
supported software artifact can be transformed into a semantic twin and restored back
without losing structure, references, or AI-generated modifications.

A second, distinct path handles **secrets**, which are redacted irreversibly and never
restored.

---

# 2. Design Principles

1. **Local-first** — all processing happens on the user's machine.
2. **Deterministic** — identical identifiers under the same project key always produce
   identical aliases, on any machine, with no central allocator.
3. **Scoped identity** — an entity is identified by scope, type, and name, never by name
   alone.
4. **AST for sanitize, lexer for restore** — sanitization needs structure to be correct;
   restoration must survive fragments, diffs, and syntactically invalid AI output.
5. **Language agnostic** — each language has its own parser, but all share one identity
   graph and one edit-list representation.
6. **Reversible for identifiers, irreversible for secrets** — these are different
   operations and never share a code path.
7. **Verify before export** — the system proves the twin is clean rather than assuming it.
8. **Non-destructive** — any transformation that cannot be verified is abandoned, leaving
   the original intact.

---

# 3. High-Level Architecture

```
                +----------------------+
                |   User Workspace     |
                +----------+-----------+
                           |
                           v
                +----------------------+
                |   Import Pipeline    |
                +----------+-----------+
                           |
                           v
                +----------------------+
                |  Secret Detector     |  one-way redaction
                +----------+-----------+
                           |
                           v
                +----------------------+
                |   Parser Engine      |
                | MD / SQL / TS / YAML |
                +----------+-----------+
                           |
                           v
                +----------------------+
                | Identity Extractor   |
                +----------+-----------+
                           |
                           v
                +----------------------+
                |  Identity Graph      |
                +-----+----------+-----+
                      |          |
          +-----------+          +-------------+
          |                                    |
          v                                    v
+----------------------+          +----------------------+
| Semantic Twin        |          | Mapping Vault        |
| (candidate)          |          | (encrypted SQLite)   |
+-----------+----------+          +----------+-----------+
            |                                |
            v                                |
+----------------------+                     |
| Verification Gate    |<--------------------+
| (leak + secret scan) |
+-----------+----------+
            |
       verified twin ------> AI
                                |
                                v
            +----------------------------------+
            |          Restore Engine          |
            |  lexical, normalizing, flagged   |
            +----------------+-----------------+
                             |
                             v
                    Real Project Patch
```

Note the gate: nothing reaches the AI without passing verification.

---

# 4. Module Breakdown

## 4.1 Import Pipeline

### Responsibility

Normalize incoming project artifacts.

### Inputs

Markdown, plain text, YAML, JSON, SQL, TypeScript/JavaScript, OpenAPI 3.x (detected by
content, not extension).

Walking is gitignore-aware and honours `.specshieldignore`. Binary files, lockfiles, and
vendored dependency trees are excluded by default.

### Output

```
Document {
    id
    path
    twin_path
    type
    content        // raw bytes, never modified at this stage
    checksum       // BLAKE3
}
```

No modifications occur at this stage.

---

## 4.2 Parser Engine

Parsers convert documents into syntax trees.

| Format | Parser | Notes |
|---|---|---|
| TypeScript / JavaScript | Tree-sitter | See §4.2.1 on its limits |
| SQL | `sqlparser` | Dialect-configurable |
| YAML | CST-preserving parser (`saphyr` / `yaml-rust2` or Tree-sitter YAML) | **Not** `serde_yaml` — archived in 2024, and value-model round-trips destroy comments and key order |
| JSON | CST-preserving parser | Not `serde_json` round-trip, for the same reason |
| Markdown | Markdown AST with source offsets | |
| OpenAPI | Semantic layer over the YAML/JSON CST | Paths, operationIds, schema names, tags |

Every parser must retain **byte offsets** for every node. No parser serializes its own tree
back to text.

### 4.2.1 Uniform parser contract

```rust
pub trait ArtifactParser {
    fn can_handle(&self, path: &Path, content: &[u8]) -> bool;

    /// Parse without mutating; must retain byte offsets.
    fn parse(&self, doc: &Document) -> Result<Parsed>;

    /// Emit candidate entities with byte spans and a scope path.
    fn extract(&self, parsed: &Parsed) -> Vec<Candidate>;

    /// Emit non-overlapping byte-range replacements.
    /// Never rewrites the file itself.
    fn plan_edits(&self, parsed: &Parsed, map: &AliasMap) -> Vec<Edit>;
}
```

All transformation is expressed as an **edit list over byte ranges**, applied by one shared
function:

```rust
pub struct Edit { start: usize, end: usize, replacement: String, identity: Uuid }
```

Edits are asserted non-overlapping and applied right-to-left. This is what preserves
formatting exactly — the original bytes outside the edit ranges are untouched.

### 4.2.2 TypeScript: known limitation

Tree-sitter produces a concrete syntax tree with **no name resolution, no scope analysis,
and no type information**. Correctly renaming a symbol requires knowing which declaration
each reference binds to — across re-exports, barrel files, type-only imports, declaration
merging, and shadowing. Tree-sitter cannot do this.

MVP therefore uses **Tree-sitter plus heuristic scoping**: a per-file lexical scope stack
combined with a module-level export/import graph. This is good but not exact.

Accordingly, the guarantee in §7 is *"the twin parses and symbol counts match"*, not *"the
twin compiles"*. Exact rename via the TypeScript compiler API in a Node sidecar is deferred
to V1.1 (§20); `oxc` / `swc` Rust resolvers are re-evaluated at that point.

---

## 4.3 Secret Detector

### Responsibility

Find and irreversibly redact secrets **before** identity extraction runs.

Secrets are not identities. They are never written to the vault as plaintext and never
restored — round-tripping a live credential back into AI-generated code would be both
meaningless and dangerous.

### Method

1. Regex rule pack — cloud provider keys, OAuth tokens, JWTs, private key PEM blocks,
   connection strings, bearer tokens, email addresses, common PII patterns.
2. Shannon-entropy heuristic over string literals and assignment right-hand sides, with a
   configurable threshold and a length floor.
3. Allowlist for known-safe placeholder values (`your-api-key-here`, example UUIDs).

### Output

Each match becomes an edit replacing the span with `<<REDACTED:TYPE>>`, plus a row in the
`redactions` table storing **only** `HMAC(project_key, match)` for idempotency across
rescans.

High-confidence matches set a blocking flag consumed by the Verification Gate (§8).

---

## 4.4 Identity Extractor

### Responsibility

Discover software entities.

Supported entity types:

| Type | Example | Alias prefix |
|---|---|---|
| Organization | AcmeBank | ORG |
| Service | CustomerService | SERVICE |
| API | BillingAPI | API |
| Endpoint | POST /subscriptions | ENDPOINT |
| Table | customer_subscription | DB_TABLE |
| Column | customer_id | COLUMN |
| DTO | CreateSubscriptionDto | DTO |
| Interface | ISubscriptionRepo | IFACE |
| Enum | PremiumPlan | ENUM |
| Event | SubscriptionCreated | EVENT |
| EnvVar | ACME_BILLING_URL | ENV |
| Host | billing.acme.internal | HOST |
| PathSegment | `services/customer-subscription` | PATH |

The extractor combines:

- AST traversal
- SQL schema inspection
- OpenAPI traversal
- rule engine
- custom dictionary and stop-list
- **prose scan** over comments, string literals, and Markdown body text, using the vault's
  real-name automaton (§8) — this is where most narrative leakage lives

Each candidate carries a `scope_path` supplied by its parser:

| Artifact | scope_path form |
|---|---|
| SQL | `db.schema.table[.column]` |
| TypeScript | `module/path.ts::EnclosingDecl` |
| OpenAPI | `#/components/schemas/Name` |
| Markdown | `project` (dictionary scope) |

Scope granularity is controlled by the project's `scope_strategy` setting
(`global` | `module` | `strict`), trading twin readability against precision.

---

# 5. Identity Graph

The Identity Graph is the canonical representation of the project.

## Node

```ts
IdentityNode {
    uuid: UUID
    scopePath: string        // part of the identity key
    type: EntityType
    realName: string
    alias: string
    origin: 'detected' | 'manual' | 'ai_new'
    status: 'active' | 'excluded' | 'unresolved'
    sourceFile: string
}
```

The identity key is `(scopePath, type, realName)`. Name alone is insufficient:
`customer_id` exists in a dozen tables, `Status` is an enum in three modules, `CreateDto`
appears in every feature folder. Collapsing them causes over-aliasing (which breaks the
twin) and ambiguous restoration simultaneously.

## Edge

```ts
IdentityEdge {
    from: UUID
    to: UUID
    relation: USES | WRITES | EXPOSES
}
```

Example:

```
SERVICE_014
    |
    | USES
    |
DTO_012

SERVICE_014
    |
    | WRITES
    |
DB_TABLE_014
```

## Cross-artifact unification

The SQL table `customer_subscription`, the OpenAPI schema `CustomerSubscription`, and the
TypeScript DTO `CustomerSubscription` must resolve to **one** identity carrying **one**
alias. Unification runs after extraction, matching on normalized name plus a compatible
type pair (Table↔DTO, Schema↔DTO, Service↔API), and is confirmable by the user.

This is the feature that makes the graph worth having rather than a dictionary.

---

# 6. Alias Generation

Aliases are deterministic and machine-independent.

## 6.1 Derivation

```
h     = HMAC-SHA256(project_key, scope_path || ":" || type || ":" || real_name)
suffix = base32(h)[0..6]                       // Crockford base32, no ambiguous chars
alias  = <prefix> + "_" + suffix                // e.g. SERVICE_H7K2QX
```

Collisions are checked against the vault's UNIQUE alias index and resolved by appending
`_2`, `_3`, … deterministically.

A sequence-counter mode (`SERVICE_014`) remains available for solo users who prefer
readability, selected at project creation.

**Why not a counter by default:** sequence allocation requires a central allocator. Two
developers on the same repository would produce different aliases for the same entity —
divergent twins, non-comparable prompts, and cross-machine restore failure. HMAC derivation
needs only a shared project key.

## 6.2 Alias styles

| Mode | Pattern | Example |
|---|---|---|
| Opaque | `TYPE_SUFFIX` | `SERVICE_H7K2QX` |
| **Typed** *(default)* | `CategoryType_SUFFIX` | `PaymentService_H7K2QX` |
| Pseudonymous | `WordType` | `AuroraService` |

Style is fixed at project creation. Changing it requires a re-key (§9.5).

## 6.3 Alias grammar

```
alias      := prefix "_" suffix [ "_" disambiguator ]
prefix     := [A-Z][A-Za-z0-9]*
suffix     := [A-Z0-9]{3,8}
```

The grammar is frozen before the first release. It is embedded in the vault's
`schema_version` contract because every stored alias depends on it.

## 6.4 Canonical form (drift tolerance)

Models mangle placeholders: `Service014`, `service_014`, `SERVICE-014`, `Service_014`,
`SERVICE_14`, `SERVICE_014s`, `SERVICE_014Impl`, backtick-wrapped forms.

The restore matcher compares **canonical forms**:

1. Uppercase.
2. Strip all non-alphanumeric characters.
3. Strip leading zeros in the suffix.
4. Strip a trailing plural `s`.
5. Strip known affixes (`IMPL`, `SERVICE`, `DTO`) only if the remainder matches exactly.

Exact matches restore silently. Canonical-only matches restore **and are flagged** in the
diff as fuzzy hits. Alias-shaped tokens matching nothing become Unresolved Identities
(§12).

## 6.5 Stability

An alias never changes once created, except by explicit re-key.

---

# 7. Semantic Twin Generator

### Responsibility

Generate AI-safe artifacts.

Transformations occur on syntax trees, expressed as edit lists (§4.2.1), never as blind
text replacement.

Example:

Real:

```ts
class CustomerSubscriptionService {}
```

Twin:

```ts
class SERVICE_H7K2QX {}
```

Also transformed: imports, exports, filenames and directory names, references, interfaces,
tests, comment prose, and string literals.

## 7.1 Path transformation

File and directory names encode real names, and TypeScript import specifiers encode paths
as string literals. Path segments are therefore first-class identities of type
`PathSegment`, and each file's twin location is stored in `files.twin_path`.

`src/services/customer-subscription.service.ts` → `src/services/PATH_K2M9QX.service.ts`

## 7.2 Verification pass — the guarantee

The requirement is **not** "the twin compiles" (unachievable without a type checker, per
§4.2.2). It is:

> The twin **parses** with the same parser, and its declaration and reference counts match
> the original.

After generating a candidate twin the system re-parses it and compares node counts. On
mismatch the transformation for that file is **rejected**; the file is emitted unaliased
and reported to the user. No broken artifact is ever produced.

---

# 8. Export Verification Gate

No content leaves the application — clipboard, file export, or patch — without passing this
gate. It is not advisory and cannot be globally skipped.

## Algorithm

1. Build an Aho–Corasick automaton over every `real_name` in the vault, expanded to case
   variants: camelCase, PascalCase, snake_case, kebab-case, SCREAMING_SNAKE, space-
   separated, and simple pluralizations.
2. Scan the twin. **Any hit is a hard block**, reported with file, line, column, and the
   matched term.
3. Re-run the Secret Detector (§4.3) over the twin as an independent second pass. Any
   high-confidence match blocks.
4. On success, present a verified state that names what was checked **and what was not** —
   business logic in prose, algorithms, architecture shape (PRD §4.3).

An individual block may be overridden by explicit per-item acknowledgement, which is
written to the audit log (§15).

This module is small and is the highest-value component in the system: it converts *"we
hope detection was complete"* into *"nothing in the vault appears in the output."*

---

# 9. Mapping Vault

Storage engine: SQLite + SQLCipher, via `rusqlite` with the bundled SQLCipher feature.

## 9.1 Schema

```sql
PRAGMA user_version = 1;                    -- read by the migration runner

CREATE TABLE project (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  root_path      TEXT NOT NULL,
  alias_style    TEXT NOT NULL,             -- opaque | typed | pseudonymous
  scope_strategy TEXT NOT NULL,             -- global | module | strict
  key_salt       BLOB NOT NULL,             -- for HMAC alias derivation
  created_at     INTEGER NOT NULL
);

CREATE TABLE identities (
  uuid         TEXT PRIMARY KEY,
  scope_path   TEXT NOT NULL,
  entity_type  TEXT NOT NULL,
  real_name    TEXT NOT NULL,
  alias        TEXT NOT NULL,
  origin       TEXT NOT NULL,               -- detected | manual | ai_new
  status       TEXT NOT NULL,               -- active | excluded | unresolved
  created_at   INTEGER NOT NULL
);
CREATE UNIQUE INDEX ux_identity ON identities(scope_path, entity_type, real_name);
CREATE UNIQUE INDEX ux_alias    ON identities(alias);   -- guarantees restore is unambiguous

CREATE TABLE files (
  id         TEXT PRIMARY KEY,
  path       TEXT NOT NULL UNIQUE,
  twin_path  TEXT NOT NULL,
  checksum   TEXT NOT NULL,                 -- BLAKE3, drives staleness detection
  parser     TEXT NOT NULL,
  indexed_at INTEGER NOT NULL
);

CREATE TABLE occurrences (
  identity_uuid TEXT NOT NULL,
  file_id       TEXT NOT NULL,
  byte_start    INTEGER NOT NULL,
  byte_end      INTEGER NOT NULL,
  kind          TEXT NOT NULL,              -- declaration | reference | comment | string | path
  PRIMARY KEY (file_id, byte_start)
);

CREATE TABLE edges (
  from_uuid TEXT NOT NULL,
  to_uuid   TEXT NOT NULL,
  relation  TEXT NOT NULL,
  PRIMARY KEY (from_uuid, to_uuid, relation)
);

CREATE TABLE redactions (                   -- one-way; never contains plaintext
  id          TEXT PRIMARY KEY,
  file_id     TEXT NOT NULL,
  byte_start  INTEGER NOT NULL,
  byte_end    INTEGER NOT NULL,
  secret_type TEXT NOT NULL,
  match_hash  TEXT NOT NULL
);

CREATE TABLE allowlist (
  term   TEXT PRIMARY KEY,
  reason TEXT
);

CREATE TABLE audit_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           INTEGER NOT NULL,
  operation    TEXT NOT NULL,
  file_count   INTEGER,
  entity_count INTEGER,
  verification TEXT,
  destination  TEXT
);
```

## 9.2 Write strategy

One transaction per file; occurrence inserts batched. Row-by-row inserts across a full
index will not meet the 30 s target — SQLCipher write throughput dominates indexing.

## 9.3 Migrations

`PRAGMA user_version` drives a migration runner present from the first release.
Retrofitting migrations onto an encrypted store later is painful, and the alias grammar
(§6.3) is part of the versioned contract.

## 9.4 Key management

- The vault key is generated locally and stored in the **operating system credential
  store**: Windows DPAPI / Credential Manager, macOS Keychain, Linux Secret Service.
- It is never written to disk in plaintext next to the database — doing so would reduce
  SQLCipher's protection to the single case of the `.db` being copied alone.
- An optional user passphrase derives a key-encryption key via **Argon2id** (parameters
  recorded in the vault header) which wraps the vault key. Required for portable vaults.
- All key material is `zeroize`d after use.
- **Key loss is unrecoverable.** A passphrase-protected escrow export is offered at
  creation, with an explicit warning.

## 9.5 Re-key

Re-keying regenerates every alias under a new project key. Used when a twin has been
over-shared, or when the alias style changes. It is a full rewrite of `identities.alias`
inside one transaction, followed by invalidation of every generated twin.

---

# 10. Restore Engine

## 10.1 Design: lexical, not AST

Sanitization is AST-first because it needs structure to be correct. **Restoration is
deliberately lexical.** What returns from an LLM is frequently:

- a code fragment, not a compilable file
- a unified diff, not a file
- Markdown with fenced blocks and prose interleaved
- code containing syntax errors
- aliases inside string literals, comments, import paths, and filenames

An AST-first restore fails on all of these. Restore is a scan over a **closed alias
vocabulary**, which is precisely what makes it robust. AST re-parsing is used only as
optional post-validation when the input happens to be a complete file.

## 10.2 Input

- AI-generated twin artifact (any of the shapes above)
- Identity Graph
- Mapping Vault

## 10.3 Algorithm

1. Tokenize the input into alias-shaped candidates per the grammar (§6.3).
2. Exact match against `identities.alias` → replace silently.
3. Canonical match (§6.4) → replace **and flag** as a fuzzy hit.
4. No match → record as an Unresolved Identity (§12); leave the token untouched.
5. `<<REDACTED:*>>` markers are left in place — never restored.
6. Non-alias symbols remain unchanged.

### Example

Twin:

```ts
const dto = new DTO_M4X2QK();
```

Restore:

```ts
const dto = new CreateSubscriptionDto();
```

## 10.4 Unambiguity invariant

Because alias derivation includes `scope_path`, and `ux_alias` enforces uniqueness, a
given alias maps to exactly one identity project-wide. Restoration of a bare fragment with
no file context is therefore never ambiguous. This invariant is asserted by the schema, not
merely assumed.

---

# 11. Prompt Envelope

Restore reliability depends substantially on whether the model was told the placeholders
are opaque. SpecShield generates the instruction and copies it with the twin:

> Tokens matching `^[A-Z][A-Za-z0-9]*_[A-Z0-9]{3,8}$` are opaque anonymized identifiers.
> Preserve them exactly — do not rename, expand, translate, pluralize, or reformat them.
> If you introduce a new entity, name it `NEW_<n>` and list every such name at the end of
> your response.

The envelope is cheap to produce and raises the success rate of every downstream feature.
Its exact wording is validated by the alias round-trip suite (§19).

---

# 12. AI Merge Algorithm

AI may introduce new code.

Example twin output:

```ts
class SERVICE_H7K2QX {}

class SERVICE_099 {}
```

`SERVICE_H7K2QX` exists. `SERVICE_099` does not.

The engine classifies unknown alias-shaped tokens as **Unresolved Identities**. The user is
prompted:

| Alias | Suggested Name |
|---|---|
| SERVICE_099 | *(user supplies)* |

After approval the node is added to the graph with `origin = 'ai_new'`, and an alias is
derived for it in the normal way.

**No automatic guessing occurs.** Silent inference here would write a wrong name into the
user's real repository.

---

# 13. Diff Engine

The system compares three versions.

```
Original            Twin                AI Twin
CustomerService  →  SERVICE_H7K2QX  →   SERVICE_H7K2QX + retry logic
```

Restoration produces:

```
CustomerService + retry logic
```

The diff viewer highlights additions, deletions, and modifications, and calls out inline:

- fuzzy-restored aliases (§6.4)
- unresolved identities (§12)
- redaction markers

Formatting-only changes are suppressed where possible.

## 13.1 Staleness detection

`files.checksum` is compared at restore time. If the real files have changed since the twin
was generated, restoring AI output would silently revert or conflict with intervening
edits. The system displays a staleness banner and **requires an explicit rescan** before
any patch derived from that twin may be applied.

---

# 14. Git Integration

SpecShield never writes directly to `main`.

Workflow:

1. Generate restored file contents.
2. Produce a unified diff using the `similar` crate (Myers).
3. **Dry-run** the patch (`git apply --check`).
4. Create or switch to a dedicated branch.
5. Apply the patch.
6. User commits normally.

Note: libgit2 has no usable `git apply` equivalent, so patch application shells out to the
user's `git`. Where `git` is unavailable, the system writes restored files and reports
clearly that patch mode is disabled — it never silently overwrites.

Undo restores the pre-apply state.

Benefits: preserved history, code-review compatibility, rollback support.

---

# 15. Audit Log

Append-only, local, never transmitted. Distinct from telemetry, which the product does not
have.

Recorded per operation: timestamp, project, operation, file count, entity count,
verification result, export destination (clipboard / file / patch), and any verification
override with its acknowledgement.

**Never recorded:** real names, aliases, artifact content, secret values.

Exportable as CSV so a security team can review what left the machine and when.

---

# 16. Error Handling

| Error | Behavior |
|---|---|
| Unknown alias | Mark unresolved; leave token untouched; report |
| Alias matched only in canonical form | Restore, flag as fuzzy in the diff |
| Parser failure | Preserve original file; exclude from twin; report |
| SQL syntax error | Skip transformation for that file |
| Twin verification failure (§7.2) | Reject transformation; emit file unaliased; report |
| Leak gate hit (§8) | **Hard block on export**; no partial copy |
| High-confidence secret in twin | **Hard block on export** until acknowledged |
| Duplicate identity | Reuse existing UUID |
| Alias collision | Deterministic `_2` suffix |
| Stale twin at restore | Block patch application; require rescan |
| Vault corruption | Open read-only recovery mode |
| Missing vault key | Prompt for passphrase / escrow; never regenerate silently |
| Git unavailable | Disable patch mode; write files; report |

No destructive operations are permitted.

---

# 17. Security Design

## 17.1 Data flow

Processed locally, never transmitted: PRDs, source code, SQL, OpenAPI, the mapping
database, the audit log.

May leave the device: the **verified** semantic twin and content the user explicitly
copies after the gate passes.

## 17.2 Encryption

- SQLCipher, AES-256
- Local device key held in the OS credential store (§9.4)
- Optional Argon2id passphrase wrapping
- `zeroize` on key material
- No telemetry, no analytics

## 17.3 Egress control

- The Tauri capability set grants **no** `http` or `shell` network permissions.
- Content Security Policy is locked to local assets.
- Auto-update is disabled by default — an updater is a network dependency in a product
  that claims none.
- CI runs the application suite with outbound network blocked and asserts zero connection
  attempts.

## 17.4 Cloud-sync detection

On project creation and on open, the system checks whether the project root or vault path
lies inside a known sync root (OneDrive, Dropbox, Google Drive, iCloud). A vault inside
such a tree is uploaded to a third-party cloud, contradicting the local-only guarantee.
The user is warned prominently and offered one-click relocation of the vault.

## 17.5 Clipboard hardening

- Payloads are marked with `ExcludeClipboardContentFromMonitorProcessing` and
  `CanIncludeInClipboardHistory = false` on Windows, suppressing clipboard history and
  Cloud Clipboard synchronization.
- The clipboard is cleared after a configurable timeout.
- Original, unsanitized content is never placed on the clipboard by any UI affordance.

## 17.6 Threat model

See PRD §4 for adversaries, protected assets, explicit non-protections, and the residual
risk statement. The essential point restated: SpecShield removes **names**, not
**semantics**. Prose business logic, algorithms, and architecture shape still reach the
model.

---

# 18. Performance Targets

**Reference machine:** 8-core x86-64, 16 GB RAM, NVMe SSD, Windows 11. Reference project:
1,000 files, ~150k LOC.

| Operation | Target |
|---|---|
| Open project (warm vault) | < 2 s |
| Cold index, 1,000 files / 150k LOC | < 30 s |
| Incremental rescan | < 2 s |
| Sanitize a 100-page PRD (~40k words) | < 10 s |
| Verification gate over the reference project | < 3 s |
| Restore a ~2k-line response | < 3 s |

Implementation notes: `rayon` for parse parallelism, batched SQLCipher transactions
(§9.2), Aho–Corasick automaton built once per session and cached against a vault
generation counter.

---

# 19. Test Strategy

Four layers, all in CI:

1. **Property tests** (`proptest`) — the round-trip invariant `restore(sanitize(x)) == x`,
   alias determinism, alias uniqueness, edit-list non-overlap.
2. **Golden corpus** — 3–5 hand-labelled synthetic projects; detection recall and precision
   measured per commit, with regressions failing the build.
3. **Snapshot tests** (`insta`) — twin output per fixture, so unintended transformation
   changes surface in review.
4. **Adversarial fixtures** — aliases inside strings and comments, shadowed identifiers,
   homoglyph names, a `Status` enum in three modules, `customer_id` in ten tables, a live-
   looking API key three lines from a DTO.

Separately, an **LLM round-trip suite** runs per release rather than per commit: real
prompts through real models, measuring alias preservation with and without the prompt
envelope (§11). It is nondeterministic, so it gates releases as a report, not as a red
build.

---

# 20. Future Architecture (Post-MVP)

### V1.1

- Java, Kotlin, C#, Python parsers
- Exact TypeScript rename via a compiler-API sidecar, or an `oxc`/`swc` resolver
- Vault merge and sharing workflows for teams

### V1.2

- PlantUML, BPMN, ER diagrams
- Richer OpenAPI semantics (examples, security schemes)

### V2

- VS Code extension
- JetBrains plugin
- Codex CLI integration
- Claude Code integration
- GitHub Actions semantic gateway — enabled cheaply by the headless core and CLI

---

# 21. Technology Stack

This table is authoritative; the PRD references it rather than duplicating it.

| Layer | Technology | Notes |
|---|---|---|
| Desktop | **Tauri v2** | v1's plugin and permission model differs materially |
| UI | React + TypeScript | |
| Backend | Rust | Core is a headless library; UI holds no logic |
| Parsing | Tree-sitter | TS/JS, YAML; see §4.2.2 limits |
| SQL | `sqlparser` | |
| YAML / JSON | CST-preserving (`saphyr` / `yaml-rust2`) | **Not** `serde_yaml` (archived 2024) |
| Storage | SQLite | |
| Encryption | SQLCipher via `rusqlite` (bundled) | |
| Key storage | `keyring`, `argon2`, `zeroize` | OS credential store |
| Hashing | BLAKE3 (checksums), HMAC-SHA256 (aliases) | |
| Scanning | `aho-corasick` | Verification gate |
| File walking | `ignore` | gitignore-aware |
| Parallelism | `rayon` | |
| Diff | `similar` (Myers) | |
| Git | `git2` for repo state; `git apply` shelled out for patches | libgit2 cannot apply patches |
| Testing | `proptest`, `insta`, `criterion` | |

---

# 22. MVP Boundaries

**Included**

- Semantic twin generation with verified output
- Scoped identity graph with cross-artifact unification
- Deterministic, machine-independent alias derivation
- Secret detection and one-way redaction
- Export verification gate
- Prompt envelope generation
- Encrypted vault with OS-keychain key management and migrations
- Bidirectional restoration with fuzzy matching and unresolved reporting
- Twin diff with staleness detection
- Git patch export with dry-run and undo
- Local audit log

**Excluded**

- Cloud synchronization
- Multi-user vault merge tooling
- Local LLM inference
- Automatic naming of AI-introduced entities
- IDE plugins
- Exact type-checker-backed rename (V1.1)
