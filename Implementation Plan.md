# SpecShield — Implementation Plan (MVP)

Companion to the PRD, SDD, and *Design Review (PRD + SDD)*. This plan assumes the review's
recommendations are accepted; where a decision is still open it is listed in §1 as a
blocking spike rather than assumed away.

**Staffing assumption:** 2 engineers (1 Rust/backend, 1 TypeScript/frontend) plus
part-time design. Durations are calendar weeks at that staffing. Adjust proportionally.

**Total: ~16 weeks to a shippable MVP**, with a demoable end-to-end slice at week 6.

---

## 0. Sequencing principle

Build the engine as a **headless Rust library with a thin CLI first**, and put the Tauri
UI on top of it afterwards. Reasons:

- The core invariant (`restore(sanitize(x)) == x`) is testable only in a headless harness.
- A CLI makes the golden corpus runnable in CI from day one.
- It keeps the desktop shell replaceable and makes the future CI/GitHub-Action gateway
  (SDD §20, V2) nearly free.

Never let the UI own logic. `crates/core` must be usable with zero Tauri dependency.

---

## 1. Blocking decisions (resolve in M0, before any storage code)

These change the on-disk format or the public data model, so they cannot be deferred.

**Status:** all eight were resolved per the recommendation below and are now recorded in
PRD v1.1 and SDD v1.1. The table is retained as the rationale trail. Reopening any of them
after M1 means a vault migration.

| # | Decision | Recommendation |
|---|---|---|
| D-1 | Alias derivation: sequence counter vs HMAC-derived | **HMAC-derived** (Review A6), sequence mode as a display option |
| D-2 | Alias style default | **Typed** — `PaymentService_014` (Review D1) |
| D-3 | Identity key | **`(scope_path, entity_type, real_name)`** (Review B1) |
| D-4 | TypeScript rename strategy | **Tree-sitter + heuristic scoping**; drop the "must compile" guarantee to "must parse + counts match" (Review C1) |
| D-5 | Vault key storage | **OS credential store, optional Argon2id passphrase** (Review A4) |
| D-6 | Secrets handling | **One-way redaction, separate from the identity graph** (Review A2) |
| D-7 | YAML/JSON libraries | CST-preserving parsers, not serde round-trip (Review C2) |
| D-8 | Tauri version | **v2** |

---

## 2. Repository layout

```
specshield/
├── Cargo.toml                  # workspace
├── crates/
│   ├── core/                   # pure logic, no I/O side effects, no Tauri
│   │   ├── model/              # IdentityNode, Edge, EntityType, Alias, Occurrence
│   │   ├── alias/              # derivation, grammar, normalization, canonical form
│   │   ├── detect/             # rule engine, dictionary, stop-list
│   │   ├── secrets/            # regex pack + entropy, one-way redaction
│   │   ├── sanitize/           # twin generation, edit-list application
│   │   ├── restore/            # lexical restore, fuzzy matcher, unresolved
│   │   ├── verify/             # Aho–Corasick leak gate
│   │   └── diff/               # three-way diff over `similar`
│   ├── parsers/                # one module per format, uniform trait
│   │   ├── markdown/  text/  json/  yaml/  sql/  typescript/
│   ├── vault/                  # SQLCipher, schema, migrations, key mgmt
│   ├── index/                  # file walking, checksums, incremental rescan
│   ├── git/                    # patch generation & guarded apply
│   └── cli/                    # specshield-cli — the CI/test harness
├── app/                        # Tauri v2 shell
│   ├── src-tauri/              # commands, capabilities, state
│   └── src/                    # React + TypeScript UI
├── corpus/                     # golden test projects + labelled ground truth
└── bench/                      # perf corpus and criterion benches
```

**Core trait** every parser implements — this is the seam that keeps formats uniform:

```rust
pub trait ArtifactParser {
    fn can_handle(&self, path: &Path) -> bool;
    /// Parse without mutating; must retain byte offsets.
    fn parse(&self, doc: &Document) -> Result<Parsed>;
    /// Emit candidate entities with byte spans and a scope path.
    fn extract(&self, parsed: &Parsed) -> Vec<Candidate>;
    /// Emit non-overlapping byte-range replacements. Never rewrites the file itself.
    fn plan_edits(&self, parsed: &Parsed, map: &AliasMap) -> Vec<Edit>;
}
```

Everything is an **edit list over byte ranges**, applied by one shared function. No parser
serializes its own AST back to text — that is what destroys formatting.

---

## 3. Data model (revised vault schema)

**SDD §9.1 is authoritative.** The DDL below is reproduced for convenience while
scaffolding; if the two ever differ, the SDD wins and this section is the one to correct.

```sql
PRAGMA user_version = 1;                    -- migration runner reads this

CREATE TABLE project (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  root_path     TEXT NOT NULL,
  alias_style   TEXT NOT NULL,              -- opaque | typed | pseudonymous
  scope_strategy TEXT NOT NULL,             -- global | module | strict
  key_salt      BLOB NOT NULL,              -- for HMAC alias derivation
  created_at    INTEGER NOT NULL
);

CREATE TABLE identities (
  uuid          TEXT PRIMARY KEY,
  scope_path    TEXT NOT NULL,              -- REVIEW B1
  entity_type   TEXT NOT NULL,
  real_name     TEXT NOT NULL,
  alias         TEXT NOT NULL,
  origin        TEXT NOT NULL,              -- detected | manual | ai_new
  status        TEXT NOT NULL,              -- active | excluded | unresolved
  created_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX ux_identity   ON identities(scope_path, entity_type, real_name);
CREATE UNIQUE INDEX ux_alias      ON identities(alias);        -- REVIEW D6 invariant

CREATE TABLE files (
  id            TEXT PRIMARY KEY,
  path          TEXT NOT NULL UNIQUE,
  twin_path     TEXT NOT NULL,              -- REVIEW B5
  checksum      TEXT NOT NULL,              -- BLAKE3
  parser        TEXT NOT NULL,
  indexed_at    INTEGER NOT NULL
);

CREATE TABLE occurrences (                  -- REVIEW B6
  identity_uuid TEXT NOT NULL,
  file_id       TEXT NOT NULL,
  byte_start    INTEGER NOT NULL,
  byte_end      INTEGER NOT NULL,
  kind          TEXT NOT NULL,              -- declaration | reference | comment | string | path
  PRIMARY KEY (file_id, byte_start)
);

CREATE TABLE edges (
  from_uuid TEXT NOT NULL, to_uuid TEXT NOT NULL, relation TEXT NOT NULL,
  PRIMARY KEY (from_uuid, to_uuid, relation)
);

CREATE TABLE redactions (                   -- REVIEW A2 — one-way, no plaintext
  id TEXT PRIMARY KEY, file_id TEXT NOT NULL,
  byte_start INTEGER NOT NULL, byte_end INTEGER NOT NULL,
  secret_type TEXT NOT NULL, match_hash TEXT NOT NULL
);

CREATE TABLE allowlist (                    -- REVIEW D7 / FR-10
  term TEXT PRIMARY KEY, reason TEXT
);

CREATE TABLE audit_log (                    -- REVIEW D2 — local only, no content
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
  operation TEXT NOT NULL, file_count INTEGER, entity_count INTEGER,
  verification TEXT, destination TEXT
);
```

Write path: one transaction per file. Batch occurrence inserts. Never row-by-row across
the whole index — that is what will blow the 30 s target.

---

## 4. Milestones

### M0 — Foundations & spikes · week 1

**Deliverables**
- Cargo workspace, CI (fmt, clippy `-D warnings`, test, audit), `git init` (the project is
  not currently under version control).
- Decisions D-1…D-8 resolved and recorded in the SDD.
- Spike: Tree-sitter TypeScript rename on a real 50-file service — measures how far
  heuristic scoping gets. Decides C1 empirically rather than by argument.
- Spike: alias-format round-trip test — feed 5 candidate alias formats through a model
  with and without the prompt envelope; measure preservation rate. This picks the alias
  grammar with data.
- Golden corpus v0 checked in: one PRD, one SQL schema, one OpenAPI YAML, one TS service,
  each with hand-labelled ground-truth entities.

**Exit:** CI green; SDD updated with decisions; alias grammar frozen.

---

### M1 — Core engine, text pipeline · weeks 2–4

The whole product proved out on Markdown and plain text, with no UI.

**Deliverables**
- `crates/vault`: SQLCipher via `rusqlite` (`bundled-sqlcipher`), migration runner, key
  management through `keyring` + optional Argon2id passphrase, `zeroize`.
- `crates/core/alias`: HMAC derivation, three alias styles, canonical-form normalizer,
  collision handling.
- `crates/core/detect`: rule engine, custom dictionary, shipped stop-list, allowlist.
- `crates/core/secrets`: regex pack + entropy scorer, one-way redaction.
- `crates/core/verify`: Aho–Corasick leak gate with case-variant generation.
- `crates/core/restore`: lexical restore, fuzzy matcher, unresolved-identity reporting.
- `crates/parsers/markdown`, `parsers/text`.
- `crates/cli`: `init`, `scan`, `sanitize`, `verify`, `restore`, `report`.

**Exit criteria (these are the product, not a formality)**
- `restore(sanitize(x)) == x` byte-for-byte across the whole corpus — asserted as a
  `proptest` property, not just fixed cases.
- Leak gate: zero vault real-names present in any generated twin; a deliberately
  mislabelled corpus entry is caught.
- Secret detector: 100% on the planted-secrets fixture, < 5 false positives per 10k LOC.
- Detection recall ≥ 0.95 / precision ≥ 0.90 on the labelled corpus, reported by
  `specshield report` in CI.

---

### M2 — Desktop shell, Workflow A end-to-end · weeks 5–6

First demoable build. PRD Workflow A complete.

**Deliverables**
- Tauri v2 shell; capability set with **no** `http`/`shell` permissions; CSP locked down.
- Screens: project create/open (with vault unlock), import via drag & drop, entity review
  table (accept / rename / exclude / never-alias), sanitize + verify, copy-with-envelope,
  paste-and-restore, restored output view.
- Clipboard hardening per Review A5.
- Cloud-sync-folder warning per Review A4.
- Prompt envelope generator (FR-6b).

**Exit:** a user imports a PRD, reviews entities, copies a verified twin plus envelope,
pastes a model's response back, and gets correct restored text — no CLI, no terminal.

---

### M3 — Structured formats · weeks 7–9

**Deliverables**
- `parsers/sql` (`sqlparser`): tables, columns, constraints, indexes, scoped identities.
- `parsers/json`, `parsers/yaml`: CST-preserving, key-order and comment safe.
- OpenAPI-aware extraction on top of the YAML/JSON parsers: paths, operationIds, schema
  names, tags. (Resolved in favour of MVP inclusion — the architect user story in PRD §7
  needs it. Now reflected in PRD FR-2 and SDD §4.2.)
- Cross-artifact identity unification: the SQL table `customer_subscription`, the OpenAPI
  schema `CustomerSubscription`, and the TS DTO must resolve to **one** identity. This is
  the feature that makes the identity graph worth having; give it explicit tests.
- Edge inference (`USES`, `WRITES`, `EXPOSES`) and graph persistence.

**Exit:** an OpenAPI spec plus its SQL schema sanitize to a consistent twin; round-trip
holds; a cross-artifact unification test passes.

---

### M4 — TypeScript & repository scale · weeks 10–12

The riskiest milestone. Budget accordingly; M0's spike de-risks it.

**Deliverables**
- `parsers/typescript` (Tree-sitter, `.ts/.tsx/.mts/.cts/.d.ts`): declarations, references,
  imports/exports, string literals, comments, per-file scope stack, module-level
  export/import graph for cross-file rename.
- Post-sanitize verification: re-parse the twin, compare declaration/reference counts,
  reject and fall back to unaliased on mismatch.
- Path and filename aliasing (`PathSegment` identities, `files.twin_path`).
- `crates/index`: gitignore-aware walking (`ignore`), BLAKE3 checksums, `rayon` parse
  parallelism, incremental rescan, staleness detection.
- Twin project export to a directory.

**Exit:** a 1,000-file / ~150k-LOC reference repo indexes in < 30 s and rescans in < 2 s on
the stated reference machine; the exported twin parses cleanly with matching symbol counts;
round-trip holds file-for-file.

---

### M5 — Diff, merge, Git · weeks 13–14

**Deliverables**
- Three-way diff engine over `similar` (Original / Twin / AI-Twin → Restored), with
  formatting-noise suppression.
- Diff viewer UI, with fuzzy-restore hits and unresolved identities called out inline.
- Unresolved-identity resolution flow (SDD §12): user names new entities, node is added,
  no auto-guessing.
- Git: unified patch generation, `git apply --check` dry run, apply onto a new branch,
  never `main`; undo; clear behaviour when git is absent.
- Staleness guard before applying any patch.

**Exit:** PRD Workflow B runs end-to-end — import repo, twin, external AI edit, review
diff, restore, patch applied to a branch, `git diff` shows only intended changes.

---

### M6 — Hardening & release · weeks 15–16

**Deliverables**
- Local audit log + CSV export (FR-9).
- Vault backup/restore, key escrow export, alias re-keying (FR-11).
- Error handling matrix from SDD §16 implemented and tested, including read-only vault
  recovery mode.
- Offline enforcement test: run the app suite with egress blocked; assert zero outbound
  connections.
- Performance benches in CI against the M4 targets.
- Packaging & signing (MSI/NSIS, DMG, AppImage), auto-update explicitly disabled or
  opt-in — an auto-updater is a network dependency in a "no internet required" product.
- Docs: threat model, residual-risk statement, security-team one-pager, user guide.

**Exit:** signed installers; all PRD §5 metrics measured and reported; security
documentation complete.

---

## 5. Milestone summary

| M | Weeks | Theme | Primary risk |
|---|---|---|---|
| M0 | 1 | Foundations, spikes, decisions | Spikes invalidate the stack choice |
| M1 | 2–4 | Core engine, text, vault, CLI | Alias/identity model churn |
| M2 | 5–6 | Tauri shell, Workflow A | Tauri v2 plugin friction |
| M3 | 7–9 | SQL, YAML/JSON, OpenAPI, graph | Cross-artifact unification is subtle |
| M4 | 10–12 | TypeScript, repo scale | **Scope resolution without a type checker** |
| M5 | 13–14 | Diff, merge, Git | Patch application edge cases |
| M6 | 15–16 | Hardening, packaging | Key management across three OSes |

---

## 6. Test strategy

Four layers, all in CI:

1. **Property tests** (`proptest`) — the round-trip invariant, alias determinism, alias
   uniqueness, edit-list non-overlap.
2. **Golden corpus** — recall/precision measured per commit; regressions fail the build.
3. **Snapshot tests** (`insta`) — twin output per fixture, so unintended transformation
   changes are visible in review.
4. **Adversarial fixtures** — deliberately hostile inputs: aliases inside strings, aliases
   in comments, shadowed identifiers, homoglyph names, a `Status` enum in three modules,
   a `customer_id` column in ten tables, a real API key three lines from a DTO.

Additionally, an **LLM round-trip suite** run manually per release rather than in CI: real
prompts through real models, measuring alias preservation. It is nondeterministic, so it
gates releases as a report, not a red build.

---

## 7. Risk register (beyond PRD §15)

| Risk | Impact | Mitigation |
|---|---|---|
| Tree-sitter scoping proves insufficient for TS | High — M4 slips | M0 spike decides early; fallback is per-file-only aliasing plus a clearly stated limitation |
| False positives make twins unreadable | High — product feels broken | Stop-list, allowlist, precision target in CI, typed alias style |
| Model mangles aliases despite the envelope | High — restore fails | M0 format spike, fuzzy matcher, unresolved reporting; never silently guess |
| Semantic leakage in prose (unfixable by design) | Medium — reputational | Documented residual risk; prose scan; optional comment stripping |
| SQLCipher build friction on Windows | Medium | Use `bundled-sqlcipher-vendored-openssl`; pin and cache in CI |
| Vault key loss | Medium | Escrow export, explicit warnings |
| Alias format change after release | High — every stored vault breaks | Freeze the grammar at M0; `schema_version` + migrations from day one |

---

## 8. Immediate next steps

**Done**

- ~~Update the PRD with the Threat Model section and FR-3b / FR-4b / FR-6b / FR-9 / FR-10 /
  FR-11 / FR-12.~~ — PRD v1.1
- ~~Update the SDD with the revised schema, the scoped identity key, the alias grammar, and
  the sanitize/restore asymmetry.~~ — SDD v1.1

**Next**

1. `git init` this directory and commit the PRD, SDD, review, and this plan. *(It is not
   currently a git repository — and per the review's OneDrive finding, move the working
   copy out of the synced tree first.)*
2. Scaffold the Cargo workspace and CI (M0).
3. Build the golden corpus v0 with hand-labelled ground truth — it gates the §5 metrics in
   the PRD and every exit criterion from M1 onward.
4. Run the two M0 spikes — Tree-sitter rename on a real 50-file service, and the alias-
   format round-trip test. They are the only things that can still invalidate this plan,
   and the second one freezes the alias grammar in SDD §6.3.
