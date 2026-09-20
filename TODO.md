# SpecShield — working context and TODOs

Hand this file to a fresh Claude session. Every item below is self-contained:
file paths, what "done" means, and how to verify it. Read §1–§3 before changing
anything — several of the invariants are load-bearing for the product's security
claim and are easy to break by accident.

---

## 1. What this is

SpecShield lets teams use commercial LLMs on proprietary code and docs by
replacing identifiers with deterministic aliases, then restoring the model's
output back to real names. Local-first desktop app; nothing goes to a server.

**The four documents are the source of truth**, in this order:

| Document | What it settles |
|---|---|
| `Product Requirements Document (PRD).md` | What is protected (§4), success metrics (§5), principles (§7), FRs (§9), alias rules (§13) |
| `Software Design Document (SDD).md` | Architecture, alias grammar (§6), vault schema (§9.1), gate (§8) |
| `Design Review (PRD + SDD).md` | Why the v1.1 specs say what they say — findings A1–E |
| `Implementation Plan.md` | Milestones M0–M6, decisions D-1…D-9, current status |

When code and docs disagree, that is a bug in one of them. Say which.

**There is one PRD.** `SpecShield (PRD) Revised.md` was a separate v2.0 document
and is folded into the PRD above; its change log records what it changed and
where its FR numbers went. The revision governs scope and principle, and v1.1's
engineering requirements survive wherever the revision was silent — dropping
FR-4b from a short document does not delete the export gate.

### Layout

```
crates/core/      engine: model, alias, edit, detect, secrets, sanitize, restore, verify, diff
crates/parsers/   markdown, text, sql, yaml, json, openapi, typescript
crates/vault/     SQLite + per-value AES-256-GCM + blind index
crates/index/     walk + BLAKE3 + rescan + staleness (M4)
crates/git/       patch generation, guarded apply, undo (M5)
crates/cli/       `specshield` binary; the CI and corpus harness
app/              Tauri v2 shell (src-tauri = Rust, src = React)
corpus/           golden corpus, labelled ground truth, generator
spikes/           M0 experiments + their reports
```

### Verify everything

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p specshield-cli -- report corpus --strict
cd app && npx tsc --noEmit && npm run build
```

All five pass on `main`. If one fails after your change, that is your change.

---

## 2. Invariants — do not break these

1. **`restore(sanitize(x)) == x`, byte-for-byte.** Property-tested in
   `crates/core/tests/roundtrip.rs`. Anything that rewrites text must go through
   `crates/core/src/edit.rs` byte-range edits — never re-serialize a parsed tree.
2. **Everything goes through the gate; only a secret is stopped by it.**
   `crates/core/src/verify.rs` scans candidate output for every *identifying*
   vault name plus case variants, and reports what it finds. The twin is
   produced anyway — `--strict` refuses instead, and `specshield verify` is the
   per-file CI form. **A high-confidence secret in a twin refuses in both
   modes**, in the CLI and the app alike: a name costs a competitor a guess, a
   live credential costs you the account and no re-key takes it back.

   This was a hard block until the tool met a real repository and wrote nothing
   at all. See SDD §8 for the reasoning, and do not quietly restore it.
3. **Secrets are one-way.** `crates/core/src/secrets.rs` redacts; nothing
   restores a redaction marker. Secrets never enter the identity graph.
4. **Identity is `(scope_path, entity_type, real_name)`**, never name alone.
   Two `Status` enums in different modules are two identities.
5. **Aliases are never re-aliased.** `detect::protected_regions` claims
   alias-shaped tokens before detection runs; without it, sanitizing twice
   destroys the mapping.
6. **The engine holds all logic.** The Tauri layer and the CLI are drivers.
   Anything the app can do, `specshield-core` can do headless.
7. **The vault file contains no real name.** Asserted by a test. Aliases *are*
   plaintext, deliberately — they are what gets sent to the model.
8. **Detection precision matters as much as recall.** A detector that flags
   everything makes the twin unreadable and degrades AI output. Both are gated
   in CI.
9. **Preserve architecture, remove identity.** PRD v2.0 §7. Only
   `EntityType::is_identity` types are aliased by default — organizations,
   products, brands, partners, payment providers, people, tenants, environments,
   domains. Services, DTOs, tables, columns and the rest stay readable, because
   an agent that cannot read your architecture cannot help you extend it.
   `specshield term` promotes any name across that line.
10. **An identity is aliased inside the compound that names it.**
   `AcmeBillingService` → `ORG_001BillingService`. Company hidden, shape intact.
   `restore` searches tokens for issued aliases so this round-trips.
11. **A single ordinary word is not an identity.** `crates/core/src/words.rs`,
   PRD §4.2. An org called `admin` or an environment called `staging` says
   nothing about who wrote it, and aliasing such names is what made a real
   repository unexportable. A compound is
   always identifying; so is a single word nobody else uses (`Vantor`). A name
   the user confirms with `specshield term` overrides the rule — that is the
   escape hatch, and it has to keep working.

---

## 3. Current state

M0 and M1 complete. M2 (desktop shell) started. D-9 resolved.

| Milestone | State |
|---|---|
| M0 foundations + spikes | done — see `spikes/M0-*.md` |
| M1 core engine, Markdown/text, vault | done — corpus gate enforced in CI |
| M2 Tauri shell | done |
| M3 SQL / YAML / OpenAPI | parsers done; P2-4 unification remains |
| M4 TypeScript + repo scale | done — parser, index, project export, path aliasing |
| M5 diff + git | done — engine, git, CLI, and the diff screen |
| M6 hardening + packaging | engine and docs done; packaging and signing remain |

Vault schema is at **v5**. v5 renumbers every alias into the `PREFIX_001` form
of PRD v2.0 §13 and orphans every twin made before it. v3 (wrapped data key) is a
*content* migration and is not keyed on `user_version`. See `crates/vault/src/schema.rs`
`DDL_VERSION`, and read it before adding a migration of either kind.

Corpus, current: all seven projects gated. Over 49 identity occurrences:
**49.0% rules-only**, **100% with dictionary**, **98.0% precision**. 225
structural occurrences and 2 ordinary-word occurrences reach the model on
purpose (PRD §4.1, §4.2); secrets 6/6, 0 false positives. Every format has a
parser, so nothing is excluded from the verdict — see
`crates/cli/src/report.rs`.

The rules-only column is the one to watch: it is what the detector finds against
an empty vault, and it is the only part of identity detection that works before
a user has typed anything.

Repo scale, measured on a synthetic 1,000-file / 151k-LOC TypeScript project
(release build, this machine): index 0.03 s, full project export 11.5 s, rescan
0.44 s. The M4 exit criteria are < 30 s and < 2 s.

---

## 4. TODOs

### P0 — wrong right now

~~**P0-1. `copy_verified_twin` does not copy anything.**~~ — **fixed**, commit
`b63075c`+. `tauri-plugin-clipboard-manager` registered, the write happens
before the audit entry so an `export` row can never describe a copy that
failed, and a failed write returns an error rather than a length. The capability
grants `clipboard-manager:allow-write-text` only — reading the user's clipboard
is not this app's business. `app/src-tauri/src/state.rs` gained six tests around
the copyable-twin state machine, including that a blocked sanitize clears the
previous twin.

Still unverified by hand: nobody has clicked the button in a running app
(P1-2). The Windows format flags remain open (P1-1).

~~**P0-2. `sanitize` does not perform the SDD §7.2 verification pass it
documents.**~~ — **fixed**. `ArtifactParser::structural_counts` supplies a
per-format fingerprint; `sanitize` compares it before and after and returns a
`Verification` describing what happened. A twin whose structure changed, or that
no longer parses, is abandoned: the unaliased original is returned with `applied`
empty, per SDD §16. Secrets stay redacted through that path — rejecting the alias
pass must not turn a verification failure into a leak.

`Verification::NotAttempted` and `Unsupported` are distinct from `Passed`, so
"no check ran" can never be read as "verified". The markdown parser implements a
real fingerprint (outline, per-depth heading counts, fences, lines) that catches
an invented heading or a broken fence; plain text returns `None` deliberately,
because counting words would reject correct sanitizes of multi-word entities.

~~**P0-3. `ProjectKey` is not zeroized.**~~ — **fixed**. `ProjectKey` derives
`ZeroizeOnDrop`, with a compile-time assertion of the trait bound: a runtime
test would have to read freed memory, so asserting the bound is the strongest
honest guarantee and it fails the build if the derive is ever dropped.

Zeroizing the key was not enough on its own — the copies around it outlived it.
Also cleared: `vault::Settings` (which hands raw key bytes to callers) now
clears them on drop, the generated array in both `init` paths is wiped once the
vault owns it, and `ProjectKey::take_bytes` clears the caller's array as it takes
ownership. `from_bytes` is still available and now documents that it copies.

**P0 is clear.** The only remaining `TODO(` markers in the codebase name their
milestone: M2 clipboard flags, M4 index, M5 diff and git.

---

### P1 — finish M2

~~**P1-1. Windows clipboard hardening.**~~ — **implemented** in
`app/src-tauri/src/clipboard.rs`.

All three opt-out formats are set (`ExcludeClipboardContentFromMonitorProcessing`,
`CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard` — the last being the
one that governs the Microsoft-account upload), plus a 2-minute clear that only
fires if the clipboard still holds SpecShield's own payload. A test exercises the
real Win32 path: write, read back, refuse to clear someone else's content, clear
its own.

`unsafe_code` is forbidden workspace-wide, so this uses `clipboard-win` rather
than hand-written Win32 calls or a relaxed lint.

**What remains open, and is now stated rather than implied:**

- The formats are advisory. A clipboard manager that ignores them still captures
  the text; nothing stops a user pasting the twin anywhere.
- **macOS and Linux have no opt-out.** macOS has
  `org.nspasteboard.ConcealedType`; Linux depends on the clipboard manager.
  Neither is implemented, so both report `NotAvailable` and fall back to the
  Tauri plugin for the write.
- The audit log records `clipboard(opted-out)` or `clipboard(unprotected)` per
  export, so which exports the platform may have retained is visible rather than
  assumed.
- The clear delay is a constant. Surfacing it in settings is UI work.

PRD §10 and SDD §17.5 have been rewritten to describe what exists, including the
platform gap.

~~**P1-2. Exercise the running app.**~~ — **done**. Workflow A walked end to end
in the running app: vault created, dictionary seeded, four terms excluded, 26
entities detected (matching the CLI on the same document), sanitized, copied,
restored. The IPC path, the gate, the clipboard write, and restore all work
against a real window.

Error paths are still unexercised — a blocked export, a wrong passphrase, an
unsupported format. Worth a deliberate pass, but no longer the top risk.

**P1-3. File picker. — DONE.** Every path field has a Browse button, the Review
step has "Open file…", and the twin has "Save twin…".

The design decision worth keeping: the dialog runs in Rust. The webview was
granted no dialog permission and no filesystem permission, and no command takes
a caller-supplied path to *read* — `pick_file` opens a dialog and returns the
contents. Granting `fs:allow-read-*` would have been two lines shorter and would
have meant the frontend could read anything on the machine. Two tests hold the
line: one pins the capability list to exactly three entries, the other asserts
`pick_file` never grows a path parameter.


**P1-4. Interactive passphrase entry. — DONE.** The CLI prompts with echo off
when neither `--passphrase` nor `SPECSHIELD_PASSPHRASE` is set, and `init` asks
twice — a typo in a passphrase nothing stores is unrecoverable in the same way
losing it is. `--passphrase` now warns that it is visible in the process list.

Two things worth remembering about the implementation:

- The prompt reads the *terminal device*, not stdin, so
  `specshield restore < response.md` asks rather than swallowing the file. The
  availability check had to match: an early version gated on
  `stdin().is_terminal()`, which would have refused to prompt in the commonest
  interactive case there is.
- The source *choice* is a pure function with tests, because the prompt itself
  needs a terminal and cannot be driven from one. The property that matters is
  that explicit sources always win: prompting when a value was supplied hangs a
  pipeline forever.


**P1-5. Tauri command coverage. — DONE.** `app/src-tauri/src/lib.rs` has 30
tests now, covering the commands rather than only the helpers: the sanitize
gate and the copyable-twin transition, the parser refusal, the standalone
gate's clean-versus-nothing-checked distinction, the staleness and unresolved
guards on apply, re-key's confirmation, escrow's passphrase check, and the
capability set.

`tauri::test`'s mock runtime does not link on Windows
(`STATUS_ENTRYPOINT_NOT_FOUND`), so the commands are split into a thin
`#[tauri::command]` wrapper and a `_in` body taking `&AppState`. The wrapper is
one line; everything worth testing is below it.

**The coverage immediately earned itself** — see the allowlist defect it found,
recorded in the commit for FR-10.
---

### P2 — M3, next milestone

~~**P2-1. SQL parser**~~ — **done**. `crates/parsers/src/sql.rs`, AST-driven via
`sqlparser`, with byte offsets from `Ident::span`. Tables, columns, enum types,
index names, and **references** — `REFERENCES t (c)` names both again, and
aliasing only the declaration leaks the name and breaks the schema.

Columns are scoped to their declaring table, so the ten `customer_id` columns in
the adversarial fixture are ten identities. Edits are still byte ranges; the AST
is never re-serialized, because that would lose comments and normalize keyword
casing and fail the round trip on the first file.

sql-schema went 5% → 100% recall. Gated total: 100% recall, 96.4% precision.

~~**P2-2. YAML and JSON parsers**~~ — **done**. `crates/parsers/src/yaml.rs`,
built on `saphyr` with spanned nodes. JSON is read through the same parser
because JSON is a subset of YAML 1.2, which keeps one node model for the OpenAPI
layer.

Provides a path-addressed node index (`components.schemas.X.properties.y`,
`servers.0.url`) with byte spans and key/value distinction — that index is what
P2-3 consumes. Plus `structural_counts` over documents, mappings, sequences,
keys, and nesting depth, which catches an alias that injects a key.

Generic YAML claims no entities of its own: nothing in the grammar says which
names are proprietary, so the prose scan does the detecting. **A restriction was
tried and removed** — see the module docs. Confining the scan to scalar values
looked principled and measured badly: 16 points of recall for 8 of precision,
and it left company names in `docker-compose.yml` environment keys.

`prose_regions` stays on the trait for TypeScript, where comments and string
literals genuinely are prose and code is not.

Documents declaring `openapi:` or `swagger:` are **declined**, because their
names live in keys that only the OpenAPI layer can classify. Processing them
here yields a twin with values aliased and schema names intact — the gate
refuses it, correctly but confusingly.

~~**P2-3. OpenAPI semantic layer**~~ — **done**.
`crates/parsers/src/openapi.rs`, a layer over the YAML node index rather than a
second parser. It supplies the one thing the grammar cannot: which keys are
names.

Detects `info.title`, schema names (typed Enum when the schema declares one),
properties, `required` entries, operationIds, parameter names, `$ref` targets,
and `{param}` in path templates. The last two matter most: a `$ref` still
pointing at the real schema name leaves it in the twin *and* breaks the spec,
and `/invoices/{invoiceId}` carries a field name in the URL.

openapi-billing: 5% → **100% recall, 100% precision**, and now gated. Gated
total across Markdown, SQL, and OpenAPI: 82 entities, 100% recall, 97.6%
precision.

Two properties the corpus never labelled (`planTier`, `subscriptionId`) were
added, on the same rule already applied to SQL columns: a spec with `customerId`
aliased and `planTier` intact is inconsistent, and which field names are
proprietary is not a judgement the tool can make.

~~**P2-4. Cross-artifact unification.**~~ — **done**. `crates/core/src/unify.rs`
proposes; `specshield unify` lists and confirms; confirming performs a scoped
re-key.

**SDD §5 was not implementable as written, and has been corrected.** "One
identity carrying one alias" cannot work: `ux_alias` maps an alias to one real
name, so a shared alias would return `customer_subscription` to the TypeScript
file or `CustomerSubscription` to the SQL file — one of them wrong, and the
round trip broken. Implemented instead: one concept, one alias **suffix**,
per-artifact prefix. `DB_TABLE_MS7JMB` and `DTO_MS7JMB` are visibly the same
thing and restore unambiguously.

Nothing unifies without confirmation, because `corpus/adversarial` has three
unrelated `Status` enums and a name match is not evidence. A proposal needs two
*different* compatible kinds. Columns are never unified — `customer_id` is in a
dozen tables.

**P2-5. Widen the corpus gate. — DONE in M4.** All six projects are gated:
98.6% recall / 95.8% precision. Nothing in `report.rs` changed; the projects
became gated on their own as the parsers landed, which is what `requires` was
for.

**P2-6. Path and filename aliasing. — DONE.** `specshield export` writes the
twin tree at aliased paths and `specshield restore <twin-dir> --out <dir>`
puts it back. The rule lives in `crates/core/src/paths.rs` because the parser
and the export both need it: a file and every import of it must land on the
same alias or the twin stops resolving.

---

**P2-7. The M5 diff viewer UI. — DONE.** Step 5, "Diff & apply", in
`app/src/App.tsx`. Hunks with inline notes, the complete note list, the SDD §12
naming form, and patch application with undo.

What was *not* done: the screen has never been driven through a running Tauri
app. It was rendered against a stubbed IPC layer in a browser — which confirms
the markup, the CSS, and the refusal logic — and the guards behind it are tested
in Rust (`app/src-tauri/src/lib.rs`). The gap is the real IPC round trip and
anything that depends on a live vault, and it is the same gap P1-5 describes.

---

**P2-10. Desktop/CLI parity. — DONE.** The app now covers everything the command
line does except `specshield report`, which measures detection metrics against
the golden corpus and is a CI tool with nothing to do inside a project.

The pipeline both surfaces run lives in `crates/project`, so there is one
implementation rather than two: `graph_from`, `detector_from`, `learn`,
`twin_paths`, `sanitize_tree`, `export`, `restore_project`, `index_project`,
`rescan_project`, `unify_*`, and `rekey`. Alias re-derivation is in
`crates/core/src/rekey.rs` for the same reason. Two copies of either would be two
chances to drift, and drift means a twin one surface produces cannot be restored
by the other.

Remaining difference: the app still has no file picker (P1-3), so it works on
pasted text and resolves typed paths against the project folder.

---

**P2-8. M6 packaging and signing.** The engine half of M6 is done and the four
security documents are written (`docs/`). What remains needs credentials that
are not the repository's to hold:

- **Installers and signing** (NSIS, DMG, AppImage). `tauri.conf.json` already
  targets all three and sets `createUpdaterArtifacts: false` — an updater is a
  network dependency in a product whose central claim is that it needs none.
  Signing needs a Windows code-signing certificate and an Apple developer
  identity. Until then: SmartScreen warnings on Windows, Gatekeeper refusal on
  macOS without an explicit override.

**P2-9. Wrapped master key. — DONE.** Schema v3. A random data key encrypts all
content; the passphrase-derived key only wraps it.

What this bought:

- `specshield passphrase` — changing a passphrase re-wraps 32 bytes. A test
  asserts not one ciphertext and not one blind index moves.
- Escrow holds the **data key**, not the passphrase, so a recovery holder never
  learns a credential the user may have reused elsewhere. `escrow-open` re-wraps
  under a passphrase they choose rather than printing a key.
- `specshield rotate-key` — re-encrypts everything under a new data key, which
  is what revoking an issued escrow actually means. There was no path to it at
  all before.

The migration runs on first open, in one transaction, and is tested against a
hand-built v2 vault covering every sealed table. Two bugs it caught are in the
commit message; the worse one is that a stale escrow used to brick the vault.

Still true and now stated precisely in Residual Risk §3.2: an escrow file is a
**bearer credential** until the key is rotated. Handing one back does not revoke
it.
---

### P3 — open questions, not yet decided

**P3-1. Concept vs. surface form.** `PlanTier` and the prose "Plan tiers" become
two identities with two aliases, so a model sees them as unrelated. This is
deliberate — interning each variant under its exact surface text is what keeps
restore byte-for-byte lossless — but linking surface forms to a shared concept
would produce better twins. See the comment in `crates/core/src/detect.rs`.

**P3-2. Homoglyphs.** `corpus/adversarial/input/homoglyph.md` contains `Vantor`
and `Vаntor` (Cyrillic U+0430), labelled as two identities. Whether the detector
should unify them under Unicode confusable folding is undecided; the fixture
exists to force the decision.

**P3-3. Alias spike part 2 was never run.** `spikes/M0-alias-format.md`.
Recoverability is settled offline; drift *frequency* needs real model calls. The
prompt pack is generated:

```bash
cargo run -p spike-alias-roundtrip -- --emit-prompts spikes/alias-roundtrip/prompts
```

12 prompts, 6 formats × envelope/no-envelope. Billable API calls — a human
should trigger this deliberately.

**P3-4. Re-run the Tree-sitter spike against a *real* service. — RUN, and it
failed.** Full write-up in `spikes/M4-typescript-real-repo.md`. Subject: a
Vite + React + TypeScript + Express + Tauri app, 158 files, 52 TypeScript of
which 15 of 20 tracked were `.tsx`.

Four defects, three fixed:

1. **The parser could not read JSX.** `parse_tree` only ever used
   `LANGUAGE_TYPESCRIPT`; `tree-sitter-typescript` ships a separate
   `LANGUAGE_TSX`, and they are different languages (`<T>x` is a type assertion
   in one and a JSX element in the other). One `return <div>{x}</div>` was enough
   to make the tree error — so **every `.tsx` file went to the model completely
   unaliased, reported as “verified clean”**, because a `None` fingerprint read
   as *no structure to compare* rather than *could not read your file*. Fixed on
   both sides: TypeScript-then-TSX in `parse_tree`, and a new
   `Verification::OriginalDidNotParse` keyed on `ArtifactParser::fingerprints()`
   that the CLI, the export summary and the desktop banner all report loudly.
2. **Function declarations were not entities.** In React the components *are*
   functions — 63 of them here against 4 arrow consts. They were interned from
   filenames and imports and left in place at their declaration sites, blocking
   the export by construction. `function_declaration`,
   `generator_function_declaration` and `function_signature` (the ambient `.d.ts`
   form) now declare alongside classes. Ground truth was extended for `submit`
   and `render` in `corpus/adversarial` — flagged, since I write both the
   detector and the grader.
3. **The corpus grader compared redacted-text offsets with source ground
   truth.** A `<<REDACTED:...>>` marker is not the length of the secret, so every
   offset after the first secret in a file was displaced — 12 bytes in
   `secret-beside-dto.ts`, scoring one correct detection as a miss *and* a false
   positive, in CI, since the fixture was written. `secrets::source_offset` now
   owns the map and `sanitize`, `scan` and the grader all use it. Corpus went
   98.6% / 96.3% on 211 entities to **99.1% / 95.9% on 213**.
4. **`specshield scan` never asked the parser** — it ran the prose scan alone and
   reported a pipeline nobody runs, promising five entities on a component where
   `sanitize` applied none. It now calls `sanitize::sanitize` against a throwaway
   graph.

Plus: **allowing a name did not clear the gate.** The scanner matches
case-insensitively and the allowlist exempted with `==`, so `specshield allow
API` could not clear an identity stored as `api` — and nothing shows a user which
case the vault holds. Both sides are case-insensitive now.

**What remains is not a bug and is a decision for a human — see P3-6.**

**P3-6. The gate has no notion of where a name is meaningful.** With everything
above fixed, the real repository is *still* blocked, by 124 distinct names across
78 files. `Node` is a real `interface Node`; `Screen` and `Choice` are real
interfaces. All correctly detected and aliased. The gate then blocks **every
occurrence of the word `node` in the project** — 1,879 of them, mostly in
`package-lock.json`, plus `.gitignore` and the CI workflow.

That is SDD §8 working as specified: every vault name, every file, case-blind,
hard block. Invisible on a corpus of `CustomerSubscription` and `PlanTier`;
crippling on a real domain model of `Node`, `Screen`, `Choice`, `Status`, `Key`,
`Error`, `Type`, `Data`. **A team could not adopt this today without allowlisting
around a hundred names.** Narrowing the product's central safety control is not a
call to make while implementing a parser, so it has not been made. Three options
in `spikes/M4-typescript-real-repo.md`; the cheapest by far is to have
`walk_declarations` consult `STOP_LIST`, which already contains `Node` and
`React` and which only the *detector* reads today.

Interim: a blocked export now lists the blocking names by frequency with the
`specshield allow` command to run. Unblocking used to mean guessing at what the
five-per-file truncation was hiding.

**Still untested:** decorators, generics with constraints, and barrel re-exports
— all absent from this codebase. Arrow-function consts are the remaining
declaration gap (`export const useScenarioStore = create(...)` leaks at its own
declaration site). A NestJS or Angular service would close out the first three.

**P3-5. Unused vault tables. — DONE.** Two wired up, one dropped.

- **`occurrences`** — written by `export`, read by `specshield where <name>` and
  the desktop “Where is it” panel. Answers both directions: where the project
  uses a name, and what an alias was before it was one.
- **`redactions`** — written by `export`, read by `specshield secrets`, the
  desktop “Secrets found” panel, and `specshield recover` (which needs no
  passphrase, and where the count matters most: those credentials are in the
  working tree whatever happens to the vault). The export reports how many were
  new, which is the one thing `match_idx` can do.
- **`edges`** — **dropped**, schema v4. It never had a producer: no parser emits
  a relation and `Relation` was never constructed. SDD §5 and PRD §11 now say the
  relation graph is deferred, what it would cost (a `relations` method on
  `ArtifactParser`, SQL `REFERENCES` first), and what it would buy (a better
  twin, not a stronger guarantee).

Four defects came out of it, two of them mine and two much older:

1. **`Applied` byte offsets were in the wrong coordinate system.** The alias pass
   runs over text in which secrets are already markers of a different length, so
   every offset past the first secret was displaced — silently, and only in files
   that contained one. Nothing had consumed those offsets before, which is why it
   had never shown. `sanitize` now maps them back to the caller's source and says
   so on `Sanitized`.
2. **A rescan threw away the twin-path mapping.** `files.twin_path` is the only
   record of where an exported file went, and `restore_project` is the only thing
   that can put it back — but `index` and `rescan` both overwrote the column with
   the real path. A routine rescan silently orphaned every twin tree already
   produced: restore found no mapping and left each file at its alias name. Found
   by running it, not by reading it.
3. **`export` never forgot deleted files.** `rescan` did; `export` did not, so
   `specshield secrets` went on naming a file that no longer existed.
4. **Keying the v3 content migration on `user_version` was wrong** — my own, and
   caught by an existing test. The DDL runner stamps the version before any
   passphrase is checked, so one mistyped passphrase would have left a pre-v3
   vault permanently unopenable. The question is now put to `meta`: the wrapped
   `data_key` row *is* v3, so it cannot drift from the truth the way a stamp can.

Still true: `occurrences` and `redactions` are written by `export` alone. A
project that has only been scanned has neither, and both readers say so rather
than showing an empty list.

---

## 5. Things that will trip you up

- **`cargo fmt` runs on save in this repo's workflow.** Patching Rust files with
  Python string replacement fights it. Prefer targeted edits.
- **The corpus `labels.json` files are generated.** Edit `spec.json` and run
  `python corpus/tools/build_labels.py`. A CI job fails if they drift. Never
  hand-edit byte offsets.
- **Detection runs on the *redacted* text, not the source.** A
  `<<REDACTED:...>>` marker is almost never the length of the secret it replaced,
  so every offset after the first secret in a file is displaced. Anything that
  shows an offset to a person, or compares one with the original, must go through
  `secrets::source_offset`. It has been wrong in three places already — see P3-4.
- **`clippy.toml` allowlists proper nouns** (`SpecShield`, `OpenAPI`, …) for the
  `doc_markdown` lint. Add new ones there rather than backticking prose.
- **The repo lives in OneDrive.** `crates/vault::cloud_sync_root` detects this
  and the app warns. Moving the working copy out is still on the list.
- **Windows + SQLCipher does not build.** That is settled (D-9); do not
  reintroduce `bundled-sqlcipher-vendored-openssl`.
- **GitHub's push protection blocks this repository's own test fixtures, and
  that is not fixable.** A push carrying `crates/core/src/secrets.rs` or
  `sanitize.rs` is rejected with *GH013 — Stripe API Key*, naming the
  `sk_live_abcdefghijklmnopqrstuvwx` and `sk_test_0000…` constants. They are the
  alphabet in order and a run of zeros; nothing about them is real.

  The tension is inherent: our own rule is
  `[sr]k_(?:test|live)_[A-Za-z0-9]{16,}`, GitHub's is effectively the same,
  so **any fixture that satisfies our test satisfies their scanner.** Weakening
  the fixture means the test stops testing what it is for, and rewriting forty
  commits of history over fake data is not proportionate.

  Resolve it by allowing the detection: the rejection prints an unblock URL,
  and *"used in tests"* is the accurate reason. Do not disable push protection
  for the repository — the per-detection allowance is the narrow fix, and it
  keeps the scanner working on everything else.

  The same shape is in `ghp_aaaa…`, `whsec_0000…` and the AWS
  `AKIAIOSFODNN7EXAMPLE` in `corpus/adversarial/`. None has tripped the scanner
  so far; GitHub validates its own token formats, and the AWS string is their
  published example.
