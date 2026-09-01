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
| `Product Requirements Document (PRD).md` | Threat model (§4), success metrics (§5), FRs (§9) |
| `Software Design Document (SDD).md` | Architecture, alias grammar (§6), vault schema (§9.1), gate (§8) |
| `Design Review (PRD + SDD).md` | Why the v1.1 specs say what they say — findings A1–E |
| `Implementation Plan.md` | Milestones M0–M6, decisions D-1…D-9, current status |

When code and docs disagree, that is a bug in one of them. Say which.

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
2. **Nothing leaves without passing the gate.** `crates/core/src/verify.rs`
   scans candidate output for every vault real-name plus case variants. In the
   app, a blocked sanitize returns `twin: None` — the frontend never receives
   unverified content.
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

---

## 3. Current state

M0 and M1 complete. M2 (desktop shell) started. D-9 resolved.

| Milestone | State |
|---|---|
| M0 foundations + spikes | done — see `spikes/M0-*.md` |
| M1 core engine, Markdown/text, vault | done — corpus gate enforced in CI |
| M2 Tauri shell | Workflow A works end to end; P1-3/4/5 remain |
| M3 SQL / YAML / OpenAPI | parsers done; P2-4 unification remains |
| M4 TypeScript + repo scale | done — parser, index, project export, path aliasing |
| M5 diff + git | done — engine, git, CLI, and the diff screen |
| M6 hardening + packaging | not started |

Corpus, current: all six projects gated, 98.6% recall / 95.8% precision;
secrets 6/6, 0 false positives. Every format now has a parser, so nothing is
excluded from the verdict — see `crates/cli/src/report.rs`.

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

**P1-3. No file picker.** `app/src/App.tsx` uses paste-in `<textarea>`s and a
typed filename. The document is now held once at the top level, so Review and
Sanitize share it and a user pastes only once — but it still has to be pasted.
Add `tauri-plugin-dialog` for open/save, and grant only the
specific dialog permissions in the capability file. Keep the capability set free
of network and shell.

**P1-4. No interactive passphrase entry in the CLI.**
`crates/cli/src/main.rs`, `passphrase()` requires `SPECSHIELD_PASSPHRASE` or
`--passphrase`. Arguments are visible in the process list, so `--passphrase` is
already the wrong answer for real use. Add a TTY prompt (`rpassword` or
equivalent) as the default when neither is set.

**P1-5. Thin test coverage in the Tauri layer.** `app/src-tauri/src/state.rs`
has six tests covering the copyable-twin state machine, and
`app/src-tauri/src/clipboard.rs` drives the real Win32 path. The *commands* in
`lib.rs` still have none — they need a harness that can stand up an `AppState`
and drive `sanitize_text` / `copy_verified_twin` without a window.

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

**P3-4. Re-run the Tree-sitter spike against a *real* service.** Still open, and
now more pointed: the M4 parser has been exercised on the six-file corpus service
and on a 1,000-file synthetic repo, but a synthetic repo only contains the shapes
its generator knew to emit. Decorators, generics with constraints, barrel
re-exports, and ambient `.d.ts` remain untested, and they are where heuristic
scoping is most likely to break.

**P3-5. Unused vault tables.** `redactions` and `edges` exist in the schema with
no writer. Occurrences have a writer in `crates/vault` but nothing in the CLI or
app calls it. (`files` gained one in M4: `specshield index`, `rescan`, and
`export` all write it.) Either wire them up as their milestones land, or drop them from
the schema — an empty table is a claim the product does not honour.

---

## 5. Things that will trip you up

- **`cargo fmt` runs on save in this repo's workflow.** Patching Rust files with
  Python string replacement fights it. Prefer targeted edits.
- **The corpus `labels.json` files are generated.** Edit `spec.json` and run
  `python corpus/tools/build_labels.py`. A CI job fails if they drift. Never
  hand-edit byte offsets.
- **`clippy.toml` allowlists proper nouns** (`SpecShield`, `OpenAPI`, …) for the
  `doc_markdown` lint. Add new ones there rather than backticking prose.
- **The repo lives in OneDrive.** `crates/vault::cloud_sync_root` detects this
  and the app warns. Moving the working copy out is still on the list.
- **Windows + SQLCipher does not build.** That is settled (D-9); do not
  reintroduce `bundled-sqlcipher-vendored-openssl`.
