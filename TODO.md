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
crates/parsers/   markdown + text today; sql/yaml/openapi = M3, typescript = M4
crates/vault/     SQLite + per-value AES-256-GCM + blind index
crates/index/     STUB — M4
crates/git/       STUB — M5
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

All five pass on `main` as of commit `063ca03`. If one fails after your change,
that is your change.

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
| M2 Tauri shell | **started** — builds, wired, but see P0-1 |
| M3 SQL / YAML / OpenAPI | not started |
| M4 TypeScript + repo scale | not started |
| M5 diff + git | not started |
| M6 hardening + packaging | not started |

Corpus, current: `prd-markdown` 100% recall / 96.2% precision (gated); secrets
6/6, 0 false positives. Projects whose parsers do not exist yet are reported but
not gated — see `crates/cli/src/report.rs`.

---

## 4. TODOs

### P0 — wrong right now

**P0-1. `copy_verified_twin` does not copy anything.**
`app/src-tauri/src/lib.rs`, the `copy_verified_twin` command.

It builds the payload, writes an `export` row to the audit log, and returns
`payload.len()`. It never touches the clipboard. The UI then reports
"N characters copied". So: the user believes they have the twin, the audit log
records an export that did not happen, and the one action the whole workflow
exists to perform is a no-op.

Fix:
- Add `tauri-plugin-clipboard-manager`, register it, and grant
  `clipboard-manager:allow-write-text` in `app/src-tauri/capabilities/default.json`.
- Write `payload` to the clipboard, and only log `export` after the write
  succeeds. A failed write must return an error, not a length.
- Keep the existing TODO comment about the Windows format flags (P1-1) — that is
  a separate, still-open problem.

Done when: clicking Copy in the running app puts the twin in the clipboard, a
failed write surfaces as an error in the UI, and the audit log has no `export`
row for a failed copy.

**P0-2. `sanitize` does not perform the SDD §7.2 verification pass it documents.**
`crates/core/src/sanitize.rs` — the module doc claims "the twin parses, and its
declaration and reference counts match the original… where that cannot be met,
the file is emitted unaliased and reported". No such check exists.

For Markdown and text this is harmless (there is nothing to re-parse), which is
why it has not bitten yet. It becomes load-bearing the moment the TypeScript
parser lands in M4, and a doc comment that overstates what the code does is how
that gets missed.

Fix now (cheap, and correct for every future parser):
- Add a `verify_twin` step to `sanitize()` that re-parses the twin with the same
  parser and compares node counts against the original.
- On mismatch: return the file unaliased plus a diagnostic, rather than the
  transformed twin.
- Wire it through `ArtifactParser` so each parser supplies its own count.
- Until a parser implements counting, the check is a no-op that *says so*.

Done when: `sanitize` cannot return a twin that fails its own re-parse, and the
`spikes/ts-rename` verification approach has a home in production code.

**P0-3. `ProjectKey` is not zeroized.**
`crates/core/src/alias.rs:62` — `TODO(M1)`, carried past M1.

`ProjectKey` holds 32 bytes of key material with no `Drop`. `crates/vault`
already zeroizes its own keys (`crates/vault/src/crypto.rs`), so this is the odd
one out.

Fix: `impl Drop for ProjectKey` using `zeroize`, or derive `ZeroizeOnDrop`. Add
`zeroize` to `specshield-core`'s dependencies.

Done when: no key material outlives its owner, and the TODO is gone.

---

### P1 — finish M2

**P1-1. Windows clipboard hardening.** `app/src-tauri/src/lib.rs`.
Cloud Clipboard syncs clipboard history to the user's Microsoft account, so a
copied twin can leave the machine by a route the gate never sees. PRD §10 and
SDD §17.5 claim this is handled; it is not.

Needs a small platform shim: set the `ExcludeClipboardContentFromMonitorProcessing`
and `CanIncludeInClipboardHistory` clipboard formats on Windows (Tauri's plugin
does not expose formats), plus clear-after-timeout. Until it exists, **the
clipboard claim in the PRD is unmet** — either implement it or downgrade the
claim.

**P1-2. The app has never been launched.** Everything typechecks and builds;
no one has run it. The IPC wiring, error paths, and every screen transition are
unexercised.

```bash
cd app && npm run tauri dev
```

Walk Workflow A end to end against `corpus/prd-markdown/input/PRD.md`, adding
`Vantor`, `Meridian Freight`, `Paylane` as ORG terms. Expect to find real bugs;
P0-1 was found by reading, not running.

**P1-3. No file picker.** `app/src/App.tsx` uses paste-in `<textarea>`s and a
typed filename. Add `tauri-plugin-dialog` for open/save, and grant only the
specific dialog permissions in the capability file. Keep the capability set free
of network and shell.

**P1-4. No interactive passphrase entry in the CLI.**
`crates/cli/src/main.rs`, `passphrase()` requires `SPECSHIELD_PASSPHRASE` or
`--passphrase`. Arguments are visible in the process list, so `--passphrase` is
already the wrong answer for real use. Add a TTY prompt (`rpassword` or
equivalent) as the default when neither is set.

**P1-5. No tests for the Tauri layer.** `app/src-tauri` has zero tests. The
commands are thin, but the state machine in `app/src-tauri/src/state.rs` is not
— particularly `set_verified_twin` clearing on a blocked sanitize. Test that
directly: a blocked sanitize after a successful one must leave nothing copyable.

---

### P2 — M3, next milestone

**P2-1. SQL parser** (`crates/parsers/src/sql.rs`, new). Use `sqlparser`.
Tables, columns, constraints, indexes. Scope columns as
`db.schema.table.column` — `corpus/adversarial` has ten `customer_id` columns
across ten tables specifically to catch a flat implementation.

**P2-2. YAML and JSON parsers**, CST-preserving. **Not `serde_yaml`** (archived
2024) and **not** a `serde_json` round-trip: deserializing to a value model and
re-serializing destroys comments and key order, which SDD §4.2 requires
preserving. See `crates/parsers/src/lib.rs` for the reasoning.

**P2-3. OpenAPI semantic layer** over the YAML/JSON CST: paths, operationIds,
schema names, tags.

**P2-4. Cross-artifact unification.** The SQL table `customer_subscription`, the
OpenAPI schema `CustomerSubscription`, and the TS interface must resolve to
**one** identity with **one** alias. This is the feature that makes the identity
graph worth having. `crates/cli/tests/corpus.rs` already asserts the corpus
contains the case.

**P2-5. Widen the corpus gate.** Each corpus project declares `requires` in its
`spec.json`. As parsers land, those projects become gated automatically —
nothing to change in `report.rs`, but re-run `--strict` and expect the aggregate
to move.

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

**P3-4. Re-run the Tree-sitter spike against a real service before M4.**
`spikes/M0-tree-sitter-rename.md` ran on 12 corpus files. Decorators, generics
with constraints, barrel re-exports, and ambient `.d.ts` are all untested, and
they are where heuristic scoping is most likely to break.

**P3-5. Unused vault tables.** `redactions` and `edges` exist in the schema with
no writer. Occurrences have a writer in `crates/vault` but nothing in the CLI or
app calls it. Either wire them up as their milestones land, or drop them from
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
