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

§10 and SDD §17.5 have been rewritten to describe what exists, including the
platform gap.

