# Design Review — SpecShield PRD v1.0 & SDD v1.0

Review pass over both documents. Findings are ordered by impact on whether the product
can actually deliver its security promise. Each finding names the affected section, the
problem, and a concrete proposed change.

---

## Summary judgement

The concept is coherent and the architecture is broadly the right shape: local-first,
AST-driven, deterministic aliasing, encrypted vault, patch-based writeback. Nothing in
the stack choice is wrong.

The gaps concentrate in four places:

1. **The threat model is never written down**, so the security claim ("confidential
   business terminology is never exposed") is stronger than what the design delivers.
2. **Identity is treated as globally unique by name**, which is false for real code and
   breaks both anonymization and restoration.
3. **"The twin must compile"** is assumed to fall out of Tree-sitter. It does not.
   Tree-sitter has no symbol resolution. This is the largest under-scoped item.
4. **There is no verification gate** before sanitized content leaves the machine. A
   security tool must prove its output is clean, not assume it.

Everything else below is secondary.

---

## A. Critical — security correctness

### A1. Missing threat model and residual-risk statement

*PRD §2, §9 Security; SDD §14*

Both documents assert data is safe without stating who the adversary is or what class of
leak remains. The product replaces **identifiers**. It deliberately preserves
**semantics** — that is the entire point of a "semantic twin". Therefore:

> `SERVICE_014 charges a 3% commission on ORG_007 payouts for EU customers above EUR 10k`

...still discloses the business rule, the jurisdiction, the fee, and the shape of the
integration. Structural re-identification is also live: a domain model plus endpoint
shapes is often enough to identify the company.

**Change:** add a *Threat Model* section to the PRD with:

- **Adversary:** honest-but-curious LLM provider retaining prompts for training or abuse
  review; secondary: local malware, cloud-backup exfiltration, insider.
- **Protected:** proprietary nouns — org, product, service, table, column, DTO, enum,
  event, endpoint, env-var, hostname names.
- **Explicitly not protected:** business logic in prose, algorithms, architecture shape,
  data-model topology, comments the user chose to keep, anything pasted by hand outside
  the tool.
- **Residual risk statement** a security team can sign off on.

Without this the tool fails its first security review, and the Security Team persona in
PRD §5 has zero requirements attached to it.

### A2. Secrets need redaction, not pseudonymization

*PRD §8 FR-3; SDD §4.3*

Neither document distinguishes the two operations the product actually needs:

| Operation | Direction | Applies to | Restore behaviour |
|---|---|---|---|
| Pseudonymization | two-way | identifiers (service, DTO, table…) | replaced back |
| Redaction | **one-way** | API keys, tokens, passwords, connection strings, private keys, JWTs, PII, emails | **never** restored |

Round-tripping a live API key back into AI-generated code is nonsensical and dangerous.
Worse, treating a secret as an alias means the secret is stored in the vault as
`real_name` and would be restored into any output containing that placeholder.

**Change:** add **FR-3b Secret Detection (Must)** — a gitleaks-style detector (regex rule
pack + Shannon-entropy heuristic) running *before* identity extraction. It replaces
matches with a non-restorable `<<REDACTED:TYPE>>` marker and **blocks export** on
high-confidence matches until acknowledged. Store only a salted hash of the match for
idempotency, never the plaintext.

### A3. No pre-export leak gate

*PRD §8 (missing FR); SDD §7*

Detection recall is 95% by the PRD's own target. Five percent of entities leaking is a
100% leak of those entities. Nothing in the design checks the twin before it is copied.

**Change:** add **FR-4b Export Verification Gate (Must)**. Before any copy/export:

1. Build an Aho–Corasick automaton over every `real_name` in the vault, plus generated
   case variants (camel, Pascal, snake, kebab, SCREAMING, spaced, pluralised).
2. Scan the twin. Any hit is a hard block, reporting file, line, and term.
3. Run the secret detector over the twin as a second pass.
4. Show a "verified clean" state that names what was checked **and what was not**.

This is roughly 200 lines of Rust and is the highest value-per-effort feature in the
product. It converts "we hope detection was complete" into "nothing in the vault appears
in the output".

### A4. Vault key management is undefined — and the current location is cloud-synced

*SDD §8, §14; PRD §9*

"Encryption key is generated locally and never transmitted" does not say where it is
stored. If the key file sits next to the database, SQLCipher protects against exactly one
thing: someone copying the `.db` alone.

That one thing is the realistic threat. Note this project currently lives at
`C:\Users\vlade\OneDrive\Desktop\SpecShield` — a **OneDrive-synced folder**. A vault
created in that tree is uploaded to Microsoft's cloud, directly contradicting PRD §9
"No cloud storage".

**Change:**

- Key held in the OS credential store (Windows DPAPI / Credential Manager, macOS
  Keychain, Linux Secret Service) via the `keyring` crate; never on disk in plaintext.
- Optional user passphrase → Argon2id (documented parameters) → key-encryption key
  wrapping the vault key. Required for the portable-vault case in A6.
- `zeroize` on all key material in memory.
- **Startup check:** detect whether the project or vault path sits inside a known sync
  root (OneDrive, Dropbox, Google Drive, iCloud) and warn prominently, with a one-click
  "move vault to a local-only path".
- Document the key-loss story: no recovery, vault unreadable, twins orphaned. Offer an
  explicit passphrase-protected key escrow export.

### A5. Clipboard is an unmodelled egress channel

*PRD §11 Workflow A*

"Sanitize & Copy" puts content on the system clipboard. On Windows, Cloud Clipboard syncs
clipboard history to the user's Microsoft account; third-party managers persist it to
disk. The twin is safe by construction, but the UI also displays and may copy originals.

**Change:** mark clipboard payloads with the `ExcludeClipboardContentFromMonitorProcessing`
/ `CanIncludeInClipboardHistory` formats on Windows, auto-clear after a configurable
timeout, and never place unsanitized text on the clipboard from any UI affordance.

### A6. Team use is blocked by sequence-allocated aliases

*PRD §12, §15; SDD §6*

The market is organizations (PRD §2), but aliases are allocated by "next sequence" against
a local vault. Two developers on the same repository produce **different aliases for the
same entity**: their twins diverge, prompts are not comparable, restore across machines
fails. "Multi-user collaboration" is out of MVP scope, but this choice makes the tool
close to unusable in the exact environment it targets, and it is expensive to change
later because it is baked into every stored alias.

**Change:** derive aliases deterministically *without a central allocator*:

```
alias = TYPE + "_" + base32( HMAC-SHA256( project_key, scope_path || ":" || type || ":" || real_name ) )[0..6]
```

Example: `SERVICE_H7K2QX`. Collisions are checked against the vault and resolved with a
`_2` suffix. Two machines sharing the same `project_key` generate identical twins with no
coordination.

Keep sequence-style aliases (`SERVICE_014`) as a selectable mode for solo users who prefer
readability. Decide this before M1 — it is a storage-format decision.

---

## B. Critical — correctness of the core algorithm

### B1. Identity is scoped, not global

*SDD §5, §6, §8*

The vault schema keys identities on `real_name` alone. In real code that is wrong:

- `customer_id` exists in a dozen tables.
- `Status` is an enum in three modules.
- `CreateDto` appears in every feature folder.
- A local variable `total` must never share an identity with a column `total`.

Collapsing them yields two failures at once: over-aliasing (renaming unrelated symbols
together, breaking the twin) and ambiguous restoration (one alias, several originals).

**Change:** the identity key is the triple `(scope_path, entity_type, real_name)`, where
`scope_path` is resolver-dependent — for SQL, `db.schema.table.column`; for TypeScript,
module path plus enclosing declaration; for Markdown, the project-wide dictionary scope.
Add `scope_path` to `identities` with a UNIQUE index on the triple, plus a
`scope_strategy` project setting (`global` | `module` | `strict`) trading twin readability
against precision.

### B2. Restore must tolerate invalid input; the SDD assumes valid ASTs

*SDD §7 vs §9*

§7 builds the twin via AST transformation. §9 restores via alias lookup. What actually
comes back from an LLM is frequently:

- a code **fragment**, not a compilable file
- a unified **diff**, not a file
- Markdown with fenced blocks and prose interleaved
- code with syntax errors
- aliases inside string literals, comments, import paths, and filenames

An AST-first restore fails on all of these.

**Change:** state the asymmetry explicitly.

- **Sanitize:** AST-first (needs scope resolution to be correct), text fallback for
  Markdown and plain text.
- **Restore:** token/lexer-level scan with a normalizing matcher; AST only as optional
  post-validation. Restore is a pure lexical operation over a closed alias vocabulary,
  which is exactly what makes it robust.

### B3. Alias normalization for LLM drift

*PRD §14 "AI renames placeholders"; SDD §9*

"Reserve placeholder namespace" does not survive contact with a model. Observed drift:
`SERVICE_014` → `Service014`, `service_014`, `SERVICE-014`, `Service_014`, `SERVICE_14`,
`SERVICE_014s`, `SERVICE_014Impl`, backtick-wrapped forms.

**Change:** define a formal **alias grammar** in the SDD and match against a canonical
form: uppercase, strip non-alphanumerics, strip leading zeros, strip a known plural `s`,
strip known affixes (`Impl`, `Service`, `Dto`) only when the remainder matches exactly.
Every non-exact match is restored **but flagged** in the diff as a fuzzy hit. Any
alias-shaped token matching nothing becomes an Unresolved Identity (SDD §10 — reuse it).

### B4. Prompt envelope — tell the model the rules

*Missing from both documents*

Restore reliability is mostly determined by whether the model was told the placeholders
are opaque. Nothing in either document generates that instruction.

**Change:** add **FR-6b Prompt Envelope Generator (Should)** — SpecShield emits, alongside
the twin, a short preamble:

> Tokens matching `^[A-Z][A-Z0-9]*_[A-Z0-9]{3,8}$` are opaque anonymized identifiers.
> Preserve them exactly — do not rename, expand, translate, or reformat them. If you
> introduce a new entity, name it `NEW_<n>` and list it at the end of your response.

Cheap, and it materially raises the success rate of every downstream feature.

### B5. Filename and path mapping has no home in the schema

*SDD §7 ("also transformed: filenames") vs §8*

The `files` table stores `id`, `path`, `checksum` — there is no twin path, so a twin
project cannot be written to disk or mapped back. Import paths inside TypeScript
(`from '../services/customer-subscription.service'`) are string literals encoding real
names and must be transformed as paths, not symbols.

**Change:** add `twin_path` to `files`, and treat path segments as first-class identities
of a `PathSegment` type so directory names alias consistently.

### B6. Occurrence tracking is required by FR-5 but absent from the schema

*PRD §8 FR-5 ("file references") vs SDD §8*

Add an `occurrences` table (`identity_uuid`, `file_id`, `byte_start`, `byte_end`,
`context`). Needed for the diff viewer, incremental rescan, provenance ("show me where
this came from"), and the leak gate's reporting.

---

## C. High — under-scoped engineering

### C1. Tree-sitter cannot do what §7 needs

*SDD §4.2, §7, §17*

Tree-sitter produces a concrete syntax tree with **no name resolution, no scope analysis,
no type information**. Correctly renaming a TypeScript class requires knowing which
declaration each reference binds to — across files, through re-exports, barrel files,
type-only imports, declaration merging, and shadowing. Tree-sitter gives none of that.

Consequently "The resulting project must compile" (SDD §7) is not achievable with the
stated stack.

**Change — pick one, explicitly:**

| Option | Correctness | Cost | Verdict |
|---|---|---|---|
| **A.** Tree-sitter + heuristic scoping (per-file scope stack, export/import graph) | good, not exact | low | **Recommended for MVP** |
| **B.** Node sidecar running the TypeScript compiler API for rename refactors | exact | high — Node dependency, IPC, breaks single-binary story | V1.1, large repos |
| **C.** `oxc` / `swc` Rust parsers with their own resolvers | good, improving | medium | evaluate at M3 |

And downgrade the guarantee to a verifiable property: **"the twin must parse, and
declaration/reference counts must match the original."** Add a post-sanitize verification
pass that re-parses the twin and compares node counts; on mismatch, reject the
transformation and leave that file unaliased — consistent with SDD §13's non-destructive
stance.

### C2. `serde_yaml` is unmaintained

*PRD §13; SDD §4.2, §17*

`serde_yaml` was archived by its author in 2024. It also does not round-trip comments or
formatting, which SDD §4.2 explicitly requires ("preserve formatting offsets").

**Change:** use a CST-preserving YAML library and treat YAML like any other syntax tree
rather than deserializing to a value model. Evaluate `saphyr` / `yaml-rust2`, or use
Tree-sitter's YAML grammar for uniformity. The same reasoning applies to JSON — do not
`serde_json::from_str` and re-serialize; you will lose key order and formatting.

### C3. libgit2 does not apply patches

*SDD §12, §17*

`git2`/libgit2 has no real equivalent of `git apply`; what exists is limited and thinly
bound in the Rust crate.

**Change:** generate a unified diff with the `similar` crate, then either (a) shell out to
`git apply --check` followed by `git apply`, or (b) write files and let the user stage
them. Always `--check` first, always onto a new branch, never onto the current `main`.
State the fallback when git is not installed.

### C4. Performance targets need units

*PRD §4; SDD §15*

"Sanitize 100-page PRD < 10s" and "index 1000 files < 30s" have no hardware baseline, no
file-size assumption, no cold/warm distinction. SQLCipher write throughput will dominate
indexing if occurrences are inserted row-by-row.

**Change:** specify the reference machine, state files as "1,000 files / ~150k LOC",
distinguish cold index from incremental rescan, and mandate batched transactions (one per
file, or per 1,000 occurrences) plus `rayon` for parse parallelism. Put a benchmark corpus
in CI so regressions surface.

### C5. Success metrics are not measurable as written

*PRD §4*

"Sensitive entities detected ≥95%" has no corpus, no ground truth, no definition of an
entity, and no false-positive budget — yet false positives are what make the twin
unreadable and degrade AI output.

**Change:** restate as recall **and** precision against a committed, labelled golden corpus
(3–5 synthetic projects: a PRD, an OpenAPI spec, a SQL schema, a TS service). Targets:
recall ≥ 0.95 on declared identifiers, precision ≥ 0.90. Restate "restoration accuracy
100%" as the falsifiable property: **`restore(sanitize(x)) == x` byte-for-byte for every
file in the corpus, with zero silent unresolved aliases**.

---

## D. Medium — product and UX gaps

### D1. Opaque aliases degrade AI output quality

*PRD §7; SDD §6*

`SERVICE_014` strips the semantic hints models rely on. Code generated against meaningless
names is measurably worse, and reviewers cannot read the twin diff.

**Change:** make alias style a project setting with three levels, dialling privacy against
utility:

| Mode | Example | Use |
|---|---|---|
| Opaque | `SERVICE_014` | maximum protection |
| Typed | `PaymentService_014` | keeps the category, hides the subject — **good default** |
| Pseudonymous | `AuroraService` | most readable, weakest |

Typed mode leaks a category name that is usually generic, and is a large usability win.
Make it explicit and per-project rather than hardcoded.

### D2. Local audit log — the Security Team persona has no features

*PRD §5, §9*

"No telemetry" (correct) is being conflated with "no logging" (wrong). A security team
signing off will ask what was sent out and when.

**Change:** add **FR-9 Local Audit Log (Should)** — append-only, local, never transmitted:
timestamp, project, operation, file set, entity counts, verification result, export
destination (clipboard / file / patch). Never log real names or content. Exportable as CSV
for compliance review.

### D3. No staleness model

*SDD §8 — `files.checksum` exists but is used by no workflow*

Once a twin is generated the real files keep changing. Restoring AI output produced from a
stale twin silently reverts or conflicts with intervening edits.

**Change:** compare BLAKE3 checksums at restore time; show a staleness banner and require
an explicit rescan before applying a patch derived from an out-of-date twin.

### D4. Undo, backup, and rotation are absent

Add vault backup/export (encrypted), alias re-keying (regenerate all aliases under a new
project key when a twin has been over-shared), and undo for the apply-patch step.

### D5. Comments and string literals are the biggest prose leak

*SDD §4.3 lists only declared entity types*

A comment reads `// Wire this into AcmeBank's legacy settlement queue before Q3`. The
identity extractor sees no declaration and leaves it verbatim.

**Change:** add a text-scan pass over comments, string literals, and Markdown prose that
applies the vault's real-name automaton (the same one as A3), plus an optional
strip-comments-entirely mode. Also detect hostnames, URLs, emails, bucket names, and
account IDs as entity types.

### D6. Restore of ambiguous fragments

When AI returns a bare snippet with no file context and an alias maps to two identities
under different scopes (B1), restoration is ambiguous. The SDD does not say what happens.

**Change:** aliases are globally unique per project by construction (the A6 HMAC includes
the scope), so ambiguity cannot arise — state this as an invariant and assert it with a
UNIQUE index. Document it in SDD §6.

### D7. Missing FRs worth adding

| ID | Requirement | Priority |
|---|---|---|
| FR-3b | Secret detection & one-way redaction | Must |
| FR-4b | Export verification gate | Must |
| FR-6b | Prompt envelope generator | Should |
| FR-9 | Local audit log | Should |
| FR-10 | Manual entity add/edit/exclude + never-alias allowlist | Must |
| FR-11 | Vault backup / restore / key rotation | Should |
| FR-12 | Project ignore rules (`.specshieldignore`, gitignore-aware) | Must |

FR-10 matters more than it looks: false positives are inevitable, and the user needs a
one-click "this is a framework name, never alias it", backed by a shipped stop-list
(React, Express, Postgres, AWS, …). Without it the twin becomes unreadable.

---

## E. Minor / editorial

- **PRD §13 and SDD §17 duplicate the stack table.** Keep it in the SDD and have the PRD
  reference it; otherwise they drift.
- **SDD §15 contains rendering artifacts** — `{"<"}2 s` should be `< 2 s`.
- **PRD §8 FR-2 lists TypeScript but not `.tsx`, `.js`, `.mjs`, `.d.ts`.** Be explicit.
- **OpenAPI is first-class in PRD §6 and SDD §4.3 but missing from FR-2's format list**,
  and SDD §16 defers the "OpenAPI semantic parser" to V1.2 — which contradicts the
  architect user story. Resolve one way or the other.
- **No versioning story for the vault schema.** Add `schema_version` and a migration
  runner from day one; retrofitting migrations onto an encrypted store is painful.
- **Alias examples are inconsistent:** PRD §3 uses `PSP_001` for Stripe; SDD §6's table
  has no PSP type. Unify the type enum in one place.
- **Tauri version unstated.** Pin Tauri v2 — v1's plugin and permission model differs
  enough to matter.
- **"No internet required" should be enforced and tested**, not merely claimed: a CI test
  running the app with egress blocked, and a Tauri capability set with no `http`/`shell`
  permissions.
