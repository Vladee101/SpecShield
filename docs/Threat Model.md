# SpecShield — Threat Model

**Version 1.0 · for security review**

This document states what SpecShield defends, against whom, where the defence is
enforced, and where it stops. It is written to be argued with. Every claim is
either enforced by code that has a test, or is listed here as unenforced.

PRD §4 is the source for adversaries and asset classes; this document adds the
enforcement points and the reasoning, and records where the implementation
differs from the design documents.

---

## 1. The problem in one paragraph

Engineers want to use commercial LLMs on proprietary material. The material's
value is partly in its **names** — the company, the clients, the services, the
data model — and partly in its **semantics** — what the code does and how the
business works. SpecShield removes the first and deliberately preserves the
second, because a twin with no semantics is useless to a model. That trade is
the entire product, and it is the first thing a reviewer should decide whether
they accept.

---

## 2. Assets

| Asset | Where it lives | Consequence of disclosure |
|---|---|---|
| **A1** Proprietary identifiers | Source, specs, schemas, file and directory names | Attribution of material to an organization; competitive intelligence |
| **A2** The alias→name mapping | The vault (`.specshield/vault.bin`) | Reverses every twin ever produced from that project |
| **A3** Secrets | Source, config, fixtures | Direct compromise of a live system |
| **A4** The project key | Sealed inside the vault | Aliases become predictable; two twins become linkable |
| **A5** Business semantics | Everything | Disclosure of how the business works — **not defended**, see §6 |

A2 is the asset with the worst blast radius. One vault reverses every twin the
project has ever produced, including those already sitting in a model
provider's logs.

---

## 3. Adversaries

| # | Adversary | Capability | Status |
|---|---|---|---|
| **T1** | LLM provider, honest-but-curious | Retains prompts for training, abuse review, or subpoena; staff may read them | **Primary** |
| **T2** | Cloud file sync | Silently uploads the vault or project tree — OneDrive, Dropbox, Google Drive, iCloud | **Primary** |
| **T3** | Clipboard history and sync | Persists or uploads clipboard contents, e.g. Windows Cloud Clipboard | **Primary** |
| **T4** | Local malware, stolen device | Reads files at rest as the user | **Partial** — vault at rest only |
| **T5** | Insider with legitimate access | Reads the real project directly | Out of scope |
| **T6** | Targeted attacker | Endpoint compromise, memory scraping | Out of scope |

T5 and T6 are out of scope because SpecShield runs as the user, with the user's
files. It cannot defend against someone who already has what it is protecting.
Saying so plainly is more useful than a mitigation that would not work.

---

## 4. Trust boundaries

```
┌─ the user's machine ────────────────────────────────────────────────┐
│                                                                     │
│   real files ──▶ parse ──▶ alias ──▶ [ EXPORT GATE ] ──▶ twin ──┐   │
│       ▲                       │                                  │   │
│       │                       ▼                                  │   │
│   patch ◀── restore ◀── vault (A2, A4)                           │   │
│       ▲                                                          │   │
└───────┼──────────────────────────────────────────────────────────┼───┘
        │                                                          │
        │                    ══ trust boundary ══                  ▼
        │                                              clipboard / file
        └──────────────── AI response ◀────────────── commercial LLM (T1)
```

**Exactly one thing crosses the boundary outward: a twin that has passed the
export gate.** Everything else — originals, the vault, the audit log, checksums,
the index — stays on the machine. The application holds no network capability at
all, so there is no code path that could send anything, deliberately or by
accident.

Inbound, the AI response is **untrusted input**. It is a string that gets
lexically rewritten; it is never executed, never parsed as configuration, and
never allowed to name an identity by itself (§5.6).

---

## 5. Defences, and where each is enforced

### 5.1 Alias derivation — A1, A4

Aliases are allocated numbers — `ORG_001`, `PRODUCT_001` — handed out per type in
first-seen order and stored in the vault (PRD §13, SDD §6.1). They carry **no information
about the name they replace**: not a hash of it, not a length, not a category beyond the
type prefix the twin needs in order to read naturally.

That is a change from v1.1, which derived them by HMAC from a project key. The reason was
cross-machine agreement for shared vaults, which PRD §15 now puts outside the MVP; the cost
was a twin nobody could read. A reviewer should note the consequence: aliases are no longer
reproducible from a key, so two vaults over the same project will disagree about which
company is `ORG_001`.

Two properties matter to a reviewer:

- **Deterministic.** The same identity always yields the same alias, so twins are
  reproducible and two machines with the same project key agree without
  coordinating. That is why the project key is sealed rather than stored beside
  the database.
- **Not a sequence.** A counter would leak how many entities exist and the order
  they were found in. An HMAC leaks neither.

Identity is `(scope_path, entity_type, real_name)` — never the name alone. Three
unrelated `Status` enums in three modules are three identities with three
aliases. Collapsing them on name would be a correctness bug *and* an information
leak, since it would reveal that the three are related.

*Enforced in* `crates/core/src/alias.rs`, `crates/core/src/sanitize.rs`.

### 5.2 The export gate — A1

Before any twin is emitted, an Aho–Corasick automaton built from **every
identifying name the vault knows** — plus case and separator variants — scans the
twin, and **reports every hit**.

**It does not refuse.** Read that plainly: a twin containing a name the vault
knows is still produced, and it is the user's decision whether to send it. That
changed after the gate met a real repository, blocked 78 of 107 files on 124
distinct names — `Node`, `Screen`, `data` — and wrote nothing at all. A control
that stops the product working does not protect anybody, because it gets turned
off or the product gets abandoned. `--strict` restores the refusal for a CI job,
and `specshield verify` has always been the per-file form.

**A high-confidence secret still refuses, in both modes.** That asymmetry is the
whole design: a leaked name costs a competitor a guess, a leaked credential is
usable immediately by anyone who reads the conversation, and no re-keying takes
it back.

"Identifying" is narrower than it was, too. A name that is a single ordinary word
— `node`, `status`, `invoice` — is neither aliased nor scanned for (PRD §4.4),
unless the user names it with `specshield term`. A vault holding a type called
`Node` used to make every `node_modules` in a lockfile a leak.

`_` and `-` are word boundaries for this scan, so `old_vantor_id` is caught. The
gate runs on the Rust side in both the CLI and the desktop app.

This is the defence that matters most, because it does not depend on the
detector being right. If detection misses a name, the gate catches it in the
output and refuses. Detection recall is a quality metric; the gate is the
security control.

**One thing opens it: the allowlist** (PRD FR-10). A name the user has marked
never-alias is excluded from the scan. That hole has to exist — without it,
allowlisting a name the vault already knows would stop it being aliased, leave
it in the twin, and then block every export forever with no way forward. It is
as wide as what the user typed and no wider, and every caller reports how many
names were excluded, so an open gate is never silent.

*Enforced in* `crates/core/src/verify.rs`. *Tested in* `crates/cli/tests/error_matrix.rs`.

### 5.3 Secret redaction — A3

Secrets are handled by a different mechanism from names, deliberately: they are
**redacted one-way** and never restored. A high-confidence finding in a twin is a
hard block. Detection is a regex pack plus an entropy scorer.

A secret that round-tripped would be a secret this tool had helpfully carried
back into a file after sending it to a model. There is no vault entry for a
redaction and no way back from `<<REDACTED:api_key>>`.

*Enforced in* `crates/core/src/secrets.rs`.

### 5.4 Vault encryption — A2, A4, T4

Per-value **AES-256-GCM** on every sensitive column, not whole-file encryption.
The key is derived with **Argon2id** from the user's passphrase; nothing about
the passphrase is stored.

Each ciphertext is bound to its location by associated data (`table:column:row`),
so a value cannot be moved between rows or columns even by someone who can write
to the database file. Searchability over ciphertext comes from a **blind index** —
an HMAC of the plaintext under a separate, domain-separated subkey — which is
also what makes the SDD §5 uniqueness constraint enforceable without decrypting.

Key material is zeroized on drop.

> **Divergence from the design documents.** SDD §9.4 and §17.2 describe SQLCipher
> and an OS credential store. Neither is what was built. Whole-file encryption
> was replaced by per-value AEAD (decision D-9) after SQLCipher's bundled build
> proved unreliable across the three target platforms, and the credential store
> was never implemented: the passphrase is the only key path. See the Residual
> Risk statement, §3.1.

*Enforced in* `crates/vault/src/crypto.rs`.

### 5.5 Egress control — T1

- The Tauri capability set grants **no** network and **no** shell permission. The
  full permission list is `core:default`, `core:window:allow-start-dragging`,
  `clipboard-manager:allow-write-text`. A test asserts that list is exactly those
  three, so widening it requires editing the test and this document.
- Clipboard access is **write-only**. Reading the user's clipboard is not this
  application's business.
- **The file picker holds no permission either.** `tauri-plugin-dialog` appears
  in `Cargo.toml`, but the webview is granted none of its permissions: the dialog
  is opened by a Rust command, which then reads the chosen file and returns its
  contents. Granting the webview `fs:allow-read-*` would have been shorter and
  would have meant the frontend could read anything on the machine. As built, the
  only way a file's contents enter the application is a file a human selected in
  a native dialog, and no command accepts a caller-supplied path to read.
- CSP is locked to local assets and the IPC origin.
- The asset protocol is disabled.
- No updater artifacts are produced. An auto-updater is a network dependency in a
  product whose central claim is that it needs no network.
- CI runs the entire test suite inside a network namespace with no route out,
  after first asserting the namespace really has no DNS — a test that would pass
  with egress available proves nothing.

*Enforced in* `app/src-tauri/capabilities/default.json`, `tauri.conf.json`,
`.github/workflows/ci.yml`.

### 5.6 Untrusted AI output — inbound

The response from a model is rewritten lexically, not parsed. Three rules:

- An alias-shaped token the vault never issued is an **unresolved identity**. It
  is left standing verbatim and blocks patch application. Nothing is guessed,
  because a guessed name is a wrong identifier committed to a real repository.
- A token that matched only after normalization is applied but **flagged as
  fuzzy** in the diff, including when the result is byte-identical to the
  original and produces no visible change.
- Redaction markers are left in place.

*Enforced in* `crates/core/src/restore.rs`, `crates/core/src/diff.rs`.

### 5.7 Writing back — integrity

Patches are dry-run (`git apply --check`) before anything is touched, are never
applied to `main`, `master`, `develop`, or `trunk`, and are reversible. A file
whose BLAKE3 checksum has changed since it was indexed blocks patch application
outright: a patch built from a stale twin can apply *cleanly* and silently revert
the edits made in between, which is worse than failing.

*Enforced in* `crates/git/src/lib.rs`, `crates/index/src/lib.rs`.

### 5.8 Cloud sync — T2

On create and on open, the project root and vault path are checked against known
sync roots (OneDrive, Dropbox, Google Drive, iCloud). A vault inside one is being
uploaded to a third party, which contradicts the local-only guarantee. The user
is warned; it is never silently overridden.

*Enforced in* `crates/vault/src/lib.rs` (`cloud_sync_root`).

### 5.9 Clipboard — T3

SpecShield sends nothing anywhere. Windows does: with Clipboard History and
cross-device sync enabled, the OS uploads clipboard text to the user's Microsoft
account **after** the gate has finished — a route off the machine the gate cannot
see.

Payloads therefore carry three registered clipboard formats, each `DWORD 0`:

| Format | Governs |
|---|---|
| `ExcludeClipboardContentFromMonitorProcessing` | clipboard monitors and loggers |
| `CanIncludeInClipboardHistory` | the local Win+V history |
| `CanUploadToCloudClipboard` | **cross-device sync to the Microsoft account** |

The third is the one that governs the upload; setting only the first two
suppresses local history and leaves sync running. The clipboard is cleared after
a timeout, and only if it still holds SpecShield's own payload — clearing
unconditionally would destroy whatever the user copied since.

**These formats are advisory, not an enforcement boundary.** They are honoured by
Windows and by well-behaved clipboard managers. A clipboard manager that ignores
them will still capture the twin. The twin has passed the gate, so this is a
disclosure of aliased content, not of real names.

*Enforced in* `app/src-tauri/src/clipboard.rs`.

### 5.10 Audit — accountability

An append-only local log records that an operation happened: timestamp,
operation, file count, entity count, verification result, destination. It records
**no real name and no content**, and is exportable as CSV. It is never
transmitted, and it is distinct from telemetry, which this product does not have.

Because the log holds nothing sensitive, it survives the loss of the vault key
and is readable in recovery mode — which is precisely when a security team needs
it.

*Enforced in* `crates/vault/src/lib.rs`. *Tested*: `the_audit_log_never_carries_a_real_name`.

---

## 6. What is deliberately not defended

SpecShield replaces identifiers while preserving semantics. The following reach
the model, by design:

- **Business logic in prose.** `SERVICE_014 charges a 3% commission on ORG_007
  payouts for EU customers above EUR 10k` discloses the rule, the jurisdiction,
  the fee, and the shape of the integration. Every name in that sentence is
  aliased and the sentence is still the secret.
- **Algorithms and implementation approach.**
- **Architecture shape** — service count, relationships, table cardinality,
  endpoint structure, module topology.
- **Comments and documentation prose**, unless the user removes them.
- **Structural re-identification.** A distinctive domain model plus endpoint
  shapes is frequently enough to identify an organization with every name
  replaced.
- **Anything pasted into a model by hand**, outside the tool.

---

## 7. Attack paths considered

| # | Path | Outcome |
|---|---|---|
| P1 | Detector misses a name; twin is exported | **Reported, not blocked.** The gate scans the output independently of detection and names every hit; the user decides. `--strict` refuses. |
| P2 | A name appears only inside a compound (`old_vantor_id`) | **Reported.** `_` and `-` are word boundaries for the gate. |
| P3 | A name leaks through a file path rather than file contents | **Reported.** Twin paths go through the same gate as content. |
| P1b | A name that is a single ordinary word is shared | **Accepted.** `node`, `status`, `invoice` are neither aliased nor scanned for unless named — PRD §4.4. This is a deliberate reduction in coverage. |
| P4 | Attacker copies the vault file | **Mitigated.** Every sensitive column is AEAD-sealed under an Argon2id-derived key; the file alone yields aliases and counts, no names. |
| P5 | Attacker copies the vault and knows the passphrase | **Not defended.** This is equivalent to having the project. |
| P6 | Model returns a token that looks like an alias but is invented | **Blocked.** Unresolved identity; left standing; blocks patching until named by a human. |
| P7 | Model drifts a token (`SERVICE_H7K2QXImpl`) | **Applied and flagged.** The substitution is reported for review even when it changes nothing visible. |
| P8 | A stale twin's patch silently reverts a colleague's edits | **Blocked.** Checksum comparison before any patch. |
| P9 | Patch applied straight to `main`, skipping review | **Blocked.** Protected branch list, refused outright. |
| P10 | Vault sits in a OneDrive folder and is uploaded | **Warned, not blocked.** The user is told; relocation is offered. |
| P11 | Twin reaches Microsoft's cloud clipboard | **Mitigated advisorily.** Three clipboard formats; a non-conforming manager defeats them. |
| P12 | Secret round-trips back into a file after a model saw it | **Blocked.** Redaction is one-way with no vault entry. |
| P13 | Application exfiltrates data itself | **Structurally impossible.** No network capability is granted; CI proves the suite passes with no route out. |
| P14 | Two identities collide on one alias, making restore ambiguous | **Blocked.** Unique index on alias plus a deterministic disambiguator. |
| P15 | Corrupt vault inspected, and inspection damages it further | **Blocked.** Recovery mode opens `immutable=1` and exposes no write method; a test asserts the bytes are unchanged. |
| P16a | A name is allowlisted and then leaves in a twin | **Permitted, and reported.** FR-10 exists so the user can decide a detection is wrong. The count of excluded names is shown on every export. |
| P16 | Recovery mode used to read names without the passphrase | **Blocked.** Only unsealed columns are readable; a test asserts no real name is reachable. |
| P17 | Compromised or buggy frontend reads arbitrary files | **Blocked.** The webview has no filesystem permission, and `pick_file` takes no path — it opens a dialog. A test asserts the signature stays that way. |

---

## 8. What a reviewer should verify independently

Do not take this document's word for any of it. These are cheap to check:

1. `cat app/src-tauri/capabilities/default.json` — the whole permission surface,
   pinned by `the_capability_set_stays_minimal`.
2. `grep -rn "reqwest\|hyper\|ureq\|curl" crates/ app/src-tauri/src/` — no HTTP client is present.
3. `cargo test --workspace` — 319 tests, including the SDD §16 error matrix.
4. `cargo run -p specshield-cli -- report corpus --strict` — detection metrics
   against a committed, hand-labelled corpus.
5. The `offline` CI job — the suite passing inside a network namespace.
6. `specshield audit --csv` on any project — what is and is not recorded.

---

## 9. Version and scope

Describes the build at commit `db804a3` (M6 engine complete). Installers are
unsigned and the desktop UI has not been driven through a running Tauri app; see
the Residual Risk statement for the full list of gaps.
