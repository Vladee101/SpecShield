# SpecShield — Security Review

**One page. Ten minutes. For the person deciding whether this may be used.**

---

## What it is

A local desktop application that rewrites **business identity** in code and
documents into stable opaque aliases — the company, its customers, products,
brands, vendors, domains, tenants, environments, and the people named in the
repository — so the result can be sent to a commercial LLM, and rewrites the
model's response back into real names.

**The architecture is deliberately left readable.** Service, DTO, table, column,
endpoint and file names travel verbatim, because an agent that cannot read the
system cannot help extend it (PRD §4.1). Any of them can be promoted to an
identity by name; none is by default.

## The one sentence that matters

> It reduces disclosure from **"who you are plus what you built"** to **"what
> you built"**. It does not make the submission non-confidential. Material whose
> *architecture* or *business logic* is the secret should not go to a commercial
> LLM, with or without this tool.

## What crosses the network

**One thing: a twin that has passed the export gate.** Nothing else — not the
originals, the mapping database, the audit log, or the file index.

The application cannot send it. Tauri capabilities grant no network and no shell
permission; the entire permission list is three entries, one of which is
*write-only* clipboard access, and a test pins it to exactly those three. There
is no HTTP client in the dependency tree. The user carries the twin out by
clipboard or file, deliberately.

The file picker is worth a sentence: the webview has no filesystem permission
either. The dialog is opened by a Rust command that reads the chosen file, so no
command accepts a path from the frontend to read.

## The control that actually protects you

Two controls with different weights, and a reviewer should know which is which.

**Secrets are the hard stop.** An API key is redacted one-way, never aliased and
never restored, and a high-confidence finding **refuses the export outright** —
in the CLI, in the app, and in `--strict` alike. There is no override.

**Names are advisory.** An Aho–Corasick automaton built from every identifying
name the vault knows, plus case and separator variants, scans the output and
**reports** every hit. The twin is produced anyway. `_` and `-` are word
boundaries, so `old_vantor_id` is caught and named.

That is a deliberate position, not an oversight. The gate used to hard-block; on
a real repository it stopped 78 of 107 files over 124 ordinary words and produced
nothing, and a control that stops the product working protects nobody. `--strict`
(export, sanitize) and `specshield verify` restore the refusal for CI.

Two further reductions a reviewer should weigh:

- A name that is a single ordinary word — an organization called `admin`, an
  environment called `staging` — is neither aliased nor scanned for unless the
  user names it (PRD §4.2).
- The gate checks the *output* independently of detection, so a detection miss is
  still caught and named — but naming it is now where the guarantee ends.

## Where the mapping lives

`.specshield/vault.bin`, per project. Every sensitive column is sealed with
AES-256-GCM under a random **data key**, which is itself wrapped by a key derived
from the passphrase with Argon2id. Each ciphertext is bound to its table, column,
and row, so values cannot be relocated. Searchability comes from a blind index
(HMAC), not from decryption. Key material is zeroized.

The indirection is what makes key management possible: changing the passphrase
re-wraps 32 bytes rather than re-encrypting the database, and escrow hands out
the data key rather than the passphrase — so a recovery holder never learns a
credential the user may have reused elsewhere.

**Nothing about the passphrase is stored.** A lost passphrase is recovered
through an escrow file or a backup, or not at all.

## Writing back

Restoring a model's response never guesses. An alias-shaped token the vault never
issued is left standing and blocks patch application until a human names it. A
token that matched only after normalization is applied but flagged for review.

Patches are dry-run first, never applied to `main`/`master`/`develop`/`trunk`, and
are reversible. A file whose checksum changed since indexing blocks patching
outright — a stale patch can apply cleanly and silently revert a colleague's work.

## What you are accepting

- Business logic, algorithms, and architecture shape reach the model in full.
- A distinctive domain model can re-identify the organization with every name
  replaced. Twins are pseudonymous, not anonymous.
- The provider retains what was submitted, under their terms.
- A proprietary name never entered in the dictionary and never appearing
  structurally is protected by nothing.
- Windows clipboard suppression is advisory; a non-conforming clipboard manager
  captures the twin.

## Gaps in this build, stated plainly

- **No OS credential store.** SDD §9.4 once described one; it does not exist. The
  CLI prompts with echo off, but for scripts the passphrase lives in an
  environment variable — and `--passphrase`, still supported for automation that
  has no alternative, is visible in the process list.
- **An escrow file is a bearer credential** until the data key is rotated.
  Handing one back does not revoke it; `specshield rotate-key` does, by
  re-encrypting the vault.
- **Installers are unsigned.**
- **The desktop UI has not been driven end to end**; verification has been through
  the CLI.
- **Alias durability through a real model API is unmeasured.**

## Accountability

An append-only local audit log records that operations happened — timestamp,
operation, file and entity counts, verification result, destination. It records
**no names and no content**, exports as CSV, and is never transmitted. There is no
telemetry of any kind.

Because it holds nothing sensitive, it is readable in recovery mode when the
vault itself will not open.

## Verify it yourself in five commands

```bash
cat app/src-tauri/capabilities/default.json          # the whole permission surface
grep -rn "reqwest\|hyper\|ureq" crates/ app/src-tauri/src/   # no HTTP client
cargo test --workspace                               # 439 tests, incl. the SDD §16 matrix
cargo run -p specshield-cli -- report corpus --strict # detection metrics, enforced
specshield audit --csv                               # exactly what is recorded
```

CI additionally runs the whole suite inside a network namespace with no route
out — after asserting the namespace really has no DNS, because a test that would
pass with egress available proves nothing.

## Recommendation to the reviewer

Approve for material where the sensitivity is in the names. Require that the
dictionary be populated before real use, that the vault sit outside cloud-sync
folders, and that an escrow export exist. Do not approve it as a control for
material where the logic itself is confidential.

---

*Full detail: [Threat Model](Threat%20Model.md) and
[Residual Risk](Residual%20Risk.md). Russian translation:
[`docs/Краткая справка для безопасника.md`](../Краткая%20справка%20для%20безопасника.md).
Build: commit `29cb980`.*
