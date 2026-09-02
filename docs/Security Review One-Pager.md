# SpecShield — Security Review

**One page. Ten minutes. For the person deciding whether this may be used.**

---

## What it is

A local desktop application that rewrites proprietary identifiers in code and
documents into stable opaque aliases, so the result can be sent to a commercial
LLM, and rewrites the model's response back into real names.

## The one sentence that matters

> It reduces disclosure from **"names plus semantics"** to **"semantics only"**.
> It does not make the submission non-confidential. Material whose *business
> logic* is the secret should not go to a commercial LLM, with or without this
> tool.

## What crosses the network

**One thing: a twin that has passed the export gate.** Nothing else — not the
originals, the mapping database, the audit log, or the file index.

The application cannot send it. Tauri capabilities grant no network and no shell
permission; the entire permission list is three entries, one of which is
*write-only* clipboard access. There is no HTTP client in the dependency tree.
The user carries the twin out by clipboard or file, deliberately.

## The control that actually protects you

Not the detector — **the gate**. Before any twin is emitted, an Aho–Corasick
automaton built from every real name the vault knows, plus case and separator
variants, scans the output. One hit blocks the export. No partial copy, no
override. `_` and `-` are word boundaries, so `old_vantor_id` is caught.

This is why a detection miss is a quality problem rather than a breach: the gate
checks the *output*, independently of whether detection was right.

Secrets are separate and one-way. An API key is redacted, never aliased, and
never restored — a high-confidence finding blocks the export.

## Where the mapping lives

`.specshield/vault.bin`, per project. Every sensitive column is sealed with
AES-256-GCM under a key derived from the user's passphrase with Argon2id. Each
ciphertext is bound to its table, column, and row, so values cannot be relocated.
Searchability comes from a blind index (HMAC), not from decryption. Key material
is zeroized.

**Nothing about the passphrase is stored.** A lost passphrase is an unrecoverable
vault; that is the design, and it is why backup and escrow exist.

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

- **No OS credential store.** SDD §9.4 describes one; it does not exist. The
  passphrase comes from an environment variable or a flag — and `--passphrase` is
  visible in the process list.
- **Escrow holds the passphrase itself**, not a revocable key, because keys derive
  directly from the passphrase.
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
cargo test --workspace                               # 319 tests, incl. the SDD §16 matrix
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

*Full detail: `docs/Threat Model.md` and `docs/Residual Risk.md`. Build:
commit `db804a3`.*
