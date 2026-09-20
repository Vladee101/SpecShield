# SpecShield — Residual Risk Statement

**Version 1.0 · read this before approving use**

This document lists what remains exposed after SpecShield has done everything it
does correctly, plus the places where the current build does less than the design
documents claim. It is deliberately the least flattering document in the
repository. A residual-risk statement that reads well has failed at its job.

---

## 1. The statement

> SpecShield reduces disclosure to a commercial LLM from **"who you are plus
> what you built"** to **"what you built"**. It does not make the submission
> non-confidential.
>
> Teams handling material where the architecture or the business logic *itself*
> is the secret should not use commercial LLMs for that material, with or
> without SpecShield.

The wording changed with PRD v2.0 and the change is not cosmetic. The product
used to alias service, DTO, table and column names as well; it no longer does,
because an agent that cannot read the architecture cannot help extend it (PRD
§4.1). **The architecture now leaves the machine intact, by design.** That is a
larger disclosure than v1.1 described. §2.1 and §2.2 state what it means.

Everything below is detail on that sentence.

---

## 2. Residual risk by design

These are not defects. They are the consequences of the trade the product makes,
and no configuration removes them.

### 2.1 Semantics reach the model in full

The twin is useful precisely because it still says what the code does. A model
reading it learns the business rules, the algorithms, the data-model topology,
the number of services and how they relate, the endpoint structure, and every
comment the user chose to keep.

`BillingService charges a 3% commission on ORG_007 payouts for EU customers
above EUR 10k` has every *identity* aliased and gives away the entire
arrangement — including, now, the name of the service that does it.

**Who this matters to:** anyone whose competitive advantage is in *what* the
system does rather than *whose* it is. For them the correct control is not to
send the material at all.

### 2.2 Structural re-identification

A distinctive domain model plus endpoint shapes is often enough to identify an
organization with every name replaced. Aliasing raises the effort; it does not
make the twin anonymous. Treat a twin as pseudonymous, never as anonymous.

**This got easier in v2.0, not harder.** Service, DTO, table and column names now
travel verbatim, and a schema is a fingerprint. A reviewer weighing this should
read it as: the twin hides the org chart and the customer list, and hands over
the system design.

### 2.3 The provider retains the twin

Once a twin is submitted it is in the provider's hands under the provider's
terms — retention, training use, abuse review, and legal process. SpecShield
changes what is in the submission. It has no influence over what happens to it
afterwards.

A **re-key** (`specshield rekey --confirm`) changes every alias in a project. It
does nothing to submissions already made; those twins remain exactly as
submitted. What it does is break the link between old twins and future ones,
which is the right response to over-sharing and nothing more than that.

### 2.4 Prose detection is heuristic

`Vantor` is not recognisable as a company name by any rule. It is found because
someone put it in the dictionary. Names nobody has named are found only if a
heuristic happens to fire.

The **export gate** is the safety net here: it scans the twin for every name the
vault knows and reports every hit, independent of whether detection was right.
It *reports* rather than refuses — that changed in v2.0, and `--strict` restores
refusal for CI. But the gate can only look for names the vault has already
learned. **A proprietary name that has never been entered in the dictionary and
never appeared structurally is not protected by anything.**

Practical consequence: the dictionary is not optional configuration. It is the
control.

### 2.5 Clipboard formats are advisory

The three Windows clipboard formats that suppress history and cloud sync are
honoured by Windows and well-behaved clipboard managers. A manager that ignores
them captures the twin anyway. The captured content has passed the gate, so this
is disclosure of aliased content — but on a machine with an aggressive clipboard
tool, the twin should be treated as having been logged.

### 2.6 The allowlist opens the gate

Marking a term never-alias (PRD FR-10) removes it from the export gate as well
as from detection. It has to: otherwise the name stops being aliased, survives
into the twin, and is reported on every export from then on.

So an allowlisted name **can leave in a twin**. That is the user's decision and
the only way the gate opens, but it is a decision, and one worth reviewing
periodically — `specshield audit` records that terms were added, and every
export reports how many names the gate was told to ignore.

### 2.7 Anything pasted by hand

SpecShield protects what goes through SpecShield.

---

## 3. Where the build does less than the documents say

These are gaps, not design decisions. Each is listed with what a reviewer should
assume instead.

### 3.1 There is no OS credential store integration

SDD §9.4 and §17.2 once described a vault key held in Windows Credential
Manager, macOS Keychain, or Linux Secret Service. **That is not implemented.**
The passphrase is the only way in: it derives a key-encryption key with Argon2id,
which wraps the vault's data key.

Consequences:

- The command line prompts with echo off when nothing else is supplied, and
  `init` asks twice. But **`--passphrase` is still visible in the process list**
  to other users on the machine — it warns each time, and it is supported
  because some automation has no alternative.
- In scripted use the passphrase is in an environment variable, with whatever
  exposure that carries in the surrounding system (CI logs, process inspection,
  crash dumps).
- Nothing about the passphrase is stored, so a forgotten passphrase means
  recovering through an escrow file or a backup. That is what they are for.

Arguably better than the design it replaced: there is no key at rest for malware
to steal. It is nonetheless *not what those sections once described*, which is
why they now describe what exists.

### 3.2 Escrow can be revoked, but only by re-encrypting

Schema v3 wraps a random data key with a passphrase-derived key, so:

- **Changing the passphrase** re-wraps 32 bytes. Nothing is re-encrypted.
- **Escrow holds the data key**, not the passphrase. Whoever holds an escrow
  file can recover access; they never learn the passphrase, which matters
  because people reuse them.
- **Revoking an issued escrow** means rotating the data key, which re-encrypts
  every stored value. `specshield rotate-key --confirm`.

The residual point: an escrow file is a *bearer* credential until you rotate.
Handing one back does not revoke it — whoever held it may have copied the key.
Rotation is the only revocation, it takes time proportional to the vault, and it
invalidates every backup taken before it as an escrow source.

### 3.3 The desktop UI has not been driven end to end

The diff and apply screen has been rendered against a stubbed IPC layer and its
guards are tested in Rust, but the application has never been driven through a
running Tauri window. The engine paths behind every screen are exercised through
the CLI, which is where all end-to-end verification in this repository has been
done.

Assume the CLI is verified and the desktop shell is not.

### 3.4 Installers are unsigned

No code-signing certificate has been applied. On Windows this means SmartScreen
warnings; on macOS, Gatekeeper refusal without an explicit override. Signing
requires credentials the project does not hold.

### 3.5 Relationships are specified and not built

`occurrences` and `redactions` are written now — the first drives
`specshield where`, the second the one-way secret index. `edges` was dropped in
schema v4 rather than kept empty: the SDD described a graph with `uses`, `writes`
and `exposes` relations and no parser ever built one. A reviewer reading §5 of
the SDD should not infer a relationship graph that does not exist.

### 3.6 Alias durability through a real model is unmeasured

Whether a commercial model preserves alias tokens across a long conversation —
and how much aliasing degrades its output quality — has **not been measured
against a real model API**. The fuzzy matcher exists because drift is expected,
and it handles the drift patterns anticipated in design. The rate at which real
models drift, and the shapes they drift into, are unknown.

This matters to a user deciding how much to trust a long session, and it is the
most significant unmeasured thing in the product.

### 3.7 Detection quality is measured on a synthetic corpus

Recall 100% and precision 98.0% are measured against a hand-labelled corpus of
seven synthetic projects committed to this repository. They are honest numbers
against that corpus and they are enforced per commit in CI. They are not a
prediction of performance on a real codebase, and the corpus was written by the
same author as the detector.

**Read the rules-only column instead.** Recall with the dictionary seeded is
100%, which mostly measures that seeding a dictionary works. Against an empty
vault — the vendor table, the hostname rule and the person markers, which is all
a user has before they type anything — it is **49.0%**. That is the number that
describes a first run.

---

## 4. Out of scope, restated

| Threat | Why not defended |
|---|---|
| Insider with legitimate repository access | They can read the real project. Nothing here changes that. |
| Endpoint compromise, memory scraping | Originals and twins are in process memory in the clear. A tool running as the user cannot defend against code running as the user. |
| Malicious model provider actively attacking the user | The response is treated as untrusted input and never executed, but a provider determined to poison a patch has the user's review as the only barrier. Review the diff. |
| Traffic analysis of when and how much is submitted | Not addressed. |

---

## 5. Conditions for safe use

SpecShield is appropriate when **all** of the following hold:

1. The sensitivity is in the *names*, not in the business logic.
2. The dictionary is populated with the organization's proprietary terms before
   real work begins — the tool cannot protect a name it has never been told.
3. The vault is not inside a cloud-sync folder. The tool warns; heed the warning.
4. A backup and an escrow export exist, stored separately.
5. Twins are treated as pseudonymous and logged by the provider, not as anonymous
   or ephemeral.
6. Patches are reviewed in a pull request, which the protected-branch rule
   enforces but which the reviewer must actually do.

It is **not** appropriate for material under a regulatory regime that prohibits
third-party processing, for material where the algorithm is the asset, or as a
substitute for an agreement with the model provider about retention.

---

## 6. Version

Describes the build at commit `29cb980`: 439 tests, clippy clean, corpus gate at
100% recall / 98.0% precision (49.0% rules-only), offline and performance gates
enforced in CI.

Russian translation: [`docs/Остаточный риск.md`](../Остаточный%20риск.md).
