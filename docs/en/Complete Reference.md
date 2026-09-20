# SpecShield — Complete Reference

**Every feature, every use case, and how to use them.**

This is the one document that covers the whole product. The two user guides
([Desktop](Desktop%20User%20Guide.md), [CLI](User%20Guide.md)) are shorter paths
through the same material for people who only need one surface; the
[Threat Model](Threat%20Model.md), [Residual Risk](Residual%20Risk.md) and
[Security One-Pager](Security%20Review%20One-Pager.md) are for reviewers. When
this document and the code disagree, that is a bug in one of them — say which.

---

## Contents

**Part I — What it is**
1. [The one-paragraph version](#1-the-one-paragraph-version)
2. [What is hidden and what is kept](#2-what-is-hidden-and-what-is-kept)
3. [The two operations](#3-the-two-operations)
4. [What it does not protect](#4-what-it-does-not-protect)

**Part II — Every feature**
5. [Projects and the vault](#5-projects-and-the-vault)
6. [The index](#6-the-index)
7. [Detection](#7-detection)
8. [Secrets](#8-secrets)
9. [The dictionary: `term` and `allow`](#9-the-dictionary-term-and-allow)
10. [Sanitizing](#10-sanitizing)
11. [Structural verification](#11-structural-verification)
12. [The export gate](#12-the-export-gate)
13. [Whole-project export](#13-whole-project-export)
14. [The prompt envelope](#14-the-prompt-envelope)
15. [Restoring](#15-restoring)
16. [Unresolved identities](#16-unresolved-identities)
17. [Diff and patch](#17-diff-and-patch)
18. [Unification](#18-unification)
19. [Provenance: `where` and `secrets`](#19-provenance-where-and-secrets)
20. [The audit log](#20-the-audit-log)
21. [Vault operations](#21-vault-operations)
22. [Recovery](#22-recovery)
23. [The corpus report](#23-the-corpus-report)

**Part III — Every use case**
24. [Use case index](#24-use-case-index)

**Part IV — User guide**
25. [Install and first run](#25-install-and-first-run)
26. [Walkthrough A — a document to ChatGPT](#26-walkthrough-a--a-document-to-chatgpt)
27. [Walkthrough B — a repository to an agent](#27-walkthrough-b--a-repository-to-an-agent)
28. [Walkthrough C — SpecShield in CI](#28-walkthrough-c--specshield-in-ci)
29. [The desktop application](#29-the-desktop-application)
30. [Command reference](#30-command-reference)
31. [Files, formats and settings](#31-files-formats-and-settings)
32. [Troubleshooting](#32-troubleshooting)
33. [Limits, stated plainly](#33-limits-stated-plainly)

---

# Part I — What it is

## 1. The one-paragraph version

SpecShield is a local-first desktop application and CLI that lets you use
commercial AI agents — ChatGPT, Codex, Claude Code, Gemini — on proprietary code
and documents. It rewrites **business identity** into stable aliases, leaves the
**architecture** readable, and rewrites the model's response back into your real
names. Nothing reaches a network: the application has no HTTP client and no
network permission, and you carry the twin out by clipboard or file, deliberately.

```text
your files  ──▶  detect  ──▶  alias  ──▶  [ gate ]  ──▶  twin  ──▶  you copy it
                                                                        │
your files  ◀──  patch  ◀──  restore  ◀────────────────────────  model's reply
```

## 2. What is hidden and what is kept

The product turns on one distinction.

| | Examples | In the twin |
|---|---|---|
| **Identity** — who you are, who you work with, where you run | `Vantor`, `Gold Business Subscription`, `Stripe`, `Jane Okafor`, `api.vantor-freight.com`, `meridian-uat` | **Replaced** |
| **Structure** — what you built | `BillingService`, `CustomerSubscription`, `customer_subscription`, `plan_tier`, `POST /subscriptions`, `charge-invoice.ts` | **Kept** |

Worked example:

```text
Acme Bank offers Gold Business Subscription.              ORG_001 offers PRODUCT_001.

BillingService stores the subscription in         ──▶    BillingService stores the subscription in
customer_subscription and charges Stripe.                customer_subscription and charges PAYMENT_PROVIDER_001.
```

Keeping structure is the product, not a concession. An agent that cannot read the
architecture cannot help extend it. A twin in which `CustomerSubscription` is
`DTO_004` tells the model nothing to build on.

**Structure is not permanently exempt.** `specshield term settlement_ledger
--entity-type table` promotes any name to an identity, and it is aliased from
then on. What changed in v2.0 is the default, not the capability.

### The nine identity categories

| Type | Alias | Found how |
|---|---|---|
| Organization | `ORG_001` | you name it |
| Product | `PRODUCT_001` | you name it |
| Brand | `BRAND_001` | you name it |
| Partner | `PARTNER_001` | **built-in vendor table**, or you name it |
| Payment Provider | `PAYMENT_PROVIDER_001` | **built-in vendor table**, or you name it |
| Person | `PERSON_001` | **markers** (`@author`, `Contact:`, `Reviewed-by:`), or you name it |
| Tenant | `TENANT_001` | you name it |
| Environment | `ENV_001` | you name it |
| Domain | `DOMAIN_001` | **hostname shape**, or you name it |

The twelve structural types — `SERVICE`, `API`, `ENDPOINT`, `DB_TABLE`, `COLUMN`,
`DTO`, `IFACE`, `ENUM`, `EVENT`, `INDEX`, `ENV_VAR`, `PATH` — exist and are used
only for names you have promoted. Note `ENV` is an *environment* and an
environment **variable** is `ENV_VAR`.

## 3. The two operations

Never confuse these:

| Operation | Direction | Applies to | On restore |
|---|---|---|---|
| **Pseudonymization** | two-way | identity names, and anything you promote | replaced back with the real name |
| **Redaction** | **one-way** | secrets — keys, tokens, passwords, connection strings, private keys, JWTs | **never** restored; `<<REDACTED:type>>` stays |

Restoring a live API key into code a model wrote would be both nonsensical and
dangerous. Secrets never enter the vault as plaintext and have no alias.

## 4. What it does not protect

SpecShield replaces names while **deliberately preserving semantics**. These
still reach the model:

- **Architecture and data-model topology.** Service count, relationships, table
  cardinality, endpoint structure. In v2.0 this is the deliverable, not a leak.
- **Business logic in prose.** *"BillingService charges a 3% commission on
  ORG_007 payouts for EU customers above EUR 10k"* gives away the rule, the
  jurisdiction, the fee, and the shape of the integration.
- **Algorithms and implementation approach.**
- **Comments and documentation** you choose to keep.
- **Anything you paste by hand**, outside the tool.
- **Structural re-identification.** A distinctive domain model plus endpoint
  shapes often identifies the organization with every name replaced — and this
  got *easier* in v2.0, not harder.

> SpecShield reduces disclosure from **"who you are plus what you built"** to
> **"what you built"**. It does not make the submission non-confidential. Material
> whose *architecture* or *business logic* is the secret should not go to a
> commercial LLM, with or without this tool.

---

# Part II — Every feature

## 5. Projects and the vault

A project is a directory with a `.specshield/vault.bin` in it. That one file
holds the identity graph, your dictionary, the file index, the audit log, and the
settings. It is a SQLite database with every sensitive value encrypted
individually under AES-256-GCM, keyed by Argon2id from your passphrase, with the
identity key bound in as additional authenticated data so a value cannot be moved
from one row to another.

```bash
specshield init /path/to/project
```

**Aliases are plaintext in the vault, deliberately** — they are what gets sent to
the model. Real names, dictionary terms and allowlist entries are not. A test
asserts no real name appears in the file.

At creation, SpecShield warns if the project or vault sits inside a OneDrive,
Dropbox, Google Drive or iCloud tree, and offers to relocate the vault. A vault
in a sync root is a vault someone else has a copy of.

**Passphrase.** Pass `SPECSHIELD_PASSPHRASE` in the environment, or let the CLI
prompt. `--passphrase` exists but arguments are visible in the process list;
prefer the environment variable. Precedence: explicit flag → environment → prompt.

## 6. The index

```bash
specshield index      # walk and hash every file
specshield rescan     # what changed since last time
```

The index records every file's path, size, mtime and BLAKE3 checksum. It respects
`.gitignore`, `.ignore`, the global gitignore, and a project-level
`.specshieldignore` (same syntax). `.git` is skipped. Binary files are detected
and excluded from parsing.

Two jobs:

- **Learn the project before producing anything from it.** Without a first pass,
  a name is only found in files that come *after* the one that declared it.
- **Staleness.** A twin made from a file you have since edited would revert that
  edit when its patch is applied. `rescan` catches it; `apply` refuses on it.

## 7. Detection

Detection runs in six passes over each file, and a parser's structural reading
runs first where one exists.

1. **Alias-shaped tokens are claimed** before anything else, so sanitizing twice
   never re-aliases an alias.
2. **Dictionary** — every term you have named, plus every identity already in the
   vault. Highest confidence.
3. **Vendor table** — roughly fifty commercial services by name (see below).
4. **People** — a name after a marker on the same line.
5. **Shape rules** — `SCREAMING_SNAKE` env vars, hostname-shaped tokens,
   `PascalCompound` names.
6. **Suggestions** — proper-noun-shaped phrases, surfaced at low confidence and
   never applied.
7. **Prose variants** — a heading reading `## Plan tiers` is `PlanTier` written
   out, and leaks it just as surely.

**Sub-token aliasing.** An identity is replaced inside the compound that carries
it: `VantorBillingService` → `ORG_001BillingService`, `vantor_invoice` →
`ORG_001_invoice`, and the path `src/vantor-billing/` → `src/ORG_001-billing/`.
The architecture around the name survives.

### The vendor table

Partner and Payment Provider are the two categories findable without being told,
because unlike `Vantor` these names are the same in every company that uses them.
The table is fixed, reviewable in a diff, and identical on every machine —
payment processors, messaging, identity, observability, business systems.

The line against the stop-list is: **do you have an account with them?**

- `React`, `Postgres`, `Kubernetes`, `AWS` — tooling. Never aliased.
- `Stripe`, `Twilio`, `Auth0`, `Datadog` — a commercial relationship. Aliased.

Vendors whose names are ordinary English words in other contexts — Square, Wise,
Block, Segment, Amplitude, Paddle, Clerk, Plaid — are **deliberately absent** and
must be named with `specshield term`. `Segment` was in the table for one commit
and matched the phrase "the final segment".

### Person markers

`@author`, `Contact:`, `Owner:`, `Maintainer:`, `Reviewer:`, `Reviewed-by:`,
`Written-by:`, `Reported-by:`, `Signed-off-by:`, `Co-authored-by:`, and their
plurals. High precision, deliberately low recall: a rule that took every
capitalised pair of words would alias half a specification. A person named only
in running prose is found the way every unguessable name is — you type it once.

### What is *not* an identity

Being an identity type is necessary, not sufficient. The name must also identify.

- A **compound** is identifying: `meridian-freight`, `Gold Business Subscription`.
- A **single word nobody else uses** is identifying: `Vantor`, `Haulwise`.
- A **single ordinary word is not**: an org called `admin`, an environment called
  `staging` or `production`, a host called `localhost`.
- **What you confirm overrides all of it.**

The word list is `crates/core/src/words.rs`, is finite, and is meant to be
extended when it is wrong.

### Scoping

Identity and structure are scoped differently, and the difference matters.

- **Structure is per file.** `customer_id` in two tables is two columns.
  Collapsing them would tell the model the tables are joined when they are not.
  Granularity is a project setting: `global` | `module` | `strict`.
- **Identity is project-wide.** Your company is your company in every file that
  names it. Per-file scoping once gave it `ORG_001` in one document and `ORG_002`
  in the next — one organization presented as two.

### Inspecting detection

```bash
specshield scan docs/prd.md
```

Prints what would be aliased, what secrets were found, and what is being
suggested for review — without producing anything.

## 8. Secrets

Scanned **before** identity extraction, so a credential can never be admitted to
the identity graph as though it were a name.

**Rule pack.** AWS access key IDs, AWS secret access keys, PEM private keys, JWTs,
database connection strings with credentials (`postgres://`, `mysql://`,
`mongodb://`, `redis://`, `amqp://`), Stripe-style `sk_`/`rk_` keys, `whsec_`
webhook secrets, GitHub `gh?_` tokens, Slack `xox?-` tokens, bearer tokens, and
email addresses (low confidence).

**Entropy pass.** A value of 20+ characters assigned to a name containing
`secret`, `token`, `password`, `api_key`, `access_key`, `auth` or `credential`,
whose Shannon entropy exceeds 4.5 bits per character. Prose and identifiers sit
at 3.5–4.2; random base64 sits above 4.8.

**Placeholders are not secrets.** `your-api-key-here`, `changeme`, `placeholder`,
`todo`, `xxxxxxxx` and friends are skipped. Redacting them trains you to click
through the block.

**Where a rule has a capture group, only the group is redacted**, so
`AWS_SECRET_ACCESS_KEY=` survives into the twin and the file keeps the shape the
model needs.

Replacement is `<<REDACTED:aws_access_key_id>>`. The vault stores a salted hash
for idempotency across rescans — never the value.

### What blocks, exactly

A secret that was **successfully redacted does not block**. The marker is safe
and the twin goes out.

What blocks is a high-confidence secret that **survived into the twin** — one
redaction did not catch. That refuses in **both** modes, strict and reporting,
with no override:

```text
REFUSED — unredacted secret(s) in the twin:
  line 4: aws_access_key_id
```

A name costs a competitor a guess; a live token costs you the account, and no
rekey takes it back. On a whole-project export, that file is **skipped and
reported** rather than the whole export failing.

Low-confidence findings — an email address — are reported and do not block.

### Your working tree is not the twin

```text
  2 secret(s) redacted, 2 not seen before — they are still in your working tree
      `specshield secrets` lists where
```

Redaction protects what you send. It does nothing about the credential still
sitting in `.env`. That is what §19's `specshield secrets` is for.

## 9. The dictionary: `term` and `allow`

Two halves of one control.

```bash
specshield term "Vantor" --entity-type organization
specshield term "Gold Business Subscription" --entity-type product
specshield term settlement_ledger --entity-type table     # promote structure
specshield allow "API" --reason "framework name"
```

`term` says *this is mine, always alias it* — and overrides the ordinary-word
rule. `allow` says *this is a false positive, leave it alone* — and removes the
term from the export gate as well as from detection, because otherwise the name
stops being aliased, survives into the twin, and gets reported forever.

**An allowlisted name can leave in a twin.** That is your decision and the only
way the gate opens. Every export counts how many names it was told to ignore, so
an open gate is never silent.

Matching is case-insensitive on both sides, deliberately: the gate and the
detector must agree, or a term the gate reports and the detector ignores is a
deadlock with no way out.

The dictionary is not optional configuration. **It is the control.** A name that
has never been entered and never appeared structurally is not protected by
anything.

## 10. Sanitizing

```bash
specshield sanitize docs/prd.md                    # to stdout
specshield sanitize docs/prd.md --out twin.md
specshield sanitize docs/prd.md --envelope         # with the prompt preamble
specshield sanitize docs/prd.md --strict           # refuse on a gate hit
```

Sanitizing is a **byte-range edit list over the original**, never a
re-serialization of a parsed tree. Formatting, comment placement, key ordering,
link syntax, tables and fenced code all survive exactly.

Order of operations: redact secrets → detect against the redacted text → intern
each identity → plan non-overlapping edits → apply → verify structure → map byte
offsets back into your file's coordinates.

## 11. Structural verification

After every sanitize, the parser fingerprints the original and the twin and
compares them. The guarantee is not "the twin compiles" — that needs a type
checker. It is: **the twin parses, and its structure matches**.

| Result | Meaning |
|---|---|
| **Passed** | Same structure. Aliases applied. |
| **Unsupported** | This parser has no fingerprint (plain text). Reported, not treated as a pass. |
| **OriginalDidNotParse** | The parser claimed the file and could not read it. Much worse than Unsupported, and reported separately — folding the two together once told a user their untouched React source was "verified clean". |
| **NotAttempted** | No parser was supplied. |
| **TwinDidNotParse** | Aliasing abandoned; the unaliased (still redacted) original is returned. |
| **StructureChanged** | Aliasing abandoned, with the differing counts printed so the bug is findable. |

What each parser actually counts:

| Parser | Fingerprint |
|---|---|
| Markdown | headings, headings per level `h1`–`h6`, fences, lines |
| SQL | statements, tables, columns, constraints, indexes, types |
| YAML / JSON | documents, mappings, sequences, scalars, keys, max depth |
| OpenAPI | the YAML fingerprint plus paths and schemas |
| TypeScript | identifiers, type identifiers, properties, classes, interfaces, enums, imports |
| PlantUML | diagrams, diagram ends, declarations, declarations per keyword, arrows, braces, notes, lines |
| Plain text | none — reported as `Unsupported` |

**Aliasing is abandoned rather than a broken file emitted.** A file that would be
corrupted comes through unaliased and is reported.

## 12. The export gate

```bash
specshield verify twin.md          # exit 0 clean, 1 leak, 2 nothing to check
```

An Aho–Corasick automaton built from every real name the vault knows, plus
generated case and separator variants — camelCase, PascalCase, snake_case,
kebab-case, SCREAMING_CASE, spaced, pluralized. `_` and `-` are word boundaries,
so `old_vantor_id` is caught and named. The secret detector runs again as an
independent second pass.

**Two modes, and the default changed in v2.0:**

| Mode | Behaviour | For |
|---|---|---|
| **Reporting** *(default)* | Writes the twin, lists what survived, with file, line and column | Getting work done |
| **`--strict`** | Refuses to write | CI, and teams who want the old behaviour |

A hit is not automatically wrong — the detector may have missed an occurrence, or
you may not mind sharing the name. `specshield allow` settles the second case.

**A gate that cannot fail is not a gate.** `verify` on a project with no interned
identities exits **2** and says so, rather than going green having checked
nothing. Note that a dictionary term is not enough: a name is interned the first
time it is *aliased*, so run `sanitize` or `export` first.

**Secrets are not part of this choice.** A high-confidence secret that survived
into the twin refuses in both modes (§8).

## 13. Whole-project export

```bash
specshield export ../twin
specshield export ../twin --strict
```

Sanitizes every parseable file into a new directory (which must not already
exist), renames the identity-bearing part of each path, and records where each
twin file came from. The summary reports alias applications, identities in the
vault, gate results, paths renamed, occurrences recorded, files with no structure
to verify, and structural verification results.

Path rewriting is identity-only: `src/vantor-billing/charge.ts` becomes
`src/ORG_001-billing/charge.ts`. The directory keeps `billing`, the file keeps
its name, and every import inside still resolves — which it would not if the tree
were aliased while the code was not.

Restoring a whole twin project puts each file back at its real path:

```bash
specshield restore ../twin-from-model --out ../restored
```

## 14. The prompt envelope

```bash
specshield sanitize docs/prd.md --envelope
```

> Tokens matching `^[A-Z][A-Z0-9_]*_[0-9]{3,}$` are opaque anonymized
> identifiers. Preserve them exactly — do not rename, expand, translate,
> pluralize, or reformat them. If you introduce a new entity, name it `NEW_<n>`
> and list every such name at the end of your response.

Restore reliability depends substantially on the model having been given this.
Send it with the twin.

## 15. Restoring

```bash
specshield restore reply.md
cat reply.md | specshield restore
specshield restore ../twin-dir --out ../restored
```

Restore is **lexical, not AST-based**, on purpose: model output is routinely a
code fragment, a unified diff, Markdown-wrapped prose, or syntactically invalid.
A parser would refuse where a lexer succeeds.

**Drift tolerance.** Aliases are matched through a canonical form — uppercased,
non-alphanumerics dropped, leading zeros stripped within digit runs, and a
trailing `s` removed only after a digit. So `org_001`, `Org-001`, `ORG001`,
`ORG_1` and `ORG_001s` all resolve to `ORG_001`. **Every non-exact match is
restored and flagged** for review — never silently.

**Embedded aliases.** `ORG_001BillingService` is found inside the token and
restored to `VantorBillingService`, because that is how sub-token aliasing wrote
it in the first place.

**Ambiguity is refused, not guessed.** If two aliases share a canonical form,
neither is fuzzy-matched; exact matching still works for both. Guessing between
two identities is the one failure mode with no safe recovery.

## 16. Unresolved identities

An alias-shaped token the vault never issued is a model invention. It is **left
standing verbatim** in the restored text and **blocks patch application** until a
human names it.

```bash
specshield resolve SERVICE_099 --name NotificationDispatcher --entity-type service
```

Nothing is guessed. A wrong guess writes a wrong name into your repository.

## 17. Diff and patch

```bash
specshield diff src/billing.ts --ai reply.ts                 # look, change nothing
specshield apply src/billing.ts --ai reply.ts --dry-run
specshield apply src/billing.ts --ai reply.ts --branch feature/ai-billing
specshield undo
```

`diff` compares **three** versions: the file on disk, the twin that was sent, and
the twin that came back. Fuzzy-restored aliases and unresolved identities are
called out inline; formatting-only changes are suppressed where possible.

`apply` refuses on:

- an **unresolved identity** — see §16;
- a **stale file** — the BLAKE3 checksum changed since indexing, so the patch
  would revert your edit;
- **`main`** — it applies onto a branch, never onto the current checked-out
  default branch.

It dry-runs the patch before touching anything, and `undo` reverses the last
applied patch. Git history is preserved; without Git it degrades with a clear
message rather than failing obscurely.

## 18. Unification

```bash
specshield unify                                     # list proposals
specshield unify --confirm CustomerSubscription      # link them
```

The SQL table `customer_subscription`, the OpenAPI schema `CustomerSubscription`
and the TypeScript interface are one concept in three artifacts, and should carry
one alias so the model sees one thing.

**A shared name is not a proposal.** A proposal needs a compatible pair of
*different* kinds — a table and a DTO, a service and an API. Identities sharing a
name *and* a kind are a collision, not a concept: three unrelated `Status` enums
in three modules are three things, and giving them one alias would break the twin
and make restore ambiguous.

**Nothing is unified until you confirm it.** Confirming re-derives aliases, and
any twin already sent is orphaned — its aliases no longer resolve. The CLI says
so:

```text
Linked 3 identities as concept "CustomerSubscription".
Re-derived 2 alias(es).

Those aliases changed, so any twin already sent to a model is orphaned:
its aliases no longer resolve. Re-sanitize before the next request.
```

## 19. Provenance: `where` and `secrets`

```bash
specshield where "Acme Bank"     # by real name, case-insensitive
specshield where ORG_001         # by alias, exact
```

```text
ORG_001  ORG  Acme Bank
  scope: identity
  2 occurrence(s):
      docs/prd.md:1:3  (reference)
      docs/prd.md:3:1  (reference)
```

Answers both directions: *where in my project is this name*, and *what was this
alias before it was one*. Note `scope: identity` — that is the project-wide scope
every identity type shares (§7). It reads what the last export recorded, so an
unexported project has nothing to say.

```bash
specshield secrets
```

Lists every secret this project redacted and where it still is — **position and
rule only, never a value**, because the vault never held one. The twin is safe;
your working tree is not, and that is the point of the command. Files that have
since been deleted are dropped from the report.

## 20. The audit log

```bash
specshield audit
specshield audit --limit 200
specshield audit --csv > audit.csv
```

Append-only, local, inside the vault.

```text
when                 operation         files entities  result     destination
1788711760           export               3       7  clean      ../ref-twin
1788711588           term.add             -       1  -          -

2 entr(ies). No real names, no content — FR-9.
```

Records timestamp, operation, file count, entity count, verification result and
destination. A clipboard export records **whether the opt-out actually applied**:
`clipboard(opted-out)` or `clipboard(unprotected)`. A security team reading the
log needs to know which exports the platform may have retained.

**It never contains a real name or any artifact content, and is never
transmitted.** This is distinct from telemetry, which the product does not have.

## 21. Vault operations

```bash
specshield backup vault-2026-09-06.bin
specshield restore-vault vault-2026-09-06.bin --into /path/to/project
```

`restore-vault` never writes over an existing vault.

```bash
specshield escrow escrow.json --escrow-passphrase "<second passphrase>"
specshield escrow-open escrow.json --escrow-passphrase "<second passphrase>"
```

Escrow wraps the vault's **data key**, not your passphrase, under a second,
separate passphrase. Whoever holds the file and that passphrase can open the
vault — the CLI prints that warning before writing it. `escrow-open` re-wraps the
key under a passphrase you choose, so it never reveals the original one. **Key
loss is unrecoverable**; this is the only mitigation.

```bash
specshield passphrase                # re-wrap the data key
specshield rotate-key --confirm      # re-encrypt every stored value
specshield rekey --confirm           # reissue every alias
```

Three operations that sound alike and are not:

| Command | Changes | Twins keep working? | Old escrow/backups still open? |
|---|---|---|---|
| `passphrase` | how the data key is wrapped | yes | yes |
| `rotate-key` | the data key; every value re-encrypted | **yes** | **no** — that is what revoking an escrow means |
| `rekey` | every alias | **no** — every shared twin is orphaned | yes |

`rotate-key` and `rekey` print what they would do unless `--confirm` is given.

## 22. Recovery

```bash
specshield recover --project /path/to/project
```

Read-only inspection of a vault that will not open. **Needs no passphrase and
reveals no real name.** Reports what the vault holds — schema version, row counts,
integrity — and what is wrong with it. For the case where you need to know whether
the data is there before deciding what to do.

## 23. The corpus report

```bash
specshield report corpus
specshield report corpus --strict     # non-zero exit if targets are missed
specshield report corpus --verbose    # every detection not in ground truth
```

Measures detection recall and precision against a committed, hand-labelled golden
corpus of seven synthetic projects. Consumed by CI. Targets: recall ≥ 0.95,
precision ≥ 0.90.

**Two recall columns, and the left one is the honest one.**

- **Rules-only** — what the detector finds against an empty vault: the vendor
  table, the hostname rule, the person markers. The only part that works before
  you have typed anything.
- **With dictionary** — seeds the types nothing could guess (organization,
  product, brand, tenant, environment) and nothing else, so a grader that already
  knows `Stripe` never gets credit for the vendor table.

Three buckets are reported separately: identity occurrences (gated), structural
occurrences (left in the twin on purpose), and ordinary-word occurrences.

---

# Part III — Every use case

## 24. Use case index

### Getting started

| I want to… | Do this |
|---|---|
| Start using SpecShield on a project | `specshield init .` then §9 |
| See what it would find, changing nothing | `specshield scan <file>` |
| Know which formats this build handles | `specshield report corpus` prints them; desktop shows them on the project screen |
| Understand why a name was or was not aliased | §7, and `scan` shows confidence per candidate |

### Sending something to a model

| I want to… | Do this |
|---|---|
| Sanitize one document and paste it into ChatGPT | §26 |
| Sanitize a whole repository for an agent | §27 |
| Include the instruction that stops the model mangling aliases | `sanitize --envelope` |
| Check a twin before sending it | `specshield verify twin.md` |
| Refuse to produce a twin at all if a name survived | add `--strict` |
| Send only part of a repository | `.specshieldignore`, §31 |

### Getting the answer back

| I want to… | Do this |
|---|---|
| Restore a pasted reply | `specshield restore reply.md` |
| Restore a whole twin project an agent edited | `specshield restore ../twin --out ../restored` |
| See what the model changed before accepting it | `specshield diff <file> --ai reply` |
| Turn the reply into a reviewable commit | `specshield apply <file> --ai reply --branch …` |
| Undo what I just applied | `specshield undo` |
| Deal with a token the model invented | `specshield resolve NEW_1 --name … --entity-type …` |
| Understand why restore flagged something | §15 — every non-exact match is flagged |

### Controlling what gets hidden

| I want to… | Do this |
|---|---|
| Hide my company name | `specshield term "Acme Bank" --entity-type organization` |
| Hide a product, brand, customer or partner | `--entity-type product` / `brand` / `tenant` / `partner` |
| Hide a person | `--entity-type person`, or rely on `@author` / `Contact:` markers |
| Hide a table or service the model does not need | `--entity-type table` — structure is exempt by *default*, not by rule |
| Stop aliasing a false positive | `specshield allow "<name>" --reason "…"` |
| Hide an ordinary word that really is mine | `specshield term account --entity-type table` |
| Make one concept share one alias across SQL, OpenAPI and code | `specshield unify --confirm <concept>` |

### Secrets

| I want to… | Do this |
|---|---|
| Find every credential in my repository | `specshield scan`, or `specshield export` then `specshield secrets` |
| See where a redacted secret still lives in my working tree | `specshield secrets` |
| Understand why export refuses | A high-confidence secret that redaction missed blocks in **both** modes — §8 |
| Get a secret back after restore | You cannot, by design — §3 |

### Security review and compliance

| I want to… | Do this |
|---|---|
| Show a security team what leaves the machine | [Security One-Pager](Security%20Review%20One-Pager.md), §12, §20 |
| Prove nothing was transmitted | `specshield audit --csv`; the app has no network permission |
| Understand the residual risk | [Residual Risk](Residual%20Risk.md), §4 |
| Show the detection quality is measured, not claimed | `specshield report corpus` |
| Audit which names the gate was told to ignore | Every export counts them; `audit` records term additions |

### Operations

| I want to… | Do this |
|---|---|
| Back up the vault | `specshield backup <dest>` |
| Survive losing my passphrase | `specshield escrow` — **before** you lose it |
| Change my passphrase | `specshield passphrase` |
| Revoke an escrow file I shared | `specshield rotate-key --confirm` |
| Reissue every alias after over-sharing a twin | `specshield rekey --confirm` |
| Open a vault that will not open | `specshield recover` |
| Find out what changed since my last twin | `specshield rescan` |

### CI

| I want to… | Do this |
|---|---|
| Fail a build if a real name reaches a twin | `specshield verify` — exit 1 |
| Fail a build if detection quality regresses | `specshield report corpus --strict` |
| Produce a twin in CI and refuse on any leak | `specshield export ../twin --strict` |
| Full example | §28 |

---

# Part IV — User guide

## 25. Install and first run

SpecShield ships as a desktop application (Windows, macOS, Linux) and a CLI
binary. The engine is the same; the app and the CLI are drivers. Anything the app
can do, the CLI can do headless.

**Installers are not yet signed.** On Windows, SmartScreen will warn; on macOS,
Gatekeeper will. Verify the checksum published with the release.

First run, from a terminal:

```bash
cd /path/to/your/project
export SPECSHIELD_PASSPHRASE='a long passphrase you will not lose'
specshield init .
```

That creates `.specshield/vault.bin`. Add it to `.gitignore` — it is your vault,
not your code. Then name what only you can name:

```bash
specshield term "Acme Bank"                    --entity-type organization
specshield term "Gold Business Subscription"   --entity-type product
specshield term "Meridian Freight"             --entity-type tenant
```

Vendors, hostnames and marked people need no configuration.

## 26. Walkthrough A — a document to ChatGPT

**1. See what it finds.**

```bash
specshield scan docs/prd.md
```

```text
docs/prd.md (markdown)

7 entit(ies) would be aliased:
      2  reference Acme Bank
     21  reference Acme Bank
     38  reference Gold Business Subscription
    101  reference Jane Okafor
    137  reference Stripe
    162  reference Adyen
    192  reference api.acmebank.com

2 suggestion(s) NOT applied — confirm with `term`:
     75  0.35         Haulwise
    114  0.85         BillingService
```

Two things to read here. `Acme Bank` and `Gold Business Subscription` were found
because you named them; `Jane Okafor` because of the `Contact:` line; `Stripe`
and `Adyen` from the vendor table; `api.acmebank.com` from its shape.

`Haulwise` is a brand nothing can guess — name it. `BillingService` is
architecture and is *supposed* to stay; it appears as a suggestion only so you can
promote it if you disagree.

```bash
specshield term "Haulwise" --entity-type brand
```

**2. Sanitize, with the envelope.**

```bash
specshield sanitize docs/prd.md --envelope --out twin.md
```

```text
Twin written to twin.md
Tokens matching `^[A-Z][A-Z0-9_]*_[0-9]{3,}$` are opaque anonymized identifiers. …

verified clean: 8 identities applied, 90 patterns checked
  structure verified against the original (SDD §7.2)
  0 secret(s) redacted (one-way, never restored)
  1 suggestion(s) NOT applied — review with `term`:
      "BillingService"

NOT checked: business logic in prose, algorithms, architecture shape (PRD §4.3).
```

The twin:

```text
# ORG_001 billing

ORG_001 offers PRODUCT_001 under the BRAND_001 brand.

Contact: PERSON_001

BillingService charges PAYMENT_PROVIDER_001 and falls back to PAYMENT_PROVIDER_002. The API is served
from DOMAIN_001.

The customer_subscription table holds the rows.
```

Read that last stderr line every time. It is the honest part.

**3. Send it.** Paste the envelope, then `twin.md`, into the model.

**4. Bring the answer back.**

```bash
specshield restore reply.md > restored.md
```

```text
Acme Bank new plan is Gold Business Subscription. Jane Okafor approved it.
A new SERVICE_099 handles retries for Stripe.

restored 4 alias(es)
  review line 1: "ORG_001s" matched "Acme Bank" (Canonical)
  1 unresolved identit(ies) — name them before applying:
      line 2: SERVICE_099
```

The restored text goes to stdout; the report goes to stderr, so
`specshield restore reply.md > restored.md` gives you the file and still shows
you what needs reviewing.

`ORG_001s` was restored **and flagged** — never silently. `SERVICE_099` is a
model invention: the vault never issued it, so it stays as it is and blocks
`apply` until you name it (§16).

## 27. Walkthrough B — a repository to an agent

**1. Index and learn the project.**

```bash
specshield index
```

**2. Export the twin.**

```bash
specshield export ../project-twin
```

```text
Exported 412 file(s) to ../project-twin
  1,208 alias applications, 34 identities in the vault
  the gate found vault names in 2 file(s) — listed above (SDD §8)
  9 path(s) renamed in the twin tree
  1,208 occurrence(s) recorded — `specshield where <name>` (FR-5)
  3 file(s) had no structure to verify against
  every parsed file verified structurally (SDD §7.2)
```

Two files still contain a vault name. Look at them:

```text
2 vault name(s) survived into this twin:
  README.md:14:8   "Acme"
  src/legacy.ts:88:22  "acmebank"
```

Both are real misses — `Acme` alone and a lowercase compound the detector did not
split. Name them and re-export:

```bash
specshield term "Acme" --entity-type organization
rm -rf ../project-twin && specshield export ../project-twin
```

**3. Point the agent at `../project-twin`.** It is a working project: imports
resolve, the schema is readable, the architecture is intact.

**4. Bring the edited twin back.**

```bash
specshield restore ../project-twin --out ../restored
```

**5. Review and apply, file by file.**

```bash
specshield diff src/billing.ts --ai ../restored/src/billing.ts
specshield apply src/billing.ts --ai ../restored/src/billing.ts --dry-run
specshield apply src/billing.ts --ai ../restored/src/billing.ts --branch feature/ai-billing
```

If a file changed on disk since the export, `apply` refuses and tells you to
`rescan`. That refusal is protecting your edit.

## 28. Walkthrough C — SpecShield in CI

Two independent jobs. The first gates content; the second gates the detector.

```yaml
- name: Build and verify the twin
  env:
    SPECSHIELD_PASSPHRASE: ${{ secrets.SPECSHIELD_PASSPHRASE }}
  run: |
    specshield index
    specshield export "$RUNNER_TEMP/twin" --strict

- name: Detection quality must not regress
  run: specshield report corpus --strict
```

`--strict` on `export` refuses to write anything if a vault name reached a twin.
`--strict` on `report` exits non-zero if recall or precision falls below target.

For a single file:

```bash
specshield verify twin.md    # 0 clean · 1 leak or unredacted secret · 2 nothing to check
```

Exit **2** deserves attention: it means the project has no interned identities, so
the gate checked nothing. A green build there would be a lie.

## 29. The desktop application

Five numbered steps and three tools, kept visually apart — an audit log is not
step six of sanitizing a document.

### Steps

**1. Project.** Create or open a vault. Shows the identity count and the formats
this build supports. Warns about cloud-sync locations.

**2. Review.** Load a file, scan it, and see entities, secrets and suggestions.
Add dictionary terms and allowlist entries inline. The entity-type picker groups
**identity** types above the rule and **structure** below it — choosing one below
the rule is the deliberate act of hiding something the model would otherwise get
to read.

**3. Sanitize & verify.** Produces the twin, runs structural verification, runs
the gate, and offers:

- **Copy** — with or without the prompt envelope. On Windows the payload is
  marked with the three clipboard opt-out formats.
- **Save** — write the twin to a file.

Neither is offered until the twin exists and has been checked.

**4. Restore.** Paste the model's reply. Fuzzy matches and unresolved identities
are listed; unresolved ones can be named here.

**5. Diff & apply.** Three-way review, patch status, branch selection, dry run,
apply, undo.

### Tools

**Whole project** — index and rescan; export a twin directory; unification
proposals; `where` lookup; the secrets report; and a standalone verify box you can
paste anything into.

**Audit log** — the local log, with CSV export.

**Vault** — backup and restore; escrow export and open (with the warning shown
before the file is written); rekey with a preview before confirmation; and
read-only recovery for a vault that will not open.

### Parity with the CLI

The application is at parity apart from `specshield report`, which measures
detection metrics against the golden corpus and is a CI tool.

**Original, unsanitized content is never placed on the clipboard by any UI
affordance.** There is no "copy original" button, deliberately.

## 30. Command reference

Every command takes `--project <PATH>` (default `.`) and `--passphrase
<PASSPHRASE>`; prefer `SPECSHIELD_PASSPHRASE` in the environment, because
arguments are visible in the process list.

### Setup

| Command | What it does |
|---|---|
| `init [PATH]` | Create the vault, identity graph and settings |
| `term <NAME> [--entity-type <T>]` | Add a confirmed term. Default type `organization` |
| `allow <TERM> [--reason <R>]` | Mark a term never-alias |

### Inspect

| Command | What it does |
|---|---|
| `scan <FILE>` | What would be detected, without producing anything |
| `where <NAME>` | Where an identity appears — by real name or by alias |
| `secrets` | Every redacted secret and where it still is |
| `audit [--limit N] [--csv]` | The local audit log |
| `recover` | Read-only inspection of a vault that will not open |
| `report [CORPUS] [--strict] [--verbose]` | Detection metrics against the golden corpus |

### Produce

| Command | What it does |
|---|---|
| `index` | Walk, hash and record every file |
| `rescan` | What changed since the last index |
| `sanitize <FILE> [--out F] [--envelope] [--strict]` | The twin for one file |
| `export <DEST> [--strict]` | The twin for the whole project |
| `verify <FILE>` | The export gate. Exit 0 / 1 / 2 |

### Bring back

| Command | What it does |
|---|---|
| `restore [INPUT] [--out DIR]` | Restore a reply, or a whole twin directory |
| `resolve <ALIAS> --name <N> [--entity-type <T>] [--scope <S>]` | Name a model invention |
| `diff <FILE> --ai <AI> [--twin <T>]` | Three-way review; writes nothing |
| `apply <FILE> --ai <AI> [--twin <T>] [--branch <B>] [--dry-run]` | Restore and apply as a patch on a branch |
| `undo` | Reverse the last applied patch |
| `unify [--confirm <CONCEPT>]` | Cross-artifact unification proposals |

### Vault

| Command | What it does |
|---|---|
| `backup <DEST>` | Copy the vault |
| `restore-vault <BACKUP> --into <DIR>` | Put a backup back; never overwrites |
| `escrow <OUT> --escrow-passphrase <P>` | Passphrase-protected key escrow |
| `escrow-open <FILE> --escrow-passphrase <P> [--new-passphrase <P>]` | Get back in with an escrow file |
| `passphrase [--new-passphrase <P>]` | Change the vault passphrase |
| `rotate-key [--confirm]` | Rotate the data key; revokes old escrows and backups |
| `rekey [--confirm]` | Reissue every alias; orphans every shared twin |

## 31. Files, formats and settings

### Supported formats

| Format | Extensions | Structural verification |
|---|---|---|
| Markdown | `.md`, `.markdown`, `.mdown`, `.mkd` | headings by level, fences, lines |
| Plain text | `.txt`, `.text`, `.log`, `.csv` | none — reported as Unsupported |
| SQL | `.sql` | statements, tables, columns |
| YAML | `.yaml`, `.yml` | nodes, keys, depth |
| JSON | `.json` | as YAML 1.2 |
| OpenAPI | 3.x in YAML or JSON, **recognised by content** | paths, operations, schemas |
| PlantUML | `.puml`, `.plantuml`, `.pu`, `.iuml`, `.wsd`, or any file opening `@start` | diagram blocks, declarations, braces, arrows |
| TypeScript / JavaScript | `.ts`, `.tsx`, `.mts`, `.cts`, `.d.ts`, `.js`, `.jsx`, `.mjs`, `.cjs` | declarations, imports, functions |

Future: Java, Kotlin, C#, Python.

### Files on disk

| Path | What it is |
|---|---|
| `.specshield/vault.bin` | The vault. **Add to `.gitignore`.** Never in a sync root |
| `.specshieldignore` | Project ignore rules, `.gitignore` syntax |

### Ignore rules

`.gitignore`, `.ignore`, the global gitignore and `.specshieldignore` are all
respected — and gitignore is honoured **whether or not `git init` has been run**,
because a project is a project either way. `.git` and `.specshield` are skipped.
Hidden files are *not* skipped: a `.env` is exactly the file you want scanned.
Files over **5 MB** are skipped, and binary files are excluded from parsing.

A project's ignored files are ignored for a reason — `node_modules` is not your
code, and indexing it turns a 1,000-file repository into a 90,000-file one.
`.specshieldignore` is applied on top of `.gitignore`, for the vendored tree that
*is* committed or the generated directory a team wants out of every twin.

### Environment

| Variable | Effect |
|---|---|
| `SPECSHIELD_PASSPHRASE` | The vault passphrase. Preferred over `--passphrase` |

That is the only one. Ignore rules live in files, not in the environment.

### Settings

Fixed at project creation, in the vault: project name, root path, and scope
strategy — `global` \| `module` \| `strict`, defaulting to `module`. This
controls how finely *structural* names are scoped; identity is always
project-wide.

**There is no alias-style setting.** v1.1 offered opaque, typed and pseudonymous
styles; aliases are now sequential and allocated per vault, and that is the only
format.

## 32. Troubleshooting

**"no vault at ./.specshield/vault.bin"** — you are not in the project directory,
or you have not run `init`. Pass `--project`.

**`verify` exits 2, "NOT CHECKED"** — the project has no interned identities, so
there was nothing to scan for. A dictionary term is not enough; a name is
interned the first time it is *aliased*. Run `sanitize` or `export` first.

**"aliasing ABANDONED: structure changed"** — the twin would not have had the same
shape as the original, so the file came through unaliased and redacted. The
differing counts are printed. This is the safety behaving correctly; the bug is
in a parser, and the counts are how it gets found.

**"verified clean: 0 identities applied"** on a file full of names — either the
vault has no terms yet (§9), or the parser claimed the file and could not read it.
The second case reports `OriginalDidNotParse` explicitly.

**The gate reports a name I do not mind sharing** — `specshield allow "<name>"
--reason "…"`. It is counted on every export from then on.

**`sanitize` or `verify` refuses even without `--strict`** — that is a secret,
not a name, and specifically one that survived redaction into the twin. Redacted
secrets do not block. Remove or rotate the credential, or report the pattern that
should have caught it.

**`export` skipped a file, listing it as unredacted** — same cause, but a
whole-project export skips that one file and writes the rest rather than failing
everything.

**`apply` refuses: "file has changed since indexing"** — you edited the file after
the twin was made. The patch would revert your edit. `rescan`, re-export, redo.

**`apply` refuses: "unresolved identity"** — the model invented an alias. Name it
with `resolve`, or remove it from the reply.

**Restore left `ORG_001` in the text** — that alias is not in this vault. Check
you are restoring against the project the twin came from, and that no `rekey` has
happened since.

**`where` returns nothing** — it reads what the last export recorded. Run
`export` first.

**I lost my passphrase** — if you have an escrow file and its separate passphrase,
`escrow-open`. Otherwise the vault is unrecoverable. This is not a limitation to
work around; it is the property that makes the vault worth having.

**Windows SmartScreen / macOS Gatekeeper warns** — installers are not yet signed.
Verify the published checksum.

## 33. Limits, stated plainly

- **Architecture leaves the machine intact.** By design (§2), and the largest
  single thing to understand before approving the tool.
- **A name never entered and never appearing structurally is not protected by
  anything.** The dictionary is the control, not optional configuration.
- **`Vantor` and `vantor` are separate identities with separate numbers.** Restore
  is byte-for-byte, so an alias maps to exactly one spelling; sharing a number
  would return one of them in the wrong case.
- **Two vaults do not agree.** Aliases are allocated from a counter, so two
  developers importing the same project get different twins. Sharing the vault is
  the supported answer.
- **TypeScript scoping is heuristic.** There is no type checker. Per-type property
  renaming waits for a compiler-API sidecar.
- **Clipboard opt-outs are advisory.** A clipboard manager that ignores them
  captures the twin anyway; macOS and Linux opt-outs are not implemented, and the
  audit log records which exports were protected.
- **There is no OS credential store integration yet.** The passphrase is the key.
- **Alias durability through a real model is unmeasured.** Whether a commercial
  model preserves alias tokens across a long conversation is not yet tested
  against a live API.
- **Detection quality is measured on a synthetic corpus.** Seven hand-labelled
  projects, not a survey of real repositories.
