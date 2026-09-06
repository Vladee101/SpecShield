# Product Requirements Document (PRD)

## SpecShield

**Identity Gateway for Secure Agentic Software Development**

### Version

v2.0 (MVP)

### Status

Draft

---

## Change Log

### v2.0 — merges *SpecShield (PRD) Revised* into v1.1

v2.0 was written as a separate short document and is folded in here. There is now
one PRD. The revision governs **scope and principle**; v1.1's engineering
requirements survive wherever the revision was silent about them, because a
document that drops FR-4b does not thereby delete the export gate.

| Change | Origin |
|---|---|
| **Architecture is preserved; only identity is neutralized.** Services, DTOs, tables, columns, endpoints and file names stay readable. §4.1, §7 | Revised §3, §7 |
| Identity model widened to nine categories — organization, product, brand, partner, payment provider, person, tenant, environment, domain. FR-3, §13 | Revised FR-3 |
| Aliases are sequential and allocated per vault — `ORG_001`. §13 | Revised §13 |
| §8.2 *Alias styles* **deleted**: opaque / typed / pseudonymous no longer exist | Revised §13 |
| PlantUML added to FR-2, and removed from Out of Scope | Revised FR-2 |
| The export gate reports by default and refuses under `--strict`. FR-4b | Product decision, 2025-09 |
| §4 restructured around what the product protects; the adversary table moves to §4.5 | — |
| §5 metrics restated over identity occurrences, with rules-only and with-dictionary columns | — |
| Section numbering follows the revision where the two disagreed (§7 principles, §8 example, §13 aliases); **FR IDs follow v1.1 and are unchanged** | — |

Where the two documents used the same number for different things, the mapping
is:

| Revised | Here | Why |
|---|---|---|
| FR-6 One-Click Copy | FR-4b | Copy is the end of the export path, and the gate is what makes it safe |
| FR-7 One-Click Restore | FR-6 | v1.1 numbering; 90-odd citations in the source tree depend on it |
| FR-8 Diff Viewer | FR-7 | as above |
| FR-9 Git Patch Export | FR-8 | as above |
| — | FR-3b, FR-4b, FR-6b, FR-9…FR-12 | v1.1 requirements the revision did not mention and did not remove |

### v1.1 — incorporates *Design Review (PRD + SDD)*

| Change | Origin |
|---|---|
| Added §4 Threat Model with explicit protected / not-protected / residual risk | Review A1 |
| Rewrote §5 Success Metrics as measurable recall/precision against a labelled corpus | Review C5 |
| Added FR-3b Secret Detection (one-way redaction, distinct from pseudonymization) | Review A2 |
| Added FR-4b Export Verification Gate | Review A3 |
| Added FR-6b Prompt Envelope Generator | Review B4 |
| Added FR-9 Local Audit Log, FR-10 Manual Entity Control, FR-11 Vault Backup & Rotation, FR-12 Project Ignore Rules | Review D2, D7 |
| Identity is now scoped — `(scope_path, entity_type, real_name)` | Review B1 |
| Aliases are HMAC-derived, not sequence-allocated; three selectable alias styles | Review A6, D1 — **both reversed in v2.0** |
| Added key-management, clipboard, and cloud-sync requirements to §10 NFRs | Review A4, A5 |
| OpenAPI moved into MVP scope | Review E |
| §18 references the SDD stack table rather than duplicating it | Review E |

---

## 1. Executive Summary

SpecShield is a **local-first desktop application** that lets software teams use
commercial AI agents — ChatGPT, Codex, Claude Code, Gemini — without exposing
confidential business identity.

Unlike a redaction tool, SpecShield **preserves the software architecture** and
anonymizes only business identity. Services, repositories, database schemas,
DTOs, APIs, and project structure stay intact, so the agent can read the system
it is being asked to extend.

The application performs **bidirectional identity anonymization**: artifacts are
converted into an identity-neutral twin before being shared with a model, and the
generated output is restored to the organization's own terminology with one
click.

Secrets — API keys, tokens, credentials — take a separate, **one-way** redaction
path and are never restored.

Before anything leaves the machine, SpecShield **checks** the twin against the
vault and reports every real identifier that survived; under `--strict` it
refuses to write.

The product targets organizations whose security policies prohibit uploading
internal code or documentation to cloud LLMs.

---

## 2. Problem Statement

Engineering teams increasingly rely on AI for requirements analysis,
architecture, code generation, refactoring, SQL, tests, and documentation.

Many organizations prohibit commercial LLMs because project artifacts reveal
confidential information:

- customer names
- product and brand names
- partner organizations
- payment providers and other vendors
- internal domains and hostnames
- tenant identifiers
- environment names
- the people who work on the project
- secrets and credentials

Existing DLP tools target personally identifiable information and are not built
for software engineering workflows. The result is a standing conflict between
security policy and developer productivity.

---

## 3. Vision and Goals

Become the secure identity gateway between proprietary software projects and
commercial AI agents.

> **Preserve architecture. Remove identity.**
>
> The model should understand **how the software works** and never learn **who it
> belongs to**.

**Business goals**

- Enable safe adoption of commercial AI agents.
- Reduce the security objection to cloud LLM usage.
- Eliminate manual redaction.

**User goals**

- One-click sanitize, one-click restore.
- No loss of architectural context.
- Deterministic restoration.
- No change to the development workflow.

---

## 4. What SpecShield Protects

This section defines the security claim: what leaves, what stays, and what
remains disclosed anyway. It is the basis on which a security team can approve
the tool, and every number in §5 is measured against it.

### 4.1 Identity and structure

The product turns on one distinction.

| | Examples | In the twin |
|---|---|---|
| **Identity** — who you are, who you work with, where you run | `Vantor`, `Gold Business Subscription`, `Stripe`, `Jane Okafor`, `api.vantor-freight.com`, `meridian-uat` | **Replaced** |
| **Structure** — what you built | `BillingService`, `CustomerSubscription`, `customer_subscription`, `plan_tier`, `POST /subscriptions`, `charge-invoice.ts` | **Kept** |

Keeping structure is not a concession; it is the product. An agent that cannot
read the architecture cannot help extend it, and a twin in which
`CustomerSubscription` is `DTO_004` and `chargeInvoice` is `SERVICE_014` tells
the model nothing it can build on. Asking a model to work on a system it cannot
read is the opposite of the point.

**Structure is not permanently exempt.** `specshield term <name>` promotes any
name to an identity, and from then on it is aliased like any other. A table
called `settlement_ledger` that a team considers proprietary is one command away
from being hidden. What changed in v2.0 is the *default*, not the capability.

### 4.2 What counts as an identifying name

Being an identity type is necessary and not sufficient. The name also has to
identify something.

- A **compound** name is identifying. `meridian-freight`, `Gold Business
  Subscription`. The combination is yours whatever the parts are.
- A **single word nobody else uses** is identifying. `Vantor`, `Paylane`,
  `Haulwise`.
- A **single ordinary word is not**. An organization called `admin`, an
  environment called `staging` or `production`, a host called `localhost`. On its
  own it says nothing about who wrote it, and aliasing it makes the twin
  unreadable while hiding nothing.
- **A name the user confirms overrides all of this.** `specshield term staging
  --entity-type environment` says *this ordinary word is mine*. It is the mirror
  of FR-10's allowlist: one says "this generic word is mine", the other says
  "this name of mine is generic".

The word list lives in `crates/core/src/words.rs`, is finite, and is meant to be
extended when it is wrong. §5 reports how many labelled names fall into the
ordinary-word bucket, so the cost of this rule is a number rather than a claim.

### 4.3 What SpecShield explicitly does not protect

SpecShield replaces names while **deliberately preserving semantics** — that is
what makes the twin useful. The following therefore still reach the model:

- **Architecture and data-model topology.** The number of services, their
  relationships, table cardinality, endpoint structure. In v2.0 this is not a
  leak the product is trying to close; it is the deliverable.
- **Business logic expressed in prose.** *"BillingService charges a 3% commission
  on ORG_007 payouts for EU customers above EUR 10k"* discloses the rule, the
  jurisdiction, the fee, and the shape of the integration.
- **Algorithms and implementation approach.**
- **Comments and documentation prose** the user chooses to keep.
- **Anything the user pastes into a model by hand**, outside the tool.
- **Structural re-identification.** A distinctive domain model plus endpoint
  shapes is often enough to identify the organization, even with every name
  replaced. Preserving structure makes this materially easier than it was in
  v1.1.

### 4.4 Residual risk statement

> SpecShield reduces disclosure to a commercial LLM from *"who you are plus what
> you built"* to *"what you built"*. It does not make the submission
> non-confidential. Teams handling material where the architecture or the
> business logic is itself the secret should not use commercial LLMs for that
> material, with or without SpecShield.

This statement must appear in the product's onboarding and in the security
one-pager.

### 4.5 Adversaries

| # | Adversary | Capability | In scope |
|---|---|---|---|
| T1 | **LLM provider (honest-but-curious)** | Retains submitted prompts for training, abuse review, or subpoena; staff may read them | **Primary** |
| T2 | **Cloud backup / file sync** | Silently uploads the vault or project tree (OneDrive, Dropbox, Google Drive, iCloud) | **Primary** |
| T3 | **Clipboard history services** | Persists or syncs clipboard contents (e.g. Windows Cloud Clipboard) | **Primary** |
| T4 | **Local malware / stolen device** | Reads files at rest as the user | Partial — vault at rest only |
| T5 | **Insider with legitimate access** | Reads the real project directly | Out of scope |
| T6 | **Nation-state / targeted attacker** | Endpoint compromise, memory scraping | Out of scope |

---

## 5. Success Metrics

All metrics are measured by CI against a committed, hand-labelled **golden
corpus** of seven synthetic projects: a PRD, an OpenAPI spec, a SQL schema, a
TypeScript service, a mixed repository, an adversarial set, and an identity set
covering every category in §13. Performance is measured on the reference machine
defined in SDD §18.

| Metric | Definition | Target |
|---|---|---|
| Detection recall | Labelled **identity** occurrences detected ÷ total labelled identity occurrences | ≥ 0.95 |
| Detection precision | Correct detections ÷ total detections | ≥ 0.90 |
| Structural occurrences | Labelled names left in the twin on purpose (§4.1) | reported, not gated |
| Ordinary-word occurrences | Identity types whose name is one common word (§4.2) | reported, not gated |
| Restoration correctness | `restore(sanitize(x)) == x` byte-for-byte, all corpus files | 100% |
| Silent restore failures | Aliases neither restored nor reported as unresolved | 0 |
| Leak gate | Vault real-names present in a reported-clean twin | 0 |
| Secret detection | Planted secrets found in the secrets fixture | 100% |
| Secret false positives | Per 10,000 LOC | < 5 |
| Sanitize a 100-page PRD | ~40k words, cold | < 10 s |
| Restore an AI response | ~2k lines pasted | < 3 s |
| Offline functionality | Outbound connections observed under egress block | 0 |

**Recall is reported in two columns, and the left one is the honest one.**

- **Rules-only** is what the detector finds against an empty vault: the built-in
  vendor table, the hostname rule, and the person markers. It is the only part of
  identity detection that works before a user has typed anything.
- **With dictionary** seeds the identity types nothing could guess —
  organization, product, brand, tenant, environment — and nothing else, so a
  grader that already knows `Stripe` never gets credit for the vendor table.

Today: 49 gated identity occurrences, **49.0% rules-only**, **100% with
dictionary**, **98.0% precision**, 6 of 6 secrets. 225 structural occurrences and
2 ordinary-word occurrences reach the model on purpose.

Precision is a first-class target, not a nicety: false positives make the twin
unreadable and measurably degrade the quality of AI output generated from it.

---

## 6. Target Users

### Primary

- System Analysts
- Solution Architects
- Software Developers
- QA Engineers

### Secondary

- Engineering Managers
- Security & Compliance Teams — served by §4, FR-4b, and FR-9

### User stories

**System Analyst.** As a system analyst, I want to sanitize a PRD before sending
it to ChatGPT so that customer and product names are never exposed, and I want
the tool to tell me what survived before I copy it.

**Developer.** As a developer, I want Codex to generate code against my real
architecture while my company's identity stays hidden, and I want the result
restored into my repository as a reviewable Git patch.

**Architect.** As an architect, I want OpenAPI specs, SQL schemas and diagrams to
stay structurally intact while partner and vendor names are anonymized, and I
want the same entity to carry the same alias across all of them.

**QA.** As a QA engineer, I want generated test cases restored using real product
terminology automatically.

**Security Engineer.** As a security engineer, I want to see what left the
machine and when, and I want the tool to refuse to export anything containing a
known real identifier or a live secret.

---

## 7. Product Principles

### Preserve Structure

Never renamed by default:

- Service names
- Repository and module names
- DTOs, interfaces, enums, events
- Database tables and columns
- API paths, endpoints, operation IDs
- Method and class names
- File and directory names, except the identity-bearing part of one (FR-3b)

### Neutralize Identity

Always replaced:

- Organizations and customers
- Products and brands
- External partners and payment providers
- Domains and hostnames
- Tenant identifiers
- Environment names that identify a customer
- People named in the codebase

And, separately and irreversibly, **secrets**: API keys, tokens, passwords,
connection strings, private keys, JWTs (FR-3b).

This lets a model reason about the software without learning the business behind
it.

---

## 8. Worked Example

### Original

```text
Acme Bank offers Gold Business Subscription.

BillingService stores the subscription in
customer_subscription and charges Stripe.
```

### Identity-neutral twin

```text
ORG_001 offers PRODUCT_001.

BillingService stores the subscription in
customer_subscription and charges PAYMENT_PROVIDER_001.
```

Three things are worth reading off this.

- **The architecture is untouched.** `BillingService`, `customer_subscription`
  and the sentence structure survive, so a model can be asked to add a retry, a
  column, or a test.
- **`Stripe` needed no configuration.** It is in the built-in vendor table (§13),
  along with the payment, messaging, identity and observability services a
  company actually transacts with. `Acme Bank` and `Gold Business Subscription`
  are unguessable and are named once with `specshield term`.
- **Restoration is byte-exact.** Feeding the model's reply back through restore
  reproduces the original spelling of every name, including case.

### 8.1 Two distinct operations

The product performs two transformations that must never be confused:

| Operation | Direction | Applies to | On restore |
|---|---|---|---|
| **Pseudonymization** | two-way | identity names, and any name the user promotes | replaced back with the real name |
| **Redaction** | **one-way** | secrets — API keys, tokens, passwords, connection strings, private keys, JWTs | **never** restored; the marker remains |

Restoring a live API key into AI-generated code would be both nonsensical and
dangerous. Secrets are never stored as identities and never enter the mapping
vault as plaintext.

---

## 9. Functional Requirements

### FR-1 Project Creation

The system shall create a local project containing:

- encrypted vault
- identity graph
- project settings — scope strategy, ignore rules
- custom terminology and allowlist
- session history

At creation the system shall warn if the project root or vault path lies inside a
known cloud-sync root, and offer to relocate the vault (see §10 Security).

**Priority:** Must

### FR-2 Import Artifacts

Supported formats (MVP):

| Format | Extensions |
|---|---|
| Markdown | `.md`, `.markdown`, `.mdown`, `.mkd` |
| Plain text | `.txt`, `.text`, `.log`, `.csv` |
| YAML | `.yaml`, `.yml` |
| JSON | `.json` |
| SQL | `.sql` |
| TypeScript / JavaScript | `.ts`, `.tsx`, `.mts`, `.cts`, `.d.ts`, `.js`, `.jsx`, `.mjs`, `.cjs` |
| OpenAPI | OpenAPI 3.x documents in YAML or JSON, recognized by content |
| PlantUML | `.puml`, `.plantuml`, `.pu`, `.iuml`, `.wsd`, or any file opening with `@start` |

Future: Java, Kotlin, C#, Python.

**Priority:** Must

### FR-3 Identity Detection

The system shall detect identity-bearing entities automatically, and shall detect
structural entities in order to scope and preserve them.

Identity categories, and the alias each takes:

| Type | Alias | Found how |
|---|---|---|
| Organization | `ORG_001` | dictionary |
| Product | `PRODUCT_001` | dictionary |
| Brand | `BRAND_001` | dictionary |
| Partner | `PARTNER_001` | built-in vendor table, dictionary |
| Payment Provider | `PAYMENT_PROVIDER_001` | built-in vendor table, dictionary |
| Person | `PERSON_001` | markers — `@author`, `Contact:`, `Reviewed-by:` — and dictionary |
| Tenant | `TENANT_001` | dictionary |
| Environment | `ENV_001` | dictionary |
| Domain | `DOMAIN_001` | hostname shape, dictionary |

Detection covers declarations, references, **comments, string literals, Markdown
prose, and diagram labels**. An identity is aliased inside the compound that
carries it: `VantorBillingService` becomes `ORG_001BillingService`, and
`src/vantor-billing/` becomes `src/ORG_001-billing/`.

Identity is **scoped**, and the scope differs by class:

- **Structure is scoped per file** — the identity key is
  `(scope_path, entity_type, real_name)`, so `customer_id` in two tables and
  `Status` in two modules are distinct identities. Scope resolution granularity
  is a project setting: `global` | `module` | `strict`.
- **Identity is scoped project-wide.** Your company is your company in every file
  that names it, and per-file scoping gave it two aliases in two documents — one
  organization presented to the model as two.

**Priority:** Must

### FR-3b Secret Detection and Redaction

The system shall scan every imported artifact for secrets **before** identity
extraction, using a regex rule pack plus a Shannon-entropy heuristic.

Matches are replaced with a non-restorable marker of the form
`<<REDACTED:TYPE>>`. The system stores only a salted hash of each match — never
the plaintext — for idempotency across rescans.

Secrets **block export in both modes**, strict and reporting, until the user
explicitly acknowledges each one. This is the one hard gate the product keeps
(cf. FR-4b).

> **Divergence from the revision, stated deliberately.** *SpecShield (PRD)
> Revised* §13 lists a `SECRET_001` alias pattern alongside the identity types.
> There is no such alias and there will not be one: an alias implies a restore
> path, and restoring a live credential into code a model wrote is not something
> to offer. The redaction marker stays.

Path segments are rewritten under this requirement too: only the identity-bearing
part of a directory or file name is replaced, so `src/vantor-billing/charge.ts`
becomes `src/ORG_001-billing/charge.ts` and the imports inside it still resolve.

**Priority:** Must

### FR-4 Sanitization

Generate an identity-neutral twin preserving:

- syntax and references
- imports and module resolution
- relationships
- document structure
- original formatting, comment placement, and key ordering
- **the architecture** — code structure, SQL schema, class hierarchy, business
  logic (§4.1)

The twin must remain valid, parseable code and valid documentation.
Specifically, the twin **must parse**, and its structural fingerprint must match
the original's. Where a transformation cannot meet this bar, the affected file is
left unaliased **and reported**, rather than emitted in a broken state.

**Priority:** Must

### FR-4b Export Verification Gate

No content leaves the application — clipboard, file export, or patch — without
passing verification:

1. Scan the twin for every `real_name` in the vault, including generated case
   variants (camelCase, PascalCase, snake_case, kebab-case, SCREAMING_CASE,
   spaced, pluralized).
2. Report every hit with file, line, and matched term.
3. Re-run the secret detector over the twin as an independent second pass.
4. Display a state that names both what was checked and what was **not** checked
   (per §4.3).

**Two modes, and the default changed in v2.0.**

| Mode | Behaviour | For |
|---|---|---|
| **Reporting** *(default)* | Writes the twin and lists what survived | A developer getting work done |
| **`--strict`** | Refuses to write | CI, and teams that want the old behaviour |

A hit is not automatically wrong: the detector may have missed an occurrence, or
the name may be one the team does not mind sharing. `specshield allow "<name>"`
settles the second case permanently. Every allowed name is counted on each
export, so an open gate is never silent.

Secrets are the exception and block in both modes (FR-3b).

**Priority:** Must

### FR-5 Mapping Vault

Store encrypted mappings locally.

Each identity contains:

- UUID
- scope path
- real name
- alias
- entity type
- origin — detected, manual, or AI-introduced
- status — active, excluded, unresolved

Occurrences (file, byte range, kind) are stored separately and support the diff
viewer, incremental rescan, provenance, `specshield where`, and the verification
gate.

The vault is versioned and migrated. No cloud synchronization.

**Priority:** Must

### FR-6 Restore Response

The user shall paste AI output and press **Restore**.

The system replaces every known placeholder with its original identifier while
preserving all newly generated content.

Restoration operates lexically over a closed alias vocabulary, so it tolerates
code fragments, unified diffs, Markdown-wrapped responses, and syntactically
invalid input. Alias matching is normalized to survive model drift (`Org001`,
`org_001`, `ORG-001`, `ORG_001s`), and an alias embedded in a token it was
substituted into — `ORG_001BillingService` — is found and restored. Every
non-exact match is restored **and flagged** for review; every alias-shaped token
matching nothing is reported as an unresolved identity.

**Priority:** Must

### FR-6b Prompt Envelope Generator

Alongside the twin, the system shall generate and copy a short instruction
preamble telling the model that placeholders are opaque, must be preserved
verbatim, and that new entities must be named `NEW_<n>` and listed.

Restore reliability depends substantially on the model having been given this
instruction.

**Priority:** Should

### FR-7 Twin Diff

Display side-by-side comparison:

- Twin version
- Restored version
- Added / Modified / Deleted

Fuzzy-restored aliases and unresolved identities are called out inline.
Formatting-only changes are suppressed where possible.

The system shall detect when the twin is **stale** — the real files have changed
since it was generated — and require an explicit rescan before any patch derived
from it is applied.

**Priority:** Must

### FR-8 Git Integration

Generate restored patches instead of overwriting files.

The system shall:

- generate a unified diff
- dry-run the patch before applying it
- apply only onto a new branch, never onto the current checked-out `main`
- support undo
- degrade gracefully with a clear message when Git is not available

The system shall preserve Git history.

**Priority:** Should

### FR-9 Local Audit Log

The system shall maintain an append-only local log recording: timestamp, project,
operation, file count, entity count, verification result, and export destination
(clipboard, file, or patch).

The log never contains real names or artifact content, and is never transmitted.
It is exportable as CSV for compliance review.

This is distinct from telemetry, which the product does not have.

**Priority:** Should

### FR-10 Manual Entity Control

The user shall be able to add, rename, exclude, and merge entities, and mark any
term as **never alias**.

`specshield term <name> --entity-type <type>` promotes any name — including a
structural one — to an identity that is aliased from then on. This is the
mechanism by which §4.1's default is overridden, and it is the reason preserving
structure is a default rather than a limitation.

The system ships with a stop-list of common framework, library, and tooling names
(React, Express, Postgres, Kubernetes, …) that are never aliased. The stop-list
and the vendor table (§13) are opposites, and the question that separates them is
*do you have an account with them?*

False positives are inevitable; without this requirement the twin becomes
unreadable.

**Priority:** Must

### FR-11 Vault Backup, Escrow, and Re-Key

The system shall support:

- encrypted vault backup and restore
- passphrase-protected key escrow export, with an explicit warning that key loss
  is unrecoverable
- alias renumbering — reissuing all aliases, for use when a twin has been
  over-shared

**Priority:** Should

### FR-12 Project Ignore Rules

The system shall respect `.gitignore` and a project-level `.specshieldignore`,
and shall exclude binary files, lockfiles, and vendored dependency trees by
default.

**Priority:** Must

---

## 10. Non-Functional Requirements

### Security

- Local-only execution
- AES-256-GCM encrypted vault, per-value, with the identity key bound as
  additional authenticated data
- **Key management:** the vault key is held in the operating system credential
  store (Windows DPAPI / Credential Manager, macOS Keychain, Linux Secret
  Service) and never written to disk in plaintext. An optional user passphrase
  derives a key-encryption key via Argon2id. All key material is zeroized in
  memory after use.
- **Cloud-sync detection:** the application warns when the project root or vault
  path lies inside a OneDrive, Dropbox, Google Drive, or iCloud tree, and offers
  to relocate the vault to a local-only path.
- **Clipboard hardening:** on Windows, payloads are marked with the three opt-out
  clipboard formats — `ExcludeClipboardContentFromMonitorProcessing`,
  `CanIncludeInClipboardHistory`, and `CanUploadToCloudClipboard`, the last of
  which governs cross-device sync to the user's Microsoft account. The clipboard
  is cleared after a timeout, and only if it still holds SpecShield's own payload.
  Original, unsanitized content is never placed on the clipboard by any UI
  affordance.

  These formats are advisory: a cooperating OS and clipboard manager honour them,
  and one that ignores them still captures the text. macOS and Linux opt-outs are
  not implemented, and the audit log records which exports were protected and
  which were not.
- No telemetry, no analytics, no auto-update network dependency
- No internet required — enforced by a network-capability-free application
  configuration and verified by an egress-blocked test in CI
- No cloud storage

### Performance

Measured on the reference machine defined in SDD §18.

- Startup under 2 seconds
- Cold indexing of a 1,000-file / ~150k-LOC project under 30 seconds
- Incremental rescan under 2 seconds
- Sanitize a 100-page PRD under 10 seconds
- Restore a pasted response under 3 seconds

### Reliability

- Deterministic aliases — the same vault always produces the same alias for the
  same identity, and renumbering is an explicit operation (FR-11)
- Lossless restoration, verified as a property test over the golden corpus
- Atomic restore and patch operations, with undo
- No destructive operations: on parser failure the original file is preserved
  unmodified

### Usability

- Drag & drop import
- One-click sanitize, verify, and copy
- One-click restore
- No command line required

---

## 11. Identity Graph

Every software artifact belongs to a semantic graph rather than a text
dictionary.

Example node:

| Field | Value |
|---|---|
| ID | UUID |
| Scope Path | `identity` |
| Alias | `ORG_001` |
| Real Name | `Vantor` |
| Type | Organization |
| Origin | manual |
| Status | active |

Relationships (`uses`, `writes`, `exposes`) are **specified and not built** — see
SDD §5. The `edges` table was dropped in schema v4 rather than kept empty. What
*is* recorded is where each identity appears (FR-5), which the extractor produces
as a by-product of aliasing it; what uses what is a separate analysis no parser
performs yet.

The graph guarantees consistent anonymization across documents and code: an
organization named in a PRD, in a diagram label, and in a directory name resolves
to a **single** identity carrying a single alias.

Aliases are unique within a project by construction, because they are allocated
from a per-type counter held in the vault. Restoration is therefore never
ambiguous, even for a bare code fragment with no file context.

**One known limit.** `Vantor` and `vantor` are separate identities with separate
numbers. Restore is byte-for-byte, so an alias maps to exactly one spelling, and
sharing a number would return one of the two in the wrong case. Fixing it means
an alias grammar that carries case, which changes the format §13 publishes and
the shape the export gate looks for.

---

## 12. User Workflow

### Workflow A — PRD to ChatGPT

1. Import PRD
2. Detect identities and secrets
3. Review — accept, rename, exclude, never-alias
4. Sanitize
5. **Verify** — the export gate reports what survived
6. Copy twin + prompt envelope
7. Paste into ChatGPT
8. Paste response into SpecShield
9. Restore, reviewing fuzzy matches and unresolved identities

### Workflow B — Repository to Codex

1. Import repository
2. Create the identity-neutral twin
3. Verify and export the twin project
4. Open the twin in Codex
5. The agent generates code against the real architecture
6. Review the twin diff
7. Resolve unresolved identities
8. Restore, generate patch, dry-run, apply to a branch
9. Commit to Git

---

## 13. Identity Alias Rules

Aliases are **sequential, human-readable, and allocated per vault**.

| Entity | Pattern |
|---|---|
| Organization | `ORG_###` |
| Product | `PRODUCT_###` |
| Brand | `BRAND_###` |
| Partner | `PARTNER_###` |
| Payment Provider | `PAYMENT_PROVIDER_###` |
| Person | `PERSON_###` |
| Tenant | `TENANT_###` |
| Environment | `ENV_###` |
| Domain | `DOMAIN_###` |

Structural types have prefixes too — `SERVICE`, `API`, `ENDPOINT`, `DB_TABLE`,
`COLUMN`, `DTO`, `IFACE`, `ENUM`, `EVENT`, `INDEX`, `ENV_VAR`, `PATH` — and are
used only for names the user has promoted under FR-10. Note that `ENV` is an
*environment* and an environment **variable** is `ENV_VAR`.

```text
Acme Bank  →  ORG_001
```

**This reverses v1.1.** Aliases were HMAC-derived from a project key so that two
machines sharing that key produced identical twins, and there were three
selectable styles (opaque, typed, pseudonymous). Both are gone. Sequential
numbers are what a person can hold in their head while reading a twin and a
diff, and §15 now says plainly that cross-machine alias compatibility is out of
scope rather than quietly solved.

**The built-in vendor table.** Partner and Payment Provider are the two identity
categories that can be found without being told, because unlike `Vantor` these
names are the same in every company that uses them. SpecShield ships a fixed,
reviewable table of roughly fifty commercial services — payment processors,
messaging, identity, observability, business systems. The line against the
stop-list (FR-10) is *do you have an account with them?* `Postgres` and `React`
are tooling and are never aliased; `Stripe` and `Auth0` are commercial
relationships and are. Vendors whose names are ordinary English words in other
contexts are deliberately absent and must be named with `specshield term`.

---

## 14. Security Boundaries

**Never leaves the device**

- Source code, PRDs, SQL, OpenAPI, diagrams — in their original form
- The mapping vault
- Original identities
- Secrets, in any form

**May leave**

Only the identity-neutral twin the user explicitly copies or exports — which
carries the architecture (§4.3).

---

## 15. Out of Scope (MVP)

- PDF OCR
- DOCX editing
- Java, Kotlin, C#, Python parsers
- BPMN and ER diagrams
- Multi-user collaboration and vault merge workflows
- Cloud synchronization
- IDE plugins
- Local LLM inference
- Automatic secret rotation
- Automatic naming of AI-introduced entities

**Cross-machine alias compatibility is out of scope**, and in v2.0 it is out of
scope rather than solved. Aliases are allocated from a counter in each vault, so
two developers importing the same project produce different twins. Sharing the
vault is the supported answer; deriving aliases from a shared key is not, and the
readability of a sequential number was judged worth more than the property
(§13).

---

## 16. MVP Deliverables

### Included

- Local desktop application and CLI
- Encrypted project vault with OS-keychain key management
- Scoped identity graph, project-wide for identity and per-file for structure
- Identity detection across Markdown, text, YAML, JSON, SQL, OpenAPI, TypeScript
  and PlantUML
- Built-in vendor table and person markers, so the tool finds something before
  the user types anything
- Identity-neutral twin generation with structural verification
- Secret detection and one-way redaction
- Export verification gate, reporting by default and refusing under `--strict`
- Prompt envelope generator
- Bidirectional restoration with fuzzy matching and unresolved reporting
- Twin diff viewer with staleness detection
- Git patch generation
- Local audit log

### Excluded

- Multi-user projects and team collaboration tooling
- VS Code and JetBrains plugins
- GitHub integration
- Cloud accounts
- Local LLM inference

---

## 17. Risks

| Risk | Mitigation |
|---|---|
| AI renames or reformats placeholders | Prompt envelope (FR-6b), formal alias grammar, normalizing fuzzy matcher, unresolved reporting — never a silent guess |
| Broken imports or references | Structural verification after every sanitize; fall back to leaving the file unaliased and reporting it |
| Missed identities | Export verification gate (FR-4b), manual review, recall measured in CI |
| **Structure preserved is structure disclosed** | Stated as residual risk (§4.3, §4.4) rather than mitigated. It is the deliberate trade the product makes |
| False positives make the twin unreadable | Stop-list and allowlist (FR-10), precision target in CI, structure exempt by default |
| A name the tool cannot guess | `specshield term`, and a report that names what it left behind rather than staying silent |
| Large repositories | Incremental indexing, gitignore-aware walking, parallel parsing |
| TypeScript scope resolution without a type checker | Heuristic scoping validated by spike; limitation stated explicitly; compiler-API sidecar deferred to V1.1 |
| Vault key loss | Key escrow export with explicit warning |
| Vault synced to cloud storage by the user's environment | Startup detection and relocation offer |

---

## 18. Technical Architecture

See **SDD §21 Technology Stack** for the authoritative stack table. It is not
duplicated here so the two documents cannot drift.

---

## 19. Product Positioning

**SpecShield is not a DLP product.**

It is a developer productivity and security tool that lets organizations adopt
agentic software development by anonymizing business identity while preserving
complete architectural understanding for the agent — and by showing, artifact by
artifact, what it did and what it did not.
