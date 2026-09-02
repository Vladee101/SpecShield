# SpecShield — User Guide

**Version 1.0**

SpecShield lets you use a commercial LLM on proprietary material by replacing
your identifiers with stable aliases, and rewriting the model's answer back into
real names.

Read the box below before anything else. It is the one thing that will get
someone in trouble.

> **SpecShield removes names, not meaning.** The twin still says what your code
> does — the business rules, the algorithms, how many services there are and how
> they relate. `SERVICE_014 charges a 3% commission on ORG_007 payouts for EU
> customers above EUR 10k` has every name aliased and still gives away the whole
> arrangement.
>
> If the *logic* is your secret, do not send it to a commercial LLM, with or
> without this tool.

---

## 1. Two ways to work

**Workflow A — one document.** Paste a PRD or a file in, get a twin, copy it to a
model, paste the answer back. This is the desktop app's main path, and it works
for anything: specs, prose, a single source file.

**Workflow B — a repository.** Index a project, export the whole tree as a twin,
work on it with a model, then review the changes as a diff and apply them as a
git patch on a branch. This is the command line's main path.

Both use the same engine and the same vault.

---

## 2. Getting started

### Create a project

```bash
cd /path/to/your/project
export SPECSHIELD_PASSPHRASE='choose something long'
specshield init . --alias-style typed
```

This creates `.specshield/vault.bin`. **Add `.specshield/` to your
`.gitignore`** — it holds the mapping from every alias back to a real name.

Three alias styles, fixed at creation:

| Style | Looks like | Trade |
|---|---|---|
| `opaque` | `SERVICE_H7K2Q3` | Strongest. Hardest for a model to reason about. |
| `typed` *(default)* | `PrimaryService_H7K2Q3` | Keeps a generic category. Recommended. |
| `pseudonymous` | `AuroraService` | Most readable. Weakest protection. |

Changing the style later means a re-key, which changes every alias (§8).

### Two things about the passphrase

**It cannot be recovered.** Nothing about it is stored anywhere. Lose it and the
vault is unreadable, permanently — every twin you have ever produced becomes
unrestorable. Do §7 (backup and escrow) today, not later.

**Prefer the environment variable over `--passphrase`.** Command-line arguments
are visible to other users on the machine in the process list.

### Teach it your names

This step is not optional, and it is the one people skip.

```bash
specshield term "Vantor" --entity-type organization
specshield term "Meridian Freight" --entity-type organization
```

No rule can recognise `Vantor` as a company name. It is found because you said
so. Once entered, it is found everywhere, in every file, forever — including in
prose, comments, and string literals.

**A proprietary name you never enter, and that never appears as a declaration in
code, is protected by nothing.** Spend twenty minutes on this before real work.

Entity types: `organization`, `service`, `api`, `endpoint`, `table`, `column`,
`dto`, `interface`, `enum`, `event`, `index`, `env-var`, `host`, `path-segment`.

---

## 3. Workflow A — one document

### See what would happen

```bash
specshield scan docs/PRD.md
```

Shows what would be aliased, what is only a suggestion, and any secrets found.
Writes nothing.

### Produce the twin

```bash
specshield sanitize docs/PRD.md --out /tmp/PRD.twin.md --envelope
```

`--envelope` prints a short instruction telling the model to preserve alias
tokens exactly. Include it with your prompt; it measurably reduces drift.

If the export is **blocked**, you get no twin at all — see §9.

### Bring the answer back

```bash
specshield restore response.md > restored.md
```

Read what it reports. Three things are worth your attention:

- **Fuzzy matches.** The model changed a token slightly and it was matched by
  normalization rather than exactly. That is a good guess, not a certainty, and
  it just wrote a real name into your text.
- **Unresolved identities.** The model invented an entity — an alias-shaped token
  nobody issued. It is left exactly as it is. Name it with `specshield resolve`
  (§5) if you want it restored.
- **Redaction markers.** `<<REDACTED:api_key>>` stays. Secrets are one-way and
  never come back; put the real value in yourself.

---

## 4. Workflow B — a repository

```bash
specshield index .                    # walk, hash, record
specshield export ../project-twin     # sanitize every file into a twin tree
```

The export writes nothing unless **every** file passes the gate — a directory
that is clean apart from one leak is not clean.

Filenames and directories are aliased too, and consistently with the imports
inside the files, so the twin still resolves as a project:

```
src/domain/customer-subscription.ts   →   src/domain/PATH_4Y1B5S.ts
import "../domain/customer-subscription"  →  import "../domain/PATH_4Y1B5S"
```

Work on the twin with your model. Then, per file:

```bash
specshield diff src/services/billing.ts --ai response.ts
```

You get two things kept deliberately separate: what the **model** changed, and
what would land in **your repository** after restoring. A line that differs only
because restore matched loosely is a very different thing from a line the model
rewrote.

Then apply:

```bash
specshield apply src/services/billing.ts --ai response.ts --dry-run
specshield apply src/services/billing.ts --ai response.ts
```

This creates `specshield/restore`, applies the patch there, and leaves you to
review with `git diff` and commit normally. It will never apply to `main`,
`master`, `develop`, or `trunk`.

`specshield undo` reverses the last patch.

### What blocks an apply

- **An unresolved identity.** Applying would write an alias into your source as a
  name nobody chose. Name it first (§5).
- **A stale file.** The file changed since it was indexed, so this twin was made
  from content that no longer exists. Applying could succeed *cleanly* and
  silently revert whatever was edited in between. Re-sanitize and re-run the
  request.
- **No git.** The restored content is written to `<file>.restored` and your
  original is untouched. Move it yourself.

### Excluding files

`.gitignore` is respected. For things git tracks but you never want in a twin —
a committed vendor tree, generated files — add `.specshieldignore`, same syntax:

```
vendor/
*.generated.ts
```

---

## 5. When the model invents something

The model writes `class SERVICE_099 {}`. No such alias was ever issued.
SpecShield will not guess what it meant, because a guessed name is a wrong
identifier committed to your repository.

```bash
specshield resolve SERVICE_099 --name RetryPolicy --entity-type service
```

The token now maps to `RetryPolicy` permanently. Re-run the diff and it restores.

---

## 6. Cross-artifact concepts

The SQL table `customer_subscription`, the OpenAPI schema `CustomerSubscription`,
and the TypeScript DTO are one thing seen from three sides. SpecShield can make
that visible to the model:

```bash
specshield unify                                   # list proposals
specshield unify --confirm customersubscription    # accept one
```

Confirmed members share an alias *suffix* with different prefixes —
`DB_TABLE_MS7JMB`, `DTO_MS7JMB` — so a model sees the connection while restore
stays unambiguous.

**Nothing is ever unified without confirmation.** Three unrelated `Status` enums
in three modules share a name and are three different things; merging them on
name alone would be wrong and would lose data.

---

## 7. Backup, escrow, recovery

Do these on day one.

```bash
specshield backup ~/secure/project.vault.backup
specshield escrow ~/secure/project.escrow --escrow-passphrase 'held by security'
```

The **backup** is a consistent encrypted copy, opened by the same passphrase. It
is not a second factor: whoever has it and the passphrase has the mapping.

The **escrow** file holds the vault passphrase itself, sealed under a second,
separate passphrase. Give it to whoever holds recovery responsibility — they can
get back in without knowing your passphrase. That also means they can get *all*
the way in; there is no partial access.

To use them:

```bash
specshield restore-vault ~/secure/project.vault.backup --into .specshield/vault.bin
specshield escrow-open ~/secure/project.escrow --escrow-passphrase 'held by security'
```

Neither ever writes over an existing vault.

### When the vault will not open

```bash
specshield recover
```

Read-only, needs no passphrase, and tells you what is wrong: a wrong passphrase,
a corrupt file, or a vault from a newer version. It reports how many identities
and files the vault holds and shows the audit log. **It reveals no real names** —
it is a diagnosis, not a way in — and it cannot modify the file it is inspecting.

---

## 8. Re-keying

If a twin has been shared more widely than intended:

```bash
specshield rekey             # shows what would happen
specshield rekey --confirm   # does it
```

Every alias in the project changes. **Every twin you have already shared becomes
unrestorable** — that is the point when a twin has escaped, and a disaster
otherwise. Back up first. It will not run without `--confirm`.

Re-keying does nothing to submissions already made. Those twins are still in the
provider's logs exactly as sent; what changes is that they no longer connect to
anything you produce from now on.

---

## 9. When an export is blocked

```
EXPORT BLOCKED — 2 real name(s) survived into the twin:
  src/billing.ts:22:11  "Vantor"
```

You get **no twin**. This is the tool working: something the vault knows to be a
real name was still present in the output.

Usually one of:

- **A name in prose or a comment** the parser did not treat as an identifier. The
  gate caught it in the output, which is exactly its job.
- **A name inside a compound**, like `old_vantor_id`. `_` and `-` are word
  boundaries for this scan.
- **A common word that is also one of your table names.** If `invoice` is a table,
  the word "invoice" in a sentence is flagged. If that is wrong for you, add it to
  the allowlist.

There is no override that emits the twin anyway.

---

## 10. Using `verify` as a CI gate

```bash
specshield verify build/output.md
```

Exit `0` clean, `1` on a leak, `2` if there was **nothing to check**.

That third one matters. A name is interned the first time it is aliased, so a
project where nothing has been sanitized yet has no names for the gate to look
for — and a gate that scans zero patterns would otherwise report "clean" and go
green having checked nothing. It exits `2` and says so instead.

In CI, run `specshield export` (or a `sanitize`) before `verify`, and treat any
non-zero exit as a failure.

---

## 11. Audit

```bash
specshield audit
specshield audit --csv > audit.csv
```

Records that operations happened — when, which, how many files and entities, the
verification result, where the output went. **No names, no content**, never
transmitted. It is for answering "what left this machine and when", and it is
readable even when the vault is not.

This is not telemetry. There is none.

---

## 12. Habits worth having

1. **Populate the dictionary first.** The single highest-value twenty minutes.
2. **Keep the vault out of OneDrive, Dropbox, iCloud, or Google Drive.** The tool
   warns you; the warning is real — the vault would be uploaded to a third party.
3. **Back up and escrow on day one.** There is no passphrase recovery.
4. **Send the envelope with the twin.** Fewer drifted tokens to review.
5. **Read the fuzzy matches.** They are guesses that wrote real names.
6. **Review the patch in a pull request.** The branch guard makes sure you can;
   it cannot make you.
7. **Ask yourself whether the logic is the secret.** If it is, this tool is not
   the control you need.

---

## 13. Command reference

| Command | What it does |
|---|---|
| `init` | Create a project vault |
| `term` | Add a name to the dictionary |
| `scan` | Report what would be detected; write nothing |
| `sanitize` | Produce and verify a twin for one file |
| `verify` | Run the export gate over a file; exit 1 on a leak, 2 if nothing could be checked |
| `restore` | Rewrite AI output back into real names |
| `unify` | List or confirm cross-artifact concepts |
| `index` / `rescan` | Walk and hash the project; report what changed |
| `export` | Sanitize the whole project into a twin tree |
| `diff` | Three-way review of what AI output would change |
| `resolve` | Name an entity the model invented |
| `apply` / `undo` | Apply the restored change as a git patch, or reverse it |
| `audit` | Show or export the local audit log |
| `backup` / `restore-vault` | Copy the vault; put a copy back |
| `escrow` / `escrow-open` | Export and use a key escrow |
| `rekey` | Regenerate every alias under a new key |
| `recover` | Inspect a vault that will not open |
| `report` | Detection metrics against the golden corpus |

Every command takes `--project <path>` (default `.`) and `--passphrase`, though
`SPECSHIELD_PASSPHRASE` is preferred.

---

*Security detail: `docs/Security Review One-Pager.md`, `docs/Threat Model.md`,
and `docs/Residual Risk.md`.*
