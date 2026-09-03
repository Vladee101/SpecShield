# SpecShield — Desktop User Guide

**Version 1.0 · the application, not the command line**

The desktop app does everything the command line does, bar one CI tool (§12).

Five numbered steps handle one document at a time: paste in, copy out, paste the
answer back. Three tabs beside them handle the repository, the audit log, and the
vault itself.

The [User Guide](User%20Guide.md) covers the same ground from the command line.

Read the box first. It is the one thing that gets people in trouble.

> **SpecShield removes names, not meaning.** The twin still says what your code
> does — the business rules, the algorithms, how the pieces relate. Every name in
> `SERVICE_014 charges a 3% commission on ORG_007 payouts for EU customers above
> EUR 10k` is aliased and the sentence still gives away the arrangement.
>
> If the *logic* is your secret, do not send it to a commercial LLM, with or
> without this tool.

---

## 1. The layout

The bar across the top is the workflow, in order, and then the tools:

| | Step | What happens |
|---|---|---|
| 1 | **Project** | Create or open a vault |
| 2 | **Review** | See what would be aliased; teach it your names |
| 3 | **Sanitize & verify** | Produce the twin, pass the gate, copy it |
| 4 | **Restore** | Paste the model's answer back |
| 5 | **Diff & apply** | Review the change and apply it as a git patch |
| — | **Whole project** | Index, export a twin tree, unify concepts, find where a name is used, list secrets, check anything |
| — | **Audit log** | What this project recorded, and CSV export |
| — | **Vault** | Backup, escrow, re-key, recovery |

Steps 1–4 are the everyday loop. Step 5 is for when the answer should land in a
real file in a real repository. The three tools are unnumbered because they are
not part of the sequence.

You can move between steps freely; the document you loaded in step 2 stays
loaded through step 3, which is deliberate. An earlier version kept a separate
copy per screen, and it was possible to review one document and sanitize
whatever you happened to paste next.

---

## 2. Step 1 — Project

**Project folder** is a path on disk, e.g. `C:\work\billing`. The vault is
created inside it at `.specshield\vault.bin`.

**Passphrase** derives the vault key. Two things to know:

- **It cannot be recovered.** Nothing about it is stored anywhere. Lose it and
  every twin you have produced becomes unrestorable, permanently.
- Make a backup and an escrow today, on the **Vault** tab (§11).

**Alias style** is fixed at creation:

| Style | Looks like | Trade |
|---|---|---|
| Opaque | `SERVICE_H7K2Q3` | Strongest. Hardest for a model to reason about. |
| Typed *(default)* | `PrimaryService_H7K2Q3` | Keeps a generic category, hides the subject. Recommended. |
| Pseudonymous | `AuroraService` | Most readable. Weakest protection. |

Press **Create new** for a new project, **Open** for an existing one.

### The cloud-sync banner

If the project sits in OneDrive, Dropbox, Google Drive, or iCloud, a warning
appears at the top of the window and stays there.

Take it seriously. A vault in a synced folder is uploaded to a third party, and
the vault is the mapping from every alias back to every real name — the single
most sensitive artifact the tool produces. Move the project somewhere local.

The header also shows the project name, the alias style, and how many identities
the vault holds. **Close** locks the vault and drops the keys from memory.

---

## 3. Step 2 — Review

This screen answers "what would happen", and writes nothing.

**Open file…** picks a file from disk and fills in both the name and the
content. Or paste the content and give it a **filename** yourself — the name is
what decides which parser is used, so `schema.sql` is parsed as SQL and `PRD.md`
as Markdown.

Then press **Scan**.

You get three lists.

**Entities** — what would be aliased, with the type and the confidence. These are
above the confidence floor and will be applied.

**Suggestions — not applied.** Below the floor. Two buttons each:

- **Confirm** adds it to the dictionary using the type the detector worked out,
  so it is aliased everywhere from now on.
- **Never alias** adds it to the allowlist, so it is left alone everywhere —
  and the export gate stops looking for it too. Both halves, or the name would
  survive into the twin and block every export from then on. This is the only
  way the gate opens, so be deliberate: an allowlisted name can leave in a twin.

Neither is a guess on the tool's part. Nothing in this list is aliased unless you
say so.

**Secrets — redacted one-way.** API keys, tokens, connection strings. These are
**not** aliased; they are replaced with `<<REDACTED:type>>` and there is no way
back. A secret that could round-trip would be a secret this tool had carried back
into your file after a model saw it.

### The Dictionary box — the most important thing on this screen

```
[ a name only you can identify, e.g. your company ]  [ ORG ▾ ]  [ Add ]
```

No rule can recognise `Vantor` as a company name. It is found because you said
so. Once added it is found everywhere — in code, in prose, in comments, in string
literals — in this document and every future one.

**A proprietary name you never add, and that never appears as a declaration in
code, is protected by nothing.** Spend twenty minutes here before real work.
This is the single highest-value thing you can do with the application.

---

## 4. Step 3 — Sanitize & verify

Press **Sanitize**. One of two things happens.

### It passes

You see the twin, how many identities were applied, how many patterns the gate
checked, and — importantly — a **"not checked"** list. That list is what
SpecShield did *not* protect: business logic in prose, algorithms, architecture
shape. It is shown on every success on purpose, because it is the part people
forget.

Two copy buttons:

- **Copy twin + prompt envelope** — recommended. The envelope is a short
  instruction telling the model to preserve alias tokens exactly, which
  measurably reduces drift and therefore how much you have to review later.
- **Copy twin only**.
- **Save twin…** writes it to a file you choose. Like the copy buttons, this
  reads the twin from the application's own memory rather than taking it from
  the interface — there is no path by which the screen could write *original*
  content to a file you think holds a twin.

The clipboard is cleared after two minutes, and only if it still holds
SpecShield's payload — clearing unconditionally would destroy whatever you copied
since.

> **Windows clipboard note.** The payload carries three flags that tell Windows
> not to put it in clipboard history or sync it to your Microsoft account. They
> are honoured by Windows and by well-behaved clipboard managers. A clipboard
> manager that ignores them will still capture the twin. The twin has passed the
> gate, so that is aliased content — but on a machine with an aggressive
> clipboard tool, assume it was logged.

### Names survived into it

```
The gate found vault names in the twin. **You still get the twin** — the banner is
amber, lists what it found, and leaves the decision to you. An unredacted secret
is different: that banner is red and there is no twin at all, in either mode.
```

**You get no twin at all.** It is not shown and cannot be copied — there is no
override.

The table lists what leaked and where. Usually one of:

- A name in prose or a comment that the parser did not treat as an identifier.
  The gate caught it in the output, which is exactly its job.
- A name inside a compound like `old_vantor_id`. `_` and `-` are word boundaries
  for the scan.
- A high-confidence secret still present in the twin.

Fix the document or add the term, and sanitize again.

### The structural check

Below the twin you will see one of:

- *structure verified against the original* — the twin was re-parsed and has the
  same shape. This is what you want.
- *structure NOT checked* — the format has no structure to compare.
- *aliasing ABANDONED* — the twin no longer parses, so **the original was emitted
  unchanged**. Nothing was aliased. Do not send it.

---

## 5. Step 4 — Restore

Paste whatever the model returned — a whole file, a fragment, a diff, prose with
code in it. Restoration is lexical, so none of it needs to parse.

Press **Restore**. Three things deserve your attention:

**Review these.** The model changed a token slightly and it was matched by
normalization rather than exactly — `SERVICE_H7K2QXImpl` back to
`CustomerService`. That is a good guess with evidence, not a certainty, and it
just wrote a real name into your text.

**Unresolved identities.** Alias-shaped tokens the vault never issued: the model
invented an entity. They are left exactly as they are. SpecShield never guesses a
name into your work, because a guessed name is a wrong identifier you then commit.

**Redaction markers.** `<<REDACTED:api_key>>` stays. Put the real value back
yourself.

---

## 6. Step 5 — Diff & apply

This screen turns an AI response into a change in a real file, with review.

It needs three things: the **original** (the document from step 2), the **twin**
that was sent (carried over automatically from step 3 — if you have not sanitized
in this session it asks you to paste it), and the **response**.

Press **Review**.

### Reading the diff

Each hunk shows added lines with `+` and removed lines with `−`, and is labelled
`added`, `removed`, `changed`, or **`formatting only`**. That last one means the
text is identical once whitespace is normalized — a model that reindented your
file produces a patch touching every line, and you should be able to see that is
all it did before deciding to throw it away.

The counters distinguish two different things: **changes** are what would land in
your repository, **model-side edits** are what the model actually did. A line
that differs only because restore matched loosely is not the same as a line the
model rewrote.

### "Everything worth checking"

A table of every note, including ones that fall inside no hunk. This matters more
than it sounds: a fuzzy match can restore to text *identical* to the original and
produce no visible change at all. The guess still happened and still wrote a real
name. Those cases are exactly the ones you would otherwise never see.

### Naming what the model invented

If there are unresolved identities you get a table with a field for each. Fill in
the real name, pick the type, press **Name it**. No suggestion is offered and no
default filled in — a plausible-looking guess is how a wrong identifier ends up
committed.

The review re-runs, and the token now restores.

### Applying

The **Apply** panel either offers a branch name or explains why it cannot
proceed:

- *Unresolved identities remain* — name them first.
- *`<file>` is not a file under the project root* — the filename must be a real
  path relative to the project folder.
- *This file has changed since it was indexed* — the twin was made from content
  that no longer exists. Applying could succeed **cleanly** and silently revert
  whatever was edited in between.
- *git is not available* — patch mode is off.

When it can proceed, it names the branch (default `specshield/restore`) and warns
if your working tree is dirty, because **Undo** reverses the patch and will fail
if your own edits overlap it.

**Apply to branch** dry-runs the patch first, creates the branch, and applies it.
It will never apply to `main`, `master`, `develop`, or `trunk` — the review that
catches a wrong identifier happens in a pull request, and a patch applied to
`main` has skipped it.

Then review with `git diff` and commit normally. **Undo** reverses it and removes
the branch if SpecShield created it.

---

## 7. What the app protects, in one place

- Only a twin that passed the gate can be copied. The copy command reads it from
  the app's own memory and takes no text argument, so there is no path by which
  the interface can put original content on your clipboard.
- The application has **no network capability at all** — not disabled, not
  configured off; never granted. Its entire permission list is three entries, one
  of which is write-only clipboard access.
- Every guard is enforced in the engine, not in the interface. Buttons are
  disabled as a courtesy; the checks behind them run again regardless.

---

## 8. Habits worth having

1. **Fill the dictionary before real work.** Everything else depends on it.
2. **Heed the cloud-sync banner.**
3. **Make a backup and an escrow today** (command line, §9). There is no
   passphrase recovery.
4. **Send the envelope with the twin.** Fewer drifted tokens to review.
5. **Read the fuzzy matches.** They are guesses that wrote real names.
6. **Read the "not checked" list** at least once, properly.
7. **Ask whether the logic is the secret.** If it is, this is not your control.

---

## 9. Whole-project work

Everything in §3–§6 handles one document. The **Whole project** tab handles the
repository, and runs the same pipeline the command line does.

### Index and rescan

**Index project** walks the tree, hashes every file, and records the checksums.
`.gitignore` and `.specshieldignore` are both respected — the second is for
things git tracks but you never want in a twin, like a committed vendor tree.

**Rescan** says what moved, and — the point of the exercise — which recorded
twins are now **stale**. A stale twin was made from content that no longer
exists, and a patch built from one can apply *cleanly* while silently reverting
whatever was edited in between.

### Export a twin project

Sanitizes every file into a new directory. Filenames and directories are aliased
too, consistently with the imports inside the files, so the twin still resolves
as a project:

```
src/domain/customer-subscription.ts   →   src/domain/PATH_4Y1B5S.ts
import "../domain/customer-subscription"  →  import "../domain/PATH_4Y1B5S"
```

**Nothing is written unless every file passes the gate.** A directory that is
clean apart from one secret is not clean, so a refused export leaves no partial
tree behind.

**Restore a twin project** is the inverse: every file back at its real path. It
works only because the vault recorded the mapping when the twin was exported.

### Cross-artifact concepts

The SQL table, the OpenAPI schema, and the TypeScript DTO can be one thing seen
from three sides. Confirming a concept gives them a shared alias *suffix* with
different prefixes — `DB_TABLE_MS7JMB`, `DTO_MS7JMB` — so a model sees the
connection while restore stays unambiguous.

**Nothing is unified without confirmation.** A name match is not evidence: three
unrelated `Status` enums share a name and are three different things.

Confirming re-derives the affected aliases, which orphans any twin already sent.

### Check anything

Runs the export gate over text that did not come from Sanitize — a file edited by
hand, or a fragment about to be pasted somewhere.

If it says **nothing was checked**, that is not the same as clean: the project has
no identities yet, so the gate had nothing to look for. A dictionary term is not
enough — a name is interned the first time it is aliased.

---

## 10. Audit log

Everything the application recorded: when, which operation, how many files and
entities, the verification result, and where the output went. **No names, no
content**, never transmitted, and not telemetry — there is none.

**Export CSV** writes it beside the vault for compliance review.

It holds nothing sensitive, which is why it is still readable in recovery mode
when the vault itself will not open.

---

## 11. Vault

The operations that make a lost or over-shared vault survivable. Do the first two
today.

**Backup** makes a consistent encrypted copy, opened by the same passphrase. It
is not a second factor: whoever has it and the passphrase has the whole mapping.
**Restore** never writes over an existing vault, and proves the backup opens
before the destination exists.

**Key escrow** seals this vault's *data key* under a second, separate
passphrase. Give it to whoever holds recovery responsibility: they can get back
in and never learn your passphrase. They do get all the way in — there is no
partial access — and handing the file back does not revoke it. Only rotating the
data key does that.

**Re-key** changes every alias in the project. Every twin already shared stops
resolving, which is the point when one has escaped and a disaster otherwise. It
is behind a consent checkbox, and it clears the session's twin because that twin
no longer restores.

**Recovery** is for a vault that will not open. It needs no passphrase, reveals
no real name, and cannot modify the file it inspects. It tells you whether the
problem is a wrong passphrase, a corrupt file, or a vault from a newer build, and
reports what the vault still holds.

---

## 12. Differences from the command line

The application now covers everything the command line does, except one thing:

- **`specshield report`** measures detection recall and precision against the
  committed golden corpus. It is a CI tool, not a user feature, and there is
  nothing for it to do inside a project.

Two things exist only in the application, because they only make sense here:

- **"Never alias"** on a scan suggestion, and hardened clipboard copy.

Every path field has a **Browse…** button and stays typeable. The picker is the
convenient way to name a path, not the only one.

Worth knowing about how it works: the dialog is opened by the Rust side, and the
window itself holds no filesystem permission at all. The only way a file's
contents enter the application is a file you chose in a dialog — no part of the
interface can read a path on its own.

---

*Security detail: [Security Review One-Pager](Security%20Review%20One-Pager.md),
[Threat Model](Threat%20Model.md), [Residual Risk](Residual%20Risk.md).*
