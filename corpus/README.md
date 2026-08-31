# Golden corpus

Hand-labelled synthetic projects. CI measures detection recall and precision
against these every commit, and regressions fail the build — this directory is
what makes the PRD §5 metrics real rather than aspirational.

**Everything here is synthetic.** Never add a real project, a real customer
name, or a real credential, even redacted: the corpus is committed and visible
to everyone with repo access. The planted secrets are published documentation
examples (AWS's own `AKIAIOSFODNN7EXAMPLE`) or obviously-invalid placeholders.

## Current state

| Project | Entities | Occurrences | Secrets | Covers |
|---|---:|---:|---:|---|
| `prd-markdown` | 14 | 25 | — | prose entities, org names, business terminology |
| `sql-schema` | 14 | 19 | — | tables, columns, the repeated `customer_id` case |
| `openapi-billing` | 14 | 25 | — | paths, operationIds, schema names |
| `ts-service` | 20 | 60 | — | declarations, references, imports, comments, string literals, path segments |
| `mixed-repo` | 11 | 13 | — | one identity across four formats, plus ignore rules |
| `adversarial` | 17 | 20 | 6 | the hostile cases below |
| **Total** | **90** | **162** | **6** | |

All six share one fictional domain — **Vantor**, a freight billing platform —
so cross-artifact unification is testable: the SQL table
`customer_subscription`, the OpenAPI schema `CustomerSubscription`, and the
TypeScript interface `CustomerSubscription` must resolve to **one** identity
carrying **one** alias (SDD §5).

## Layout

```
corpus/
  <project>/
    input/          artifacts as they would be imported
    spec.json       hand-written: what should be detected, and why
    labels.json     GENERATED: ground truth with computed byte offsets
  tools/
    build_labels.py generator
```

## Never hand-edit `labels.json`

Byte offsets are computed, never written by hand. A corpus whose ground truth
is subtly wrong is worse than no corpus, because it moves the recall and
precision numbers silently.

```bash
python corpus/tools/build_labels.py
```

`crates/cli/tests/corpus.rs` re-validates every committed label against every
committed input on each `cargo test` — 13 checks, including that each span
actually contains the name it claims. Editing a fixture without regenerating
fails the build.

## `spec.json`

```json
{
  "description": "why this project exists",
  "entities": [
    {
      "real_name": "CustomerSubscription",
      "entity_type": "dto",
      "scope_path": "src/domain/customer-subscription.ts::CustomerSubscription",
      "files": ["src/domain/customer-subscription.ts"],
      "line_range": [6, 12],
      "note": "optional rationale"
    }
  ],
  "secrets": [
    { "file": ".env", "match": "AKIAIOSFODNN7EXAMPLE", "secret_type": "aws_access_key_id" }
  ],
  "negative_files": ["aliases-in-text.ts"],
  "never_alias": ["Express", "Postgres"],
  "ignored_paths": ["node_modules/left-pad/index.js"]
}
```

| Field | Meaning |
|---|---|
| `files` | Restrict matching to these files. Omit to search the whole project. |
| `line_range` | Restrict to a line span — this is how ten `customer_id` columns in one file become ten scoped identities. |
| `negative_files` | Zero detections expected. **Every** hit is a false positive against the precision target. |
| `never_alias` | Detecting these counts as a false positive. Framework and vendor names. |
| `ignored_paths` | Must be excluded by ignore rules; contributes nothing either way. |

The generator matches whole tokens only (so `invoice` does not match inside
`invoice_id`) and claims longer names first (so `CustomerSubscription` is
labelled before `Subscription` could claim a span inside it).

## Scoring

- **Recall** = labelled occurrences detected ÷ total labelled occurrences.
  Per-occurrence rather than per-entity: missing one occurrence of a detected
  entity is still a leak.
- **Precision** = correct detections ÷ all detections. Hits in
  `negative_files`, on `never_alias` terms, and in `ignored_paths` all count
  against it.
- Targets: recall ≥ 0.95, precision ≥ 0.90 (PRD §5).

Precision is a first-class target. False positives make the twin unreadable and
measurably degrade the AI output generated from it, so a detector that flags
everything is not "safe" — it is unusable.

## Adversarial fixtures

Each targets a specific way the pipeline can produce a wrong result *silently*,
which is the failure mode that matters in a security tool.

| Fixture | Attacks |
|---|---|
| `modules/*-status.ts` | Three unrelated `Status` enums. One alias for all three breaks the twin and makes restore ambiguous. |
| `customer-id-ten-tables.sql` | Ten `customer_id` columns, ten scopes, ten identities. |
| `shadowed.ts` | `subscription` bound at three scopes. Renaming the outer binding must not touch the inner ones — the case Tree-sitter cannot resolve on its own (SDD §4.2.2). |
| `aliases-in-text.ts` | Alias-shaped tokens inside strings and comments, plus `MAX_RETRIES` / `HTTP_OK`. **Negative fixture**: any detection is a false positive. |
| `homoglyph.md` | `Vantor` and `Vаntor` (Cyrillic U+0430). A byte-exact detector finds one and misses the other. |
| `planted-secrets.env` | Five secret classes for one-way redaction, including a low-confidence email. |
| `secret-beside-dto.ts` | A credential three lines from a DTO: one must be redacted one-way, the other pseudonymized two-way, and they must not share a code path (SDD §4.3). |

## Known gaps

- **No `expected/` twin snapshots yet.** They arrive with the sanitizer in M1,
  as `insta` snapshots, so unintended transformation changes surface in review.
- **Path-segment entities are labelled only where they appear in file
  *content*** (import specifiers). Filename-to-twin-path mapping is a
  `files.twin_path` concern and is verified separately.
- **The homoglyph fixture has no defined resolution yet.** It is labelled as two
  identities; whether the detector should unify them under Unicode confusable
  folding is an open M1 question, and the fixture exists to force the decision.
