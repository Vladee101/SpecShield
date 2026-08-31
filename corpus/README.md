# Golden corpus

Hand-labelled synthetic projects. CI measures detection recall and precision
against these every commit, and regressions fail the build — this directory is
what makes the PRD §5 metrics real rather than aspirational.

**Everything here is synthetic.** Never add a real project, a real customer
name, or a real credential, even redacted: the corpus is committed and public
to everyone with repo access.

## Layout

```
corpus/
  <project>/
    input/          artifacts as they would be imported
    labels.json     ground truth: every entity, its span, type, and scope
    expected/       optional snapshot of the twin, for insta
```

## Planned projects (M0)

| Project | Covers |
|---|---|
| `prd-markdown` | prose entities, org names, business terminology |
| `sql-schema` | tables, columns, the repeated `customer_id` case |
| `openapi-billing` | paths, operationIds, schema names, cross-artifact unification with `sql-schema` |
| `ts-service` | declarations, references, imports, comments, string literals |
| `mixed-repo` | all of the above plus path aliasing and ignore rules |

## Adversarial fixtures (SDD §19)

Deliberately hostile inputs live in `corpus/adversarial/`:

- aliases inside string literals and comments
- shadowed identifiers
- homoglyph names
- a `Status` enum in three modules
- `customer_id` in ten tables
- a live-looking API key three lines from a DTO

## `labels.json`

```json
{
  "entities": [
    {
      "real_name": "CustomerSubscriptionService",
      "entity_type": "service",
      "scope_path": "src/services/subscription.ts::",
      "file": "input/src/services/subscription.ts",
      "byte_start": 6,
      "byte_end": 33
    }
  ],
  "secrets": [
    { "file": "input/.env", "byte_start": 12, "byte_end": 52, "secret_type": "aws_access_key" }
  ],
  "never_alias": ["Express", "Postgres"]
}
```

`never_alias` entries are counted as false positives if detected — that is what
holds the precision target honest.
