# M0 Spike — Alias format round trip

**Question:** which alias format survives a model round trip, and does the
prompt envelope help? Freezes the SDD §6.3 grammar.

**Reproduce:**

```bash
cargo run -p spike-alias-roundtrip
```

---

## Status: part 1 complete, part 2 not run

The question splits into two, and only one of them needs a model:

| | Question | Needs a model? | Status |
|---|---|---|---|
| **Part 1** | *If* drift D happens to format F, can the matcher still recover it? | No — fully determined by our own `canonical()` | **Done** |
| **Part 2** | How often does each drift actually happen, with and without the envelope? | Yes | **Not run** — see below |

Part 1 alone is decision-relevant: a format that is unrecoverable under common
drift is disqualified regardless of how rare that drift proves to be. Part 2
only ranks the survivors.

**Why part 2 was not run:** it requires sending prompts to commercial model APIs
— an external, billable action on your account that I should not initiate
without you asking for it. The prompt pack is generated and ready:

```bash
cargo run -p spike-alias-roundtrip -- --emit-prompts spikes/alias-roundtrip/prompts
```

12 prompts (6 formats × envelope/no-envelope), each a complete paste-ready
request asking a model to modify a class whose identifiers are aliases. The
procedure for scoring responses is printed by that command.

---

## Part 1 results

### Recoverability under drift

| Format | Sample | Recovered | Under common drift |
|---|---|---:|---:|
| `sequence` | `SERVICE_014` | 9/10 | 5/5 |
| `opaque-hmac` | `SERVICE_H7K2Q3` | 9/10 | 5/5 |
| `typed-hmac` | `PrimaryService_H7K2Q3` | 9/10 | 5/5 |
| `delimiter-wrapped` | `__SERVICE_014__` | 9/10 | 5/5 |
| `namespaced` | `SS_SERVICE_014` | 9/10 | 5/5 |
| `pseudonymous` | `AuroraService` | 8/10 | 5/5 |

Drifts tested: verbatim, lowercased, PascalCased, underscores stripped,
hyphenated, leading zeros dropped, pluralized, backtick-wrapped, suffixed with
`Impl`, word-split.

### Three findings that change something

**1. The delimiter-wrapped format buys nothing.** `__SERVICE_014__`
canonicalizes to exactly the same form as `SERVICE_014` — canonicalization
strips non-alphanumerics, so the sentinels are invisible to the matcher. The
idea behind that format was that visible delimiters would discourage a model
from rewriting the token. Even if that were true, the format offers **zero**
additional recovery, and it makes every alias four characters longer in every
prompt. **Disqualified.** If sentinels are wanted for their psychological effect
on the model, they belong in the envelope wording, not in the alias.

**2. Affix drift is unrecoverable by the normalizer, as designed.** Every format
fails `SERVICE_014Impl`. This is SDD §6.4 step 5, which is deliberately assigned
to the *matcher* rather than the normalizer, because stripping `Impl` is only
safe when the remainder matches an existing alias exactly. The spike confirms
the step is genuinely needed rather than theoretical — **it must land with the
restore engine in M1**, not be deferred further.

**3. Pseudonymous aliases lose to pluralization.** `AuroraServices` does not
recover, because the plural rule only strips a trailing `s` that follows a
digit — a guard that exists so a real name ending in `s` is not mangled. Formats
with a digit-bearing suffix are unaffected. This is a concrete cost of
`AliasStyle::Pseudonymous` beyond the already-documented weaker protection.

### False-positive risk

Zero of 13 real identifiers drawn from the corpus are alias-shaped, including
the ones designed to be adversarial:

```
MAX_RETRIES  DEFAULT_TIMEOUT  HTTP_OK  API_BASE_URL
AWS_ACCESS_KEY_ID  PAYLANE_WEBHOOK_SECRET  VANTOR_BILLING_URL
```

This validates the digit rule added to SDD §6.3 during the scaffold. Without it
every one of those would be reported as an unresolved identity, and the M1
unresolved-identity flow would be unusable in any real codebase.

---

## Recommendation

**Keep the current grammar and the current default.** `typed-hmac`
(`PrimaryService_H7K2Q3`) ties for best recoverability, carries the digit rule
that suppresses false positives, needs no central allocator, and keeps the
category hint that helps model output quality.

Two changes to make now:

1. **Drop `delimiter-wrapped` from consideration.** It is strictly dominated.
2. **Schedule affix stripping into M1's restore matcher.** Not optional.

One change to hold until part 2:

3. Whether `pseudonymous` stays a shipped option. Its pluralization weakness is
   real but only matters if models pluralize often — which is what part 2
   measures.

---

## Caveats

- **The cross-format collision output is contrived.** It reports `sequence` and
  `delimiter-wrapped` colliding, but a project uses one format, so they never
  coexist. The meaningful reading is the narrower one stated above: `__X__` and
  `X` are the same token to the matcher.
- **The drift list is from documented model behaviour, not measurement.** Which
  drifts occur, and how often, is precisely what part 2 is for. Treat the
  Common/Occasional labels as hypotheses.
- **One task, one language.** All 12 prompts ask for the same TypeScript
  modification. A wider task set (SQL, Markdown, refactoring vs. generation)
  would likely surface drift patterns this list does not contain.
