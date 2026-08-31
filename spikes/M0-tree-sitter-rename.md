# M0 Spike — Tree-sitter TypeScript rename

**Question:** can Tree-sitter plus heuristic scoping rename TypeScript
correctly enough for the MVP, or does D-4 need a compiler-API sidecar?

**Reproduce:**

```bash
cargo run -p spike-ts-rename -- corpus/ts-service/input corpus/adversarial/input
```

---

## Verdict

**Option A holds for named declarations. It does not hold for object
properties.** That split is sharper than the plan anticipated, and it changes
what MVP can promise.

| Capability | Verdict |
|---|---|
| Classes, interfaces, enums, functions, type aliases, variables, imports | **Works.** 100% lexical resolution, correct across files |
| Shadowed bindings | **Works.** Correctly distinguished three `subscription` bindings at three scopes |
| Twin parses, symbol counts match (SDD §7.2) | **Works.** 18/18 renames verified |
| Object properties and interface members | **Fails.** 25 of 47 property-position identifiers are unresolvable without type information |

---

## Measurements

Sample: 12 TypeScript files, ~250 LOC — the `ts-service` and `adversarial`
corpus projects.

```
resolution rate:                              100.0%  (23/23 non-ambient refs)
cross-file references via the import graph:   11
unresolved (non-ambient):                     0
shadowed bindings correctly separated:        2
rename verification failures:                 0
modules with parse errors:                    0
property references needing type info:        25
```

### What the 100% actually means

It is a rate over references the resolver can *see*. Identifiers in property
position — `x.customerId`, and the `customerId:` key of an object literal — are
excluded from that denominator, because lexical scoping cannot resolve them even
in principle. Reading the headline number without that caveat would be the
easiest way to mis-scope M4.

---

## The property blind spot

Tree-sitter parses this correctly and still cannot tell you what it means:

```ts
const subscription: CustomerSubscription = {
  subscriptionId: crypto.randomUUID(),
  customerId: dto.customerId,
  planTier: dto.planTier ?? PlanTier.Trial,
};
```

Five property-position identifiers on three lines. To rename the
`CustomerSubscription.customerId` member, you must know that this object literal
*is* a `CustomerSubscription` and that `dto` *is* a `CreateSubscriptionDto` —
both type-inference questions. Tree-sitter computes neither.

This matters more than it first appears: `customerId`, `planTier`,
`amountCents`, `invoiceId`, and `subscriptionId` are all **Column entities** in
the corpus ground truth. They are exactly the names a database schema leaks.
Detected in SQL and OpenAPI, they would be renamed there and left untouched in
TypeScript — producing a twin that is internally inconsistent *and* a leak the
verification gate would correctly refuse to export.

### Recommendation: scope properties globally in MVP

Rename every property-position identifier matching a known member name to the
same alias, project-wide, regardless of which type it belongs to.

- **Sound.** Interface declaration, object literal keys, and member accesses all
  receive the same new name, so the twin stays consistent and parses.
- **Restore stays unambiguous**, because one name maps to one alias.
- **Cost:** two unrelated interfaces both having `customerId` receive the same
  alias, disclosing that they share a field name. That is a small, bounded leak.
- **Risk:** a same-named property on a third-party type (`response.customerId`
  from a vendor SDK) would be renamed too, breaking the twin. Mitigated by the
  stop-list and allowlist (PRD FR-10), and caught by the §7.2 parse check.

Concretely: `scope_strategy` applies to declarations; properties are pinned to
`global` in MVP. Exact per-type property renaming waits for the compiler-API
sidecar in V1.1.

---

## What did work, and is worth keeping

**Cross-file rename through the import graph.** 11 references resolved across
module boundaries with nothing more than import-specifier tracking. Renaming
`CustomerSubscription` in `domain/` correctly reached its three importers.

**Shadowing.** `adversarial/shadowed.ts` binds `subscription` three times —
module-level `const`, function parameter, block-scoped `const`. The resolver
separated all three, and renaming the module-level binding touched **one** site
(its own declaration), correctly leaving the inner bindings alone. This was the
case most likely to disqualify Option A, and it passed.

**The §7.2 verification pass is cheap and works.** Re-parsing the twin and
comparing identifier counts caught nothing here because nothing broke, but it
runs in microseconds and is the mechanism that turns "we think the rename was
right" into "the twin parses and has the same shape".

---

## Caveats on this spike

- **12 files, not the 50 the plan called for.** No real service was available to
  test against, and generating synthetic bulk would add volume without adding
  language constructs. The findings are structural — they concern which
  constructs defeat lexical scoping — so file count does not change them. What a
  larger real codebase *would* add: decorators, generics with constraints,
  namespace merging, `export * from`, barrel files, and `.d.ts` ambient
  declarations. **Re-run this spike against a real service before M4 starts.**
- **The scope-id recovery between passes is fragile.** The spike allocates scope
  ids in pass 1 and recovers them in pass 2 by node identity. It works, but the
  production implementation should build the scope tree once and carry it,
  rather than reconstructing it.
- **The count check is weak on its own.** Comparing identifier counts catches
  catastrophic breakage, not subtle wrongness — renaming the wrong symbol
  preserves the count. It is a necessary check, not a sufficient one; the
  verification gate (SDD §8) is what actually protects the export.

---

## Actions

1. **D-4 confirmed as Option A** — Tree-sitter plus heuristic scoping — with the
   property limitation recorded in SDD §4.2.2.
2. **Add the property scoping rule** to SDD §4.4: properties use `global` scope
   in MVP.
3. **Re-run against a real 50+ file service** before M4 begins, to surface
   decorators, generics, and barrel-file re-exports.
4. Keep the parse-and-count verification; treat it as a smoke test rather than a
   correctness proof.
