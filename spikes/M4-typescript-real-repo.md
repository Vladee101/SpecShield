# M4 spike, part 2 — the TypeScript parser against a real repository

**P3-4.** Status: **run, and it failed.** Four defects found, three fixed, one
design question left open for a decision that is not the parser's to make.

---

## Why this was still open

The TypeScript parser had been exercised on two things: the six-file corpus
service, and a synthetic 1,000-file repository. TODO.md said what was wrong with
that, and was right:

> a synthetic repo only contains the shapes its generator knew to emit.

The generator emitted classes and interfaces. The corpus service is classes and
interfaces. So the parser had never met a file its author did not already have in
mind.

## The subject

`SAsimulator` — a Vite + React + TypeScript application with an Express server
and a Tauri shell. Copied to a scratch tree with `node_modules`, `dist` and
`target` excluded; everything else, including `.env` and both `package-lock.json`
files, left in place, because a real export sees them.

| | |
|---|---|
| Files indexed | 158 (107 text, 83 with a parser) |
| TypeScript / TSX | 52 files, ~2,300 LOC |
| `.tsx` share | 15 of 20 tracked TS files |
| Largest text file | `package-lock.json`, 204 KB |

The four constructs P3-4 named as untested: **decorators — absent. Generics with
constraints — absent. Barrel re-exports — absent. Ambient `.d.ts` — present, but
only the two-line `vite-env.d.ts` Vite generates.** So this repository does not
close those out, and they stay open. What it has instead is JSX, function
components, hooks, a Zustand store, near-duplicate `src/` and `client/src/`
trees, and a lockfile — none of which the corpus has, and all of which found
something.

---

## 1. The parser could not read JSX. Every `.tsx` file went out unaliased.

`tree-sitter-typescript` ships two grammars, `LANGUAGE_TYPESCRIPT` and
`LANGUAGE_TSX`. They are different languages, not a superset and a subset: `<T>x`
is a type assertion in one and a JSX element in the other, which is why `tsc`
picks by extension. `parse_tree` only ever used the first.

One line is enough. These two files differ only in the `return`:

```tsx
export interface Stage { name: string; }
export function JourneyMap({ stage }: { stage: Stage }) {
  return stage.name;                        // interface and members aliased
  return <div>{stage.name}</div>;           // nothing aliased at all
}
```

The JSX version produced a tree with errors, so `structural_candidates_in`
returned nothing and `structural_counts` returned `None`.

**And it was reported as "verified clean."** That is the part that matters. A
`None` fingerprint was read as *this parser has no structure to compare* — the
honest answer for plain text — when here it meant *this parser could not read
your file*. A user sanitizing a React component saw a green result and their own
untouched source, and had no way to tell.

Fixed two ways, because the reporting bug is the more dangerous of the two and
would outlive any particular grammar problem:

- `parse_tree` now tries TypeScript and falls back to TSX. That order is not
  arbitrary: `<T>x` parses cleanly as TypeScript and is an error under TSX, so
  the assertion syntax must be tried first, and a file that parses cleanly as
  TypeScript contains no JSX by definition. Trying rather than switching on the
  extension is deliberate — `EXTENSIONS` already claims `.js`, and JSX in a
  `.js` file is ordinary.
- `Verification::OriginalDidNotParse` is now distinct from `Unsupported`, keyed
  on a new `ArtifactParser::fingerprints()`. The CLI prints **"gate passed, but
  NOTHING WAS ALIASED"**; the desktop banner turns amber and says the same; an
  export lists the files separately from `unchecked`.

## 2. Components are functions, and functions were not entities.

`walk_declarations` handled `class_declaration`, `interface_declaration`,
`enum_declaration`, `type_alias_declaration` and `import_statement`. Not
`function_declaration`.

In this repository that is 63 declarations against 4 arrow-function consts. Every
component — `AdrArtifact`, `EventSchemaArtifact`, `JourneyMapArtifact`,
`RequireAuth` — was interned into the vault from its *filename* and its
*imports*, and then left in place at its own declaration site, which blocks the
export by construction.

`function_declaration`, `generator_function_declaration` and `function_signature`
(the ambient form a `.d.ts` is made of) now declare, alongside classes. All four
component names left the leak report.

**Ground truth was extended, and I am saying so because I write both the detector
and the grader.** `corpus/adversarial` contains `export function submit(...)` and
`export function render(...)`, never labelled. On the merits they are the user's
own exported names, exactly as the DTO three lines above them is; a twin that
aliases `CreateSubscriptionDto` and leaves the `submit` that takes it is
inconsistent, and blocks the moment another file calls it. `render` is
deliberately a generic word — aliasing it costs twin readability, and FR-10's
allowlist is the escape hatch, exactly as it is for a table called `invoice`.

## 3. The corpus grader was scoring against the wrong byte offsets.

Tracking down a "missed" label led somewhere else entirely. Detection runs on the
*redacted* text, and a `<<REDACTED:...>>` marker is almost never the length of
the secret it replaced — so every offset after the first secret in a file is
displaced. `report.rs` compared those offsets with ground truth directly.

In `secret-beside-dto.ts` the shift is 12 bytes, and it cost twice: one correct
detection counted as a **miss and a false positive at once**. It had been doing
that in CI since the fixture was written.

`secrets::source_offset` now owns the mapping, and `sanitize`, `specshield scan`
and the grader all go through it. The corpus numbers moved *up*:

| | before | after |
|---|---|---|
| Entities | 211 | 213 |
| Recall | 98.6% | **99.1%** |
| Precision | 96.3% | **95.9%** |

Precision is down 0.4 points because function declarations now fire across the
corpus; recall is up on a larger ground truth. Both still pass PRD §5.

## 4. `specshield scan` was answering a question nobody asked.

It called `detector.scan_text` — the prose scan — and never asked the parser.
On the React component it promised five entities where `sanitize` applied none,
and not one of the five was something `sanitize` would have found. A command
whose entire job is *tell me what would happen* now runs what happens: it calls
`sanitize::sanitize` against a throwaway graph and reports `applied` and
`suggestions`. It is less code than it replaced.

## 5. Allowing a name did not clear the gate.

`LeakScanner`'s automaton is built `ascii_case_insensitive`, so an identity
stored as `api` blocks the word `API` anywhere. The allowlist exemption compared
with `==`. A user who reads `"API"` in the leak report and types
`specshield allow API` sees the block persist, and cannot fix it, because nothing
shows them which case the vault holds. Both the gate and the detector now exempt
case-insensitively, which is the rule the gate already uses to match.

---

## What is left, and it is not a bug

With all of the above fixed, the export is **still blocked** — by 124 distinct
names, over 78 files.

```
124 distinct name(s) are doing the blocking:
  1879  node
   148  screen
   124  choice
    77  API
    69  scenario
```

None of that is a parsing failure. `Node` is a real `interface Node` in
`src/api/client.ts`; `Screen` is a real interface; `Choice` is a real interface.
They are correctly detected, correctly aliased, and correctly in the vault.

The gate then blocks **every occurrence of the word `node` in the project** —
1,879 of them, most in `package-lock.json`, plus `.gitignore`, the CI workflow,
and every `res.node` property access that has nothing to do with the type.

This is the gate working exactly as SDD §8 specifies. It scans candidate output
for every vault name plus case variants, hard-blocks, and has no notion of
*where* a name is meaningful. On a synthetic corpus of `CustomerSubscription`
and `PlanTier` that is invisible. On a real domain model — `Node`, `Screen`,
`Choice`, `Status`, `Key`, `Context`, `Error`, `Type`, `Data` — it means most of
a repository is a leak.

**A team could not adopt this today without allowlisting on the order of a
hundred names.** That is the finding, and it is a design decision rather than a
defect, so it has not been changed here. Three options, in the order I would
consider them:

1. **A vendor and language stop list for structural candidates.** `STOP_LIST`
   exists and already contains `Node` and `React` — but only the *detector*
   consults it. The parser interns `interface Node` regardless, which is
   defensible in isolation and is how `Node` got into the vault. Extending the
   stop list to `Error`, `RequestInit` and the TypeScript lib globals, and
   consulting it from `walk_declarations`, would remove a large share of the 124
   without touching a single name the user actually owns.
2. **Scope the gate to file types that can carry the name.** A TypeScript type
   called `Node` leaking into `package-lock.json` is not a plausible disclosure;
   the lockfile's `node` is npm's. This narrows the product's central safety
   control and would need care, but "every vault name, every file, case-blind" is
   the widest possible rule and it is not obviously the right one.
3. **Require a minimum specificity for an identity.** A single dictionary-word
   type name could be surfaced for confirmation rather than interned silently,
   the way low-confidence candidates already are.

The interim workflow is real and now usable: an export lists the blocking names
by frequency with the `specshield allow` command to run, which it did not before
— the per-file list is 78 files truncated at five leaks each, and unblocking used
to mean four rounds of guessing at what the truncation was hiding.

---

## Measurements

Release build, this machine, 158 files:

| | |
|---|---|
| `index` | 0.43 s |
| `export` (learn + sanitize + gate) | 40 s |

40 seconds for 107 text files, against 11.5 s for the 1,000-file synthetic
repository. The difference is not file count: it is 204 KB and 192 KB lockfiles
scanned against an automaton built from a vault full of common words. Not
investigated further — worth doing before this is called fast enough for a repo
of any size.

Secret detection: the repository's `.env` holds one non-secret variable
(`VITE_API_URL`) and the detector correctly reported nothing. No planted
credentials were available to test against, so this run says nothing about secret
recall.

## Still untested after this

Decorators, generics with constraints, and barrel re-exports — absent from this
codebase. Arrow-function consts (`export const X = () => ...`) are present but
rare here, and are the remaining declaration gap: `useScenarioStore` leaks at its
own declaration site for exactly that reason. A NestJS or Angular service would
close out the decorators and give the constrained generics a real workout.
