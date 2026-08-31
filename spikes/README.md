# Spikes

Time-boxed experiments that answer a specific open question, then stop. Spike
code is not production code: it exists to produce a verdict, and it reports its
own failures rather than papering over them.

Each spike has a report beside it recording what was measured, what the verdict
was, and what the spike could *not* determine.

| Spike | Question | Verdict | Report |
|---|---|---|---|
| `ts-rename` | Can Tree-sitter plus heuristic scoping rename TypeScript correctly? (D-4) | Yes for declarations, **no for object properties** | [M0-tree-sitter-rename.md](M0-tree-sitter-rename.md) |
| `alias-roundtrip` | Which alias format survives a model round trip? (SDD §6.3) | Keep typed-hmac; drop delimiter-wrapped | [M0-alias-format.md](M0-alias-format.md) |

Both build in CI so they cannot rot silently, and both are cheap to re-run when
the inputs change — the ts-rename spike in particular should be re-run against a
real 50+ file service before M4 starts.
