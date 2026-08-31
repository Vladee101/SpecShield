# Performance corpus

Benchmarks for the PRD §5 / SDD §18 targets, run with `criterion` and compared
against a stored baseline in CI so regressions surface as a diff.

**Reference machine** (SDD §18): 8-core x86-64, 16 GB RAM, NVMe SSD, Windows 11.
CI runners are slower and noisier; treat CI numbers as regression detection, and
quote the reference machine for the published targets.

| Benchmark | Target | Milestone |
|---|---|---|
| `open_project` | < 2 s warm | M1 |
| `sanitize_prd` | < 10 s for ~40k words | M1 |
| `verify_gate` | < 3 s over the reference project | M1 |
| `restore_response` | < 3 s for ~2k lines | M1 |
| `index_cold` | < 30 s for 1,000 files / ~150k LOC | M4 |
| `rescan_incremental` | < 2 s | M4 |

The reference project is generated rather than committed — see
`bench/generate.rs` (M4). Committing 150k LOC of synthetic source would
dominate the repository.

## Watch items

- **SQLCipher write throughput dominates indexing.** One transaction per file,
  batched occurrence inserts (SDD §9.2). A row-by-row regression here will blow
  the 30 s target long before parsing does.
- **The leak-gate automaton is built once per session** and cached against a
  vault generation counter. Rebuilding it per file turns an O(n) scan into
  O(n·m).
