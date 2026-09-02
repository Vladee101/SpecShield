#!/usr/bin/env python3
"""Generate the reference project the M4 performance targets are stated against.

The Implementation Plan's M4 exit criterion is "a 1,000-file / ~150k-LOC
reference repo indexes in < 30 s and rescans in < 2 s". A target measured
against whatever happened to be on the developer's disk is not a target, so the
project is generated deterministically here and rebuilt identically in CI.

The shape matters as much as the size. Real TypeScript services are mostly
interface and method declarations with imports between modules, which is what
the parser actually spends its time on — a million lines of `const x = 1` would
measure nothing.

Usage:
    python bench/build_reference.py [DEST] [FILES]
"""

from __future__ import annotations

import pathlib
import sys

FILES = 1000
LINES_PER_FILE = 151


def build(dest: pathlib.Path, files: int) -> int:
    total = 0
    for i in range(files):
        module = i // 40
        directory = dest / "src" / f"mod{module:02d}"
        directory.mkdir(parents=True, exist_ok=True)

        body = [
            f'import {{ Thing{i} }} from "../mod{module:02d}/thing{i}";',
            "",
            f"export interface Record{i} {{",
        ]
        body += [f"  field{i}_{j}: string;" for j in range(20)]
        body += ["}", "", f"export class Service{i} {{"]
        body += [
            f"  method{i}_{j}(): number {{ return {j}; }}"
            for j in range(LINES_PER_FILE - 26)
        ]
        body.append("}")

        (directory / f"file{i:04d}.ts").write_text("\n".join(body) + "\n", encoding="utf-8")
        total += len(body)

    (dest / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    return total


def main() -> int:
    dest = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/reference-project")
    files = int(sys.argv[2]) if len(sys.argv) > 2 else FILES

    if dest.exists():
        print(f"{dest} already exists; remove it first", file=sys.stderr)
        return 1

    dest.mkdir(parents=True)
    lines = build(dest, files)
    print(f"{files} files, {lines} lines at {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
