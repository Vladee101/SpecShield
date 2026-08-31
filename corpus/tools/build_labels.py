#!/usr/bin/env python3
"""Generate labels.json for each corpus project from its spec.json.

Byte offsets are computed, never hand-written: a corpus whose ground truth is
subtly wrong is worse than no corpus, because it silently moves the recall and
precision numbers that CI gates on (PRD §5).

Usage:
    python corpus/tools/build_labels.py            # regenerate every project
    python corpus/tools/build_labels.py ts-service # one project

`crates/cli/tests/corpus.rs` re-validates the committed labels against the
committed inputs on every `cargo test`, so an edit to an input file that is not
followed by a regeneration fails the build.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent

# Entity types recognised by specshield-core (see EntityType in model.rs). Kept
# here so a typo in a spec fails loudly rather than producing an unmatchable
# label.
ENTITY_TYPES = {
    "organization", "service", "api", "endpoint", "table", "column", "dto",
    "interface", "enum", "event", "env_var", "host", "path_segment",
}


def token_spans(text: str, needle: str) -> list[tuple[int, int]]:
    """Whole-token byte spans of `needle` in `text`.

    Identifier characters on either side disqualify a match, so `Order` does
    not match inside `Reorder` and `invoice` does not match inside
    `invoice_id`. Offsets are byte offsets into UTF-8, which is what the Rust
    side indexes with.
    """
    data = text.encode("utf-8")
    target = needle.encode("utf-8")
    spans = []
    start = 0
    while (found := data.find(target, start)) != -1:
        end = found + len(target)
        before = data[found - 1:found]
        after = data[end:end + 1]
        ident = re.compile(rb"[A-Za-z0-9_]")
        if not (before and ident.match(before)) and not (after and ident.match(after)):
            spans.append((found, end))
        start = found + 1
    return spans


def line_of(text: str, byte_offset: int) -> int:
    return text.encode("utf-8")[:byte_offset].decode("utf-8", "ignore").count("\n") + 1


def build(project: Path) -> dict:
    spec = json.loads((project / "spec.json").read_text(encoding="utf-8"))
    root = project / "input"

    entities: list[dict] = []
    claimed: dict[str, list[tuple[int, int]]] = {}

    # Longest names first: labelling `CustomerSubscription` before
    # `Subscription` stops the shorter name claiming a span inside the longer
    # one and inflating the ground-truth count.
    for entry in sorted(spec.get("entities", []), key=lambda e: -len(e["real_name"])):
        entity_type = entry["entity_type"]
        if entity_type not in ENTITY_TYPES:
            raise SystemExit(f"{project.name}: unknown entity_type {entity_type!r}")

        name = entry["real_name"]
        files = entry.get("files")
        line_range = entry.get("line_range")

        targets = (
            [root / f for f in files]
            if files
            else sorted(p for p in root.rglob("*") if p.is_file())
        )

        occurrences = []
        for path in targets:
            if not path.exists():
                raise SystemExit(f"{project.name}: {path} listed in spec but missing")
            text = path.read_text(encoding="utf-8")
            rel = path.relative_to(project).as_posix()
            taken = claimed.setdefault(rel, [])

            for start, end in token_spans(text, name):
                if any(start < c_end and c_start < end for c_start, c_end in taken):
                    continue  # already claimed by a longer name
                if line_range:
                    line = line_of(text, start)
                    if not line_range[0] <= line <= line_range[1]:
                        continue
                taken.append((start, end))
                occurrences.append({
                    "file": rel,
                    "byte_start": start,
                    "byte_end": end,
                    "line": line_of(text, start),
                })

        if not occurrences:
            raise SystemExit(
                f"{project.name}: {name!r} ({entity_type}) matched nothing — "
                "stale spec or renamed fixture"
            )

        entities.append({
            "real_name": name,
            "entity_type": entity_type,
            "scope_path": entry["scope_path"],
            "note": entry.get("note"),
            "occurrences": occurrences,
        })

    secrets = []
    for entry in spec.get("secrets", []):
        path = root / entry["file"]
        text = path.read_text(encoding="utf-8")
        spans = token_spans(text, entry["match"])
        if not spans:
            raise SystemExit(f"{project.name}: secret {entry['match']!r} not found in {entry['file']}")
        start, end = spans[0]
        secrets.append({
            "file": path.relative_to(project).as_posix(),
            "byte_start": start,
            "byte_end": end,
            "line": line_of(text, start),
            "secret_type": entry["secret_type"],
            "confidence": entry.get("confidence", "high"),
        })

    # Files where zero detections are expected: every hit is a false positive.
    negative = []
    for rel in spec.get("negative_files", []):
        path = root / rel
        if not path.exists():
            raise SystemExit(f"{project.name}: negative_files lists {rel}, which is missing")
        negative.append(path.relative_to(project).as_posix())

    entities.sort(key=lambda e: (e["entity_type"], e["real_name"]))

    return {
        "$comment": "GENERATED by corpus/tools/build_labels.py — edit spec.json, not this file.",
        "project": project.name,
        "description": spec.get("description", ""),
        "entity_count": len(entities),
        "occurrence_count": sum(len(e["occurrences"]) for e in entities),
        "entities": entities,
        "secrets": secrets,
        "requires": spec.get("requires", []),
        "milestone": spec.get("milestone", ""),
        "negative_files": negative,
        "never_alias": spec.get("never_alias", []),
        "ignored_paths": spec.get("ignored_paths", []),
    }


def main() -> int:
    wanted = sys.argv[1:]
    projects = [
        p for p in sorted(CORPUS.iterdir())
        if (p / "spec.json").exists() and (not wanted or p.name in wanted)
    ]
    if not projects:
        print("no projects matched", file=sys.stderr)
        return 1

    for project in projects:
        labels = build(project)
        out = project / "labels.json"
        out.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"{project.name}: {labels['entity_count']} entities, "
              f"{labels['occurrence_count']} occurrences, "
              f"{len(labels['secrets'])} secrets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
