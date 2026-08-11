#!/usr/bin/env python3
"""Print the canonical GlacierEQ implementation source-tree SHA."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_tree_sha() -> str:
    parts: list[str] = []
    for sub in ("src", "scripts", "tests"):
        base = ROOT / sub
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in {".py", ".md", ".json"}:
                rel = path.relative_to(ROOT).as_posix()
                parts.append(f"{rel}:{file_sha(path)}")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


if __name__ == "__main__":
    print(source_tree_sha())
