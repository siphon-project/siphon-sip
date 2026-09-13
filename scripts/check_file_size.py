#!/usr/bin/env python3
"""Fail when a Rust file carries more production lines than it should.

Why production lines and not total LOC: a third of the files over 1,000 lines in
this tree are 40-60% inline `#[cfg(test)]`. Counting those would flag the
best-tested modules first and reward moving tests out of the file to satisfy a
number, which is exactly backwards for a codebase whose test rule is
non-negotiable.

Why 1,500: it is where this tree's cohesive single-purpose modules actually sit
(`script/engine.rs` 1,574, `admin/mod.rs` 1,572, `registrant/mod.rs` 1,504,
`control/registry.rs` 1,493, `registrar/backend.rs` 1,485). A lower bar would
flag modules that are fine and the allowlist would become noise; a higher one
misses the files that genuinely need splitting.

This is a *file* gate. The thing that actually produced `dispatcher.rs` was
function length, not file length — the file grew by adding to functions, not by
adding functions. `clippy::too_many_lines` covers that and is the more important
of the two.

Usage:
    scripts/check_file_size.py            # gate (CI)
    scripts/check_file_size.py --list     # print every file's production count
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

THRESHOLD = 1500
ALLOWLIST = Path(__file__).with_name("file_size_allowlist.txt")

CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]")


def production_lines(path: Path) -> int:
    """Total lines minus every `#[cfg(test)]`-gated item.

    Walks brace depth from the attribute to the end of the item it guards, so a
    `#[cfg(test)] mod tests` and a lone `#[cfg(test)] const` are both excluded.
    Braces inside string literals can skew the walk; that only ever *over*-counts
    production lines, so the gate errs toward flagging rather than hiding.
    """
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    total = len(lines)
    test_lines = 0

    index = 0
    while index < total:
        if not CFG_TEST.match(lines[index]):
            index += 1
            continue
        end = index
        depth = 0
        opened = False
        while end < total:
            depth += lines[end].count("{") - lines[end].count("}")
            if "{" in lines[end]:
                opened = True
            if opened and depth <= 0:
                break
            # A `#[cfg(test)]` on a one-line item (a const, a use) never opens a
            # brace; stop at the end of that statement rather than running on.
            if not opened and end > index and lines[end].rstrip().endswith(";"):
                break
            end += 1
        test_lines += end - index + 1
        index = end + 1

    return total - test_lines


def load_allowlist() -> dict[str, int]:
    """`path  max_lines  # justification` per line."""
    allowed: dict[str, int] = {}
    if not ALLOWLIST.is_file():
        return allowed
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            sys.exit(f"error: malformed allowlist entry: {raw!r}")
        allowed[parts[0]] = int(parts[1])
    return allowed


# `tests/` and `benches/` are test code end to end — there is no production
# half to measure, and a long scenario file is not the problem this gate exists
# for. `fuzz/` likewise.
EXCLUDED_ROOTS = ("tests/", "benches/", "fuzz/")

# A module whose whole file is tests carries no `#[cfg(test)]` *inside* it — the
# attribute sits on the `#[cfg(test)] mod tests;` declaration in the parent — so
# the stripper sees every line as production. That is the shape the module split
# produces (each module's tests move to its own file beside it), so match on the
# filename instead.
def is_test_file(path: Path) -> bool:
    name = path.name
    return name == "tests.rs" or name.endswith("_tests.rs")


def tracked_rust_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "*.rs"], capture_output=True, text=True, check=True
    ).stdout.split()
    return [
        Path(p)
        for p in listed
        if Path(p).is_file()
        and not any(part in p for part in ("/tests/", "/benches/", "/fuzz/"))
        and not p.startswith(EXCLUDED_ROOTS)
        and not is_test_file(Path(p))
    ]


def main() -> int:
    counts = {str(p): production_lines(p) for p in tracked_rust_files()}

    if "--list" in sys.argv:
        for path, count in sorted(counts.items(), key=lambda kv: -kv[1])[:40]:
            print(f"{count:>7}  {path}")
        return 0

    allowed = load_allowlist()
    over: list[tuple[str, int, int]] = []
    shrunk: list[tuple[str, int, int]] = []

    for path, count in sorted(counts.items()):
        cap = allowed.get(path)
        if cap is None:
            if count > THRESHOLD:
                over.append((path, count, THRESHOLD))
        elif count > cap:
            over.append((path, count, cap))
        elif count <= THRESHOLD:
            # It no longer needs an exemption at all.
            shrunk.append((path, count, cap))

    for path in sorted(set(allowed) - set(counts)):
        print(f"warning: allowlist names {path}, which no longer exists — drop the entry")

    if shrunk:
        print("These files are now under the threshold; remove their allowlist entries:")
        for path, count, cap in shrunk:
            print(f"  {path}: {count} production lines (allowed {cap}, threshold {THRESHOLD})")
        print()

    if over:
        print(f"FAIL: {len(over)} file(s) over their production-line budget:")
        for path, count, cap in over:
            print(f"  {path}: {count} production lines (budget {cap})")
        print()
        print(
            "Split the file, or add it to scripts/file_size_allowlist.txt with a\n"
            "one-line justification. Raising an existing entry's number needs that\n"
            "justification edited in the same diff — that edit is the review hook."
        )
        return 1

    print(
        f"OK: no file over {THRESHOLD} production lines "
        f"({len(allowed)} allowlisted, {len(counts)} files checked)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
