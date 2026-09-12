#!/usr/bin/env python3
"""Pin the number of `#[allow(clippy::too_many_lines)]` so it can only fall.

The lint is set at its target (300). Twelve functions exceed it and are allowed
individually with a reason. Without this the easy way past the gate is another
`#[allow]`, which is how a lint ends up enabled and meaningless.

Lower BUDGET whenever the split removes one.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BUDGET = 12
NEEDLE = "#[allow(clippy::too_many_lines)]"


def main() -> int:
    tracked = subprocess.run(
        ["git", "ls-files", "*.rs"], capture_output=True, text=True, check=True
    ).stdout.split()

    found: list[str] = []
    for path in tracked:
        file = Path(path)
        if not file.is_file():
            continue
        for number, line in enumerate(
            file.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            if NEEDLE in line:
                found.append(f"{path}:{number}")

    if len(found) > BUDGET:
        print(f"FAIL: {len(found)} {NEEDLE} (budget {BUDGET}).")
        print("Split the function instead of allowing it. Current sites:")
        for site in found:
            print(f"  {site}")
        return 1

    if len(found) < BUDGET:
        print(
            f"{len(found)} {NEEDLE} — below the budget of {BUDGET}. "
            f"Lower BUDGET in this script to lock the gain in."
        )
        return 0

    print(f"OK: {len(found)} {NEEDLE}, at the budget of {BUDGET}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
