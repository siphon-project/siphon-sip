#!/usr/bin/env python3
"""Pin the number of `#[allow(clippy::disallowed_methods)]` so it can only fall.

`clippy.toml` disallows the calls that park a thread (`Handle::block_on`,
`block_in_place`, `to_socket_addrs`, blocking connects, `thread::sleep`,
`blocking_recv`): on a thread attached to the interpreter each one holds a
garbage collection's stop-the-world open. What is left goes through the
released helpers in `src/script/blocking.rs` / `src/script/waits.rs`, or runs
on a dedicated thread that never attaches, each allowed with its reason beside
it. Without this the easy way past the lint is another `#[allow]`.

Counts `src/` only: test, bench and example crates allow it at their root.

Lower BUDGET whenever one goes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BUDGET = 16
NEEDLE = "#[allow(clippy::disallowed_methods)]"


def main() -> int:
    tracked = subprocess.run(
        ["git", "ls-files", "src/*.rs"], capture_output=True, text=True, check=True
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
        print("Route the wait through script::blocking / script::waits instead. Current sites:")
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
