# Splitting a script across multiple files

Once a script grows past a few handlers you'll want to move shared helpers into
their own `.py` files. siphon puts the script's own directory on the Python
`sys.path`, so a plain `import` of a sibling module just works — no
`sys.path.insert` boilerplate.

## Sibling helper next to the script

```
/etc/siphon/
  siphon.yaml
  main.py
  helpers.py
```

```python
# helpers.py
def normalize_number(raw: str) -> str:
    digits = "".join(c for c in raw if c.isdigit())
    if digits.startswith("00"):
        return "+" + digits[2:]
    return digits
```

```python
# main.py
from siphon import proxy, log
import helpers

@proxy.on_request("INVITE")
def on_invite(request):
    request.ruri.user = helpers.normalize_number(request.ruri.user or "")
    request.relay()
```

Point the config at the main script as usual — nothing else is needed:

```yaml
script:
  path: "/etc/siphon/main.py"
```

## Shared library across scripts

For helpers shared by several scripts (or several NFs) that don't live next to
any one script, list the directories in `include_paths`. They're added to
`sys.path` after the script's own directory.

```yaml
script:
  path: "/etc/siphon/pcscf.py"
  include_paths:
    - "/etc/siphon/lib"          # e.g. /etc/siphon/lib/ims_common.py
```

```python
# pcscf.py
import ims_common               # resolved from /etc/siphon/lib
```

## Hot-reload

Helper modules hot-reload exactly like the main script. Editing and saving
`helpers.py` (or anything under an `include_paths` directory) triggers a reload,
and siphon re-imports the helper from its new source — you don't have to touch
`main.py` to pick up a helper change.

## Rules and limits

- **Absolute imports only.** The main script runs as a plain module, not a
  package, so `from . import helpers` does **not** work — use `import helpers`.
- **No cross-request state in helpers.** The same rule as the main script: don't
  keep per-call state in module-level dicts/lists (it isn't shared across the
  worker threads or replicas and is wiped on reload). Use the `cache` namespace
  for shared state. Pure functions and constants are fine.
- **A helper named after a stdlib module shadows it** — the same foot-gun as a
  normal `python script.py`. Give helpers distinct names (`sip_helpers.py`, not
  `email.py`).
