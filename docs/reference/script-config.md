# Script configuration (`script_config`)

A script holds dispatch logic. The tables that logic walks (routes, rule lists,
policy) belong to whoever operates the node and change on a different schedule
than the code. `script_config:` is where they live, and the `config` namespace
is how a script reads them.

## The `script_config:` key

The value is either the document itself or the path of a YAML file holding it.

```yaml
# siphon.yaml, path form: the file is watched and reloaded
script_config: /etc/siphon/routes.yaml
```

```yaml
# siphon.yaml, inline form: fixed for the life of the process
script_config:
  routes:
    default: gateway-a.example.com
    prefixes:
      - prefix: "+1555"
        gateway: gateway-b.example.com
```

- The top level is a mapping. Below it, anything YAML can say with plain
  mappings, sequences and scalars; mapping keys are scalars, and YAML tags
  (`!!binary`, custom tags) are refused.
- `${VAR}` and `${VAR:-default}` are expanded in both forms, with the rules
  `siphon.yaml` itself follows.
- A relative path is resolved like `script.path`: against the directory holding
  `siphon.yaml` when the file is there, else against the working directory.
- A file that is missing or does not parse at startup stops siphon, naming the
  file. Without the key the document is empty.
- Quote anything that is a string but looks like a number. YAML reads an
  unquoted `+1555` as the integer 1555 and `0031` as 31, so a dialling prefix
  or a number with a leading zero written bare is not the text you typed, as a
  value and as a mapping key alike.

## Reloading

The path form follows `script.reload`. Under `auto` (the default) the file is
watched and read again when it changes; under `sighup` it is not watched. In
both modes `SIGHUP` reads it again, and so does `POST /admin/script/reload`,
whose reply carries `"script_config": "reloaded"`, `"unchanged"` or `"failed"`
(with the reason in `script_config_error` and a `422`).

A reload replaces the whole document at once: a handler sees the old document
or the new one, never a mix. A file that cannot be read or does not parse is
logged at `error` with the file and the reason, and the last good document
keeps serving.

Reloading the document does not reload the script. Read values where they are
used, inside the handler, rather than copying them into module-level variables
when the script loads: those copies are taken once and never see a reload.

## Reading it from a script

```yaml
# /etc/siphon/routes.yaml
routes:
  default: gateway-a.example.com
  by_prefix:
    "+1555": gateway-b.example.com
    "+15550100": gateway-c.example.com
```

```python
from siphon import b2bua, config

@b2bua.on_invite
def route(call):
    number = call.ruri.user
    gateway = config.require("routes.default")
    # Longest prefix first, one narrow lookup per length.
    for length in range(len(number), 0, -1):
        found = config.get("routes.by_prefix." + number[:length])
        if found is not None:
            gateway = found
            break
    call.dial(f"sip:{number}@{gateway}")
```

`+15550100` goes to `gateway-c.example.com`, `+15550199` to
`gateway-b.example.com`, anything else to `gateway-a.example.com`. Edit the
file and the next call routes by the new table.

The table is a mapping keyed by prefix, not a list to walk, for a reason: each
`config.get` copies what it returns, so asking for the whole list on every call
costs as much as the list is long, while a lookup by key costs the same for ten
routes or a hundred thousand. Keep a list for what really is one (an ordered
rule set of a handful of entries) and key anything that grows.

Keys are dotted paths. Each segment is a mapping key or a zero-based sequence
index (`routes.prefixes.0.gateway`); a mapping key written as an integer in
YAML (`31: nl`) is matched by the segment `31`; `""` is the whole document. A
key that itself contains a dot cannot be named this way: fetch its parent and
index that.

Every call returns plain data (`dict`, `list`, `str`, `int`, `float`, `bool`,
`None`) as a new copy, so nothing a handler does to the value reaches another
handler or the next call. The copy costs as much as the value is large: on a
per-message path ask for the narrowest key you need, not the whole document.

## `config` namespace

::: siphon_sdk.mock_module.MockScriptConfig
