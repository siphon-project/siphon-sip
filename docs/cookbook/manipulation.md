# SIP & SDP manipulation

The classic header-manipulation (HMR) job: rewrite, add, or strip headers and
SDP as a message crosses a boundary. SIPhon hands you the parsed message and
gets out of the way. You decide what changes, in Python, with the whole standard
library (including `re`) available. There is no manipulation DSL to learn; it is
just code.

## Headers

Every header operation is a method on the `request` (or, on the B2BUA, the
`call`). Names are case-insensitive.

```python
from siphon import proxy

@proxy.on_request
def edit(request):
    # read
    ua = request.get_header("User-Agent")        # str | None
    has_pai = request.has_header("P-Asserted-Identity")

    # strip inbound internal headers by name prefix (case-insensitive), e.g. X-*
    request.remove_headers_matching("X-")

    # then stamp our own
    request.set_header("X-Trunk", "wholesale-a")  # replace (or add if absent)
    request.ensure_header("Max-Forwards", "70")   # set only if not already present
    request.remove_header("P-Preferred-Identity")

    # one value out of a multi-value header
    request.remove_from_header_list("Supported", "100rel")

    request.relay()
```

| Call | What it does |
|---|---|
| `get_header(name)` / `header(name)` | Read a header value (`None` if absent). |
| `has_header(name)` | Presence check. |
| `set_header(name, value)` | Replace the header, or add it if absent. |
| `ensure_header(name, value)` | Set only if not already present. |
| `remove_header(name)` | Remove a header by name. |
| `remove_headers_matching(prefix)` | Remove every header whose **name starts with** `prefix` (case-insensitive). |
| `remove_from_header_list(name, value)` | Drop one value from a comma-separated header. |

## Regex

`remove_headers_matching` is a **name-prefix** strip, not a regex. When you need
a real regular expression, reach for Python's `re` on the value you read. The
scripts are ordinary Python, so the whole `re` module is there:

```python
import re
from siphon import proxy

SCANNERS = re.compile(r"sipvicious|friendly-scanner|sipcli", re.IGNORECASE)

@proxy.on_request
def drop_scanners(request):
    # drop known scanners silently (no response = no fingerprint)
    if SCANNERS.search(request.get_header("User-Agent") or ""):
        return

    # rewrite inside a header value
    diversion = request.get_header("Diversion")
    if diversion:
        request.set_header("Diversion", re.sub(r"sip:(\d+)@", r"tel:\1;", diversion))

    request.relay()
```

## SDP

Parse the body, edit it, apply it back. `apply()` sets the body, `Content-Type`,
and `Content-Length` for you.

```python
from siphon import proxy, sdp

@proxy.on_request("INVITE")
def edit(request):
    if not request.has_body("application/sdp"):
        request.relay(); return

    s = sdp.parse(request)

    # keep only G.711
    s.filter_codecs(["PCMU", "PCMA"])

    # strip video
    s.remove_media("video")

    # put audio on hold
    for m in s.media:
        if m.media_type == "audio":
            m.port = 0

    # session- and media-level a= attributes
    s.set_attr("ice-lite")                 # flag attribute
    for m in s.media:
        m.set_attr("ptime", "20")

    s.apply(request)
    request.relay()
```

The full `sdp` surface (media sections, codecs, `a=` attributes, connection
lines) is in the [SDP reference](../reference/sdp.md).

## On the B2BUA

At an SBC boundary, the same header and SDP methods exist on the `call`, but the
right tool for *which headers cross the A↔B boundary* is a **header policy**, not
per-header code. Pick a preset, then apply per-call deltas only for the
exceptions:

```python
from siphon import b2bua

@b2bua.on_invite
def on_invite(call):
    call.remove_headers_matching("X-")           # strip internal headers
    call.dial(
        "sip:+15551234567@carrier.example.net",
        header_policy="sip-trunk-edge@2026",     # the boundary hygiene preset
        copy=["X-Account-Id"],                    # let this one through
        strip=["History-Info"],                   # drop this one
    )
```

Script `call.set_header()` / `call.remove_header()` always win over the preset.
The presets and precedence are covered in the [SBC recipe](sbc.md).

## Test it

Exercise the logic without a running server using the
[`siphon-sip` mock SDK](https://github.com/siphon-project/siphon-sip/tree/main/sdk):

```python
from siphon_sdk import mock_module
from siphon_sdk.request import Request

mock_module.install()

# internal headers are stripped, and the request is relayed
request = Request(method="INVITE", headers={"X-Internal-Trace": "abc"})
edit(request)
assert request.get_header("X-Internal-Trace") is None
assert request.last_action.kind == "relay"

# a scanner is dropped: no routing action was taken
scanner = Request(method="INVITE", headers={"User-Agent": "friendly-scanner"})
drop_scanners(scanner)
assert scanner.actions == []
```

## The line

The manipulation is yours to define; SIPhon just gives you a clean, parsed
message to change and re-serializes it correctly (Via, Content-Length, header
ordering). What to rewrite, and why, is your policy.

## See also

- Real script: [`examples/teams_sbc.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/teams_sbc.py) (B2BUA header hygiene at a Teams boundary).
- [Request reference](../reference/request.md) · [SDP reference](../reference/sdp.md).
- [Number normalization](number-normalization.md) for policy-driven E.164 identity rewriting.
