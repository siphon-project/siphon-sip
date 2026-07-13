# Number normalization

Every carrier wants phone numbers in a different shape: Teams Direct Routing
wants `+E.164`, an IMS core wants `tel:+E.164`, a national PSTN trunk wants the
national `0X` form, some interconnects want `00`-international or bare digits.
Instead of hand-rewriting `From` / `To` / `P-Asserted-Identity` / R-URI per call
with `set_*_user`, declare a **number policy** once and apply it with one call.

## The idea

A policy maps each identity header to a target format under a home numbering
plan. `rewrite_identities()` walks the message and reformats every dialable
userpart in place — leaving display names, tags, hosts, non-numbers and
preserved service codes untouched.

| Format | Example |
|--------|---------|
| `e164` | `+31612345678` |
| `plain` | `31612345678` |
| `international` | `0031612345678` |
| `national` | `0612345678` |

## Config

```yaml
# siphon.yaml
numbering:
  country_code: "31"           # home country calling code (numeric, 31 = NL)
  trunk_prefix: "0"
  international_prefix: "00"
  assume: national             # a bare 612345678 is a national number

number_policies:
  # Everything canonical +E.164 for the IMS core.
  "ims-e164@2026":
    default: e164

  # What a national PSTN trunk expects on the wire.
  "pstn-national@2026":
    default: national
    headers:
      request-uri: national      # the trunk dials the national form
      From: international         # present CLI as 00-intl
      P-Asserted-Identity: international
    preserve_users: ["112", "0800*"]   # never touch emergency / service codes

script:
  path: "/etc/siphon/edge.py"
```

## Proxy: normalize inbound to the core

```python
from siphon import proxy

@proxy.on_request("INVITE")
def route(request):
    # Whatever shape the trunk sent (00…, 0X, bare), make it +E.164
    # before it hits the IMS core.
    request.rewrite_identities("ims-e164@2026")
    request.relay()
```

Or inline, without a named policy:

```python
request.rewrite_identities(format="e164")
request.rewrite_identities(format="national", headers=["From", "request-uri"])
```

## B2BUA: normalize per direction

At a trunk↔IMS SBC, normalize the A-leg into canonical `+E.164` for your routing
logic and CDRs, then format the B-leg for the carrier you dial:

```python
from siphon import b2bua

@b2bua.on_invite
def on_invite(call):
    # ingress: canonicalise whatever the A-leg carrier sent
    call.rewrite_identities("ims-e164@2026")

    dest = call.to_uri          # now guaranteed +E.164 for routing / CDR

    # egress: format the identities and the dial target for the trunk
    call.dial(dest,
              header_policy="sip-trunk-edge@2026",
              number_policy="pstn-national@2026")
```

`number_policy=` applies to every branch of `call.fork(...)` too, and
`b2bua.default_number_policy` sets a default for calls that don't pass one.

## Parse a single number

```python
from siphon import numbers

n = numbers.parse("0031612345678")
n.e164        # "+31612345678"
n.national    # "0612345678"
n.cc          # "31"
n.nsn         # "612345678"
```

## Diverting numbers (Diversion / History-Info)

`Diversion` (RFC 5806) and `History-Info` (RFC 7044) carry the diverting party's
number inside structured, indexed entries. They're **off by default**. Opt in
with a `diversion:` block — it rewrites only the diverting number per entry and
preserves the `index`, `reason`, the embedded escaped `cause`, entry ordering,
and any privacy-restricted entry:

```yaml
number_policies:
  "carrier-x-egress@2026":
    default: e164
    diversion:
      format: e164
      apply_to: [Diversion, History-Info]
      respect_privacy: true      # skip privacy-restricted entries
```

## Testing it

Exercise your script without a running server using the
[`siphon-sip` mock SDK](https://github.com/siphon-project/siphon-sip/tree/main/sdk):

```python
from siphon_sdk import mock_module
from siphon_sdk.request import Request

mock_module.install()
mock_module.get_numbers().configure(country_code="31")

request = Request(method="INVITE",
                  ruri="sip:0201234567@example.com",
                  from_uri="sip:0612345678@example.com")
request.rewrite_identities(format="e164")

assert request.from_uri.user == "+31612345678"
assert request.ruri.user == "+31201234567"
```

See the [Numbers API reference](../reference/numbers.md) for the full surface.
