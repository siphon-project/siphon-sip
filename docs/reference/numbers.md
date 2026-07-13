# Numbers (E.164 normalization)

The `numbers` namespace and `rewrite_identities()` reformat the dialable
userpart of every identity header into a single target E.164 shape, so a call
leaves siphon in exactly the format the next hop expects (Teams wants `+E.164`,
an IMS core wants `tel:+E.164`, a national trunk wants `0X`, and so on).

```python
from siphon import numbers

n = numbers.parse("0031612345678")
n.e164          # "+31612345678"
n.national      # "0612345678"
n.format("plain")   # "31612345678"
```

One call rewrites the whole message. Display names, tags, hosts, non-numbers
and preserved service/emergency codes are left untouched.

```python
@proxy.on_request("INVITE")
def route(request):
    request.rewrite_identities("teams-outbound@2026")   # named policy
    request.relay()
```

## Formats

| Token | Example | Meaning |
|-------|---------|---------|
| `e164` | `+31612345678` | leading `+`, country code, NSN |
| `plain` | `31612345678` | E.164 digits, no `+` |
| `international` | `0031612345678` | international access prefix + digits |
| `national` | `0612345678` | national trunk prefix + NSN (home country only; a foreign number falls back to the international access form) |

## Home numbering plan

Parsing and formatting are driven by the `numbering:` config block — the home
country calling code plus the trunk / international prefixes:

```yaml
numbering:
  country_code: "31"           # numeric calling code (31 = NL), not an ISO code
  trunk_prefix: "0"
  international_prefix: "00"
  assume: national             # how to read a bare, prefix-less number
  min_national_digits: 5       # shorter bare numbers are treated as short codes
```

## Named policies

Policies are named, versioned presets in `number_policies:`, referenced by
`request.rewrite_identities("<name>")` or `call.dial(number_policy="<name>")`.
Pin the `@version` so a siphon upgrade never silently shifts the set of headers
being reformatted.

```yaml
number_policies:
  "teams-outbound@2026":
    default: e164
    headers:                     # per-header overrides on top of default
      request-uri: e164
      P-Asserted-Identity: e164

  "pstn-national@2026":
    default: national
    headers:
      request-uri: national      # what the trunk dials
      From: international         # CLI presented as 00-intl
    on_unparseable: keep         # keep | strip (P-headers only)
    preserve_users: ["112", "911", "0800*"]
    diversion:                   # opt-in — see below
      format: e164
```

## The diversion family

`Diversion` (RFC 5806) and `History-Info` (RFC 7044) carry the diverting-party
number inside structured, multi-valued, indexed entries — a History-Info URI
embeds an escaped `cause`. They are **off by default** and handled by a separate
opt-in `diversion:` block that rewrites only the userpart of each entry,
preserving `index`, `reason`, the embedded `cause`, entry ordering, and any
privacy-restricted entry (`respect_privacy: true`, the default).

## `numbers` namespace

::: siphon_sdk.numbers.MockNumbersNamespace

## Parsed number

Returned by `numbers.parse(...)`.

::: siphon_sdk.numbers.Number

## `rewrite_identities()`

Both the proxy request and the B2BUA call expose `rewrite_identities(policy=None,
format=None, headers=None, home=None)`, which walks the identity headers and
reformats each dialable userpart in place, returning the number of headers
changed. Pass **either** a named `policy` from `number_policies:` **or** an
inline `format` with an optional `headers` list and `home` override. See
[`request.rewrite_identities`](request.md) and
[`call.rewrite_identities`](call.md) for the full signatures and examples.

On the B2BUA, `call.dial(number_policy="<name>")` / `call.fork(number_policy=…)`
(or the `b2bua.default_number_policy` config default) normalize the A-leg
identity headers that flow to the B-leg plus the dial/fork target as the final
step before the INVITE is built.
