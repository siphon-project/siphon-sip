# Outbound-registration provisioning contract (v1)

The JSON a `registrant.backend: http` source answers with, so a controller that
owns trunks as data can hand siphon the list instead of having them written into
`siphon.yaml` by hand.

The models are typed in [`siphon_sdk.registrants`](https://pypi.org/project/siphon-sip/)
and mirrored by the Rust structs in `src/registrant/source.rs`. A runnable
reference server — serving this and the [gateway contract](gateway-api.md)
off one table — is `examples/provisioning_api_server.py`.

```python
from siphon_sdk.registrants import RegistrantListResponse, RegistrantRow
```

## Configuration

```yaml
registrant:
  backend: http                 # static (default) | database | http
  http:
    url: "http://127.0.0.1:8080/registrants"
    refresh_secs: 30            # how often to re-read and reconcile
    timeout_ms: 2000
    auth_header: "Bearer ${PROVISIONING_TOKEN}"
    # Optional: one trunk by AoR, for the restart clean-up (see "Lookup by AoR").
    lookup_url: "http://127.0.0.1:8080/registrants/lookup?aor={aor}"
  default_interval: 3600        # used by a row that omits `interval`
```

The SQL form reads the same fields as columns:

```yaml
registrant:
  backend: database
  database:
    url: "postgresql://siphon@db.internal/siphon"
    query: "SELECT aor, registrar, username, password, realm, expires AS interval,
             contact, transport, enabled FROM registrants WHERE node = $1"
    refresh_secs: 30
    # Optional: the one trunk whose AoR is $1 (see "Lookup by AoR").
    lookup_query: "SELECT aor, registrar, username, password, realm, contact, transport,
                    enabled FROM registrants WHERE aor = $1"
```

`aor`, `registrar` and `username` are required; every other column is optional
and takes the default below. When the statement references `$1`, siphon binds
`server.instance_id` to it, so a deployment can shard its trunks across nodes.

## Response (source → siphon)

`GET {url}` returns the **complete desired state**, not a delta.

```json
{
  "version": "1",
  "registrants": [
    {
      "aor": "sip:trunk1@carrier.example",
      "registrar": "sip:carrier.example:5060",
      "username": "trunk1",
      "password": "…",
      "realm": "carrier.example",
      "interval": 1800,
      "transport": "udp",
      "enabled": true,
      "gateway": "carriers"
    }
  ]
}
```

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `aor` | string | — | Address of record to register |
| `registrar` | string | — | Where the REGISTER goes; a host with no port defaults to 5060, or 5061 for `tls` |
| `username` | string | — | Digest username |
| `password` | string | — | Plaintext password. Supply this **or** `ha1`, never both |
| `ha1` | string | — | `H(username:realm:password)` hex |
| `ha1_algorithm` | string | `"md5"` | Hash `ha1` was computed with: `md5`, `sha-256`, `sha-512-256` |
| `realm` | string | from the challenge | Realm hint |
| `interval` | int | `registrant.default_interval` | Re-registration interval, seconds |
| `contact` | string | from the local address | Contact URI override |
| `transport` | string | `"udp"` | `udp`, `tcp` or `tls` |
| `enabled` | bool | `true` | `false` de-registers without removing the row |
| `gateway` | string | — | `gateway:` group this trunk's calls egress through |
| `hold_secs` | int | — | Seconds after the last successful read during which this node may keep refreshing the trunk while the source is unreadable; past it the trunk stops registering with nothing sent. Absent: never. `0`: on the first failed read. Negative or above `4294967295`: the row is rejected. See [Behavior notes](#behavior-notes) |

## Choosing between `password` and `ha1`

A trunk password has to be **recoverable** to register with, which is what makes
this different from a credential view: the H(A1) that `auth.backend: database`
exposes is enough to *verify* a subscriber, but not to *be* one.

- **`password`** answers whatever the registrar challenges with. The general
  case, and the only one that works when the realm is not known ahead of the
  first challenge.
- **`ha1`** cannot be reversed to the password, so a store holding one cannot
  leak it. It is still password-equivalent **for its realm** — anything holding
  it can register as that trunk — and it is bound to one hash
  (RFC 7616 §3.4.3), so a registrar that challenges with SHA-256 cannot be
  answered from an MD5 one. siphon reports that mismatch rather than answering
  wrongly, because a wrong H(A1) produces a well-formed response the registrar
  reads as a bad password.
- **The `http` source** is the form for a deployment that seals its secrets at
  rest: the controller unseals in-process and serves the credential over a
  trusted local channel, so siphon never sees the sealed form and no sealing
  construction has to enter siphon.

## Typed contract models

`siphon_sdk.registrants` is the single typed source for the shapes above —
zero-dependency dataclasses, mirroring the Rust serde structs in
`src/registrant/source.rs`. Build your endpoint against them rather than
hand-assembling dicts:

```python
from fastapi import FastAPI
from siphon_sdk.registrants import RegistrantListResponse, RegistrantRow

app = FastAPI()

@app.get("/registrants")
def registrants() -> dict:
    return RegistrantListResponse(registrants=[
        RegistrantRow(
            aor="sip:trunk1@carrier.example",
            registrar="sip:carrier.example:5060",
            username="trunk1",
            password="…",
            gateway="carriers",
        ),
    ]).to_dict()
```

`to_dict()` omits absent optionals rather than emitting `null`, matching the
Rust `skip_serializing_if`, so what it produces is exactly the payload shown
above. `from_dict()` is the inverse, for reading a payload back in a test.

### `RegistrantListResponse`

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `registrants` | `list[RegistrantRow]` | `[]` | The complete desired state |
| `version` | `str` | `"1"` | Contract version; a mismatch is logged, not fatal |

### `RegistrantRow`

One registering trunk. `aor`, `registrar` and `username` are required
positionally; everything else is keyword-with-default and maps one-to-one onto
the JSON fields in the table above.

| Field | Type | Default |
| ----- | ---- | ------- |
| `aor` | `str` | — |
| `registrar` | `str` | — |
| `username` | `str` | — |
| `password` | `str \| None` | `None` |
| `ha1` | `str \| None` | `None` |
| `ha1_algorithm` | `str` | `"md5"` |
| `realm` | `str \| None` | `None` |
| `interval` | `int \| None` | `None` |
| `contact` | `str \| None` | `None` |
| `transport` | `str` | `"udp"` |
| `enabled` | `bool` | `True` |
| `gateway` | `str \| None` | `None` |
| `hold_secs` | `int \| None` | `None` |

## Fetch before every de-REGISTER

A digest entry never sends `Expires: 0` blind. Whatever clears its binding
(graceful shutdown, `registration.remove()` or a source dropping or disabling the
trunk, a source update that moves it to another registrar, destination or
transport, and the restart clean-up below) first sends a **fetch** on the
binding's Call-ID at the next CSeq: a REGISTER with no `Contact` and no `Expires`
(RFC 3261 §10.2.3), which changes nothing. Only when its 2xx lists this node's
own Contact (the one the entry last registered, compared as SIP URIs; a contact
with an effective expiry of 0 is not listed) does siphon send `Expires: 0`, on
the same Call-ID at the CSeq after the fetch's. Otherwise nothing more is sent,
it is logged at info with the AoR and registrar, and the binding is left to
expire. That covers a 2xx listing only other Contacts or none, any non-2xx, a
transport failure and Timer F.

The reason is a registrar that keeps one binding per AoR (not the multi-binding
of §10.3): another node's REGISTER replaced this node's binding, so an
`Expires: 0` on this node's Contact, or on the AoR, clears the live node's. The
typical case is a trunk whose lease moved to another node, which has registered
already by the time this one shuts down or drops it.

A challenge to the fetch or to the de-REGISTER (RFC 3261 §22) is answered once
each with the entry's own credentials. A live entry holds them, so no lookup is
involved. The persisted binding record is dropped at every outcome. If the same
trunk is added again and registers on the same Contact, registrar and destination
before the fetch is answered, the `Expires: 0` is not sent either: it would clear
the new entry's binding.

**Shutdown stays bounded.** The fetch and the de-REGISTER share the existing
shutdown answer bound (`SHUTDOWN_ANSWER_WAIT`, 20 seconds from the signal,
overlapping the drain). When the fetch has no final answer by then, or fails,
shutdown ends without sending `Expires: 0`: that is the safe side, since the
binding then expires on its own. The extra round trip is the cost of not
clearing another node's binding.

**IMS entries are unchanged.** An AKA entry, or any entry with an IPsec UE, sends
its `Expires: 0` directly, as before (a UE de-registers over the SA set it
registered over, TS 24.229 5.1.1.6). An S-CSCF keeps every contact of the IMPU
rather than replacing them, and an unprotected fetch would not reach the
protected port. The one-binding-per-AoR hazard does not arise there.

## Lookup by AoR (optional)

With `registrar.backend: redis` siphon keeps one record per granted binding
under `registrar.redis.registrant_key_prefix` (default `siphon:registrant:`), so
a node that is **killed without a graceful shutdown** can clear what it left on
the registrar when it restarts. Without that, a trunk whose lease moved to
another node meanwhile stays registered from the dead node, as a second contact,
until the old binding expires (up to one `interval`).

At restart, once the source has been read for the first time, siphon clears
every stored binding no live entry owns in two steps, on the stored Call-ID and
a CSeq above every one the process before used (§10.2.4). It first sends a
**fetch**: a REGISTER with no `Contact` and no `Expires` (§10.2.3), which
changes nothing and is answered with the bindings the registrar holds. Only when
that 2xx lists this node's stored Contact (compared as SIP URIs, §19.1.4:
case, parameter order and the like do not matter) does it send `Expires: 0`
(§10.2.2) for it, the CSeq after the fetch's. In every other case the binding is
not this node's to clear, or is gone already, and it is left: the 2xx lists only
other Contacts or none, the fetch is refused, or it times out. That is logged
at info with the AoR and registrar, and the record is dropped. The reason is a
registrar that keeps one binding per AoR (not the multi-binding of §10.3):
another node's REGISTER replaced this node's binding, and an `Expires: 0` on
this node's Contact would clear the other node's. A fetch and its de-REGISTER
are one attempt toward the bound below. A live entry that has not registered yet and
targets the same contact takes the binding over instead (same Call-ID, CSeq
continued), so its first REGISTER refreshes it. Rows the source returned that
siphon rejected count as still listed and are left alone.

**No credential is stored.** A registrar that challenges the fetch or the
de-REGISTER (RFC 3261 §22) is answered from a lookup of the trunk by AoR, once
for each. Configure it with
`lookup_url` (HTTP) or `lookup_query` (database); without one the challenge is
not answered, the binding expires as it would have, and the record is dropped
(logged with the AoR and registrar).

- `lookup_url` is a template with an `{aor}` placeholder, replaced by the AoR
  percent-encoded as a URL query component. siphon `GET`s it with the same
  `Authorization` header as the list.
- The answer is **one trunk row**: exactly the JSON of one element of
  `registrants`. Only `username` and `password` (or `ha1` with `ha1_algorithm`)
  and `realm` are read. It must be answered whether or not the trunk is listed
  for this node and **whether or not it is `enabled`**: the trunk may have moved
  to another node or been switched off, which is why its binding is being
  cleared.
- `404` means the AoR is unknown. Any other non-2xx, a timeout or a body that
  does not parse is treated the same: the challenge is not answered.
- `lookup_query` is a statement returning the one row whose AoR is `$1`, in the
  columns of `query`.

A de-REGISTER is sent only for a Contact that is exactly a socket this node
registers from (an explicit IP and port equal to a specific listener or the
egress address: wildcards, names, a missing port and per-entry addresses never
qualify) and that no other node's record holds for the same AoR. Both are
checked again right before every send, the authorised retry included; anything
that cannot be established, Redis unreadable included, leaves the binding to
expire. A registrar keys a binding by its Contact (RFC 3261 §10.3), so a wrong
`Expires: 0` would delete a live binding. Records are only ever rewritten or
removed by Call-ID, so a newer registration's record is never touched.

**Known limit.** On a registrar that replaces the AoR's binding on every
REGISTER, another node can register between the fetch and the de-REGISTER that
follows (a restart's clean-up, a removal and shutdown alike), and the `Expires: 0`
then clears its binding. Nothing closes that window; the binding returns at the
other node's next refresh.

Records hold the AoR, registrar, destination, transport, the Contact sent, the
Call-ID, the next CSeq, the local address, the interval, the grant's end and an
attempt counter (at most 3 start-ups try one binding). They expire by themselves
once the registrar would have dropped the binding. IMS AKA / IPsec entries are
not covered (their de-REGISTER needs the USIM's state). The Contact's user part
is derived from the `username` unless the row sets `contact`; set `contact` if
the username must not appear in Redis at all.

## Behavior notes

- **Reconcile, not reload.** Every `refresh_secs` siphon re-reads the source and
  applies only the difference. A row it has already registered unchanged is left
  completely alone — same Call-ID, same CSeq, same refresh timer — so polling
  does not churn the estate.
- **A change re-registers at once.** When a row's credentials, registrar,
  contact, interval or transport change, siphon refreshes that binding
  immediately, keeping its Call-ID and continuing its CSeq so the registrar sees
  a refresh rather than an unrelated new registration (RFC 3261 §10.2.4).
- **A removed or disabled row de-registers.** siphon sends `Expires: 0`
  (RFC 3261 §10.2.2) rather than dropping local state and leaving the binding on
  the registrar until it ages out.
- **An unreadable source changes nothing, unless a row asked for a hold.** A
  failed read keeps the current registrations. Reconciling an outage to "no
  trunks" would tear down the whole estate because a database was briefly down,
  so an endpoint that cannot answer should fail the request rather than return
  an empty list — an empty `200` is indistinguishable from "delete everything".
  The exception is a row with `hold_secs`. With several nodes sharing one
  controller, each trunk leased to one node and each node served only its own,
  a node whose controller died while siphon lived would otherwise keep
  refreshing a trunk another node has taken over, and at a registrar that keeps
  one binding per AoR that refresh steals the binding. So once the source has
  failed to read and `hold_secs` have passed since the last successful read, the
  node stops registering the trunk: the entry is dropped **without a REGISTER of
  any kind** (no `Expires: 0`, no fetch: it cannot know who holds the binding
  now), a refresh that was about to go is refused, the stored binding record is
  kept for a later restart's clean-up, and `siphon_registrant_source_standdowns_total`
  counts it with a warning naming the AoR. Registrant events report it as
  `stood_down`. The next successful read that serves the row registers it afresh.
  A change of `hold_secs` alone re-registers nothing. Entries from
  `registrant.entries` and scripts never have a hold.

  **For controllers:** the anchor is siphon's last *successful read*, not your
  lease's last renewal. Serve `hold_secs` as the time remaining on the lease at
  serve time (lease expiry minus now, minus a small margin), not the full lease
  length. Otherwise a node can still refresh in the gap between the lease's last
  renewal and its last read.

  **What stand-down stops.** It stops new REGISTERs and abandons the ones in
  flight: the entry's client transaction ends, so Timer E retransmits nothing,
  and a REGISTER built just before the hold ran out is refused when it is about
  to be sent (the Call-ID is remembered as stood down for as long as a
  transaction can live). It cannot recall a request already handed to the
  transport, which may still leave: that window is bounded by the transport
  queue and any connect in progress. Keep a margin of a few seconds below the
  lease's remaining time in the `hold_secs` you serve to cover it.
- **The source owns only what it created.** Entries from `registrant.entries`
  and from `registration.add()` in a script are never updated or removed by a
  reconcile, and a row whose AoR one of them already holds is skipped with a
  warning. Without that, the first pass would delete the IMS soft-UE and every
  other registration no database knows about.
- **A malformed row is skipped, not fatal.** One bad trunk must not stop the
  other nine hundred; it is counted and logged with its AoR.
- **Push, when polling is too slow.** `POST /admin/registrants/refresh` applies
  a change the moment the controller saves a row, so `refresh_secs` is the floor
  rather than the mechanism.
