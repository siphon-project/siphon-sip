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
- **An unreadable source changes nothing.** A failed read keeps the current
  registrations. Reconciling an outage to "no trunks" would tear down the whole
  estate because a database was briefly down, so an endpoint that cannot answer
  should fail the request rather than return an empty list — an empty `200` is
  indistinguishable from "delete everything".
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
