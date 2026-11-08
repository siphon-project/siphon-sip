# IMS control

The namespaces that make SIPhon an IMS core: iFC evaluation (`isc`), 5G SBI /
N5 policy authorization and Nbsf discovery (`sbi`), SIP presence (`presence`),
lawful intercept (`li`), and the Session Recording Server hooks (`srs`).

## `isc` namespace

Initial Filter Criteria evaluation (3GPP TS 29.228 / IMS Service Control).

A service profile may name shared iFC sets (`<SharedIFCSetID>`, TS 29.228
Annex B.2) that the S-CSCF holds locally, configured under `isc:`:

```yaml
isc:
  shared_ifc_sets:
    - id: 1
      file: /etc/siphon/sifc/1.xml   # <InitialFilterCriteria> elements
```

They are merged with the profile's own iFCs by priority at evaluation, and
with one configured Cx SAR advertises the `SiFC` feature so the HSS sends the
ids (TS 29.229 §7.1.1). A diverted request takes the ORIGINATING_CDIV iFCs,
and SessionDescription trigger points read the SDP passed as `body`:

```python
matches = isc.evaluate(
    served_user, request.method, str(request.ruri), headers,
    session_case="originating_cdiv",
    body=request.body if request.get_header("Content-Type") == "application/sdp" else None,
)
```

::: siphon_sdk.mock_module.MockIsc

## `sbi` namespace

5G Service-Based Interface — N5/Npcf policy authorization plus Nbsf_Management
PCF discovery.

### Outbound TLS

Use HTTPS endpoint URLs for TLS on SBI (TS 33.501 clause 13.1). The optional
`tls` block applies to the manager's HTTP client and the Npcf and Nbsf clients
created at startup:

```yaml
sbi:
  npcf_url: "https://pcf.example.com"
  bsf_url: "https://bsf.example.com"
  tls:
    ca: "${SBI_TLS_DIR}/ca.pem"
    cert: "${SBI_TLS_DIR}/client-chain.pem"
    key: "${SBI_TLS_DIR}/client-key.pem"
    trust_public_roots: true
```

`ca` is an optional PEM bundle of trusted CA certificates. `cert` is a PEM
client certificate chain (leaf first), and `key` is its PEM private key; both
must be supplied together for mutual TLS. Paths support the usual `${VAR}`
expansion. `trust_public_roots` defaults to `true`, adding the configured CAs
to the public roots. Set it to `false` to trust only the supplied CAs. Omitting
`tls` preserves public roots and sends no client certificate.

Unreadable files, invalid certificates or keys, mismatched identities, and
HTTP client construction failures stop startup with an error. Files are read
once when the manager is created. Restart after certificate or CA rotation,
including cert-manager updates: SIGHUP and script reload do not rebuild this
manager. This block configures outbound connections, not the callback listener.

Rust consumers should handle the `Result` returned by `SbiManager::new` and
clone `manager.client()` for Npcf, Nbsf, Nchf, or other SBI requests.
`client_with_timeout` builds a client with the same cached TLS material and a
different timeout. NRF discovery and access-token requests are not yet
implemented; future implementations must use this configured client too.

### Static bearer authentication

For an SCP or producer that authenticates consumers with a pre-shared token:

```yaml
sbi:
  npcf_url: "https://pcf.example.com"
  bsf_url: "https://bsf.example.com"
  bearer_token_file: "${SBI_TOKEN_DIR}/bearer-token"
```

An empty `bearer_token_file`, `ca`, `cert` or `key` is unset, so a shared
configuration can take each from the environment (`"${SBI_CA_FILE:-}"`) and
leave it out where the variable is not set.

The optional path supports normal environment expansion and can be used alongside
`sbi.tls`. The file is read once at startup, with surrounding whitespace trimmed.
Empty or unreadable files and tokens outside RFC 6750's `b64token` grammar stop
startup with an error naming the file. Tokens contain ASCII letters, digits,
`-`, `.`, `_`, `~`, `+`, or `/`, optionally followed by trailing `=` padding.
Token values are redacted from Debug output.

Every client built by `SbiManager`, including timeout-specific clients, sends
`Authorization: Bearer <token>` unless the request supplies its own Authorization
header. Omitting the setting preserves the existing behavior. Restart to rotate
the token; reload does not reread it.

A token that identifies the consumer to the SCP it sends through goes in
`Proxy-Authorization` instead (RFC 9110 section 11.7.2), which leaves
`Authorization` to a producer's access token:

```yaml
sbi:
  bearer_token_file: "${SBI_TOKEN_DIR}/scp-token"
  bearer_token_header: proxy-authorization   # default: authorization
```

With a token configured, `npcf_url`, `bsf_url`, `nchf_url`, and `nrf_url` must
use HTTPS, except that HTTP is allowed for loopback IP literals and `localhost`.
Remote HTTP endpoints fail startup. Use HTTPS for dynamically discovered PCF
endpoints too (`pcf_scheme: https`); startup validation covers configured URLs.
Rust consumers must supply their peer URLs in `SbiConfig` for this validation.

### PCF callbacks

The PCF calls back on the address in `sbi.notif_listen` (plain HTTP by default).
Advertise the externally reachable callback base as `notif_uri`; the PCF appends the
TS 29.514 suffix for each callback, so one listener serves both.

`notifUri` is a required attribute of the create (TS 29.514), so
`sbi.create_session` needs a callback URI on every call, with or without
`events`. Set it once in the configuration and a script can leave the
argument out; `notif_uri=` on a call overrides it. With neither, the call
raises `ValueError` and nothing is sent.

```yaml
sbi:
  notif_listen: "0.0.0.0:8080"
  notif_uri: "http://192.0.2.10:8080/sbi/events"   # how the PCF reaches notif_listen
```

To serve HTTPS directly, configure `notif_tls`. TLS negotiates `h2` through
ALPN for TS 29.500 HTTP/2, with `http/1.1` as a fallback:

```yaml
sbi:
  notif_listen: "0.0.0.0:8443"
  notif_uri: "https://notif.example.net:8443/sbi/events"
  notif_tls:
    cert: "${SBI_NOTIF_CERT:-}"
    key: "${SBI_NOTIF_KEY:-}"
    client_ca: "${SBI_NOTIF_CLIENT_CA:-}"
```

`cert` is the PEM server certificate chain (leaf first); `key` is its PEM
private key. Set both environment variables to enable TLS. A nonempty
`client_ca` names a PEM CA bundle: clients must present a certificate verified
against it (mutual TLS). Without it, no client certificate is requested.
These inbound settings are independent of the outbound `sbi.tls` settings.

Empty paths count as unset. With no `notif_tls`, or both `cert` and `key`
unset, the listener stays plain HTTP; `client_ca` alone does not enable TLS.
Setting only one of `cert` and `key` fails startup. Unreadable or invalid TLS
files fail startup and name the offending file; there is no fallback to HTTP.
Files are loaded once at startup; restart to rotate certificates or trust anchors.
Handshake failures affect only that connection.

`notif_uri` is always the operator's advertised URI and is never rewritten.
Use `https://` when the PCF reaches a TLS endpoint, accounting for any proxy
or address translation in front of the listener.

| Route | Body (verbatim dict) | Hook |
|---|---|---|
| `POST /sbi/events/notify` | `EventsNotification` | `@sbi.on_event` |
| `POST /sbi/events/terminate` | `TerminationInfo` | `@sbi.on_terminate` |

Both answer `204` once the handlers ran (a handler that raises is logged and
still acknowledged), `400` for a body that is not JSON, and `503` when siphon's
Python executor could not take the job, so the PCF knows the callback was not
handled. Any other path is `404`.

A termination can arrive for any app session created with `notif_uri`. Events
only arrive for what the session subscribed to, with
`create_session(events=[...], notif_uri=...)` or
`update_session(events=[...])`.

The bare `POST /sbi/events`, which reached `@sbi.on_event` for a PCF that posted
to the advertised URI without a suffix, was deprecated in 1.9.0 and removed in
1.10.0. It now answers `404` like any other unknown path. A PCF that appends the
TS 29.514 suffix — which is what the spec defines — is unaffected.

::: siphon_sdk.mock_module.MockSbi

### `BsfError`

Raised by `sbi.discover_pcf_binding(...)` when the BSF is unhealthy. A BSF
that has no binding for the address is healthy: it answers `204` (TS 29.521
§4.2.4.2; some servers answer `404`) and the lookup returns `None`.

::: siphon_sdk.mock_module.BsfError

## `presence` namespace

SIP presence document publish/lookup and subscription tracking (RFC 3856 /
6665).

::: siphon_sdk.mock_module.MockPresence

## `li` namespace

Lawful intercept (ETSI X1/X2/X3) and SIPREC recording triggers.

::: siphon_sdk.mock_module.MockLi

## `srs` namespace

Session Recording Server acceptance hooks (RFC 7866 SIPREC).

::: siphon_sdk.mock_module.MockSrs

### `SrsSession`

A completed recording session.

::: siphon_sdk.srs.SrsSession

### `RecordingMetadata`

Parsed RFC 7866 recording metadata from a SIPREC INVITE.

::: siphon_sdk.srs.RecordingMetadata

### `SrsParticipant`

::: siphon_sdk.srs.SrsParticipant

### `SrsStreamInfo`

::: siphon_sdk.srs.SrsStreamInfo
