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

### PCF callbacks

The PCF calls back over HTTP on the address in `sbi.notif_listen`. Advertise
`http://<notif_listen>/sbi/events` as `notif_uri`; the PCF appends the
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
