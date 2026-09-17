# CDR records

The record siphon writes to its CDR sinks: one JSON object per HTTP POST, per
line of the JSON-lines file, per syslog message. `siphon_sdk.cdr` is the typed
mirror of that shape, so a collector imports the contract rather than guessing
at a dict.

```python
from siphon_sdk.cdr import CallDetailRecord

record = CallDetailRecord.from_json(line)
record.call_id, record.duration_secs, record.destination_ip
record.reason_cause                # Q.850 cause off the Reason header
record.extra["billing_id"]         # cdr.write(extra={...}) lands here
```

For writing CDRs from a script see the [`cdr` namespace](observability.md#cdr-namespace);
this page is the record a collector receives.

## Take the body as a dict

```python
from fastapi import FastAPI
from siphon_sdk.cdr import CallDetailRecord

app = FastAPI()

@app.post("/cdr")
async def collect(payload: dict) -> dict:
    record = CallDetailRecord.from_dict(payload)
    ...
    return {"ok": True}
```

Custom fields are **flattened into the top level** of the JSON, not nested:
`cdr.write(extra={...})`, an LCR route's `cdr_fields`, `lcr_attempts`, and a
`MEDIA` record's per-leg figures all arrive as ordinary top-level keys.
`from_dict()` routes every unrecognised key into `.extra`. Annotating the handler
parameter as the model instead makes the framework validate against the declared
fields and drop all of them before your code runs.

`examples/cdr_collector.py` is a runnable version of the above.

## Three record kinds, one shape

| `method` | What it is | Notes |
|----------|-----------|-------|
| `INVITE` / `BYE` / … | the call record | parties, timing, teardown side, `destination_ip` |
| `REGISTER` | a registrar state change | `cdr.include_register`; the change is in `reg_event` |
| `MEDIA` | end-of-call media summary | carries no URIs — join it to the call on `call_id` |

`is_media` / `is_register` tell them apart.

## Which egress address is which

A call record's `destination_ip` is the **signalling** next hop — where siphon
sent the INVITE. A media-anchored call's RTP does not have to go to the same
host, and its media peer is a `MEDIA` record's per-leg `remote_address`. Neither
substitutes for the other.

## Not measured is not zero

A leg's quality figures (`mos_average`, `jitter_ms`, `loss_percent`, `rtt_ms`)
read `None` when the media engine relayed that leg without a userspace actor: a
kernelized relay has no jitter buffer to measure with, so it reports counters
only, plus `packets_lost` when the datapath's RFC 3550 §A.1 gap estimate is
non-zero. A plain G.711 passthrough call is exactly that case, so `None` MOS
across every leg is the expected shape, not a truncated record. Treat `None` as
"no measurement", never as a bad call.

The addresses, counters, codec and payload type are present either way.

## `CallDetailRecord`

::: siphon_sdk.cdr.CallDetailRecord

## `MediaLeg`

::: siphon_sdk.cdr.MediaLeg

## `LcrAttempt`

::: siphon_sdk.cdr.LcrAttempt
