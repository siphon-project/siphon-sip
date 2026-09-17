# Observability

Cross-cutting utility namespaces: structured logging (`log`), the named cache
backends (`cache`), call detail records (`cdr`), custom Prometheus metrics
(`metrics`), and periodic / one-shot timers (`timer`).

## `log` namespace

::: siphon_sdk.mock_module.MockLog

## `cache` namespace

Named cache backends (Redis + local LRU) from the `cache:` config list.

::: siphon_sdk.mock_module.MockCache

## `cdr` namespace

Call detail record writing from scripts.

::: siphon_sdk.mock_module.MockCdr

### The record a collector receives

Every sink writes the same shape: one JSON object per HTTP POST, per line of the
JSON-lines file, per syslog message. `siphon_sdk.cdr.CallDetailRecord` is the
typed mirror of it, so a collector imports the contract rather than guessing at
a dict:

```python
from siphon_sdk.cdr import CallDetailRecord

record = CallDetailRecord.from_json(line)
record.call_id, record.duration_secs, record.reason_cause
record.extra["billing_id"]        # cdr.write(extra={...}) lands here
```

Three record kinds share the one shape, told apart by `method`:

| `method` | What it is | Notes |
|----------|-----------|-------|
| `INVITE` / `BYE` / … | the call record | the URIs, timing, teardown side |
| `REGISTER` | a registrar state change | `cdr.include_register`; the change is in `reg_event` |
| `MEDIA` | end-of-call media summary | no URIs — join it to the call on `call_id` |

Custom fields are **flattened into the top level** of the JSON, not nested:
`cdr.write(extra={...})`, an LCR route's `cdr_fields`, `lcr_attempts`, and a
`MEDIA` record's per-leg figures all arrive as ordinary top-level keys.
`CallDetailRecord.from_dict()` routes every unrecognised key into `.extra` — a
body model that validates against the declared fields drops them instead, so
take the body as `dict` and parse it:

```python
@app.post("/cdr")
async def collect(payload: dict) -> dict:
    record = CallDetailRecord.from_dict(payload)
    if record.is_media:
        for leg in record.media_legs:
            print(leg.role, leg.codec, leg.packets_lost, leg.mos_average)
    return {"ok": True}
```

`media_legs` parses the `near_` / `far_` / `leg2_` string extras back into
numbers. A leg's quality figures (MOS, jitter, loss percent, RTT) read `None`
when the media engine relayed that leg without a userspace actor — that is "not
measured", not "measured as zero", and a kernelized relay reports counters only.

`examples/cdr_collector.py` is a runnable FastAPI collector built on this.

::: siphon_sdk.cdr.CallDetailRecord

::: siphon_sdk.cdr.MediaLeg

### Writing to several sinks

`cdr.backends` takes a list, and every record is written to every entry:

```yaml
cdr:
  enabled: true
  auto_emit: true
  backends:
    - type: file
      path: /var/log/siphon/cdr.jsonl
      rotate_size_mb: 100
    - type: http
      url: https://collector.example.com/v1/cdr
      auth_header: "Bearer ..."
```

This is the usual shape: the file is the durable copy on the node, and the
collector is what the billing or reporting side consumes. With one sink, a
record the collector fails to take exists nowhere else, and until the collector
exists the file is the only place records can go.

Each sink gets its own channel and its own writer task, so a slow or failing
sink cannot delay, block or drop another's records. `channel_size` applies per
sink; a full channel drops for that sink alone, logged and counted under its
name in `siphon_cdr_dropped_total{sink}`. Per-sink ordering is preserved.

There is no retry or durable queue for the HTTP sink. A file sink beside it is
how a deployment gets durability without one.

The single form — `backend:` plus its matching `file:` / `syslog:` / `http:`
block — is unchanged and means one sink of that kind. Setting both `backend` and
`backends` is refused at config load rather than guessed at.

## `metrics` namespace

Custom Prometheus counters, gauges, and histograms that appear on `/metrics`.

::: siphon_sdk.mock_module.MockMetrics

### `Counter`

::: siphon_sdk.mock_module.MockCounter

### `Gauge`

::: siphon_sdk.mock_module.MockGauge

### `Histogram`

::: siphon_sdk.mock_module.MockHistogram

## `timer` namespace

Periodic (`@timer.every`) and one-shot (`timer.set`) callbacks.

::: siphon_sdk.mock_module.MockTimer

### `TimerHandle`

Returned by `timer.set(...)` — cancel a scheduled one-shot.

::: siphon_sdk.mock_module.MockTimerHandle
