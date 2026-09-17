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

This namespace is the writing side. What comes out the other end — the JSON
object every sink writes, its three record kinds, and the typed
`siphon_sdk.cdr.CallDetailRecord` a collector parses it with — is
[CDR records](cdr.md).

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
