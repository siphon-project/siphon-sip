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
