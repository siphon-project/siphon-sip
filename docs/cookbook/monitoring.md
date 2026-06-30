# Monitoring & observability

You can see what SIPhon is doing four ways: Prometheus metrics (built-in + your own),
the admin API, Call Detail Records, and full SIP tracing to Homer. None of them block
the call path.

## Prometheus metrics

Enable the endpoint:

```yaml
metrics:
  prometheus:
    listen: "0.0.0.0:9090"
    path: "/metrics"
```

SIPhon exports built-in gauges/counters; the ones worth alerting on:

| Signal | Alert when | Why |
|---|---|---|
| `siphon_memory_allocated_bytes` | `rate(...[30m]) > 0` at flat call rate | A real memory leak |
| `siphon_pyexec_jobs_shed_total` | sustained `rate() > 0` | Handler pool saturated → SIP retransmits |
| `siphon_pyexec_pool_size` vs `_pool_max` | pinned equal + all busy for minutes | Pool fully grown and saturated |
| `siphon_proxy_dialog_sessions` | grows under flat completed-call load | Dialog state not draining |
| `siphon_rtpengine_instances_up` | drops below your engine count | An RTPEngine is unhealthy |

See [Handler execution model](../handler-execution-model.md) for the pool internals.

### Your own metrics

The `metrics` namespace adds counters, gauges, and histograms that appear on the same
`/metrics` endpoint:

```python
from siphon import metrics

calls = metrics.counter("calls_total", "Calls processed", labels=["direction", "result"])
active = metrics.gauge("calls_active", "Active calls", labels=["direction"])
setup  = metrics.histogram("call_setup_seconds", "INVITE→200 latency",
                           buckets=[0.1, 0.25, 0.5, 1, 2.5, 5])

calls.labels(direction="outbound", result="ok").inc()
active.labels(direction="outbound").inc()      # ... .dec() when it ends
setup.observe(0.342)
```

## Admin API — health, readiness, registrations

A separate HTTP port for probes and runtime inspection:

```yaml
admin:
  listen: "0.0.0.0:9091"
```

| Endpoint | Use |
|---|---|
| `GET /admin/health` | liveness — `200` while the process is alive (survives drain) |
| `GET /admin/ready` | readiness — `200`, or **`503` while draining** (SIGTERM) |
| `GET /admin/stats` | uptime + active registration count |
| `GET /admin/registrations[/{aor}]` | inspect bindings |
| `DELETE /admin/registrations/{aor}` | force-unregister |

Point Kubernetes liveness at `/admin/health` and readiness at `/admin/ready` so a
draining pod leaves rotation cleanly — see [Deployment & operations](../deployment.md).

## Call Detail Records

```yaml
cdr:
  enabled: true
  backend: http              # file | http | syslog
  http:
    url: "https://collector.example.com/v1/cdr"
    auth_header: "Bearer tok123"
```

CDRs are written asynchronously (a bounded channel, never blocks a call) with the
call's timing, parties, transport, disconnect initiator, and response code. Add your
own fields from a script:

```python
from siphon import cdr
cdr.write(request, extra={"billing_id": "B-12345", "account": "ACC-789"})
```

## Full SIP tracing → Homer

Stream every SIP message to a [Homer](https://github.com/sipcapture/homer) /
heplify-server collector over HEP — invaluable for debugging call flows:

```yaml
tracing:
  hep:
    endpoint: "127.0.0.1:9060"
    version: 3
    transport: udp           # udp | tcp | tls
    agent_id: "siphon-sbc"   # per-role name so nodes appear separately in Homer
```

## Putting it together

A solid baseline: scrape `/metrics` with Prometheus + alert on the table above; probe
`/admin/health` + `/admin/ready` from your orchestrator; ship CDRs to your billing
collector; and point HEP at Homer for call-flow forensics. For the production alert
set and capacity guidance, see [Deployment & operations](../deployment.md#metrics-and-alerting).

## See also

- Real example: [`examples/timer_example.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/timer_example.py) (periodic health pushes), [`siphon.yaml`](https://github.com/siphon-project/siphon-sip/blob/main/siphon.yaml).
- [Deployment & operations](../deployment.md) — the ops runbook.
