# Media engines: rtpengine vs siphon-rtp

SIPhon does not relay media itself — it drives an external **media engine** that
anchors and transforms RTP. You pick one of two engines with `media.backend`:

| | `rtpengine` *(default)* | `siphon-rtp` |
|---|---|---|
| **Status** | Production | **Experimental** (pre-release) |
| **Project** | [sipwise/rtpengine](https://github.com/sipwise/rtpengine) | in-house, pure-Rust |
| **Control transport** | NG protocol, bencode over **UDP** | native JSON over a persistent **TCP** connection |
| **Datapath** | userspace or in-kernel (`xt_RTPENGINE` module) | userspace, optional AF_XDP acceleration |
| **Packaging** | distro package / container; kernel module for the fast path | single static binary, no kernel module |
| **Auth on the control channel** | none (bind to loopback / a trusted net) | optional shared-secret handshake |
| **Async events to SIPhon** | none | DTMF + media-timeout pushed on the same connection |
| **HA in SIPhon** | weighted round-robin over `instances[]` | weighted round-robin + **per-call-id affinity** over `instances[]` |

!!! warning "siphon-rtp is experimental — use rtpengine in production"
    The siphon-rtp engine is pre-release. Run it for evaluation and lab work;
    keep `rtpengine` (the default) for production until siphon-rtp stabilises.
    SIPREC/MPTY subscriptions are not implemented on siphon-rtp yet and surface a
    clear engine error if a script calls them.

**What is the same either way.** The `rtpengine` scripting namespace
(`offer` / `answer` / `delete`, `play_media`, `play_dtmf`, `silence_media`,
`@rtpengine.on_dtmf`, …), the [media profiles](cookbook/media-rtp.md#built-in-profiles),
and the [`MediaSessionStore`](cookbook/media-rtp.md) are **identical**. Only the
engine you run and the `media:` block that points at it change — a script written
for one backend runs unmodified on the other. The differences are entirely
operational, and that is what the rest of this page covers.

---

## Managing rtpengine

rtpengine is a separate daemon you install and operate on its own (systemd unit,
optional kernel module, `rtpengine.conf`). SIPhon only needs its **NG control
port**.

Run it so its NG listener is reachable by SIPhon and its media range is
firewallable:

```ini
# /etc/rtpengine/rtpengine.conf
[rtpengine]
interface = 10.0.0.10           # media interface (public/relay IP)
listen-ng = 127.0.0.1:22222     # NG control (what SIPhon talks to)
port-min  = 30000
port-max  = 40000
recording-dir = /var/spool/rtpengine
```

Point SIPhon at it:

```yaml
# siphon.yaml
media:
  backend: rtpengine              # optional; this is the default
  rtpengine:
    address: "127.0.0.1:22222"    # NG control protocol (UDP)
    timeout_ms: 1000
  sdp_name: "SIPhon"              # masks the endpoint identity in o=/s=
  health_check_interval_secs: 5
```

Several engines load-balance with weighted round-robin:

```yaml
media:
  rtpengine:
    instances:
      - { address: "10.0.0.1:22222", weight: 2 }
      - { address: "10.0.0.2:22222", weight: 1 }
```

**Operate it as its own service.** Lifecycle (start/stop/upgrade), the kernel
module for the in-kernel fast path, `recording-dir` and the CDR/PCAP outputs,
and its metrics/exporter are all rtpengine's own — see the upstream
documentation. SIPhon's responsibility ends at the NG control port; it probes
each instance with an NG `ping` (see [Health](#health-and-observability)).

---

## Managing siphon-rtp

siphon-rtp is a **single static binary** with no kernel module. It listens on a
JSON-over-TCP **control** port (what SIPhon drives) and binds media sockets on a
relay IP. There is nothing else to install.

### Run the daemon

```bash
siphon-rtp \
  --control 0.0.0.0:8080 \          # JSON/TCP control — what SIPhon connects to
  --relay-bind-ip 10.0.0.10 \       # bind media to the reachable relay IP (NOT loopback)
  --port-min 30000 --port-max 40000 \  # bounded, firewallable media range (needed for HA takeover)
  --metrics-addr 127.0.0.1:9091 \   # Prometheus /metrics + /healthz + /readyz
  --media-timeout-secs 30 \         # reap a call with no media after N seconds
  --shutdown-grace-secs 25 \        # drain live calls on SIGTERM before exiting
  --node-id rtp-a                   # stable id reported to cluster load queries
```

Key flags (full list: `siphon-rtp --help`):

| Flag | Purpose |
|---|---|
| `--control <addr>` | JSON/TCP control listener (default `127.0.0.1:8080`) — SIPhon's `media.siphon_rtp.address` |
| `--ng <addr>` | also expose an **rtpengine NG/bencode UDP** listener, so Kamailio/OpenSIPS (or SIPhon's `rtpengine` backend) can drive the same daemon |
| `--relay-bind-ip <ip>` | bind media sockets to the reachable IP; the production posture (default loopback is lab-only) |
| `--port-min` / `--port-max` | bounded media port range — firewallable, and required for HA takeover (a standby re-binds the same ports) |
| `--metrics-addr <addr>` | Prometheus `/metrics`, `/healthz` (liveness), `/readyz` (readiness) |
| `--max-control-rps <n>` | per-connection control-request flood cap (default 200; `0` disables) |
| `--shutdown-grace-secs <n>` | bounded drain of live calls on SIGTERM/SIGINT |
| `--config <path>` | rtpengine-style TOML config; CLI flags still override it |

`--control` and `--ng` can run **at the same time**: expose `--control` for
SIPhon's native backend and `--ng` for a legacy controller during a migration.

### Point SIPhon at it

```yaml
# siphon.yaml — single engine
media:
  backend: siphon-rtp
  siphon_rtp:
    address: "10.0.0.1:8080"                          # siphon-rtp --control
    control_secret: "${SIPHON_RTP_CONTROL_SECRET}"    # optional; must match the engine's secret
    timeout_ms: 2000
  sdp_name: "SIPhon"
  health_check_interval_secs: 5
```

Several engines for HA (weighted round-robin **plus per-call-id affinity** — every
command for one call stays on the same control connection, because siphon-rtp keys
call ownership to the connection):

```yaml
media:
  backend: siphon-rtp
  siphon_rtp:
    control_secret: "${SIPHON_RTP_CONTROL_SECRET}"    # shared across all instances
    timeout_ms: 2000                                  # default; per-instance timeout_ms overrides
    instances:
      - { address: "10.0.0.1:8080", weight: 2 }
      - { address: "10.0.0.2:8080", weight: 1, timeout_ms: 3000 }
```

SIPhon opens one persistent TCP connection per instance, reconnects with backoff
if an engine restarts (it boots fine even when the engine is down — commands
issued during the connect window wait up to their `timeout_ms`), and runs the
auth handshake on every (re)connect when `control_secret` is set.

### Security

The control channel is a management plane. Either bind `--control` to a trusted
network and firewall it, **or** set a `control_secret` on both sides (the engine
and `media.siphon_rtp.control_secret`) so SIPhon must authenticate before issuing
any command. Bind media with `--relay-bind-ip` to the intended relay IP and open
only `--port-min…--port-max` at the firewall.

---

## Health and observability

**On the SIPhon side**, both backends are probed on
`media.health_check_interval_secs` and export the *same* gauges (the
`rtpengine` name is historical — it covers whichever engine is configured):

- `siphon_rtpengine_instances_total` — configured instances
- `siphon_rtpengine_instances_up` — how many answered the last probe
- `siphon_rtpengine_instance_up{address}` — 0/1 per instance

rtpengine is probed with an NG `ping`; siphon-rtp with a native `ping` command.

**On the engine side**, siphon-rtp additionally serves its own metrics when you
pass `--metrics-addr`: `GET /metrics` (OpenMetrics), `GET /healthz` (liveness),
`GET /readyz` (readiness) — wire these into your load balancer and Prometheus.
rtpengine exposes its own exporter separately.

---

## Switching backends

Because the scripting API is identical, moving a deployment from rtpengine to
siphon-rtp (or back) is a **config-only** change — the script does not change:

1. Run the target engine (sections above).
2. Flip `media.backend` and fill in the matching `rtpengine:` / `siphon_rtp:`
   block.
3. Restart SIPhon. The same [media recipe](cookbook/media-rtp.md) runs unchanged.

The example scripts are backend-agnostic and work either way — see
[`examples/proxy_rtpengine.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/proxy_rtpengine.py)
and [`examples/b2bua_rtpengine.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/b2bua_rtpengine.py);
only the `media:` block in `siphon.yaml` differs.

## See also

- [Media & RTP profiles](cookbook/media-rtp.md) — the offer/answer/delete recipe
  and the profile catalogue (both backends).
- The **siphon-rtp** engine's own documentation for engine internals, the
  datapath, TURN, and recording.
