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
| **Async events to SIPhon** | DTMF only, over a **separate** event log (`media.events` ← rtpengine's `dtmf-log-ng-tcp-uri`) | DTMF **and** media-timeout, pushed on the **same** control connection |
| **HA in SIPhon** | weighted round-robin over `instances[]` | weighted round-robin + **per-call-id affinity** over `instances[]` |

!!! warning "siphon-rtp is experimental — use rtpengine in production"
    The siphon-rtp engine is pre-release. Run it for evaluation and lab work;
    keep `rtpengine` (the default) for production until siphon-rtp stabilises.

**What is the same either way.** The `rtpengine` scripting namespace
(`offer` / `answer` / `delete`, `play_media`, `play_dtmf`, `silence_media`,
`@rtpengine.on_dtmf`, …), the [media profiles](cookbook/media-rtp.md#built-in-profiles),
and the [`MediaSessionStore`](cookbook/media-rtp.md) are the same on both. Only the
engine you run and the `media:` block that points at it change — a script written
for one backend runs unmodified on the other, unless it uses one of the
engine-specific profile fields below. The rest of the differences are
operational, and that is what the rest of this page covers.

**What is not.** A few media-profile fields exist only on the engine that can
perform them. siphon **refuses to start** if a `media.profiles` entry asks for
something its `media.backend` cannot honour, naming the profile and the field —
a `ws_uri` the engine never receives would otherwise answer the call and bridge
it nowhere, with nothing logged and silence on the line.

| Profile field | `siphon-rtp` | `rtpengine` | `rtpproxy` |
|---|---|---|---|
| `ws_uri`, `ws_vad`, `ws_barge_in`, `ws_vad_threshold`, `ws_vad_hangover_ms` | yes | — | — |
| `ws_tee`, `ws_tee_direction`, `ws_tee_channels` | yes | — | — |
| `noise_suppression`, `echo_cancellation` | yes | — | — |
| `received_from`, `rtcp_mux` | yes | yes | — |
| `address_family` | yes | yes | — [^af] |

[^af]:
    `address_family` on `rtpproxy` warns at boot rather than failing the load:
    rtpproxy's `6` modifier states the family of the address the command already
    carries, so the call still works and only IPv4/IPv6 interworking is lost.

---

## WebSocket audio: bridge vs tee

`siphon-rtp` can stream a call's decoded audio to a WebSocket media server in
two different shapes. They look similar in config and are not interchangeable —
picking the wrong one is the most likely way to get this wrong.

| | `ws_uri` — **bridge** | `ws_tee` / `attach_ws_tee` — **tee** |
|---|---|---|
| The WS server is | leg A's far side | an extra listener |
| A↔B relay | **not wired** | stays wired |
| Audio direction | bidirectional | send-only |
| SIPREC / recording on the leg | n/a (there is no B leg) | keep running |
| Typical use | voice-AI answers the call | live transcription, agent assist, compliance |

**Bridge (`ws_uri`).** The engine dials the URI and the WS server *becomes* the
far end: it receives the caller's audio as L16 and what it sends back is encoded
toward the caller. There is no second SIP leg. This is the voice-AI
answer-the-call shape, usually paired with `rtpengine.answer_local(...)` and the
built-in `voice_ai` profile.

**Tee (`ws_tee`).** The call relays or transcodes exactly as it otherwise would,
*and* a copy of the decoded audio is streamed out. Additive: one decode feeds
the peer, the recorder, any SIPREC fork and the tee — there is no second jitter
buffer and no second decode. A plain in-kernel relay is promoted to the
userspace pipeline for the tee's lifetime and demoted again on detach.

A tee never affects the call. If the consumer stalls the engine drops frames
rather than backing up the media path, and reports the count on the
`ws_tee_ended` event.

Declare a tee on a profile:

```yaml
media:
  backend: siphon-rtp
  profiles:
    recorded_call:
      offer:
        ws_tee: "wss://asr.internal/stream/{call_id}"
        ws_tee_direction: both      # both (default) | caller | callee
        ws_tee_channels: 2          # 2 = caller/callee stereo, 1 = mixed mono
      answer: {}
```

…or attach and detach one mid-call from a script:

```python
@b2bua.on_answer
async def on_answer(call, reply):
    await rtpengine.answer(reply)
    try:
        await rtpengine.attach_ws_tee(call, f"wss://asr.internal/{call.call_id}")
    except RuntimeError as error:
        log.warn(f"transcription tee unavailable: {error}")   # never fail the call

@b2bua.on_bye
async def on_bye(call):
    await rtpengine.detach_ws_tee(call)      # idempotent; the call teardown also does it
```

`ws_tee_channels` only means anything with `ws_tee_direction: both` — a
single-leg tee is always mono. Unset leaves the engine's default: 2 channels
for both legs, 1 for one.

**Know when a tee dies.** A tee can end without the call ending — the server
closes the socket, or the transport fails. Nothing about the call changes, so
this is invisible unless you watch for it:

```python
@rtpengine.on_ws_tee_ended
def tee_down(call_id, from_tag, stream_id, reason, frames_sent, frames_dropped):
    if reason != "detached":                  # the only orderly end
        log.warn(f"tee {stream_id} died: {reason} after {frames_sent} frames")
    if frames_dropped:
        log.warn(f"tee {stream_id} dropped {frames_dropped} frames — consumer too slow")
```

siphon also logs an unexpected tee end at WARN whether or not a handler is
registered. `@rtpengine.on_ws_tee_started` gives the matching start, carrying
the negotiated `channels` and `sample_rate` so a consumer decodes the binary
frames rather than guessing; `stream_id` correlates the control event with the
`start` envelope on the socket.

Both the bridge and the tee can run at a wire rate independent of the legs'
codec rates. `ws_sample_rate` applies to the `ws_uri` bridge in **both**
directions, so an 8 kHz G.711 call can speak 16 kHz to an inference server, and
a server rendering 24 kHz audio into that call plays at the right speed and
pitch instead of the wrong one. `ws_tee_sample_rate` (or
`attach_ws_tee(..., sample_rate=...)`) is send-only and changes only what the
tee consumer receives. Both must be a multiple of 1000 within 8000–48000; the
engine fails the offer rather than clamping, so siphon rejects a bad value at
boot.

---

## Answering-machine detection

The media half of AMD: the engine watches a leg's decoded audio for the short
single tone an answering machine plays before it starts recording, and reports
it. Without it a transfer cannot tell a person from a voicemail box, and the
caller gets bridged into the greeting.

Arm it **per leg**. The profile used toward the callee is what watches the party
that might be a machine:

```yaml
media:
  backend: siphon-rtp
  profiles:
    screened_callee:
      offer:
        replace: ["origin"]
      answer:
        replace: ["origin"]
        beep_detection: true
        beep_cadence_guard_ms: 4500   # default
```

```python
@rtpengine.on_beep
def machine(call_id, from_tag, to_tag, frequency_hz, duration_ms, offset_ms):
    log.info(f"{call_id}: answering machine ({frequency_hz:.0f} Hz at {offset_ms} ms)")
    b2bua.terminate(call_id, "Answering machine detected")
```

Three things to know:

- **It fires once per leg per call.** The engine drops the detector after the
  first tone, so a handler never de-duplicates, and there is no mid-call re-arm —
  a fresh `offer`/`answer` with the flag set re-arms it.
- **`beep_cadence_guard_ms` is also the detection latency.** It is the window the
  detector waits to rule out a repeat, which is what tells a record tone from a
  cadenced ringback, busy or congestion tone. The event therefore arrives that
  long *after* the beep. Lowering it trades cadence robustness for latency.
- **`offset_ms` is the offset of the tone, not of the event.** It counts decoded
  audio seen on the leg before the tone started, so it is the right number to
  reason about "how far into the call" — the event trails it by the guard.

Detection needs decoded audio, so like `noise_suppression` it promotes a
same-codec plaintext call onto the userspace media pipeline, and it is inert on
a codec whose native rate is neither 8 nor 16 kHz.

---

## Prompts, tones and overlays

`rtpengine.play_media(...)` replaces a party's outgoing audio with a prompt. Its
source can be a file, raw bytes, an engine prompt-DB id, a **synthesised tone**,
or a URL the **engine** fetches:

```python
await rtpengine.play_media(call, tone="ringback_eu")            # preset
await rtpengine.play_media(call, tone="425/1000,0/4000*inf")     # cadence spec
await rtpengine.play_media(call, url="https://prompts.internal/welcome.wav")
```

A tone needs no provisioned audio file and renders at the leg's codec rate, so it
is never resampled. A preset name is told from a cadence spec by the `/`. An
HTTP source is fetched by the engine from its own network position, bounded
engine-side and off the media path — a URL that never answers ends the
*playback*, never the leg — so restrict the reachable hosts if you do not fully
trust whoever supplies the URL.

**Overlays** mix audio *under* a party's live egress instead of replacing it, and
return a handle so you can change or stop that one playback:

```python
bed = await rtpengine.play_overlay(call, file="/prompts/hold.wav", repeat=0)
await rtpengine.play_media(call, file="/prompts/agent.wav")
await rtpengine.set_play_gain(call, bed, -18)     # duck the bed under the prompt
await rtpengine.stop_media(call, play_id=bed)     # stop just the bed
```

Up to four overlays run per direction, each with its own `play_id` and its own
completion. Starting a fifth is rejected rather than displacing one — a script
that lost a playback it believes is running has no way to notice.

Tones, HTTP sources, overlays, per-play gain and a targeted `stop_media` are
native `siphon-rtp` features. On the rtpengine and rtpproxy backends they raise
rather than silently downgrading: an overlay quietly turned into a supersede
would cut the party's live audio.

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
