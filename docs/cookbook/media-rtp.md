# Media & RTP profiles

SIPhon anchors and transforms media through a pluggable media engine —
[RTPEngine](https://github.com/sipwise/rtpengine) over its NG control protocol by
default, or the native **siphon-rtp** engine ([choosing and managing an
engine](../media-engines.md)). A **profile** is a named bundle of engine flags —
SRTP↔RTP interworking, WebRTC, ICE handling, transcoding direction — that you
select per call with one argument.

This page is the **scripting recipe** — the `offer` / `answer` / `delete`
lifecycle and the profile catalogue. It is identical for both backends. For
*which* engine to run and *how to operate each one*, see
[Media engines: rtpengine vs siphon-rtp](../media-engines.md).

## Config

```yaml
# siphon.yaml
media:
  rtpengine:
    address: "127.0.0.1:22222"     # NG control protocol (UDP)
    timeout_ms: 1000
  sdp_name: "SIPhon"               # masks the endpoint identity in o=/s=
  health_check_interval_secs: 5    # exported as siphon_rtpengine_instances_up
```

Multiple engines load-balance with weighted round-robin:

```yaml
media:
  rtpengine:
    instances:
      - { address: "10.0.0.1:22222", weight: 2 }
      - { address: "10.0.0.2:22222", weight: 1 }
```

## Choosing a media engine

SIPhon drives one of three media engines, chosen with `media.backend`:

| `media.backend` | Engine | Control transport |
|---|---|---|
| `rtpengine` *(default)* | [RTPEngine](https://github.com/sipwise/rtpengine) | NG protocol, bencode over UDP |
| `siphon-rtp` | the in-house **siphon-rtp** engine | native JSON over a persistent TCP connection |
| `rtpproxy` | classic [rtpproxy](https://github.com/sippy/rtpproxy) relay | text protocol over UDP |

Everything else on this page — the `offer` / `answer` / `delete` lifecycle, the
profiles, and the `rtpengine` scripting namespace — is **identical** for all
backends; only the transport underneath changes.

!!! warning "siphon-rtp is experimental"
    The siphon-rtp engine is pre-release, so this backend is **experimental** —
    use the default `rtpengine` backend in production until it stabilises.
    SIPREC/MPTY subscriptions are not yet implemented on siphon-rtp.

See [Media engines: rtpengine vs siphon-rtp](../media-engines.md) for the full
comparison, the `media.siphon_rtp` config, and how to run and operate each engine.

### Classic rtpproxy (keep your existing relay)

Migrating an OpenSIPS / Kamailio / Sippy deployment? Point siphon at your existing
`rtpproxy` instead of standing up a new media engine — the script is unchanged, only
the config differs:

```yaml
media:
  backend: rtpproxy
  rtpproxy:
    address: "127.0.0.1:22222"     # rtpproxy -s udp:<addr>
    timeout_ms: 1000
    retries: 2                     # UDP retransmits (same cookie); rtpproxy de-dupes

# or several, for HA / weighted load-balancing (per-call-id affinity)
media:
  backend: rtpproxy
  rtpproxy:
    instances:
      - { address: "10.0.0.1:22222", weight: 2 }
      - { address: "10.0.0.2:22222", weight: 1 }
```

siphon speaks rtpproxy's classic `U`/`L`/`D` protocol on the wire. Because rtpproxy
only hands back a relay port (it does **not** rewrite SDP itself), siphon rewrites the
`c=`/`m=` lines for you — per media stream, including held media (`m=… 0`). Profiles
still apply, but only the flags rtpproxy understands: a profile's
`direction: ["internal","external"]` becomes bridge mode (`ie`/`ei`) and an
`asymmetric` flag maps through; IPv6 is detected per stream. SRTP/DTLS/ICE flags are
ignored — rtpproxy is a plain RTP relay (use `rtpengine` or `siphon-rtp` for SRTP↔RTP,
WebRTC, or transcoding). A profile's
[`address_family`](#ipv4-and-ipv6-interworking) is unsupported here too — rtpproxy's
`6` modifier reports the family of the address the command carries, it cannot select
one for the relay — and siphon warns at boot naming any profile that sets it. It has
the same weighted round-robin + per-call-id affinity and per-instance `V` health
probes as the other backends.

!!! note "rtpproxy is anchor-only"
    The extra `rtpengine` verbs — announcements / tones (`play_media`, `play_dtmf`),
    gating (`silence_media` / `block_media`), DTMF events, and SIPREC/MPTY
    subscriptions — are not available on the rtpproxy backend and raise a clear
    error. They need `rtpengine` or `siphon-rtp`.

## The offer / answer / delete lifecycle

Anchor the offer when the INVITE arrives, the answer when the 2xx comes back, and
release on teardown. RTPEngine rewrites the SDP so media flows through it.

On a **proxy**:

```python
from siphon import proxy, registrar, rtpengine

@proxy.on_request
async def route(request):
    if request.in_dialog:
        if request.method == "BYE":
            await rtpengine.delete(request)
        elif request.method == "INVITE" and request.body:
            await rtpengine.offer(request, profile="srtp_to_rtp")  # re-INVITE
        request.loose_route() and request.relay()
        return

    contacts = registrar.lookup(request.ruri)
    if request.method == "INVITE" and request.body:
        await rtpengine.offer(request, profile="srtp_to_rtp")
    request.record_route()
    request.fork([c.uri for c in contacts])

@proxy.on_reply
async def reply_route(request, reply):
    if 200 <= reply.status_code < 300 and reply.has_body("application/sdp"):
        await rtpengine.answer(reply, profile="srtp_to_rtp")
    reply.relay()

@proxy.on_cancel
async def cancel_route(request):
    await rtpengine.delete(request)   # release media for an abandoned call
```

On a **B2BUA** it's the same three calls in `@b2bua.on_invite` / `on_answer` /
`on_bye` (+ `on_failure` / `on_cancel`); pass `call=` to `answer()` so it reuses the
A-leg Call-ID that matched the offer (see [the SBC recipe](sbc.md)).

!!! warning "Always release"
    `offer` without a matching `delete` leaks an RTPEngine session until its
    inactivity timeout. Handle every teardown path — `on_bye`, `on_failure`,
    `on_cancel` (proxy: `@proxy.on_cancel`) — or media lingers.

## Built-in profiles

| Profile | Interworking |
|---|---|
| `rtp_passthrough` | Plain RTP both sides — anchoring only (the default) |
| `srtp_to_rtp` | SRTP UE ↔ RTP core (VoLTE/secure access ↔ trunk) |
| `rtp_to_srtp` | The reverse pairing — RTP access ↔ SRTP core |
| `ws_to_rtp` | WebSocket UE (RTP/AVPF + ICE) ↔ RTP core |
| `wss_to_rtp` | Secure WebSocket (DTLS-SRTP/AVPF + ICE) ↔ RTP core |
| `srs_recording` | Recording sink — plain RTP, media handover + port latching |
| `siprec_src` | SIPREC SRC subscription leg toward the recorder |
| `voice_ai` | Plain RTP toward the caller, audio bridged to a WebSocket AI backend |

`ws_to_rtp` / `wss_to_rtp` are what make a **WebRTC** gateway work — terminate the
browser's DTLS-SRTP + ICE on one side, plain RTP toward your core on the other.

## Custom profiles

Define your own under `media.profiles` — any RTPEngine flag, per direction:

```yaml
media:
  profiles:
    srtp_to_srtp:
      offer:
        transport_protocol: "RTP/SAVP"
        ice: "remove"
        replace: ["origin"]
        direction: ["external", "internal"]
      answer:
        transport_protocol: "RTP/SAVP"
        ice: "remove"
        replace: ["origin"]
        direction: ["internal", "external"]
```

```python
await rtpengine.offer(request, profile="srtp_to_srtp")
```

### IPv4 and IPv6 interworking

`address_family` pins the family the engine allocates its **own** relay endpoints
in for that side of the call. Leave it unset (the default) and the engine follows
the offered SDP, which gives you a single-family relay — fine until one side is
v6-only. Set it per direction to bridge, e.g. a v6 VoLTE access leg reaching a v4
core:

```yaml
media:
  profiles:
    v6_access_to_v4_core:
      offer:                     # toward the core: hand it a v4 endpoint
        replace: ["origin"]
        address_family: "IP4"
      answer:                    # back toward the v6 UE
        replace: ["origin"]
        address_family: "IP6"
```

The value is the SDP `addrtype` spelling, `IP4` or `IP6` (`ipv4` / `ipv6` are
accepted and normalised; anything else fails the config load, because a media
engine ignores an unknown family silently and you would get a relay in the wrong
family with no error). The engine needs an interface configured in the target
family — rtpengine's `interface=` must list both, otherwise it has nothing to
allocate from.

Works on **rtpengine** (sent as the dedicated `address family` NG key) and
**siphon-rtp** (the `address_family` control field). The classic **rtpproxy**
backend has no equivalent and logs a warning at boot if a profile sets it.

### Bridge a leg's audio to a WebSocket server

`ws_uri` hands a leg's audio to an external WebSocket media server instead of a
far SIP leg: the engine dials the URI and relays the leg's RTP to it as L16
(decode → uplink, downlink → encode). The WS server *is* that leg's far side, so
this is the shape a call answered by a speech backend takes — pair it with
[`rtpengine.answer_local`](#the-offer--answer--delete-lifecycle), which
synthesises the 2xx answer with the engine as the far side.

```yaml
media:
  backend: siphon-rtp          # required — see the capability table below
  siphon_rtp:
    address: "127.0.0.1:9000"
  profiles:
    voice_ai:                  # overrides the built-in of the same name
      offer: &voice_ai_flags
        transport_protocol: "RTP/AVP"
        ice: "remove"
        dtls: "off"
        replace: ["origin"]
        ws_uri: "wss://ai.example.com/stream/{call_id}"
        ws_vad: true           # emit speech_started / speech_stopped edges
        ws_barge_in: true      # cut playout locally on the caller's speech
        ws_vad_threshold: 2000000
        ws_vad_hangover_ms: 300
        noise_suppression: true
        echo_cancellation: true
      answer: *voice_ai_flags
```

The URI supports `{call_id}`, `{from_tag}`, `{from_user}` and `{to_user}`,
expanded per call. An unrecognised placeholder fails rather than passing through
as a literal, so a typo cannot reach the engine as part of the URI path.

When the endpoint depends on something only the script knows — a session token,
a tenant lookup — pass it per call instead. It wins over the profile's own value,
and is recorded on the media session so a later `answer` reuses the same bridge
without repeating it:

```python
@b2bua.on_invite
async def on_invite(call):
    sdp = await rtpengine.answer_local(
        call,
        profile="voice_ai",
        ws_uri=f"wss://ai.example.com/stream?token={await mint_token(call.call_id)}",
    )
    if sdp is not None:
        call.answer(200, "OK", body=sdp, content_type="application/sdp")
```

The built-in `voice_ai` profile sets the DSP and VAD flags but deliberately
leaves `ws_uri` unset — there is no sensible default endpoint, so supply it in
YAML or per call as above.

`ws_uri`, the `ws_*` knobs, `noise_suppression` and `echo_cancellation` are
**`siphon-rtp` only**. siphon refuses to start if a `media.profiles` entry sets
one on another backend, and a script naming such a profile gets a `ValueError`
naming the field — see [media engines](../media-engines.md) for the full
capability table.

### Gate media ingress to the signalling source

`received_from: true` carries the real post-NAT source IP siphon saw the request
arrive from, and the engine gates that leg's ingress to it. For a NATed UA whose
`c=` line advertises an unroutable private address, that is a **tighter**
RTPBleed source gate than the signalled address could give. Only the IP is
carried — media and signalling ports differ, so the port is never gated.

```yaml
media:
  profiles:
    nated_access:
      offer:
        replace: ["origin"]
        received_from: true
      answer:
        replace: ["origin"]
        received_from: true
```

Off by default, because it is wrong for a deployment whose media legitimately
arrives from a different address than its signalling (a separate media gateway,
or a carrier that splits the two). Honoured by **rtpengine** (the `received from`
NG key) and **siphon-rtp**; **rtpproxy** has no equivalent and fails the config
load.

`rtcp_mux` takes the same RFC 5761 directives rtpengine does — `offer`,
`require`, `demux`, `accept`, `reject`, `remove` — to override the mux decision
the engine would derive from the offered SDP. Empty (the default) mirrors the
offer. An unknown token fails the config load rather than being silently dropped
by the engine.

## Shape the SDP yourself

For codec filtering, hold, or attribute tweaks without RTPEngine, use the `sdp`
namespace:

```python
from siphon import sdp

s = sdp.parse(request)
for m in s.media:
    if m.media_type == "audio":
        s.filter_codecs(["PCMU", "PCMA"])   # keep only G.711
        # m.port = 0                          # ... or put audio on hold
s.apply(request)
```

## More media control

The `rtpengine` namespace also drives announcements and tones (`play_media`,
`play_dtmf`), gating (`silence_media` / `block_media`), DTMF events (`@rtpengine.on_dtmf`),
and conference/MPTY subscriptions — useful for IVR, MMTel announcements, and recording.

### React to a dead media path

The media engine reaps a call whose media stops flowing (no packets past its
inactivity window). Handle `@rtpengine.on_media_timeout` to release the per-call
state that no BYE will now clear — Rx/N5 QoS sessions, offline charging, dialog
or session-store entries. It is the media-path analogue of the abandoned-call
teardown `@proxy.on_cancel` / `@b2bua.on_cancel` cover.

```python
from siphon import rtpengine, log

@rtpengine.on_media_timeout
def media_gone(call_id, from_tag):
    log.warn(f"media timeout on {call_id} — releasing call state")
    # e.g. diameter.rx_str(session_id) / sbi.delete_session(...) / cdr.write(...)
```

Filter to a specific call with `@rtpengine.on_media_timeout(call_id=..., from_tag=...)`,
the same shape as `@rtpengine.on_dtmf`.

!!! note "siphon-rtp only, for now"
    This event is delivered by the native **siphon-rtp** backend, which pushes it
    over its control connection. The rtpengine backend's event log carries only
    DTMF, so `@rtpengine.on_media_timeout` does not fire under rtpengine yet —
    see [Media engines](../media-engines.md).

## See also

- Real examples: [`examples/proxy_rtpengine.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/proxy_rtpengine.py), [`examples/b2bua_rtpengine.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/b2bua_rtpengine.py).
- [SBC (B2BUA)](sbc.md) — media anchoring in a topology-hiding SBC.
