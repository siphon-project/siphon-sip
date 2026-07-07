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

SIPhon drives one of two media engines, chosen with `media.backend`:
[RTPEngine](https://github.com/sipwise/rtpengine) (`rtpengine`, the default) or
the in-house **siphon-rtp** (`siphon-rtp`). Everything on this page — the
`offer` / `answer` / `delete` lifecycle, the profiles, and the `rtpengine`
scripting namespace — is **identical** for both; only the engine you run and the
`media:` block that points at it change.

!!! warning "siphon-rtp is experimental"
    The siphon-rtp engine is pre-release, so this backend is **experimental** —
    use the default `rtpengine` backend in production until it stabilises.
    SIPREC/MPTY subscriptions are not yet implemented on siphon-rtp.

See [Media engines: rtpengine vs siphon-rtp](../media-engines.md) for the full
comparison, the `media.siphon_rtp` config, and how to run and operate each engine.

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
| `ws_to_rtp` | WebSocket UE (RTP/AVPF + ICE) ↔ RTP core |
| `wss_to_rtp` | Secure WebSocket (DTLS-SRTP/AVPF + ICE) ↔ RTP core |

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

## See also

- Real examples: [`examples/proxy_rtpengine.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/proxy_rtpengine.py), [`examples/b2bua_rtpengine.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/b2bua_rtpengine.py).
- [SBC (B2BUA)](sbc.md) — media anchoring in a topology-hiding SBC.
