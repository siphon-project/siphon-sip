# SBC (B2BUA)

A Session Border Controller sits between two networks as a back-to-back user agent:
two fully independent dialogs, topology hiding, media anchoring, and control over
exactly which headers cross the trust boundary. In SIPhon the B2BUA is first-class —
no entity IDs, no bridge calls, just `@b2bua.*` handlers and a `call` object.

## The call lifecycle

```python
from siphon import b2bua, gateway, log

@b2bua.on_invite
def on_invite(call):
    call.media.anchor(engine="rtpengine")     # hide media topology
    call.remove_headers_matching("^X-")        # strip internal headers
    gw = gateway.select("carriers")            # pick a trunk
    call.dial(gw.uri, timeout=30)              # dial the B-leg

@b2bua.on_early_media
def on_early_media(call, reply):
    log.info(f"[{call.id}] early media {reply.status_code}")

@b2bua.on_answer
def on_answer(call, reply):
    log.info(f"[{call.id}] answered")

@b2bua.on_failure
def on_failure(call, code, reason):
    call.reject(code, reason)                  # propagate to the A-leg

@b2bua.on_bye
def on_bye(call, initiator):
    call.media.release()
    log.info(f"[{call.id}] ended by {initiator.side}")

@b2bua.on_cancel
def on_cancel(call):                            # caller abandoned before answer
    log.info(f"[{call.id}] cancelled")
```

Each B-leg gets its own Call-ID and From-tag by default, so the two dialogs are fully
decoupled — **topology hiding out of the box**. Other call methods: `call.fork(targets)`
(ring several B-legs), `call.reject(code, reason)`, `call.terminate()`,
`call.set_header` / `remove_header`, and B-leg userpart rewrites
(`call.set_ruri_user` / `set_from_user` / `set_to_user`).

## Header policies — control what crosses the boundary

The whole point of an SBC is deciding which headers leak between two networks. SIPhon
handles this with **named, versioned header policies** instead of hand-rolled
strip/copy logic on every call.

```python
call.dial(
    "sip:5112@ims.example.com",
    header_policy="ims-trust-domain-boundary@2026",
    copy=["X-Operator-Tag"],                       # also let this one through
    strip=["History-Info"],                        # also drop this one
    translate=[("Diversion", "rfc7044")],          # rewrite Diversion → History-Info
)
```

### Built-in presets

Pin the version (`@2026`) so a SIPhon upgrade can't silently change which headers
cross the boundary.

| Preset | Use at | Behaviour |
|---|---|---|
| `transparent-b2bua@2026` | general SBC (default) | today's strip set; behaviour-equivalent to pre-policy SIPhon |
| `ims-intra-trust-domain@2026` | S-CSCF ↔ AS | passes `P-*` headers + end-to-end PRACK / preconditions |
| `ims-trust-domain-boundary@2026` | P-CSCF / IBCF / BGCF edge | strict trust-boundary hygiene |
| `sip-trunk-edge@2026` | plain SIP trunk | strips `P-*` / `X-*` |

Set a default for all calls in `siphon.yaml` and override per call as needed:

```yaml
b2bua:
  default_header_policy: "ims-trust-domain-boundary@2026"
```

### Per-call deltas

On top of the preset, `copy` / `strip` / `translate` apply per call — for emergency
calls, aggregator quirks, etc. that the YAML preset can't express. `translate` ops in
v1 are `rfc7044` and `diversion-to-history-info`.

### Precedence (highest wins)

1. Script `call.set_header()` / `call.remove_header()` — always wins
2. `copy=` / `strip=` / `translate=` per-call deltas
3. The named preset's overrides
4. The named preset's default copy/strip set
5. **Framework-auto headers** — `Via`, `Call-ID`, `CSeq`, `Max-Forwards`,
   `Content-Length`, `From`, `To`, `Contact`, `Record-Route`, `Route`,
   `Proxy-Authorization`, `Proxy-Authenticate`. Never policy-able.

!!! note "One intentional change from pre-policy SIPhon"
    Every preset strips `Proxy-Authenticate` on B→A responses. RFC 3261 §22.3 makes
    it hop-by-hop, so passing it through would point the A-leg's
    `Proxy-Authorization` at the wrong realm. Opt back in with
    `copy=["Proxy-Authenticate"]` if you really want the old transparent behaviour.

## Add media anchoring

`call.media.anchor(engine="rtpengine")` hides the media path too. For SRTP↔RTP
interworking, WebRTC, transcoding, hold, or announcements, drive RTPEngine directly —
see [Media & RTP profiles](media-rtp.md):

```python
from siphon import b2bua, rtpengine

@b2bua.on_invite
async def on_invite(call):
    await rtpengine.offer(call, profile="srtp_to_rtp")   # SRTP UE ↔ RTP trunk
    call.dial(str(call.ruri))

@b2bua.on_answer
async def on_answer(call, reply):
    await rtpengine.answer(reply, profile="srtp_to_rtp", call=call)

@b2bua.on_bye
async def on_bye(call, initiator):
    await rtpengine.delete(call)
```

## Hybrid: proxy + SBC in one script

INVITEs go to `@b2bua.on_invite`; REGISTER/OPTIONS/etc. go to `@proxy.on_request` —
in the same script, same process. So you can B2BUA calls (topology hiding + media)
while lightly proxying registrations:

```python
@proxy.on_request("REGISTER")
def on_register(request):
    if auth.require_digest(request, realm=DOMAIN):
        registrar.save(request)

@b2bua.on_invite
def on_invite(call):
    call.media.anchor(engine="rtpengine")
    call.dial(gateway.select("carriers").uri)
```

## See also

- Real examples: [`scripts/b2bua_default.py`](https://github.com/siphon-project/siphon-sip/blob/main/scripts/b2bua_default.py), [`examples/b2bua_gateway.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/b2bua_gateway.py), [`examples/b2bua_rtpengine.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/b2bua_rtpengine.py).
- [Media & RTP profiles](media-rtp.md) — the RTPEngine profiles in depth.
- [Hardening & security](security.md) — STIR/SHAKEN at the edge, TLS, IPsec.
