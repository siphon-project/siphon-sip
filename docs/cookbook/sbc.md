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
`call.set_header` / `remove_header`, and B-leg URI rewrites — userpart
(`call.set_ruri_user` / `set_from_user` / `set_to_user`) and host
(`call.set_from_host` / `set_to_host`).

### Keeping a tenant domain in the From

Topology hiding rewrites the B-leg From host to SIPhon's advertised address and the To
host to the dial target. That's the right default, but a multitenant downstream that
selects the tenant from the From domain needs the original domain to survive — a
domainless From lands the call in its unauthenticated/default routing context. Pin it:

```python
@b2bua.on_invite
def on_invite(call):
    call.set_from_host("tenant.example.com")   # keep the tenant domain in From
    call.dial(str(call.ruri), next_hop="sip:pbx.example.com:5060")
```

`set_from_host` opts that leg out of the From host-rewrite; `set_to_host` pins the To
host the same way (a declarative replacement for hand-building
`set_header("To", "<sip:user@host>")`). Only the host changes — scheme, user, port,
params, and tags are preserved — and both apply to `call.dial()` and `call.fork()`.

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

Need a posture none of them quite match? Define your own — see
[Custom policies](#custom-policies) below.

### Custom policies

When your posture is "that preset, except for these headers", define your own in
`siphon.yaml` rather than repeating `copy=[…]` on every `dial()` call site. Custom
policies live in the same namespace as the built-ins, so scripts and
`default_header_policy` select them the same way.

```yaml
header_policies:
  "trunk-edge-plus@1":
    extends: "sip-trunk-edge@2026"
    request:
      copy: ["X-Account-Ref"]           # crosses despite the base's X-* strip
      strip: ["Alert-Info"]
      rewrite:
        P-Asserted-Identity: host-to-advertised
      translate:
        Diversion: diversion-to-history-info
    response:
      strip: ["Server"]

b2bua:
  default_header_policy: "trunk-edge-plus@1"
```

The base supplies each direction's default and its rules; the rules you write are
matched first, so they win. A direction you leave out is inherited verbatim, and an
`extends:` with no rules at all is just a stable local alias for a built-in.

Drop `extends:` to declare a policy in full, in which case each direction needs its
own `default:` (`copy` or `strip`):

```yaml
header_policies:
  "locked-down@1":
    request:
      default: strip
      copy: ["Allow", "Supported", "Content-Type"]
    response:
      default: copy
      strip: ["P-*", "Server", "User-Agent"]
```

Header names are exact and case-insensitive; a trailing `*` is a prefix match
(`"X-*"`), not a glob. Within one direction an exact name beats a prefix and a longer
prefix beats a shorter one, so `strip: ["X-*"]` alongside `copy: ["X-Account-Ref"]`
does what it looks like. `rewrite:` ops are `host-to-advertised`,
`replace-with-server-header` and `replace-with-user-agent-header`; `translate:` ops
are `diversion-to-history-info` (alias `rfc7044`).

The map key is the name scripts pin and must carry an `@version` — same rule as the
built-ins — and it may not take a built-in's name. Policies are resolved and
validated at startup, so an unknown op, a rule aimed at a framework-managed header,
or a `default_header_policy` naming a policy nothing defines stops the node at boot
instead of surfacing mid-call.

### Per-call deltas

On top of the preset, `copy` / `strip` / `translate` apply per call — for emergency
calls, aggregator quirks, etc. that a policy can't express. `translate` ops in v1 are
`rfc7044` and `diversion-to-history-info`. Per-call deltas match exact header names
only; prefix patterns are a config-side feature.

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

## Authenticate the caller before dialling anything

A B2BUA facing untrusted callers should challenge them, not just route them.
Registering any `@b2bua.*` handler takes INVITE off the proxy path, so a
`@proxy.on_request("INVITE")` challenge would never run — pass the `call` to the
digest helpers instead:

```python
from siphon import auth, b2bua, gateway, log

@b2bua.on_invite
def on_invite(call):
    if not auth.require_proxy_digest(call, realm=DOMAIN):
        return                      # 407 armed; siphon answers the A-leg

    log.info(f"authenticated {call.auth_user}")
    call.media.anchor(engine="rtpengine")
    call.dial(gateway.select("carriers").uri)
```

An unauthenticated caller gets siphon's own 407 and **no B-leg is dialled** —
the challenge is armed as the call's deferred reject, so the call actor is
dropped before any trunk sees traffic. That ordering is the point: a toll-fraud
probe never reaches your carrier. The caller re-INVITEs with credentials,
`require_proxy_digest` returns `True`, and the hop-by-hop `Proxy-Authorization`
is stripped before the B-leg INVITE is built (RFC 3261 §22.3).

Pair it with anti-spoofing on the caller ID, as on the proxy path:

```python
    from_user = call.from_uri.user if call.from_uri else None
    if call.auth_user != from_user:
        call.reject(403, "Forbidden")
        return
```

!!! note "Two different auth directions"
    Challenging on the `call` is siphon authenticating **its caller**.
    `call.dial(..., auth_passthrough=True)` is the opposite: a *downstream* PBX
    or trunk challenges, and siphon relays that challenge to the caller to answer
    end-to-end. A third option, `call.set_credentials(user, password)`, has
    siphon answer the downstream challenge itself.

## Upstream trunk requiring mutual TLS

Some upstream SIP trunks require siphon to present a **client certificate** when
it dials out over TLS — mutual TLS (for example Microsoft Teams Direct Routing).
Without one, the peer aborts the handshake with `CertificateUnknown`. Attach the
client identity in the top-level `tls:` block:

```yaml
tls:
  certificate: "/etc/siphon/tls/example.com.crt"   # inbound server cert
  private_key:  "/etc/siphon/tls/example.com.key"
  # Presented on OUTBOUND TLS when the upstream trunk requests a client cert:
  client_certificate: "/etc/siphon/tls/client.crt"
  client_private_key: "/etc/siphon/tls/client.key"
```

Then dial the trunk over TLS as usual — the B2BUA presents the configured client
certificate automatically:

```python
@b2bua.on_invite
def on_invite(call):
    call.media.anchor(engine="rtpengine")
    call.dial("sip:+15551234567@sbc.example.com;transport=tls")
```

Both `client_certificate` and `client_private_key` must be set together (or
neither); a one-sided setting or an unreadable file fails startup. The outbound
handshake also sends the target hostname (`sbc.example.com`) as SNI, so a
hostname-vhost trunk front-end can route it. Server-certificate verification is
unchanged (permissive) — this only adds the client certificate siphon presents.

!!! warning "Terminate strict peers (Teams) as a B2BUA, not a plain proxy"
    Microsoft Teams Direct Routing rejects any `Contact` or `Record-Route` whose
    host is an IP (403 Forbidden) — it must be the SBC FQDN that matches the TLS
    certificate. The B2BUA rewrites `Contact` to siphon's advertised address, so
    set `advertised_address` (or the per-listener `advertise`) to that FQDN and it
    satisfies the requirement. A **pure proxy** (`@proxy.on_request` relaying
    INVITEs) forwards the upstream UA's `Contact` verbatim — typically a PBX's
    private IP — which Teams refuses; RFC 3261 §16 forbids a proxy from rewriting
    another UA's `Contact`, so this is by design, not a bug. Front Teams-facing
    signalling with `@b2bua.on_invite`. siphon's OPTIONS keepalive and its 200 OK
    to Teams' OPTIONS already carry the advertised FQDN in `Contact` plus an
    `Allow` advertising the supported methods (including `REFER`/`NOTIFY`).

## See also

- Real examples: [`scripts/b2bua_default.py`](https://github.com/siphon-project/siphon-sip/blob/main/scripts/b2bua_default.py), [`examples/b2bua_gateway.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/b2bua_gateway.py), [`examples/b2bua_rtpengine.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/b2bua_rtpengine.py).
- [Media & RTP profiles](media-rtp.md) — the RTPEngine profiles in depth.
- [Hardening & security](security.md) — STIR/SHAKEN at the edge, TLS, IPsec.
