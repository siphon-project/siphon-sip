# Transports & networking

SIPhon's transport layer is **Rust-only** — Python scripts never touch a socket.
You declare what to listen on in `siphon.yaml`; the framework terminates the
transport, frames SIP messages, and hands your handlers a parsed request. This
page covers the parts of networking that bite in the real world: WebSocket/WebRTC
access, running behind NAT or a load balancer (`advertised_address`), bridging a
call from one transport to another, and IPv4 ↔ IPv6.

| Transport | Spec | Notes |
|---|---|---|
| **UDP** | RFC 3261 §18 | The default for PSTN gateways and legacy UEs. |
| **TCP** | RFC 3261 §18 | Persistent connections, pooled outbound. |
| **TLS** | RFC 5246 (TLS 1.3 default) | Cert/key in the top-level `tls:` block; supports mTLS. |
| **WS** | RFC 7118 | SIP over WebSocket — browser / WebRTC UEs. |
| **WSS** | RFC 7118 + TLS | Secure WebSocket — shares the `tls:` cert. |
| **SCTP** | RFC 4168 | Off by default — opt-in `sctp` Cargo feature (Linux, `libsctp`). |

---

## Configuring listeners

Every transport under `listen:` takes a **list** of bind addresses, so you can
serve several addresses and address families on the same transport:

```yaml
listen:
  dscp: CS3                     # DiffServ marking for all SIP packets (RFC 4594);
                                # name (CS3, EF, AF41…) or 0–63; "BE"/0 disables.
  udp:
    - "0.0.0.0:5060"            # all IPv4
    - "[::]:5060"               # all IPv6
  tcp:
    - "0.0.0.0:5060"
  tls:
    - "0.0.0.0:5061"            # requires the tls: block below
  ws:
    - "0.0.0.0:8080"            # SIP over WebSocket
  wss:
    - "0.0.0.0:8443"            # SIP over Secure WebSocket (shares tls: cert)

tls:
  certificate: "/etc/siphon/tls/example.com.crt"
  private_key:  "/etc/siphon/tls/example.com.key"
  method: "TLSv1_3"             # TLSv1_2 | TLSv1_3
  # INBOUND mTLS — siphon verifies clients that connect INTO it (applies to
  # listen.tls AND listen.wss):
  verify_client: false
  client_ca: "/etc/siphon/tls/client-ca.pem"
  # OUTBOUND mTLS — the cert siphon PRESENTS when it dials OUT to an upstream
  # trunk that requires a client certificate:
  client_certificate: "/etc/siphon/tls/client.crt"
  client_private_key: "/etc/siphon/tls/client.key"
```

The two mTLS directions are independent. `verify_client` / `client_ca` govern
**inbound** mutual TLS — siphon verifying the certificate of a peer connecting
*into* it. `client_certificate` / `client_private_key` govern **outbound** mutual
TLS — the certificate siphon *presents* when it dials *out* to an upstream SIP
trunk that requires a client certificate (for example Microsoft Teams Direct
Routing). Both outbound fields must be set together, or neither; a one-sided
setting or an unreadable file is a hard startup error. Outbound TLS also now
sends the resolved target hostname as SNI (RFC 6066) instead of the destination
IP, so a hostname-vhost front-end can route the handshake; bare-IP next hops
send no SNI, as before.

A listener can be a **plain string** (`"10.0.0.1:5060"`) or the **extended form**
with a per-socket advertised host and DSCP override (like OpenSIPS
`socket … as …`):

```yaml
listen:
  tls:
    - address: "10.0.0.1:5061"
      advertise: "sip.example.com"   # what peers should see in Via/Record-Route
      dscp: EF                       # overrides the global listen.dscp
```

!!! note "SCTP is opt-in"
    SIP-over-SCTP links the `libsctp` system library and is Linux-only, so it's
    behind the `sctp` Cargo feature and absent from the default build. See the
    README for the `--features sctp` install.

For TLS/mTLS hardening (cipher policy, client-cert trunks, who terminates), see
the [Hardening & security recipe](cookbook/security.md).

---

## WebSocket & WebRTC (ws / wss)

`listen.ws` / `listen.wss` implement **SIP over WebSocket (RFC 7118)**: siphon
performs the HTTP `Upgrade` handshake, confirms the `Sec-WebSocket-Protocol: sip`
subprotocol, and then exchanges SIP messages as WebSocket text frames (binary
frames are also accepted — some WebRTC stacks send them). **WSS reuses the
top-level `tls:` certificate** — it's a separate listener only because the
handshake differs (HTTP WebSocket upgrade vs. a raw TLS record stream).

### Browsers are a one-way street

A browser can't accept an inbound TCP connection, so per **RFC 5626 (Outbound)**
the connection the UE opened **is the only path back to it**. SIPhon registers
every accepted WS/WSS connection in a flow registry keyed by the UE's source
address, and:

- **Responses** travel back down the same connection automatically.
- **Terminating requests** (an INVITE *to* a registered browser) reuse that
  stored connection — there is no dial-back. If the UE's connection is gone, it's
  unreachable until it re-REGISTERs.

To make that terminating path explicit and robust, capture the connection as a
**flow** at REGISTER and route back over it — see
[Flow tokens & connection reuse](#flow-tokens-connection-reuse).

!!! warning "Don't lose the flow"
    Because the inbound connection is the only return path, a browser-facing
    deployment should run RFC 5626 keepalives (see [below](#nat-traversal-for-clients))
    and enable `registrar.liveness` so a dropped socket clears the binding instead
    of black-holing terminating calls.

### Signaling vs. media

The SIP/WebSocket layer above is **only signaling**. WebRTC media —
DTLS-SRTP, ICE, AVPF — is terminated by **RTPEngine**, not siphon, using the
`ws_to_rtp` / `wss_to_rtp` profiles (browser DTLS-SRTP+ICE on one side, plain RTP
toward your core on the other). That pairing is what makes a working WebRTC
gateway; the SIP side stays pure RFC 7118. See
[Media & RTP profiles](cookbook/media-rtp.md#built-in-profiles).

```python
# WebRTC access edge: browser on WSS, core on UDP/TCP. Signaling is ordinary
# proxy routing; the media transform is one profile argument.
@proxy.on_request("INVITE")
async def route(request):
    if request.body:
        await rtpengine.offer(request, profile="wss_to_rtp")   # DTLS-SRTP ↔ RTP
    request.record_route()
    request.relay()
```

---

## Flow tokens & connection reuse

WebSocket is the sharp case, but the problem is general: **connection-oriented
clients** (WS, WSS, and also plain TCP/TLS behind NAT) can only be reached over
the connection *they* opened. The R-URI in their Contact is frequently a private,
NATed, or IPsec-protected address that nothing on the public network can dial.
This is exactly what **RFC 5626 (SIP Outbound)** addresses, and SIPhon gives you
two layers for it.

### Layer 1 — automatic connection reuse (zero config)

SIPhon registers every accepted stream connection in a process-global registry
keyed by the client's source address (with an IP-only fallback for NAT). Responses
always go back over the originating connection, and a terminating request whose
target address matches a live connection reuses it. For a single-node proxy where
the same box holds the registration and routes the call, browser delivery often
*just works* with no extra code.

### Layer 2 — flow tokens (explicit, robust, multi-node)

When address-matching isn't enough — multiple flows from one NAT, an IPsec port
pair that must be preserved, or a multi-instance / P-CSCF deployment where the
terminating request enters a *different* process — capture the connection as an
opaque **flow** at REGISTER and carry a **token** that names it. This is the
SIPhon realization of RFC 5626 flow tokens (it also ships the standardized
`<addr>~<transport>` Route-token codec as a primitive in
[`src/transport/flow.rs`](https://github.com/siphon-project/siphon-sip/blob/main/src/transport/flow.rs)).

The pattern is three steps:

```python
from siphon import proxy, registrar

# (1) REGISTER — stash the live flow under an opaque token, and advertise that
#     token in a Path (RFC 3327) so terminating requests come back through us.
@proxy.on_request("REGISTER")
def register(request):
    token = request.call_id                  # any stable opaque string
    request.add_path(f"sip:{token}@edge.example.com;lr")
    registrar.save(request, flow_token=token)   # binding remembers the flow
    # IMS P-CSCF convenience (uses ipsec.path_host): request.add_pcscf_path(token)

# (2) TERMINATING INVITE — our Path comes back as the topmost Route. Consume it,
#     recover the token, resolve the binding, and relay back over the captured flow.
@proxy.on_request("INVITE")
def terminate(request):
    if request.loose_route():
        token = request.consumed_route_user      # the token off the consumed Route
        binding = registrar.lookup_by_token(token)
        if binding and binding.is_local and binding.flow.is_alive:
            request.relay(flow=binding.flow)     # bypass DNS; back down the wire
            return
    request.reply(404, "Not Found")
```

`request.relay(flow=...)` **bypasses DNS resolution of the Contact URI entirely**
and writes straight to the captured connection; the egress Via host/port is taken
from `flow.local_addr`, so the exact listener (and, for IMS, the IPsec protected
port pair) is preserved.

Forking works the same way: fork the **`Contact` objects** from
`registrar.lookup()` (not bare URI strings) and SIPhon automatically attaches each
*locally-accepted* binding's flow to its branch — the only way a parallel fork can
ring a WebSocket UE.

### The `Flow` object

`Contact.flow` (and `request.flow` for the inbound side) is an opaque view —
treat it as a handle to pass to `relay(flow=...)`, and read these to defend
against a dead path:

| Field | Meaning |
|---|---|
| `flow.transport` | `"udp"` / `"tcp"` / `"tls"` / `"ws"` / `"wss"`. |
| `flow.remote_addr` | The UE's source address (where the REGISTER came from). |
| `flow.local_addr` | The listener address the REGISTER landed on (the egress socket). |
| `flow.is_alive` | UDP: always `True`. Stream: `True` only while the **exact** accepted connection is still open **on this process**; a reconnected or closed UE reports `False`. |

!!! warning "Multi-node: gate on `is_local` first"
    A flow is only usable on the process that accepted the REGISTER. With a shared
    Redis registrar, a lookup on another node returns the binding but its flow
    points at a connection that node doesn't hold. Check `Contact.is_local` before
    trusting `flow.is_alive` / `relay(flow=...)`; otherwise route the call to the
    owning instance (subscriber affinity — see
    [Deployment](deployment.md#why-the-affinity-hash-matters)). This is also why
    enabling `registrar.liveness` matters: a stale stream binding that no live
    connection backs should be cleared, not dialed.

---

## Behind NAT or a load balancer

When the address siphon **binds** isn't the address peers should **reach it on**
— a cloud instance with a private NIC and an elastic public IP, or a node behind
a SIP-aware load balancer — set the **advertised address**. It's the host siphon
writes into the headers it generates: **Via** sent-by, **Record-Route**,
**Contact** (B2BUA), and the SDP `o=`/connection line it rewrites for topology
hiding. (Actual media addresses are RTPEngine's job, not siphon's.)

Two levels, per-listener wins:

```yaml
# Global: one public identity for every transport (the common cloud case).
advertised_address: "203.0.113.10"        # or an IPv6 literal: "2001:db8::1"

# Per-listener: override per socket — e.g. behind a load balancer that presents
# a different public address per transport. Falls back to advertised_address
# for any transport without its own advertise.
listen:
  udp:
    - address: "10.0.0.1:5060"
      advertise: "sip-udp.example.com"
  tls:
    - address: "10.0.0.1:5061"
      advertise: "sip-tls.example.com"
```

!!! danger "Binding `0.0.0.0` / `[::]` requires an advertised address"
    With a wildcard bind and **no** advertised address, siphon can't know which
    local IP to put in Via/Contact, so it falls back to `127.0.0.1` and logs a
    warning — remote peers won't be able to route back to it. Always pair a
    wildcard bind with `advertised_address` (or a per-listener `advertise`).

A few properties worth knowing:

- **Outbound-only.** The advertised address is purely for headers siphon *emits*.
  Inbound routing — “is this R-URI one of mine?”, loop detection — uses the actual
  bind addresses and the `domain.local` list, never the advertised address. Put
  your real served domains and local IPs in `domain.local`.
- **Per-transport.** A bridged call (in on TLS, out on UDP) gets the *outbound*
  transport's advertised address in its Via, and a Record-Route per side (see
  [Inter-transport routing](#inter-transport-routing)).
- **Load balancers:** put the LB/health-check sources in `security.trusted_cidrs`
  so probes aren't rate-limited, and prefer a topology that preserves the client
  source IP:port (`externalTrafficPolicy: Local` / `hostNetwork` on Kubernetes —
  see [Deployment](deployment.md#kubernetes-kept-deliberately-light)).

---

## Choosing the egress socket (`send_socket`)

On a multi-homed host — several listeners across interfaces — routing usually
picks the outbound transport, but not *which local socket* the request leaves
from. `send_socket=` pins it, the way Kamailio's `force_send_socket()` and
OpenSIPS' `$fs` do. It takes a `"<transport>:<ip>:<port>"` string naming one of
siphon's **own** configured listeners:

```python
# Proxy — relay this trunk call out of the carrier-facing NIC.
request.relay("sip:carrier.example.net", send_socket="udp:203.0.113.10:5060")

# Proxy — fork; the pin applies to every branch.
request.fork(contacts, send_socket="udp:10.0.0.1:5060")

# B2BUA — dial the B-leg out of a specific interface.
call.dial("sip:bob@10.0.0.2:5060", send_socket="tcp:10.0.0.1:5060")
```

What it does:

- **Advertises the right Via.** The outgoing Via sent-by is the selected
  listener's advertised address (its `advertise:`, else its bound IP) with the
  listener's port, so the peer's response comes back to the same socket. This is
  the correctness reason to use `send_socket` instead of hand-rolling a Via
  rewrite — get the sent-by wrong and the response lands on the wrong listener
  (or nowhere).
- **UDP** pins the exact `(ip, port)` listener socket as the egress.
- **TCP/TLS** bind the source **IP** (interface); the source *port* stays
  ephemeral, because binding a listen port for an outbound connection collides on
  the 4-tuple in `TIME_WAIT`. Source-bound and default connections to the same
  peer are pooled separately, so they never reuse each other.

Rules and fall-backs:

- A **malformed** spec raises `ValueError` at the scripting API (immediate, so
  you catch typos in tests).
- A **well-formed but unknown** socket (no such listener) is logged and the
  request falls back to default routing — it is never dropped.
- Ignored when a captured **`flow=`** is set (the flow already pins egress), and
  when its **transport doesn't match** the routed transport (logged).
- WS/WSS callees can't be dialed (client-initiated); reach them with `flow=`, not
  `send_socket`.

!!! note "Multi-homed UDP fast path"
    Per-listener UDP egress is enabled automatically once the host has more than
    one UDP listener (or IPsec is configured). A single-UDP-listener deployment
    keeps the original zero-overhead send path — `send_socket` only has real work
    to do when there's more than one socket to choose between.

---

## NAT traversal for clients

Subscribers behind home NAT advertise unroutable private addresses in their Via
and Contact. SIPhon handles the return path and gives scripts the tools to fix
the bindings.

**Responses route symmetrically, always.** Every response is sent back to the
source IP:port the request actually arrived from — not the Via sent-by host (RFC
6314 / the `rport` model, applied unconditionally). This is the safe default for
*all* UACs, so there's no toggle to turn it on.

**Contact fixups.** A private Contact still has to be rewritten to the observed
source so in-dialog and terminating requests are routable:

```yaml
nat:
  fix_contact: true             # auto-rewrite Contact on responses to the source addr
  keepalive:                    # OPTIONS pings to registered contacts (NAT pinholes)
    enabled: true
    interval_secs: 30
    failure_threshold: 10       # deregister a contact after N failed pings
  crlf_keepalive:               # RFC 5626 §4.4.1 CRLF ping on TCP/TLS/WS/WSS
    enabled: true
    interval_secs: 30
    failure_threshold: 3        # close the connection after N missed pongs
```

`fix_contact: true` auto-rewrites the Contact on **responses**. For **REGISTER**,
do it in the script before saving the binding — siphon stores the observed source
alongside the contact so terminating calls reach the NATed UE:

```python
@proxy.on_request("REGISTER")
def register(request):
    request.fix_nated_register()     # write received=/rport= on the top Via
    request.fix_nated_contact()      # rewrite Contact host:port to the source addr
    # request.add_contact_alias()    # ...or the OpenSIPS-style ;alias form
    registrar.save(request)          # binding remembers the observed source
```

**Keepalives feed registration liveness.** OPTIONS keepalives deregister a contact
after `failure_threshold` failures; CRLF keepalives close a dead TCP/TLS/WS
connection, which — with `registrar.liveness.enabled` — clears its binding (RFC
5626 §4.2.2 flow failure) instead of waiting hours for `Expires`. This is what
keeps terminating delivery honest for connection-oriented clients (browsers
especially).

!!! note "force a specific egress Via"
    For multi-homed or IPsec-protected routes, `request.force_send_via(transport, "host:port")`
    overrides both the outbound transport and the Via sent-by for that relay.

---

## Inter-transport routing

The inbound and outbound transports are **independent**. A request can arrive on
WSS and leave on UDP; siphon remembers the inbound transport + connection on the
session and routes the response (and later in-dialog requests) back the way they
came. Common shapes: a WebRTC browser (WSS) calling a SIP trunk (UDP), a TLS
access edge fronting a UDP core, a TCP UE reaching a UDP gateway.

**How the outbound transport is chosen**, in order:

1. An explicit `;transport=` parameter on the relay target or the R-URI.
2. **DNS, RFC 3263** — NAPTR then SRV (`_sips._tcp`, `_sip._tcp`, `_sip._udp`),
   then A/AAAA. siphon resolves these natively for its own routing.
3. Otherwise the **inbound transport** (same transport in and out).

**The return path is remembered, not re-derived.** The session stores the inbound
transport, source address, and (for stream transports) the exact connection, and
responses go back over it — reusing the live TCP/TLS/WS connection where one
exists. When the two legs use **different** transports, siphon inserts **two
Record-Route headers** (one per side, each carrying its own `;transport=`), so
in-dialog requests come back to the proxy on the correct transport for their
direction. Record-routing is therefore required for any call you want to bridge:

```python
# WebRTC browser (WSS) ↔ SIP trunk (UDP): one record_route(), siphon double-RRs
# across the transport boundary so the in-dialog BYE finds its way back on each leg.
@proxy.on_request("INVITE")
async def route(request):
    if request.body:
        await rtpengine.offer(request, profile="wss_to_rtp")
    request.record_route()                       # ← required to bridge transports
    request.relay("sip:trunk.example.com:5060;transport=udp")
```

---

## IPv4 / IPv6

SIPhon is dual-stack. Run a listener per family you want to serve — typically a
wildcard pair:

```yaml
listen:
  udp:
    - "0.0.0.0:5060"            # IPv4
    - "[::]:5060"               # IPv6
  tcp:
    - "0.0.0.0:5060"
    - "[::]:5060"
advertised_address: "2001:db8::1"   # advertised host may itself be a v6 literal
```

- **Egress family follows the destination.** Relaying to an IPv6 next hop uses an
  IPv6 outbound socket, IPv4 uses IPv4. To *originate* toward a given family you
  must have a listener of that family configured, so list both wildcard addresses
  if you route to both.
- **v6 literals are bracketed** automatically in the headers siphon writes
  (`[2001:db8::1]:5060`); the `advertised_address` may be a v6 literal too.
- **v4 ↔ v6 bridging is implicit.** Because each leg owns its own transport and
  socket family, a v6 UE calling a v4 trunk (or vice-versa) just works — the
  inbound leg stays v6, the outbound leg is v4, and the remembered return path
  keeps responses and in-dialog requests on the right family. No special config.

---

## See also

- [Hardening & security](cookbook/security.md) — TLS/mTLS, trusted CIDRs, scanner/auth bans.
- [Media & RTP profiles](cookbook/media-rtp.md) — WebRTC `ws_to_rtp`/`wss_to_rtp`, SRTP↔RTP.
- [Deployment & operations](deployment.md) — load balancers, Kubernetes networking, drain.
- [Scaling & redundancy](scaling-and-redundancy.md) — DNS SRV failover across nodes.
