# Hardening & security

A SIP port on the public internet gets scanned within minutes. This recipe collects
the layers SIPhon gives you — most are config, a few are one-liners in a script.

## 1. Drop abuse before it costs you (config)

The `security:` block runs **before any SIP parsing or scripting**, so banned/garbage
traffic never reaches your handlers:

```yaml
security:
  rate_limit:
    window_secs: 10
    max_requests: 30            # per source IP per window
    ban_duration_secs: 3600

  scanner_block:
    user_agents: ["sipvicious", "friendly-scanner", "VaxSip", "sipcli"]

  trusted_cidrs: ["10.0.0.0/8"] # own infra: never rate-limited, never banned,
                                # never refused by connection_limits

  connection_limits:            # always on — every field defaults
    max_handshakes_per_source: 32
    max_handshakes: 1024
    max_connections_per_source: 256
    max_connections: 16384

  failed_auth_ban:              # auto-ban at accept (UDP/TCP/TLS/WS/SCTP)
    threshold: 10               # weighted failures in window_secs → ban
    window_secs: 600
    ban_duration_secs: 3600
    strong_signal_weight: 3     # weight of a high-confidence abuse signal
    missing_credentials_weight: 0   # default: a credential-less request is the
                                    # RFC-mandated first leg, not evidence

  apiban:                       # optional: APIBAN community blocklist
    api_key: "your-api-key"
    interval_secs: 300
    ban_ttl_secs: 604800        # 7 days, matching the feed's own release
                                # policy. 0 = never expire.
```

`trusted_cidrs` covers the feed too: an address listed by APIBAN that matches a
trusted CIDR is dropped as the feed is ingested, so it reaches neither the
userspace ACL nor the kernel set. Put your own trunks, monitoring and management
addresses there — a community blocklist has no way to know they're yours, and
the kernel drop is port-agnostic, so a listed management address would cost you
ssh along with the trunk.

### How the scoring works

`failed_auth_ban` is a **confidence-weighted** counter, not a flat fail2ban tally.
Every abuse signal from a source IP adds to a per-IP score within `window_secs`;
crossing `threshold` bans the IP for `ban_duration_secs`. Signals are weighted by
how hard they are to fake:

| Signal | Score |
|--------|-------|
| INVITE server-transaction timeout (never ACKed) | 1 |
| Failed or timed-out TLS/WSS/WS handshake | 1 |
| Wrong password, a username the auth backend denied, or a forged/stale/replayed digest nonce | `strong_signal_weight` (default 3) |
| Non-SIP bytes on a TCP/TLS stream | `strong_signal_weight` |
| Scanner User-Agent (`scanner_block`) | `strong_signal_weight` |
| 401/407 challenge because the request carried **no** credentials | `missing_credentials_weight` (default **0** — not counted) |
| A credential check the auth backend could not answer | **never counted** |

Signals carrying present-but-wrong credentials, or garbage over TCP, score high
because they are unambiguous: the source IP is validated by the three-way handshake
so it cannot be spoofed, and a legitimate client never trips them. A **successful
authentication resets the score to zero**, so a subscriber who mistypes a password
twice then logs in is never banned, while an IP spraying garbage is banned 3× faster
than one just rattling doorknobs.

The last two rows are the ones worth understanding, because both were once counted
and both banned real subscribers:

- **A request with no credentials is not evidence.** RFC 3261 §22.2 makes it the
  opening leg of challenge-response — every client sends one before it has a nonce.
  Counting it means a handset stuck in a retry loop earns an hour-long ban, and
  behind CGNAT that address is shared, so the ban lands on every subscriber behind
  it. Volume still shows in `siphon_auth_failures_total`; set
  `missing_credentials_weight: 1` if you want the old scoring back.
- **An auth-backend outage is not an attack.** A `GET` to your credential endpoint
  that times out tells you nothing about the peer. It used to be indistinguishable
  from a wrong password, so two REGISTER retries during an outage banned the
  subscriber — exactly when every subscriber is retrying. Alert on
  `siphon_auth_backend_errors_total` instead; a non-zero rate means authentication
  is failing into 401s for everyone.

### Bounding what one source can spend

`connection_limits` is a separate, always-on layer, and it covers what the ban
counter structurally cannot: a source that opens 50 TLS connections at once and
completes none of them never produces a *completed* failure to count, while each
connection burns a real handshake and pins a task for the full 10 s handshake
timeout.

Two ceilings, because the resources differ. An in-flight handshake is CPU held
briefly and no legitimate client has many at once, so that one is tight (32 per
source). An established connection is a socket held until the peer leaves or the
300 s idle timeout reaps it, and a busy NAT legitimately holds many, so that one is
loose (256 per source). Each has a global twin for distributed floods. `0` disables
a ceiling; `trusted_cidrs` are exempt from all of them.

Refused connections are dropped silently and **not** banned — hitting a concurrency
ceiling is a capacity fact, not proof of intent, and a NAT whose UEs all re-register
after a network flap looks exactly like a flood.

!!! warning "Carrier NAT and `max_connections_per_source`"
    A CGNAT pool or a large enterprise NAT can legitimately front more registrations
    from one address than the 256 default allows, and every one of them is a paying
    subscriber. The default is a runaway detector, not a policy — raise it, or set
    `0`, wherever that is your topology. Watch
    `siphon_connections_refused_total{reason="connections_per_source"}`: it tells you
    the ceiling is binding on real traffic before the support tickets do.
    `siphon_stream_connections_active` and `siphon_handshakes_in_flight` are what you
    size against.

Bans are enforced at `recv()`/`accept()` — before any SIP parsing — and expire on
their own. `trusted_cidrs` are exempt from scoring entirely, so put your load
balancers and health checks there.

!!! tip "Drop bans in the kernel"
    With [`security.firewall`](../kernel-firewall.md), every ban is also pushed to a
    kernel nf_tables set, so abusive sources are dropped **before they reach
    SIPhon** — real defense against volume, not just userspace politeness.

In a script, you can also rate-limit a specific flow:

```python
if not proxy.rate_limit(request, window_secs=1, max_requests=5):
    return    # silently drop — don't fingerprint the server
```

## 2. Drop malformed traffic (script)

`proxy.sanity_check()` runs the RFC 4475 semantic checks (mandatory headers, CSeq,
Content-Length). Drop failures **silently** so scanners learn nothing:

```python
@proxy.on_request
def route(request):
    if not request.in_dialog and not proxy.sanity_check(request):
        return                  # silent drop
    ...
```

!!! note "Silent drop is intentional"
    Returning from a handler without `reply()`/`relay()`/`reject()` sends no response.
    For rate-limit and scanner blocking that's the point — a `403` would confirm the
    server exists. Don't "helpfully" reply.

## 3. Encrypt the signalling (config)

```yaml
listen:
  tls: ["0.0.0.0:5061"]
tls:
  certificate: "/etc/siphon/tls/cert.pem"
  private_key:  "/etc/siphon/tls/key.pem"
  method: "TLSv1_3"
  # mTLS — require and verify client certs (SIP trunks with mutual auth):
  verify_client: true
  client_ca: "/etc/siphon/tls/client-ca.pem"
```

`method` is the minimum TLS version. `TLSv1_3` here is a real 1.3-only floor —
it refuses TLS 1.2 peers on the listeners *and* on outbound connections siphon
dials, so check both sides can do 1.3 before hardening. `TLSv1_2` (the default)
negotiates 1.2 or 1.3.

`verify_client: true` requires a client cert chaining to `client_ca` (fails closed at
startup if `client_ca` is missing). It applies to `listen.tls` **and** `listen.wss`.

## 4. Authenticate subscribers (script + config)

```python
if not auth.require_digest(request, realm="example.com"):
    return                      # 401/407 challenge already sent
user = request.auth_user        # the authenticated username afterwards
```

The `auth.backend` can be `static`, `http` (REST credential lookup), `database`, or
`diameter_cx` (IMS HSS). For REGISTER-time account-takeover protection, set
`registrar.enforce_auth_aor_match: true` so a subscriber can't bind a Contact under
someone else's AoR.

## 5. Verify caller ID — STIR/SHAKEN (script)

Sign on egress, verify on ingress at a trunk edge:

```python
from siphon import proxy, stir, log

@proxy.on_request("INVITE")
def on_invite(request):
    if request.source_ip_in(["203.0.113.0/24"]):           # inbound from a peer
        result = stir.verify(request)
        if result.verstat == "TN-Validation-Failed":
            request.reply(438, "Invalid Identity Header")  # RFC 8224 §6.2.2
            return
        stir.apply_verstat(request, result)                 # convey downstream
    else:                                                    # outbound
        origid = stir.sign(request, attestation="A")
    request.record_route()
    request.relay()
```

Needs a `stir:` block with `signing` + `verification` configured.

The `source_ip_in([...])` above hardcodes the peer's CIDR. If that peer is already
a `gateway` group (a trunk you health-probe), test membership by group name instead
so you never maintain two copies of the address list — see the next section.

## 5.5. Direction & trust — `from_gateway`

`request.from_gateway("group")` (and `call.from_gateway("group")` in a B2BUA) returns
`True` when the message's **source IP** is one of the resolved addresses of the named
gateway group. It's SIPhon's equivalent of Kamailio `ds_is_from_list()` /
OpenSIPS `ds_is_in_list()` — a routing-direction predicate that replaces hardcoded
source CIDRs with the trunk list you already maintain under `gateway.groups`.

```python
from siphon import proxy, gateway

@proxy.on_request("INVITE")
def route(request):
    if request.from_gateway("teams"):
        # Inbound leg from Microsoft Teams — trust it, forward to the PBX.
        request.relay("sip:pbx.internal:5060")
    else:
        # Outbound leg from the PBX — send to Teams.
        request.relay(gateway.select("teams").uri)
```

It matches on **IP only** (source port ignored) against **every** resolved address in
the group, so a hostname that round-robins across many IPs — Teams'
`sip`/`sip2`/`sip3.pstnhub.microsoft.com`, a carrier's rotating trunk — matches on any
of them. The member set is cached and refreshed on the health-probe cycle, so the
predicate never resolves DNS on the request path.

!!! warning "Trustworthy on TCP/TLS/WS/WSS, a hint on UDP"
    On connection-oriented transports the source IP is verified by the handshake, so
    `from_gateway` is a sound **authorization** signal. On UDP the source IP is
    spoofable — treat `from_gateway` there as a best-effort **direction hint**, and
    gate real trust decisions on TLS/mTLS or digest/AKA auth.

## 6. IMS access security — IPsec (Gm)

For a P-CSCF, SIPhon does full 3GPP TS 33.203 sec-agree: parse `Security-Client`,
run AKA, install kernel IPsec SAs, and route MT requests back over the flow. It's a
substantial flow — see [`examples/ims_pcscf.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/ims_pcscf.py)
and the `ipsec:` config block. The SA lifetime tracks the registration lifetime
automatically.

## Checklist

- [ ] `security.failed_auth_ban` + `scanner_block` on, infra in `trusted_cidrs`
- [ ] `proxy.sanity_check()` on out-of-dialog requests, silent-drop failures
- [ ] TLS (and mTLS for trunks); subscriber-facing access over TLS/WSS
- [ ] Digest auth on REGISTER (+ `enforce_auth_aor_match`)
- [ ] STIR/SHAKEN at PSTN edges; IPsec at IMS Gm
- [ ] Alert on the security metrics (see [Monitoring](monitoring.md))

## See also

- Real example: [`examples/stir_shaken.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/stir_shaken.py), [`examples/ims_pcscf.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/ims_pcscf.py).
- Reference config: [`siphon.yaml`](https://github.com/siphon-project/siphon-sip/blob/main/siphon.yaml).
