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

  trusted_cidrs: ["10.0.0.0/8"] # own infra: never rate-limited, never banned

  failed_auth_ban:              # auto-ban at accept (UDP/TCP/TLS/WS/SCTP)
    threshold: 10               # weighted failures in window_secs → ban
    window_secs: 600
    ban_duration_secs: 3600
    strong_signal_weight: 3     # weight of a high-confidence abuse signal

  apiban:                       # optional: APIBAN community blocklist
    api_key: "your-api-key"
    interval_secs: 300
```

`failed_auth_ban` weights signals by confidence: a wrong-password digest, a forged
nonce, or non-SIP garbage on a TLS stream counts heavily; a single 401 challenge
counts as 1; a successful auth resets the counter. Banned IPs are dropped at
`recv()`, before parsing. Put your load balancers and health checks in
`trusted_cidrs`.

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
