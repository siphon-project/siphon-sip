# Auth & security

Authentication and the security-agreement machinery: SIP digest and IMS-AKA
challenges, P-CSCF IPsec sec-agree (3GPP TS 33.203 / RFC 3329), and
STIR/SHAKEN signing and verification.

```python
from siphon import auth

@proxy.on_request("INVITE")
async def route(request):
    if not await auth.verify_digest(request, "example.com"):
        await auth.require_proxy_digest(request, "example.com")
        return
    request.relay()
```

## Challenging in B2BUA mode

The digest helpers take a `Request` **or** a `Call`. This matters: registering
any `@b2bua.*` handler makes the dispatcher route INVITE straight to the B2BUA
path, so `@proxy.on_request` never sees it and a proxy-style challenge would
simply never run.

```python
from siphon import auth, b2bua, log

@b2bua.on_invite
async def new_call(call):
    if not await auth.require_proxy_digest(call, realm="example.com"):
        return                      # 407 armed; siphon answers the A-leg
    log.info(f"call from {call.auth_user}")
    call.dial(str(call.ruri))
```

Returning `False` arms the challenge as the call's deferred reject, the same one
`call.reject()` produces — siphon answers the A-leg INVITE and drops the call
actor, so **no B-leg is dialled** for an unauthenticated caller. On success the
caller's `Proxy-Authorization` is stripped from the message the B-leg INVITE is
built from, because it is hop-by-hop (RFC 3261 §22.3); forwarding it would only
make the next hop challenge credentials that were minted for us. The verified
username lands on `call.auth_user` and on the call's CDR.

This is the opposite direction from `call.dial(auth_passthrough=True)`, where a
*downstream* PBX issues the challenge and siphon relays it end-to-end for the
caller to answer. Use `auth_passthrough` when the credentials live at the far
end; challenge on the `Call` when siphon owns them.

### When the credential is not the subscriber identity

`request.auth_user` / `call.auth_user` hold the username exactly as it appeared
in the `Authorization` / `Proxy-Authorization` header, because that is the
string the digest response was computed over — siphon must not guess at its
structure.

Deployments where the authentication identity is not the subscriber identity
need to say so. IMS is the standard case: a private identity `user@realm`
authenticates a public identity. Any scheme carrying a validity prefix or a
tenant qualifier in the username has the same shape. Both properties are
writable, so the script reduces the credential **after** verification:

```python
@proxy.on_request("REGISTER")
async def register(request):
    if not await auth.verify_digest(request, realm="example.com"):
        await auth.require_www_digest(request, realm="example.com")
        return
    request.auth_user = request.auth_user.split(":", 1)[1]
    registrar.save(request)
```

Everything keyed on the authenticated identity reads the new value:
`registrar.enforce_auth_aor_match`, which compares it to the AoR userpart, and
the CDR's `auth_user` field. That AoR check is exactly why the reduction has to
happen — an unreduced credential never equals the AoR userpart, so every
REGISTER is answered `403` and the only way to deploy is to turn the anti-hijack
check off entirely.

Assigning it *before* verifying defeats that comparison. It is an assertion
about an identity already proven, not a way to prove one — so set it only on the
success path.

`require_ims_digest` and `require_aka_digest` take a `Request` only — IMS and
AKA digest are REGISTER-time procedures, and REGISTER never reaches the B2BUA
path. `require_ims_digest` also takes `server_name=`, the S-CSCF's own SIP URI,
which the Multimedia-Auth-Request it sends to the HSS requires; see
[Cx: registration](diameter.md#cx-registration).

`require_aka_digest` computes the vector itself from `auth.aka_credentials`
(Milenage), so it also keeps what an HSS would: a sequence number per
subscriber. Each challenge carries a later SQN (the next SEQ, IND 0, TS 33.102
annex C), starting from the credential's optional `sqn` (12 hex characters,
default `000000000001`). A UE that finds the SQN out of range answers with
`auts=`; siphon checks its MAC-S against the RAND of the challenge it answers,
and on a match takes up the UE's SQN and sends a fresh 401, on a mismatch
answers 403 (TS 33.102 6.3.5). The counters are in memory: after a restart the
first challenge carries the configured `sqn` again, and a UE further along
re-synchronises through that AUTS.

```yaml
auth:
  aka_credentials:
    "001010000000001":
      k: "465b5ce8b199b49faa5f0a2ee238a6bc"
      op: "cdc202d5123e20f62b6d676ac72cb318"
      amf: "8000"
      sqn: "000000000020"   # optional: SQN of the first challenge
```

### IMS AKA or SIP Digest

`require_ims_digest` authenticates a REGISTER against the HSS over Cx, with
IMS-AKA or with SIP Digest (TS 33.203 Annex N). Which one is decided the way
TS 24.229 clause 5.4.1.1 lists it, from the `integrity-protected` parameter the
P-CSCF writes into the Authorization header and, for a REGISTER without that
header, from P-Access-Network-Info:

| The REGISTER | Item of clause 5.4.1.1 | SIP-Authentication-Scheme asked of the HSS | Then |
|---|---|---|---|
| `integrity-protected="no"` | 1 | `Digest-AKAv1-MD5` | `AKAv1-MD5` challenge |
| `integrity-protected="yes"` | 2 | `Digest-AKAv1-MD5` when a vector is needed | the response is checked against the stored vector, a new challenge otherwise |
| `integrity-protected="tls-connected"` | 2A | none | `403`: IMS AKA over TLS (AKAv2) is not implemented |
| no Authorization, P-Access-Network-Info with `network-provided` naming a non-3GPP access | 5 | `SIP Digest` | `Digest` challenge |
| no Authorization otherwise | none applies (4, 6, 7 and 8 need NASS-IMS bundled or GPRS-IMS-Bundled authentication) | `Unknown` | the scheme the HSS answers with |
| Authorization without `integrity-protected` | 9 | `Unknown` | the scheme the HSS answers with |
| `tls-pending`, `tls-yes`, `ip-assoc-pending`, `ip-assoc-yes` | 10 | `SIP Digest` when H(A1) is needed | the response is checked against the stored H(A1), a `Digest` challenge otherwise |
| `integrity-protected="auth-done"` | 11 | none | `403`: trusted node authentication is not implemented |
| any other value | none | none | `403` |

A REGISTER whose nonce is one of a challenge this S-CSCF issued and still
holds is handled under the mechanism of that challenge, whatever the parameter
says. That is a deliberate difference from item 1, which has the S-CSCF ignore
a response next to `integrity-protected="no"`: a deployment without IPsec
between UE and P-CSCF can still complete IMS-AKA.

To `Unknown` a conformant HSS answers `SIP Digest` or `NASS-Bundled`, and
`DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED` (5006) for an IMS-AKA subscriber
(TS 29.228 clause 6.3.1 step 4). `NASS-Bundled` and `Early-IMS-Security` are
refused with `403`. An IMS-AKA item in answer to `Unknown` is challenged as
IMS-AKA. So IMS-AKA needs a P-CSCF that writes `integrity-protected`, which
`auth.stamp_integrity_protected` does.

### SIP Digest

The HSS returns H(A1) in `SIP-Digest-Authenticate`, never the password:

| AVP | Code, vendor | What `require_ims_digest` does with it |
|---|---|---|
| `Digest-Realm` | 104, none | the `realm` of the challenge (not the `realm=` argument, H(A1) is bound to it) |
| `Digest-Algorithm` | 111, none | optional, must be `MD5` |
| `Digest-QoP` | 110, none | must be `auth`; the challenge carries `qop="auth"` |
| `Digest-HA1` | 121, none | H(A1) for MD5, 32 hexadecimal digits |
| `Alternate-Digest-Algorithm` | 662, 3GPP | optional, `SHA-256` or `SHA-512-256` |
| `Alternate-Digest-HA1` | 663, 3GPP | H(A1) for that algorithm, 64 hexadecimal digits |

The 401 carries one `WWW-Authenticate: Digest` per algorithm there is a hash
for, the alternate one first, with one nonce generated by siphon (TS 24.229
clause 5.4.1.2.1B). The REGISTER that answers it is checked as clause
5.4.1.2.2A lists: same Call-ID as the challenged REGISTER, the `username` that
was challenged, the realm and an algorithm of the challenge, `qop=auth` with
`cnonce` and `nc`, and the response computed from H(A1) per RFC 7616.

| The REGISTER carries | Answer |
|---|---|
| a response that verifies | `True`, `request.auth_user` set, `Authentication-Info: qop=auth, rspauth="...", cnonce="...", nc=...` on the 200 |
| a response that does not verify, or misses one of the checks above | `403 Forbidden`, no challenge (TS 33.203 clause N.2.2.1), the nonce is dropped |
| a valid response with an `nc` not higher than the last one accepted | `401` with a fresh nonce and `stale=true` |
| a valid response under a nonce that expired or was never issued | `401` with a fresh nonce and `stale=true`, after a new request to the HSS |
| a response that is valid for neither | `403 Forbidden` |

A nonce waits 120 seconds for its first answer. Once a response under it has
verified it stays valid for `nonce_lifetime` seconds (default 3600), renewed by
every REGISTER that verifies, so a re-registration with the next `nc` needs no
challenge and no request to the HSS. No `nextnonce` is sent. A nonce belongs to
one public identity: under another one the HSS is asked again.

The HSS side, as a `@diameter.on_request` handler builds it:

```python
answer = request.answer(2001)
answer.set_avp("User-Name", private_identity)
answer.set_avp("Public-Identity", public_identity)
answer.set_avp("SIP-Number-Auth-Items", 1)
answer.insert_avp("SIP-Auth-Data-Item", [
    ("SIP-Authentication-Scheme", "SIP Digest"),
    ("SIP-Digest-Authenticate", [
        ("Digest-Realm", realm),
        ("Digest-Algorithm", "MD5"),
        ("Digest-QoP", "auth"),
        ("Digest-HA1", md5_hex(f"{private_identity}:{realm}:{password}")),
        ("Alternate-Digest-Algorithm", "SHA-256"),
        ("Alternate-Digest-HA1", sha256_hex(f"{private_identity}:{realm}:{password}")),
    ]),
])
```

A P-CSCF in front of a SIP Digest client removes the `integrity-protected` the
client sent and writes its own with `auth.set_integrity_protected(request,
value)`: nothing (`None`) on a REGISTER without a challenge response,
`"ip-assoc-pending"` on one with a response and no IP association yet,
`"ip-assoc-yes"` once there is one, and `"tls-pending"` / `"tls-yes"` over TLS
(TS 24.229 clauses 5.2.2.3 and 5.2.2.4).

What the HSS has to carry in the request, and what each of its answers leads
to, is under [Cx: registration](diameter.md#cx-registration).

## `auth` namespace

### Which algorithms a challenge offers

`require_www_digest` / `require_proxy_digest` emit one `WWW-Authenticate` /
`Proxy-Authenticate` header per algorithm in `auth.algorithms`, in that order,
all sharing one nonce (RFC 7616 §3.7 — weakest first, so a legacy MD5-only
client finds its entry and a modern one takes the strongest it supports).

```yaml
auth:
  algorithms: ["MD5", "SHA-256", "SHA-512-256"]   # the default
```

Narrow it for a client population that cannot take a multi-challenge 401. The
RFC's SHOULD assumes a client picks one from the list; some SDKs instead
abandon the registration when a 401 carries more than one `WWW-Authenticate`,
whatever the algorithms are and whatever the order, and there is nothing in the
exchange to fall back to:

```yaml
auth:
  algorithms: ["MD5"]
```

You pay for that in the algorithms you drop, so narrow only as far as the
clients require. Verification is unaffected either way — siphon accepts any
algorithm it can compute, including ones it did not offer.

An unknown name fails the config load rather than being skipped: a silently
dropped entry is a challenge set the operator did not choose, and the
difference does not show up until clients stop registering. An empty list is
refused for the same reason — a 401 carrying no challenge is unanswerable.
`AKAv1-MD5` is refused here too: IMS AKA is network-selected, and its challenge
(with the AKA nonce and `ck=`/`ik=`) comes from `auth.require_aka_digest()` or
`auth.require_ims_digest()`.

### Issuing your own challenge

`require_www_digest` / `require_proxy_digest` build the challenge for you. A
script that verifies credentials itself — rather than through a configured
`auth.backend` — builds its own `WWW-Authenticate` header instead, and needs the
engine's nonce for it:

```python
@proxy.on_request("REGISTER")
def register(request):
    header = request.get_header("Authorization")
    if header is None:
        nonce = auth.generate_nonce()
        request.set_reply_header(
            "WWW-Authenticate",
            f'Digest realm="{realm}", nonce="{nonce}", algorithm=MD5, qop="auth"',
        )
        request.reply(401, "Unauthorized")
        return

    if not auth.validate_nonce(nonce_of(header)):
        return challenge(request)        # stale — re-challenge, do not trust it
    ...
```

`auth.generate_nonce()` mints `{unix_seconds:016x}.{tag}` — the timestamp is
embedded rather than stored, so any instance in a fleet can reject a stale nonce
without shared state. `auth.validate_nonce(nonce)` returns True only for a nonce
this engine minted, no older than `auth.nonce_ttl_secs`, not future-dated beyond
60 s of clock skew, and carrying a matching HMAC tag when `auth.nonce_secret` is
configured.

Validating the nonce is what bounds replay. Without it a captured
`Authorization` is replayable forever, which is why the built-in `verify_digest`
/ `require_*_digest` paths always check it — this pair is for scripts that do
not go through them.

### Verifying against a credential you hold

By default the digest helpers verify against the configured credential source
(`auth.backend`). Pass `password=` or `ha1=` (not both) to verify against a
credential the script supplies instead, which short-circuits the backend lookup
entirely — a deployment that derives credentials in-process then needs no
credential source configured at all, rather than standing up an HTTP endpoint
for siphon to fetch a value the script already has.

```python
@proxy.on_request("REGISTER")
async def register(request):
    secret = await cache.fetch("secrets", derive_key(request))
    if secret is None or not await auth.verify_digest(request, realm, password=secret):
        await auth.require_www_digest(request, realm)
        return
    registrar.save(request)
```

Accepted by `verify_digest`, `require_digest`, `require_www_digest` and
`require_proxy_digest`, on a `Request` or a `Call` alike.

| kwarg | Holds | Trade-off |
|---|---|---|
| `password=` | the plaintext secret | One secret answers MD5, SHA-256 and SHA-512-256, because H(A1) is derived with whatever algorithm the client actually used (RFC 7616 §3.4.3). |
| `ha1=` | an already-computed H(A1) | The deployment never stores plaintext, but the hash is bound to the one algorithm it was computed for — a client answering with another will not verify. |

Passing both raises `ValueError`: one of them would be silently ignored and the
script author could not tell which.

Everything else is unchanged by a supplied credential. The anti-replay nonce
check still runs, so a captured `Authorization` cannot be replayed (RFC 7616
§3.3). A rejection still arms the 401/407 rather than returning a silent
`False`, still counts toward `failed_auth_ban`, and still increments
`siphon_credential_failures_total` — a path that authenticates without counting
would be a blind spot for anyone alerting on brute force.

A *rejection* is the case above: credentials were presented and refused. Two
neighbouring cases score differently, and both used to be conflated with it:

- **No credentials at all.** The RFC 3261 §22.2 opening leg. Counted at
  `failed_auth_ban.missing_credentials_weight`, which is `0` by default, and
  visible in `siphon_auth_failures_total`.
- **The credential source could not answer** — an HTTP auth backend timeout or
  connection failure, or no usable backend configured. Never counted: it says
  nothing about the peer. It increments `siphon_auth_backend_errors_total`,
  which is worth an alert of its own — a non-zero rate means authentication is
  failing into 401s for every subscriber.

See [Hardening & security](../cookbook/security.md) for the full scoring table.

::: siphon_sdk.mock_module.MockAuth

## `ipsec` namespace

P-CSCF IPsec security association management for the sec-agree handshake.

::: siphon_sdk.mock_module.MockIpsec

### When security associations are deleted

A pair is taken into use by `PendingSA.activate()` on the 200 to the REGISTER
that authenticated it. siphon deletes it, with the stream connections between
the protected ports and the UE's (its own are reset), when:

| What happened | When the pair goes |
|---|---|
| A 2xx to a de-REGISTER (`Expires: 0`, or every Contact at `expires=0`) is sent to the UE, relayed or answered by the script, and no live registrar binding was registered over the pair any more | When the server transaction is over: Timer J (64*T1) over UDP, T1 over TCP (TS 24.229 clause 5.2.5.1) |
| The registrar loses the last binding registered over a pair without a de-REGISTER through siphon: the script removed it on a reg-event NOTIFY, or it expired | 64*T1 after the next sweep sees it, so the NOTIFY to the UE still gets through (TS 24.229 clause 5.2.5.2) |
| A re-registration's new pair is activated | The old pair the REGISTER came over after 32 s, for the transactions pending on it; any other old pair at once (TS 33.203 clause 7.4.2a) |
| The script calls `await ipsec.delete(ue_addr, ue_port_c, delay_secs=...)` | After `delay_secs`, or at once |

A pair goes only when no other identity of the UE is still registered over it.

With a single `ipsec.pcscf_port_c`, the old and new pair of a re-registration
share the policies of the UE's protected server port; deleting one leaves the
other's in place, and the shared outbound policy moves to the new pair as the
200 leaves. With a list (`pcscf_port_c: [5064, 5068]`), each new pair takes a
port no other pair of the UE holds (TS 33.203 clause 7.4.0), so nothing is
shared: the 401 goes over the old pair, the 200 over the new, requests to the
UE move to the new pair once a message arrives over it, and the old pair then
goes after 32 s (clause 7.4.2a). If the old pair goes first, the new one is
taken into use.

### After a restart

Security associations live and die with the P-CSCF process that negotiated
them (TS 33.203). siphon never persists IK/CK, SPIs or any other SA material,
so a restart can't reinstall them, even though the registrar bindings come back
from a Redis or PostgreSQL backend. The UE still holds its side of the SAs.

A restored binding that was protected (its REGISTER arrived on
any `ipsec.pcscf_port_c` or `ipsec.pcscf_port_s`) and has no SA pair in the new
process is therefore not restored as live. At startup, before any traffic,
siphon:

- drops it from the registrar and removes it from the backend through the
  normal de-registration path, so the next boot doesn't restore it again (a
  binding another instance accepted on a shared backend leaves only this
  node's memory; its row stays with the instance that holds the SAs);
- logs one warning per binding (AoR, UE address and ports, no key material) and
  counts it in `siphon_registrar_restored_without_sa_total`;
- bars the UE's protected client and server ports from requests in clear until
  the binding would have expired (plus 32 s). Any request that still targets
  one of them while no SA pair covers it is refused at egress, logged at error
  and counted in `siphon_ipsec_unprotected_sends_refused_total`. Responses are
  not barred, and a new SA pair on those ports lifts the bar.

With the binding gone, a terminating request finds no contact and the liveness
sweep has nothing to probe. Recovery is the specified one: the UE's next
protected request goes unanswered, and it performs an initial registration
(TS 24.229 clause 5.1.1.4.1) with fresh AKA and new SAs. To get UEs back
sooner, the network can run P-CSCF restoration (TS 23.380 clause 5); siphon
doesn't implement it.

### `SecurityOffer`

A `Security-Client` offer parsed from a REGISTER (`request.parse_security_client()`).

::: siphon_sdk.mock_module.MockSecurityOffer

### `Transform`

An operator-policy transform choice (`Transform.HmacSha1_96Null`, …).

::: siphon_sdk.mock_module.MockTransform

### `AuthVectorHandle`

The opaque CK/IK container produced by `reply.take_av()`.

::: siphon_sdk.mock_module.MockAuthVectorHandle

### `PendingSA`

An allocated-but-not-yet-active SA pair, returned by `ipsec.allocate(...)`.

::: siphon_sdk.mock_module.MockPendingSA

### `SecurityServerParams`

The `Security-Server` parameters to echo back to the UE.

::: siphon_sdk.mock_module.MockSecurityServerParams

### `SAHandle`

A read-only view of the active SA that decrypted a request
(`request.matched_sa`).

::: siphon_sdk.mock_module.MockSAHandle

## `stir` namespace

STIR/SHAKEN Identity-header signing and verification.

::: siphon_sdk.mock_module.MockStir

### `StirResult`

The outcome of `stir.verify(...)`.

::: siphon_sdk.mock_module.MockStirResult
