# Auth & security

Authentication and the security-agreement machinery: SIP digest and IMS-AKA
challenges, P-CSCF IPsec sec-agree (3GPP TS 33.203 / RFC 3329), and
STIR/SHAKEN signing and verification.

```python
from siphon import auth

@proxy.on_request("INVITE")
def route(request):
    if not auth.verify_digest(request, "example.com"):
        auth.require_proxy_digest(request, "example.com")
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
def new_call(call):
    if not auth.require_proxy_digest(call, realm="example.com"):
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
def register(request):
    if not auth.verify_digest(request, realm="example.com"):
        auth.require_www_digest(request, realm="example.com")
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
path.

## `auth` namespace

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
    if secret is None or not auth.verify_digest(request, realm, password=secret):
        auth.require_www_digest(request, realm)
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

::: siphon_sdk.mock_module.MockAuth

## `ipsec` namespace

P-CSCF IPsec security association management for the sec-agree handshake.

::: siphon_sdk.mock_module.MockIpsec

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
