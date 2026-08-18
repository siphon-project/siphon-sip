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

`require_ims_digest` and `require_aka_digest` take a `Request` only — IMS and
AKA digest are REGISTER-time procedures, and REGISTER never reaches the B2BUA
path.

## `auth` namespace

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
