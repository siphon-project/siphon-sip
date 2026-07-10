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
