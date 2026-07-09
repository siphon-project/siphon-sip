# Python API reference

This section is the complete reference for the `siphon` Python module that
SIPhon injects into your scripts at runtime — every namespace, object,
property, and method a handler can touch.

It is generated directly from the docstrings and type annotations of the
[`siphon-sip`](https://pypi.org/project/siphon-sip/) package (import name
`siphon_sdk`), a pure-Python mock of the `siphon` module. The mock mirrors the
Rust engine's API one-for-one and is the single source of truth for these
signatures, so what you read here is exactly what runs in production.

The mock package doubles as a testing and authoring aid:

```bash
pip install siphon-sip
```

- **Unit-test your scripts** without the Rust binary — the
  [test harness](testing.md) simulates incoming SIP messages and captures the
  actions your handlers take (reply, relay, fork, reject, …) so you can assert
  on them with pytest.
- **Author scripts with an LLM** — every method carries rich docstrings and
  type hints, so `pip install siphon-sip` gives a model enough context to
  generate correct SIPhon scripts.

At runtime you never construct these objects yourself; the engine hands them to
your handlers. Import the namespaces you need:

```python
from siphon import proxy, registrar, b2bua, auth, log, cache
from siphon import gateway, cdr, diameter, presence, li, registration
from siphon import timer, metrics, sdp, sbi, ipsec, rtpengine, isc
```

## How this reference is organised

| Page | What it covers |
| ---- | -------------- |
| [Request](request.md) | The inbound SIP request passed to `@proxy.on_request` handlers |
| [Reply](reply.md) | The response object passed to `@proxy.on_reply` / `@proxy.on_failure` |
| [Call](call.md) | The B2BUA call object and its media handle |
| [SDP](sdp.md) | The `sdp` namespace, parsed SDP bodies, and media sections |
| [SIP types](types.md) | `SipUri`, `Contact`, `Flow`, and the captured `Action` record |
| [Proxy & B2BUA](proxy.md) | Routing handlers, forking, and subscription-dialog state |
| [Registrar](registrar.md) | Location service plus outbound trunk registration |
| [Auth & security](security.md) | Digest / IMS-AKA auth, IPsec sec-agree, STIR/SHAKEN |
| [Media](media.md) | RTPEngine media control and the QoS SDP-to-flow helper |
| [Gateway](gateway.md) | Health-probed destination groups and load balancing |
| [Diameter](diameter.md) | Cx / Rx / Sh / Rf interfaces and inbound-request handling |
| [IMS control](ims.md) | iFC evaluation, SBI/N5, presence, lawful intercept, SRS |
| [Observability](observability.md) | Logging, cache, CDR, custom metrics, timers |
| [Testing harness](testing.md) | The pytest harness and its result objects |

!!! note "Extension namespaces"
    The `smpp` and `http` namespaces come from the optional
    [SMPP](https://smpp.siphon-sip.org/) and [HTTP](https://http.siphon-sip.org/)
    addon crates and are documented on their own addon sites.
