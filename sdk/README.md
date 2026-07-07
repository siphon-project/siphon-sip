<p align="center">
  <img src="https://raw.githubusercontent.com/siphon-project/siphon-sip/main/assets/logo.svg" alt="SIPhon" width="100">
</p>

# siphon-sip

Mock library and type stubs for [SIPhon](https://github.com/siphon-project/siphon-sip) scripts — enables unit testing without the Rust binary and provides rich context for LLM-assisted script authoring.

## Install

```bash
pip install siphon-sip
```

> The PyPI distribution is **`siphon-sip`** (matching the `siphon-sip` crate). The import package is still **`siphon_sdk`** — `from siphon_sdk import …`.

## What is SIPhon?

SIPhon is a high-performance SIP proxy, B2BUA, and IMS platform written in Rust with Python scripting. Scripts use decorators to handle SIP events:

```python
from siphon import proxy, registrar, auth, log

@proxy.on_request
def route(request):
    if request.method == "REGISTER":
        if not auth.require_digest(request, realm="example.com"):
            return
        registrar.save(request)
        request.reply(200, "OK")
        return

    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return

    request.record_route()
    request.fork([c.uri for c in contacts])
```

This SDK lets you **test** these scripts with pytest — no Rust binary needed.

## Quick start

```python
from siphon_sdk.testing import SipTestHarness
from siphon_sdk.types import Contact

harness = SipTestHarness(local_domains=["example.com"])
harness.load_script("scripts/proxy_default.py")

# Pre-populate the registrar
harness.registrar.add_contact(
    "sip:alice@example.com",
    Contact(uri="sip:alice@192.168.1.5:5060"),
)

# Test REGISTER challenge
result = harness.send_request("REGISTER", "sip:alice@example.com",
                              from_uri="sip:alice@example.com")
assert result.status_code == 401  # digest challenge

# Test INVITE routing
result = harness.send_request("INVITE", "sip:alice@example.com")
assert result.action == "fork"
assert "sip:alice@192.168.1.5:5060" in result.targets
```

## Testing B2BUA scripts

```python
harness = SipTestHarness()
harness.load_script("scripts/b2bua_default.py")

harness.registrar.add_contact(
    "sip:bob@example.com",
    Contact(uri="sip:bob@10.0.0.2:5060"),
)

result = harness.send_invite(ruri="sip:bob@example.com")
assert result.action == "fork"
assert result.targets == ["sip:bob@10.0.0.2:5060"]

# Test BYE handling
result = harness.send_bye(initiator_side="a")
assert result.was_terminated
```

## Testing extension scripts (SMPP, HTTP)

The opt-in [siphon extensions](https://siphon-sip.org/extensions/) inject extra
namespaces (`smpp`, `http`) at runtime. The SDK mocks them too, with dedicated
harnesses, so extension scripts are testable from the same `pip install
siphon-sip` — no running SMSC or HTTP listener required:

```python
from siphon_sdk.smpp_testing import SmppTestHarness

harness = SmppTestHarness()
harness.load_script("scripts/gateway.py")
assert harness.bind("esme1", password="s3cret")
reply = harness.submit_sm(source_addr="15550100", destination_addr="15550101",
                          short_message=b"hi")
assert reply.ok
```

```python
from siphon_sdk.http_testing import HttpTestHarness
from siphon_sdk.http import MockResponse

harness = HttpTestHarness()
harness.add_response(MockResponse(status=200, body=b'{"ok":true}'))
harness.load_script("scripts/api.py")

resp = harness.request("GET", "/users/42")
assert resp.status == 200
```

## Inline scripts

Test scripts without separate files:

```python
harness = SipTestHarness()
harness.load_source("""
from siphon import proxy

@proxy.on_request
def route(request):
    if request.source_ip_in(["10.0.0.0/8"]):
        request.relay()
    else:
        request.reply(403, "Forbidden")
""")

result = harness.send_request("INVITE", "sip:bob@host", source_ip="10.1.2.3")
assert result.was_relayed

result = harness.send_request("INVITE", "sip:bob@host", source_ip="8.8.8.8")
assert result.status_code == 403
```

## Async handlers + RTPEngine

```python
harness = SipTestHarness()
harness.load_source("""
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    if request.method == "INVITE" and request.body:
        await rtpengine.offer(request, profile="srtp_to_rtp")
    request.relay()
""")

result = harness.send_request("INVITE", "sip:bob@host",
                              body=b"v=0\\r\\n...",
                              content_type="application/sdp")
assert result.was_relayed
assert harness.rtpengine.operations == [("offer", "srtp_to_rtp")]
```

## Controlling mock behavior

```python
# Auth: allow or deny all
harness.auth._allow = True  # all auth checks pass

# Rate limiting
harness.proxy._utils._rate_limit_allow = False  # simulate overload

# Cache: pre-populate
harness.cache.set_data("cnam", {"key": "value"})

# Registrar: add contacts directly
harness.registrar.add_contact("sip:alice@host", Contact(uri="sip:alice@1.2.3.4"))

# Log: inspect captured messages
assert any("error" in msg for level, msg in harness.log.messages)

# Reset between tests
harness.reset()
```

## Result assertions

`RequestResult` provides convenient properties:

| Property | Description |
|----------|-------------|
| `.action` | Primary action: `"reply"`, `"relay"`, `"fork"`, `"silent_drop"` |
| `.status_code` | SIP status code (200, 401, 404, etc.) |
| `.reason` | Reason phrase |
| `.targets` | Fork targets list |
| `.strategy` | Fork strategy (`"parallel"` / `"sequential"`) |
| `.was_relayed` | `True` if `relay()` was called |
| `.was_forked` | `True` if `fork()` was called |
| `.was_dropped` | `True` if handler returned without action (silent drop) |
| `.record_routed` | `True` if `record_route()` was called |
| `.request` | The mock `Request` object for header inspection |

## API reference

### Namespaces

| Import | Description |
|--------|-------------|
| `proxy` | Stateful/stateless proxy decorators and utilities |
| `registrar` | Address-of-record contact store |
| `auth` | SIP digest authentication |
| `b2bua` | Back-to-back user agent call control |
| `log` | Structured logging |
| `cache` | Named cache (local LRU + Redis) |
| `rtpengine` | RTPEngine media proxy operations |
| `gateway` | Destination groups, load balancing, health probing |
| `cdr` | Call detail records |
| `diameter` | Diameter protocol (Cx, Ro, Rx, Rf, Sh) |
| `presence` | SUBSCRIBE/NOTIFY, PIDF presence |
| `li` | Lawful intercept (ETSI X1/X2/X3, SIPREC) |
| `registration` | Outbound REGISTER client (trunk registration) |

### Request properties

| Property | Type | Description |
|----------|------|-------------|
| `method` | `str` | SIP method (`"INVITE"`, `"REGISTER"`, etc.) |
| `ruri` | `SipUri` | Request-URI |
| `from_uri` | `SipUri \| None` | From header URI |
| `to_uri` | `SipUri \| None` | To header URI |
| `from_tag` | `str \| None` | From-tag |
| `to_tag` | `str \| None` | To-tag (`None` for initial requests) |
| `call_id` | `str \| None` | Call-ID |
| `cseq` | `(int, str) \| None` | CSeq tuple |
| `in_dialog` | `bool` | Both tags present |
| `max_forwards` | `int` | Max-Forwards value |
| `body` | `bytes \| None` | Message body |
| `content_type` | `str \| None` | Content-Type |
| `transport` | `str` | `"udp"`, `"tcp"`, `"tls"`, `"ws"`, `"wss"` |
| `source_ip` | `str` | Sender IP |
| `auth_user` | `str \| None` | Authenticated username |
| `event` | `str \| None` | Event header |

### Request methods

| Method | Description |
|--------|-------------|
| `reply(code, reason)` | Send SIP response |
| `relay(next_hop=None)` | Forward to destination |
| `fork(targets, strategy="parallel")` | Fork to multiple targets |
| `record_route()` | Insert Record-Route |
| `loose_route() -> bool` | RFC 3261 loose routing |
| `get_header(name) -> str \| None` | Get header value |
| `set_header(name, value)` | Set header |
| `remove_header(name)` | Remove header |
| `has_header(name) -> bool` | Check header exists |
| `has_body(content_type) -> bool` | Check body type |
| `set_ruri_user(value)` | Set R-URI user part |
| `set_ruri_host(value)` | Set R-URI host |
| `source_ip_in(cidrs) -> bool` | CIDR membership check |
| `generate_icid() -> str` | Generate charging ID |
| `add_path(uri)` | Prepend Path header |
| `prepend_route(uri)` | Prepend Route header |
| `fix_nated_register()` | NAT fixup for REGISTER |
| `fix_nated_contact()` | NAT fixup for Contact |

### Registrar

| Method | Description |
|--------|-------------|
| `save(request, force=False)` | Save REGISTER bindings |
| `lookup(uri) -> list[Contact]` | Look up contacts (sorted by q-value) |
| `is_registered(uri) -> bool` | Check if URI has contacts |
| `service_route(uri) -> list[str]` | Get stored service routes (RFC 3608) |
| `set_service_routes(aor, routes)` | Store service routes for an AoR |
| `save_pending(request)` | IMS: save binding in pending state |
| `confirm_pending(uri)` | IMS: promote pending to active after SAR |
| `asserted_identity(uri) -> str \| None` | IMS: stored P-Asserted-Identity |
| `reginfo_xml(aor, state, version) -> str` | Generate reginfo XML (RFC 3680) |
| `on_change` | Decorator: fires on registration state changes |

### Auth

| Method | Description |
|--------|-------------|
| `require_www_digest(request, realm) -> bool` | 401 challenge |
| `require_proxy_digest(request, realm) -> bool` | 407 challenge |
| `require_digest(request, realm) -> bool` | Alias for www_digest |
| `verify_digest(request, realm) -> bool` | Verify without challenge |
| `require_ims_digest(request, realm) -> bool` | IMS AKA via Diameter Cx MAR |
| `require_aka_digest(request, realm) -> bool` | Local Milenage AKA (no HSS) |

### B2BUA call

Each B-leg gets a fresh Call-ID and From-tag by default, fully decoupling the two SIP dialogs. Use `keep_call_id()` to opt out of Call-ID regeneration.

| Property/Method | Description |
|----------------|-------------|
| `call.id` | UUID |
| `call.state` | `"calling"`, `"ringing"`, `"answered"`, `"terminated"` |
| `call.from_uri` | A-leg From URI |
| `call.ruri` | A-leg Request-URI |
| `call.reject(code, reason)` | Reject call |
| `call.dial(uri, timeout=30)` | Dial single target |
| `call.fork(targets, strategy, timeout)` | Fork to multiple |
| `call.terminate()` | End call (BYE both legs) |
| `call.keep_call_id()` | Copy A-leg Call-ID to B-leg (From-tag always unique) |
| `call.set_credentials(user, pass)` | B-leg digest auth credentials (auto 401/407 retry) |
| `call.media.anchor(engine)` | Anchor media through RTPEngine |
| `call.media.release()` | Release media anchor |
| `call.session_timer(expires, min_se, refresher)` | Per-call RFC 4028 session timer |
| `call.record(srs_uri)` | Start SIPREC recording |
| `call.stop_recording()` | Stop SIPREC recording |

## License

MIT
