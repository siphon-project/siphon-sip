# Extensions (SMPP, HTTP)

SIPhon's core speaks SIP. Protocol functionality **beyond SIP** — SMPP and HTTP
today — is provided by **opt-in extension modules**. They
are not part of the default binary: you enable a module at build time and
configure it through the `extensions:` block in `siphon.yaml`. Each module adds
a scriptable Python namespace your routing scripts can use, alongside the
built-in `proxy`, `registrar`, `cache`, and friends.

## How extensions work

- **Off by default.** The standard `siphon` binary (`cargo install siphon-sip`
  or the default container image) contains no extensions.
- **Enabled at build.** An extension-capable build is produced by the
  [`siphon-bin`](https://github.com/siphon-project/siphon-sip/tree/main/siphon-bin)
  package with the module's cargo feature turned on (e.g. `--features smpp`). It
  is a drop-in `siphon` binary — same CLI, same `siphon.yaml`, plus the module.
- **Configured in `siphon.yaml`.** An `extensions:` map points each enabled
  module at its own config file:

  ```yaml
  extensions:
    smpp: /etc/siphon/smpp.yaml
  ```

- **Loud on mismatch.** If `extensions.smpp` is configured but the running
  binary was *not* built with that feature, siphon logs a warning and skips the
  module — it never silently ignores configuration. (This mirrors the optional
  `sctp` transport feature.)

## SMPP (SMS, SMPP 3.4)

The SMPP extension turns siphon into a scriptable SMPP node — it accepts ESME
binds and can hold outbound binds to upstream SMSCs. Your script decides policy;
siphon handles the wire protocol, sessions, timers, and windowing.

### 1. Build with the feature

```bash
# Native binary
cargo build -p siphon-bin --release --features smpp

# …or a container image (mount your config + script at runtime)
docker build -f siphon-bin/Dockerfile -t siphon-smpp siphon-bin/
```

### 2. Point siphon at the SMPP config

```yaml
# siphon.yaml
extensions:
  smpp: /etc/siphon/smpp.yaml
```

The `smpp.yaml` schema (inbound listener, outbound binds, routing) is documented
in the siphon-smpp repository.

### 3. Handle PDUs in your script

```python
from siphon import smpp, log

@smpp.on_bind
async def authorise(bind):
    log.info(f"bind from {bind.system_id}")
    return bind.accept()

@smpp.on_pdu("submit_sm")
async def handle(pdu, session):
    log.info(f"{pdu.source_addr} -> {pdu.destination_addr}")
    # ...route / persist / throttle...
    return pdu.reply(message_id="abc123")
```

Scripts hot-reload exactly like the SIP side — edit and the next PDU uses the new
code.

### Further reading

The full `smpp` namespace (PDU types, bind handling, outbound `submit`/`deliver`,
delivery receipts), the complete `smpp.yaml` schema, and deployment examples live
in the **siphon-smpp** docs and repository:

- 📖 Documentation: <https://smpp.siphon-sip.org/>
- 💻 Source: <https://github.com/siphon-project/siphon-smpp>

## HTTP (route serving + outbound client)

The HTTP extension lets routing scripts **serve** inbound HTTP (`@http.route`)
and **call out** (`http.Client`) from the same asyncio loop they use for SIP —
useful for webhooks, health/readiness endpoints, small REST surfaces, and
provisioning callbacks. The server is axum + rustls (HTTP/1.1 and HTTP/2, TLS and
mutual TLS); the client is pooled reqwest.

!!! tip "Enable it for the client alone — even if you never serve a route"
    If a script makes **outbound** HTTP calls on the hot path (a REST lookup per
    INVITE, a provisioning callback, an auth token refresh), enable the `http`
    feature and use `http.Client` rather than reaching for a pure-Python library
    (`requests` / `httpx` / `urllib`). With `http.Client` the entire round-trip
    runs **in Rust** on siphon's Tokio runtime — connection pooling, TLS, and
    HTTP/1.1 + HTTP/2 framing — and each call is a real awaitable that **hands the
    asyncio driver loop back** while the request is in flight, so the driver keeps
    dispatching other handlers. A **synchronous** Python client instead does the
    protocol work in the interpreter and **blocks its driver loop for the whole
    round-trip**, stalling every other handler that shares it. Same pooled client
    across calls, no per-call setup:

    ```python
    from siphon import http, proxy

    api = http.Client("api")           # named, pooled — construct once, reuse

    @proxy.on_request("INVITE")
    async def screen(request):
        verdict = await api.get(f"/screen/{request.from_uri.user}")
        if verdict.status != 200:
            request.reply(403, "Blocked")
            return
        request.relay()
    ```

    You do **not** need to declare an `http.servers` listener to use the client —
    an `http.yaml` with only a `clients:` block is enough.

### 1. Build with the feature

```bash
cargo build -p siphon-bin --release --features http
```

### 2. Point siphon at the HTTP config

```yaml
# siphon.yaml
extensions:
  http: /etc/siphon/http.yaml
```

### 3. Serve routes in your script

```python
from siphon import http

@http.route("/healthz")
def healthz(req):
    return http.Response(status=200, body=b"ok")

@http.route("/users/{id}", methods=["GET"])
async def get_user(req):
    async with http.Client("api") as client:
        upstream = await client.get(f"/v1/users/{req.path_params['id']}")
    return http.Response(status=upstream.status, body=upstream.body)
```

### Further reading

The full `http` namespace (`Request`/`Response`/`Client`, middleware, startup
hooks, path/query params, TLS/mTLS), the `http.yaml` schema, and examples live in
the **siphon-http** docs and repository:

- 📖 Documentation: <https://http.siphon-sip.org/>
- 💻 Source: <https://github.com/siphon-project/siphon-http>

## Testing extension scripts

The [`siphon-sip` SDK](https://pypi.org/project/siphon-sip/) (`pip install
siphon-sip`) ships mocks and pytest harnesses for the extension namespaces
alongside the SIP ones, so you can unit-test SMPP and HTTP scripts without a
running SMSC or listener — and get type hints / docstrings while authoring:

```python
from siphon_sdk.smpp_testing import SmppTestHarness
from siphon_sdk.http_testing import HttpTestHarness

def test_submit_sm():
    h = SmppTestHarness()
    h.load_script("scripts/gateway.py")
    assert h.bind("esme1", password="s3cret")
    reply = h.submit_sm(source_addr="15550100", destination_addr="15550101",
                        short_message=b"hi")
    assert reply.ok

def test_healthz():
    h = HttpTestHarness()
    h.load_script("scripts/api.py")
    assert h.request("GET", "/healthz").body == b"ok"
```

## Available modules

| Module | Feature | Status | Namespace | Docs |
| --- | --- | --- | --- | --- |
| SMPP 3.4 | `smpp` | Available | `smpp` | [smpp.siphon-sip.org](https://smpp.siphon-sip.org/) |
| HTTP / HTTPS | `http` | Available | `http` | [http.siphon-sip.org](https://http.siphon-sip.org/) |
