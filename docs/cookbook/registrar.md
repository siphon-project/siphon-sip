# Registrar

A SIP registrar accepts `REGISTER`, authenticates the subscriber, and stores their
`Contact` so calls can be routed to them later. This recipe is a registrar that also
proxies calls to the registered contacts.

## Config

```yaml
# siphon.yaml
listen:
  udp: ["0.0.0.0:5060"]
  tcp: ["0.0.0.0:5060"]
domain:
  local: ["example.com"]
script:
  path: "/etc/siphon/registrar.py"

registrar:
  backend: redis            # memory | redis | postgres | python
  redis:
    url: "redis://127.0.0.1:6379"
  default_expires: 3600
  max_expires: 7200

auth:
  realm: "example.com"
  backend: static           # static | http | database | diameter_cx
  # static credentials for a quick start (use http/database in production):
  # credentials:
  #   alice: "secret"
```

`backend: redis` makes the registrar survive a restart — see
[Scaling & redundancy](../scaling-and-redundancy.md) for exactly what that does
(durability + a boot snapshot, not live cross-node sync).

## Script

```python
from siphon import proxy, registrar, auth, log

DOMAIN = "example.com"

@proxy.on_request
def route(request):
    # In-dialog requests follow the established route set.
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    # REGISTER: challenge, then store the contact. registrar.save() also sends
    # the 200 OK with the granted Expires.
    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=DOMAIN):
            return                      # 401 challenge already sent
        request.fix_nated_register()    # rewrite Contact with the observed source
        registrar.save(request)
        return

    # Anything else (INVITE, MESSAGE, …): look up the AoR and route to it.
    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return
    request.record_route()
    request.fork(contacts)              # ring all bindings; first 2xx wins
```

A few things worth knowing:

- **`registrar.save(request)` sends the 200 OK for you** (with the granted Expires,
  clamped by `max_expires`). You don't reply yourself.
- **`request.fork(contacts)`** passes the `Contact` objects (not just `.uri`). For a
  binding this node accepted, that routes over the captured inbound flow — the only
  way to reach a WebSocket UE (RFC 5626 §5.3 connection reuse). Non-local contacts
  fall back to URI routing.
- **`request.fix_nated_register()`** rewrites the Contact with the source the packet
  actually came from, so NAT'd clients are reachable. Pair it with `nat:` config.

## React to registration changes

```python
@registrar.on_change
def on_reg_change(aor, event_type, contacts):
    # event_type: "registered" | "refreshed" | "deregistered" | "expired"
    log.info(f"{aor} {event_type}: {len(contacts)} contact(s)")
```

Use this to push presence, notify an external system, or emit charging events.

## Test it

Register and look up with any SIP client, or with the in-repo
[`sipcli.py`](https://github.com/siphon-project/siphon-sip/blob/main/deploy/ha-demo/sipcli.py):

```bash
python3 deploy/ha-demo/sipcli.py register 127.0.0.1 5060 alice 127.0.0.1 5080
# -> 200
```

If you enabled the admin API (`admin.listen`), confirm the binding over HTTP:

```bash
curl http://127.0.0.1:9091/admin/registrations/sip:alice@example.com
```

## See also

- Real example: [`examples/registrar_proxy.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/registrar_proxy.py) (adds external-API contact notifications) and [`scripts/proxy_default.py`](https://github.com/siphon-project/siphon-sip/blob/main/scripts/proxy_default.py).
- [Stateful proxy](proxy.md) — routing and forking in more depth.
- [Hardening & security](security.md) — auth backends, rate limiting, bans.
