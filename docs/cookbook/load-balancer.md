# Load balancer

A front-facing proxy that spreads new transactions across a pool of backends, with
health probing and (optionally) subscriber affinity. SIPhon's `gateway` namespace is
the equivalent of OpenSIPS `dispatcher` / Kamailio `dispatcher`.

## Config

Define a named group of destinations with a balancing algorithm and health probe:

```yaml
# siphon.yaml
script:
  path: "/etc/siphon/lb.py"

gateway:
  groups:
    - name: "backends"
      algorithm: hash         # weighted (default) | round_robin | hash
      probe:
        enabled: true
        interval_secs: 5
        failure_threshold: 3
      destinations:
        - uri: "sip:backend1.example.com:5060"
          address: "10.0.0.1:5060"
          weight: 2
          attrs: { region: "us-east" }
        - uri: "sip:backend2.example.com:5060"
          address: "10.0.0.2:5060"
```

- **`weighted`** — weighted round-robin (the default).
- **`round_robin`** — even rotation, ignores weight.
- **`hash`** — consistent hash on a `key` you provide → sticky routing.

## Script

```python
from siphon import proxy, gateway, log

@proxy.on_request
def route(request):
    # In-dialog requests follow the established route set, not the LB.
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    # Pick a healthy backend. key= gives subscriber affinity: the same AoR
    # always hashes to the same backend (needed if that backend holds the
    # subscriber's registrar binding).
    destination = gateway.select("backends", key=str(request.to_uri))
    if not destination:
        log.error("no healthy backend in 'backends' group")
        request.reply(503, "Service Unavailable")
        return

    log.info(f"LB {request.method} {request.to_uri} -> {destination.uri}")
    request.record_route()
    request.relay(destination.uri)
```

### Selecting backends

```python
gw = gateway.select("backends")                          # next per algorithm
gw = gateway.select("backends", key=request.call_id)     # sticky on Call-ID
gw = gateway.select("backends", attrs={"region": "us-east"})  # filter by attribute

gw.uri        # "sip:backend1.example.com:5060"
gw.healthy    # bool
bool(gw)      # True if healthy
```

Health is probed per node (`probe.enabled`), and you can override it from a script
(`gateway.mark_down` / `mark_up`) or build groups dynamically
(`gateway.add_group` / `remove_group`).

## Why affinity matters

Registrar lookups are node-local (see
[Scaling & redundancy](../scaling-and-redundancy.md)), so a subscriber can only be
reached for a terminating call on the node that holds their binding. Hashing both the
REGISTER and the terminating INVITE for an AoR (`key=str(request.to_uri)`) sends both
to the same backend — any-node delivery with no shared live state. For pure outbound
(PSTN breakout) where there's no registrar lookup, drop the key and use
`algorithm: weighted`.

## Runnable example

A complete front-LB + two-backend + Redis demo (with a failover proof) lives in
[`deploy/ha-demo/`](https://github.com/siphon-project/siphon-sip/tree/main/deploy/ha-demo):

```bash
SIPHON_BIN=target/release/siphon deploy/ha-demo/validate.sh
```

## See also

- Real example: [`examples/proxy_gateway.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/proxy_gateway.py), [`deploy/ha-demo/lb.py`](https://github.com/siphon-project/siphon-sip/blob/main/deploy/ha-demo/lb.py).
- [Deployment & operations](../deployment.md) — front-LB + DNS SRV topologies, K8s.
- [SBC (B2BUA)](sbc.md) — load-balance *and* hide topology / anchor media.
