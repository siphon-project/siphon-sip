# IMS multi-UE (many handsets, one process)

One siphon process registering many IMS UEs, each from its own address. Every
UE is an outbound registration doing IMS-AKA over IPsec sec-agree
(3GPP TS 33.203) towards a P-CSCF, exactly as a single soft-UE does, except
that each one has its own `local_addr`: its Via and Contact host, the source of
its REGISTERs and the UE side of its four SAs. A plain-SIP tester then calls
through any of them, both ways.

```
                      siphon (one process)
tester  <--SIP-->  198.51.100.2:5060 (process listener)
                   203.0.113.11:{5060,6100,6101}  UE 1  <--IPsec-->  P-CSCF
                   203.0.113.12:{5060,6100,6101}  UE 2  <--IPsec-->  P-CSCF
                   ...
```

The runnable example is
[`examples/ims_multi_ue.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/ims_multi_ue.py)
with [`examples/ims_multi_ue.yaml`](https://github.com/siphon-project/siphon-sip/blob/main/examples/ims_multi_ue.yaml).
For a single UE on the process's own address, see
[`examples/ims_ue_b2bua.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/ims_ue_b2bua.py).

## Addresses and sockets

Each UE needs five UDP sockets on its address: the plain port (the first
`listen.udp` port, 5060 by default), and with IPsec its three protected client
ports (`ue_port_c` and the two above it, rotated through as re-authentication
replaces SA sets, TS 33.203 7.4.0) and its protected server port. siphon opens them itself at run time and closes them when the
entry moves or goes. They are bound with `IP_FREEBIND`, so an address does not
have to be on the host when it is configured; until it is, sends from it fail
in the kernel (siphon never spoofs a source), the REGISTER times out at
Timer F (32 s), the entry goes `failed` with backoff, and the process carries
on. The socket set is reconciled on every registrant tick, and a failed bind
is logged once.

So `listen.udp` only names the process's own listener. A `listen.udp` entry
on the exact address and port of a UE is used instead of a run-time socket
(static wins), which is how a deployment can pin one.

The protected ports may repeat across UEs, as they do across real handsets:
the kernel tells the SAs apart by address. Two entries may not share
`(local_addr, ue_port_c)`.

Requirements:

- the top-level `ipsec:` block (it enables the IpsecManager the UE-side SAs go
  through) and `CAP_NET_ADMIN`;
- a descriptor limit above three per UE plus the base set;
- with a P-CSCF on the same kernel, a different `ipsec.spi_range_start` on one
  of the two: the UE side allocates SPIs from 50000 upwards.

## Config

```yaml
listen:
  udp:
    - "198.51.100.2:5060"        # the process's listener only

ipsec:
  backend: netlink

registrant:
  refresh_window: [0.4, 0.6]     # refresh at 40-60 % of the grant, per refresh
  max_registers_per_sec: 20      # cap on new REGISTERs per second
  event_capacity: 4096           # script-added entries are not counted
  entries:                       # or add them from the script, as below
    - aor: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
      registrar: "sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org:5060"
      user: "001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
      auth: aka
      aka: { k: "465b5ce8b199b49faa5f0a2ee238a6bc", opc: "cd63cb71954a9f4e48a5994e37a02baf" }
      ipsec: { ue_port_c: 6100, ue_port_s: 6101 }
      ims: { imei: "01234567-000001-0", features: [mmtel, smsip] }
      local_addr: "203.0.113.11"
```

- **`refresh_window`** spreads refreshes. A fleet registered in the same
  second with a fixed half-Expires refresh stays in lockstep for ever; a
  window draws each refresh uniformly between `low` and `high` of the granted
  Expires. Default `[0.5, 0.5]`, the old fixed half. An entry may override it.
- **`max_registers_per_sec`** caps how many REGISTERs (initial, refresh and
  retry) start in any one-second window, so a restart or a mass move does not
  hit the P-CSCF with the whole fleet at once. The REGISTER answering a 401 is
  never held back, so a challenge in flight always completes. With a cap the
  loop ticks every 200 ms instead of 5 s and starts the longest-overdue
  entries first.
- **`event_capacity`** sizes the state-change buffer behind
  `@registration.on_change` and the control plane's `RegistrantChanged`. The
  default is the larger of 1024 and four per configured entry; entries added by
  a script are not in that count, so set it for the fleet. A consumer that
  falls behind gets a `snapshot` instead of the lost events.

## The script

The example keeps its UE list as constant data (an inline tuple, or a CSV in
`$MULTI_UE_CSV`) and holds no other state: the entries live in `registration`.
On load and every 10 s it adds the UEs that have no entry and restates every
UE's current address:

```python
from siphon import b2bua, registration, timer, log

def _sync():
    for row in _load_ues():
        impu = row["impu"]
        address = row.get("address") or None
        if registration.status(impu) is None:
            registration.add(impu, PCSCF, user=row["impi"], auth="aka",
                             k=row["k"], opc=row.get("opc") or None,
                             ipsec=True, ue_port_c=6100, ue_port_s=6101,
                             imei=row.get("imei") or None,
                             ims_features=["mmtel", "smsip"],
                             local_addr=address, require_local_addr=True)
        else:
            registration.set_local_addr(impu, address)

_sync()

@timer.every(seconds=10, name="multi_ue_sync")
def sync_addresses():
    _sync()
```

`set_local_addr` is idempotent: restating the address a UE already has
changes nothing. A real move deletes the old SA pair and starts a fresh
registration from the new address (same Call-ID). An empty address puts the UE
in `awaiting_address` because of `require_local_addr=True`; without it, the
entry would fall back to the process's address.

**MT** (IMS to tester): the INVITE arrives on one of the per-UE sockets, so the
address it arrived on names the UE that was called:

```python
@b2bua.on_invite
def on_invite(call):
    flow = call.flow
    called = registration.find_by_local(flow.local_addr) if flow is not None else None
    if called is not None:
        call.dial(TESTER, timeout=30)
        return
    ...
```

**MO** (tester to IMS): the tester's INVITE lands on the process's listener,
and its From userpart picks the UE. The B-leg rides that UE's SA:

```python
    impu = _impu_for_user(call.from_uri.user)
    flow = registration.flow(impu)           # defaults to the entry's address
    # A UE's route set: the P-CSCF's protected URI, then the Service-Route
    # (TS 24.229 5.1.2A.1.1).
    route = [f"<sip:{flow.remote_addr};lr>"] + registration.service_route(impu)
    call.set_header("P-Preferred-Identity", f"<{impu}>")
    call.dial(f"sip:{call.ruri.user}@{HOME}", flow=flow, route=route,
              header_policy="ims-intra-trust-domain@2026",
              copy=["P-Preferred-Identity"])
```

The INVITE leaves from the UE's protected client port to the P-CSCF's
protected server port, inside the SA, and carries the route set as Route
headers in order. A `registration.flow()` is the UE's own flow to its first
hop, so the route set rides it. A callee's flow (`contact.flow`) is the
opposite case: there `route=` is the binding's Path and replaces the flow
(RFC 3327 §5.3).

**Requests outside a call** take the same flow and route set. A MESSAGE (an MO
SMS over IP, or the RP-ACK a UE sends back for an MT one, TS 24.341):

```python
    reply = await proxy.send_request(
        "MESSAGE", f"sip:{dialled}@{HOME}", body=rpdu,
        headers={"From": f"<{impu}>", "To": f"<sip:{dialled}@{HOME}>",
                 "Content-Type": "application/vnd.3gpp.sms"},
        flow=flow, route=route, wait_for_response=True)
```

and the UE's subscription to its own reg event (TS 24.229 5.1.1.3), whose
refreshes and unsubscribe follow the subscription over the SA:

```python
@registration.on_change
async def on_registration_change(aor, event_type, state):
    if event_type != "registered":
        return
    flow = registration.flow(aor)
    handle = await proxy.subscribe_state.send(
        aor, event="reg", expires=600000, accept="application/reginfo+xml",
        headers={"From": f"<{aor}>"},
        flow=flow, route=[f"<sip:{flow.remote_addr};lr>"] + registration.service_route(aor))
    # later: await handle.refresh(), await handle.terminate()
```

Each request leaves from the UE's protected client port to the P-CSCF's
protected server port, its Via (and a SUBSCRIBE's Contact) naming the UE's
protected server port, with the route set as Route headers. A refresh or an
unsubscribe looks the registration up again and goes over the SA set it holds
then, since a re-registration replaces the set; when the registration has no
SA left it raises instead of sending outside one. `subscribe_state.send`
refuses a callee's flow. `proxy.send_request` takes one too and treats it as
`call.dial` does: it is the destination with no route set, and yields to one.

**Answers to the P-CSCF's requests** (a 200 to an MT MESSAGE, to a NOTIFY, to
an MT INVITE) arrive on the UE's protected server port and leave, over UDP,
from the UE's protected client port to the P-CSCF's protected server port
(TS 33.203 clause 7.1).

An MT request answered on a per-UE socket carries that socket's address in its
Contact and Via, not `advertised_address`, and the per-UE addresses count as
this node when siphon consumes Route entries.

## Watching the fleet

```python
counts = registration.counts()   # {"registered": 980, "failed": 3, "awaiting_address": 17, ...}
for entry in registration.list():
    entry["local_addr"], entry["failure_count"], entry["last_failure_status"]
```

`@registration.on_change` reports `awaiting_address` as an event when a UE
loses its address. The control plane carries the same state and event values
in `RegistrantChanged` and `outbound_registrations`.

## Limits

- **UDP only.** A `local_addr` on a `tcp` or `tls` entry is refused at load
  and by `registration.add`.
- **A move does not de-register the old binding.** The old address is usually
  gone already. A registrar keying on `+sip.instance` (RFC 5626, built from
  `imei`) replaces the binding; any other lets it lapse at its Expires.
- **Refreshes ride the SAs.** A registered UE re-registers over its SA set,
  and a re-challenge sets up the new set beside the old one before deleting it
  (see the registrar reference, "Protected re-registration").
  `registration.remove()` de-registers over the set and then deletes it.
- **The Contact port is the plain UDP port**, the same for every UE, as for a
  single UE.
- **Not yet validated against a live IMS core.** The behaviour is unit and
  integration tested, and `scripts/multi_ue_netns.sh` is a manual acceptance
  harness (root, network namespaces) that runs this example against a siphon
  P-CSCF and S-CSCF.

## Trying it in network namespaces

```bash
sudo -E N=20 scripts/multi_ue_netns.sh            # add CALL_TEST=1 for a call
```

It builds two namespaces joined by a veth pair, puts N /32s from
203.0.113.0/24 on a dummy interface in the UE namespace, runs
`examples/ims_pcscf.py` and `examples/ims_scscf_aka_lab.py` in the core
namespace, and checks that every UE registers, that there are 4 x N xfrm
states, that the S-CSCF holds N distinct contacts, that refreshes spread over
the window, and that moving every /32 and rewriting the address file
re-registers the fleet with no restart. It prints the UE process's descriptor
count and RSS.
