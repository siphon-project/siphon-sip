# Diameter

The `diameter` namespace exposes the IMS Diameter interfaces — Cx (HSS),
Rx (PCRF), Sh (HSS AS), and Rf (offline charging) — plus a unified inbound
`@diameter.on_request` hook for serving requests (RAR, PNR, ASR, …).

```python
from siphon import diameter

@diameter.on_request
async def handle(request):
    if request.command_name == "RAR":
        return request.answer(2001)
    return request.reject(3002)
```

### What siphon answers when the handler does not

A request the script does not answer itself gets one of three codes, and they
are meant to be distinguishable at the peer:

| Result-Code | When |
|---|---|
| `3002` DIAMETER_UNABLE_TO_DELIVER | Nothing serves the request: no `@diameter.on_request` matched its application and command, or the handler that matched returned `None`. |
| `5012` DIAMETER_UNABLE_TO_COMPLY | siphon has a handler and could not carry it out: it raised, returned something that is not a `DiameterAnswer`, or produced an answer that would not serialize. Logged at `error` with the handler's name and the exception. |
| `5014` DIAMETER_INVALID_AVP_LENGTH | The inbound message did not parse. |

The 3002/5012 split matters most on Ro, where a `3002` to a CCR-UPDATE is read
as a credit denial and the call is torn down. A handler that raises is a fault
on siphon's side of the interface, not a decision about the subscriber's
credit, so it answers `5012` — which lets an operator tell a script fault from
an OCS denial instead of seeing every live call die at its first
re-authorisation with nothing pointing at the script.

Returning `None` stays `3002` on purpose: declining is a routing answer, and it
is the documented way for a handler to say "not mine".

### Application names

A filter on `@diameter.on_request` can name the application as well as the
command (`"S6a:ULR"`, `"Gx:CCR"`), and `diameter.send_request(...,
application=...)` and `diameter.routes[].application` take the same names.
They are case-insensitive in a script and lowercase in `siphon.yaml`.

| Name | Application-Id | Vendor-Id | Specification |
|---|---|---|---|
| `Cx` | 16777216 | 10415 | TS 29.229 |
| `Sh` | 16777217 | 10415 | TS 29.329 |
| `Rx` | 16777236 | 10415 | TS 29.214 |
| `Gx` | 16777238 | 10415 | TS 29.212 |
| `S6a` | 16777251 | 10415 | TS 29.272 |
| `S6c` | 16777312 | 10415 | TS 29.338 |
| `SGd` | 16777313 | 10415 | TS 29.338 |
| `Ro` | 4 | none | RFC 8506, TS 32.299 |
| `Rf` | 3 | none | RFC 6733, TS 32.299 |

Some command codes belong to more than one application: Credit-Control (272)
is both Ro and Gx, Re-Auth (258) both Rx and Gx. A bare `"CCR"` filter matches
the command on any application; `"Gx:CCR"` and `"Ro:CCR"` match only their own
Application-Id, so one script can serve both without either handler seeing the
other's requests.

```python
@diameter.on_request("Gx:CCR")
def gx_credit_control(request):
    return request.answer(2001)

@diameter.on_request("Ro:CCR")
def ro_credit_control(request):
    return request.answer(2001)
```

An application listed under `diameter.routes` is advertised to that peer in
the CER: the 3GPP ones as a `Vendor-Specific-Application-Id` holding
`Vendor-Id` 10415 and the `Auth-Application-Id`, Ro as a bare
`Auth-Application-Id`, Rf as a bare `Acct-Application-Id`.

## Capabilities exchange: the applications siphon advertises

A node that accepts Diameter connections (`diameter.listen` with `clients`)
lists the applications it serves in the Capabilities-Exchange-Answer, as
RFC 6733 §5.3 requires. The list has two sources:

1. Every application named in a registered `@diameter.on_request` filter:
   `@diameter.on_request("S6a:AIR")` makes the node an S6a server.
2. The `applications` list in the configuration, for what the filters do not
   say.

A bare-command filter (`"RAR"`) or a catch-all handler names no application,
so it adds nothing to the list. siphon does not fall back to every application
its dictionary knows, because that would claim interfaces the script may not
implement. A script that serves through such handlers lists its applications
in the configuration, and a relay lists `relay`:

```yaml
diameter:
  listen:
    tcp: "0.0.0.0:3868"
  origin_host: "hss.epc.mnc001.mcc001.3gppnetwork.org"
  origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
  applications: [s6a, cx]      # cx, sh, rx, gx, ro, rf, s6a, s6c, sgd, or relay
  clients:
    - name: mme
      allowed_ips: ["192.0.2.0/24"]
```

With `tenants:`, each tenant has its own `applications` next to its
`identity`. The handlers belong to the one script, so the applications their
filters name are advertised to every tenant.

On the wire a 3GPP application goes out as a `Vendor-Specific-Application-Id`
(Vendor-Id 10415 with the Auth-Application-Id) and as an `Auth-Application-Id`,
base accounting (Rf) as an `Acct-Application-Id`, and `relay` as
`Auth-Application-Id` 0xffffffff. The list is read from the running script at
each handshake, so a reload that adds or removes a handler changes what the
next connection is told.

The same list goes into the Capabilities-Exchange-Request siphon sends on the
connections it opens for that tenant, `servers` and `connect_to`.

### When a connecting peer is refused

siphon compares the application ids in the peer's CER with its own list. It
looks at every `Auth-Application-Id` and `Acct-Application-Id`, including the
ones inside a `Vendor-Specific-Application-Id`, and ignores the Vendor-Id.

| siphon's list | The peer's CER | Outcome |
|---|---|---|
| empty | anything | Accepted. The CEA lists no application. |
| contains `relay` | anything | Accepted. |
| not empty | contains the Relay application (0xffffffff) | Accepted. |
| not empty | shares at least one application | Accepted. |
| not empty | shares none, or lists none at all | CEA with `5010` DIAMETER_NO_COMMON_APPLICATION, then the connection is closed. The CEA still lists what siphon serves. |

The refusal is logged at `warn` with the peer's name, what it offered and what
this node serves.

The first row is what siphon did for every peer before it advertised
applications at all, and it is kept so that a relay or agent written as a
catch-all handler keeps accepting its peers without a configuration change.
Such a node answers with a CEA that names no application, which a strict peer
refuses on its side, and siphon says so with a `warn` at startup. Setting
`applications` (to `[relay]` for an agent) fixes it.

Two things follow for a script that mixes filter styles. A script with
`@diameter.on_request("S6a:AIR")` and a catch-all for everything else
advertises S6a alone, and refuses a peer that offers only Cx. List the other
applications, or `relay`, under `applications`. And a peer that sends a CER
with no application in it is refused by any node whose list is not empty.

## Rx: QoS and bearer events

`diameter.rx_aar` asks the PCRF to authorize the media of a call. With
`specific_actions` it also subscribes to IP-CAN events (TS 29.214 §5.3.13),
one Specific-Action AVP per value. The PCRF reports each event in an RAR,
which arrives at `@diameter.on_request`. The values and their names are listed
under `rx_aar` below; `0` and `5` are void in TS 29.214 and raise `ValueError`,
like any value it does not define.

```python
from siphon import diameter, qos

result = await diameter.rx_aar(
    framed_ip=request.source_ip,
    media_components=qos.media_flows_from_sdp(
        offer=request.body, answer=reply.body, direction="orig",
    ),
    # loss of bearer, release of bearer, failed resources allocation
    specific_actions=[2, 4, 9],
)
```

Subscribe in the first AAR for a session. Apart from one-time actions such as
ACCESS_NETWORK_INFO_REPORT, a Specific-Action only counts there and then holds
for the life of the Rx session.

For an emergency session pass the service URN of the request as
`service_urn`, for example `"urn:service:sos"`. It goes out as Service-URN,
which tells the PCRF the AF session is an emergency one so it can apply its
emergency policy (TS 29.214 §4.4.1). The AVP holds the URN without its
`urn:service:` (§5.3.23), so the PCRF receives `sos`.

Every AAR carries Rx-Request-Type: INITIAL_REQUEST, or UPDATE_REQUEST when
`session_id` reuses an existing session (TS 29.214 §4.4.1, §4.4.2). It is sent
without the M-bit, so a PCRF that does not know the AVP skips it. When the Rx
peer has a `destination_host` configured, the AAR carries it as
Destination-Host.

## `diameter` namespace

::: siphon_sdk.mock_module.MockDiameter

## `DiameterRequest`

The inbound request passed to `@diameter.on_request`.

::: siphon_sdk.mock_module.MockDiameterRequest

## `DiameterAnswer`

The value a handler returns via `request.answer(...)` / `request.reject(...)`.

::: siphon_sdk.mock_module.MockDiameterAnswer
