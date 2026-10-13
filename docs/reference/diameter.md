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

These three are the generic `answer-message` of RFC 6733 section 7.2, with the
header E bit set and an `Error-Message` saying which case it was, because
siphon cannot compose the answer of a command it has no handler's answer for.
An answer the handler builds is different: `request.answer(code)` and
`request.reject(code)` set the E bit for a protocol error (3xxx) only. A
permanent failure (5xxx) a handler answers, such as `request.answer(5012)` to
a Registration-Termination-Request for a user it does not serve, is an answer
of the command and goes out with the bit clear (section 7.1.5).

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
| `Zh` | 16777221 | 10415 | TS 29.109 |
| `Zn` | 16777220 | 10415 | TS 29.109 |
| `Ro` | 4 | none | RFC 8506, TS 32.299 |
| `Rf` | 3 | none | RFC 6733, TS 32.299 |

Some command codes belong to more than one application: Credit-Control (272)
is both Ro and Gx, Re-Auth (258) both Rx and Gx, Multimedia-Auth (303) both Cx
and Zh. A bare `"CCR"` filter matches
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
  applications: [s6a, cx]      # cx, sh, rx, gx, ro, rf, s6a, s6c, sgd, zh, zn, or relay
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

## Cx: registration

The I-CSCF asks the HSS which S-CSCF serves a user with `diameter.cx_uar`,
and the S-CSCF fetches authentication vectors with a Multimedia-Auth-Request.
Both commands require the private user identity as User-Name, and the MAR
also the S-CSCF's own SIP URI as Server-Name (TS 29.229 clauses 6.1.1 and
6.1.7).

```python
from siphon import auth, diameter

SCSCF_URI = "sip:scscf.ims.example.com:6060"

# I-CSCF. user_name is the username of the REGISTER's Authorization header;
# leave it out and it is derived from the public identity (TS 24.229 5.3.1.2).
result = await diameter.cx_uar(public_identity, visited_network, user_name=private_identity)

# S-CSCF, IMS AKA: the MAR, the 401 challenge and the verification in one call.
if not await auth.require_ims_digest(request, realm=REALM, server_name=SCSCF_URI):
    return

# Or the MAR on its own, for another scheme or to hold the vector yourself.
answer = await diameter.cx_mar(public_identity, private_identity, SCSCF_URI,
                               scheme="SIP Digest")
ha1 = answer["auth_items"][0]["digest_ha1"]
```

`auth.require_ims_digest` asks for the `Digest-AKAv1-MD5` scheme, takes
Public-Identity from the To header of the REGISTER and User-Name from its
Authorization header (or derives it), and sends the MAR to the peer the `cx`
route names. Pass `server_name`: without it
the MAR goes out with no Server-Name, a warning is logged, and an HSS that
checks the command answers `DIAMETER_MISSING_AVP`. Checked against Wireshark's
Diameter dissector with `scripts/validate_diameter_cx_requests.sh`.

What the HSS answers decides what `require_ims_digest` does:

| The HSS answers | `require_ims_digest` |
|---|---|
| `DIAMETER_SUCCESS` with an IMS AKA item | sets the 401 challenge, returns `False` |
| `DIAMETER_SUCCESS` with an item that names another scheme | raises `RuntimeError` and logs an error, no challenge |
| `DIAMETER_SUCCESS` without `SIP-Auth-Data-Item`, `SIP-Authenticate` or `SIP-Authorization` | raises `RuntimeError` and logs an error, no challenge |
| `DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED` (5006) | sets `403 Forbidden`, returns `False`, logs a warning |
| any other result | sets `403 Forbidden`, returns `False`, logs a warning with the result |
| nothing (transport error or timeout) | raises `RuntimeError` |

Neither H(A1) nor the response of the UE is written to the log at any level.

After a successful authentication the S-CSCF tells the HSS with
`diameter.cx_sar`, which takes the private identity as `user_name=`
(`request.auth_user`): TS 29.228 Table 6.1.2.1 requires it in the request
whenever the S-CSCF has it.

```python
await diameter.cx_sar(public_identity, SCSCF_URI, 1, user_name=request.auth_user)
```

## GBA: Zh and Zn

The Generic Bootstrapping Architecture (TS 33.220) has two Diameter reference
points, both in TS 29.109. On **Zh** a Bootstrapping Server Function asks the
HSS for one authentication vector and the user's GBA security settings (the
GUSS). On **Zn** a Network Application Function asks the BSF for the key
material of a bootstrapping transaction.

```yaml
diameter:
  origin_host: "bsf.mnc001.mcc001.pub.3gppnetwork.org"
  origin_realm: "mnc001.mcc001.pub.3gppnetwork.org"
  peers:
    - name: hss1
      host: "192.0.2.10"
      destination_realm: "ims.mnc001.mcc001.3gppnetwork.org"
  routes:
    - application: zh          # advertised to hss1 in the CER
      peers: [hss1]
```

### Zh: the BSF asks the HSS

Zh uses the Cx command, Multimedia-Auth (303), on its own application
(16777221). The request has no Server-Name and no SIP-Number-Auth-Items, so the
HSS does not run its Cx procedure and stores no S-CSCF name. Do not send a Cx
MAR in its place.

```python
from siphon import diameter

answer = await diameter.zh_mar(impi)
if answer is None:
    ...                                    # no zh peer, or no answer in time
elif answer["experimental_result_code"] == 5401:
    ...                                    # DIAMETER_ERROR_IDENTITY_UNKNOWN
else:
    vector = answer["auth_items"][0]       # the HSS provides one
    rand, autn = vector["authenticate"][:16], vector["authenticate"][16:]
    xres = vector["authorization"]
    ck, ik = vector["confidentiality_key"], vector["integrity_key"]
    guss = answer["guss"]                  # the GBA-UserSecSettings XML, or None

# After a synchronisation failure: RAND as sent, then the AUTS of the terminal.
answer = await diameter.zh_mar(impi, authorization=rand + auts)
```

For IMS AKA the request carries no `SIP-Auth-Data-Item`: TS 29.109 clause 4.2
defines its absence as `Digest-AKAv1-MD5` and advises against sending it.
`authorization=` (30 octets, TS 29.229 clause 6.3.11) adds the item with
`SIP-Authorization`, `scheme=` names another scheme, and `guss_timestamp=`
(Unix seconds) sends the timestamp of the GUSS already held, to which the HSS
answers `guss` `"GUSS TIMESTAMP EQUAL"` when nothing changed.
`GUSS-Timestamp` goes out without the M bit, as Table 6.1 of TS 29.109
requires; every other GBA AVP carries it.

### A Grouped AVP through `send_request`

`diameter.send_request` takes a Grouped AVP as a `dict` of its members, each
keyed and typed like a top-level keyword, in the order of the `dict`. A member
can be a `dict` itself. A Time AVP takes Unix seconds. The Zh request above,
in the generic form:

```python
answer = await diameter.send_request(
    "Multimedia-Auth-Request", "Zh",
    user_name=impi,
    sip_auth_data_item={
        "sip_authentication_scheme": "Digest-AKAv1-MD5",
        "sip_authorization": rand + auts,          # bytes
    })
guss_hex = answer.get("gba_usersecsettings")       # an OctetString reads as hex
```

A member name the dictionary does not know raises `ValueError` naming the
group and the member. A keyword gives an AVP once, so a command that repeats
an AVP at the top level (several `GAA-Service-Identifier`) needs its typed
call. With `peer=None` the generic call takes any connected peer, not the one
the application's route names: pass `peer=` on a node with more than one.

### Zn: the NAF asks the BSF

```python
answer = await diameter.zn_bir(
    b_tid, naf_fqdn.encode() + ua_security_protocol_id,      # NAF-Id, bytes
    gaa_service_identifiers=["1"],
    destination_realm=b_tid.split("@", 1)[1])                # the BSF of the B-TID
if answer and answer["result_code"] == 2001:
    ks_naf = answer["me_key_material"]
    expires = answer["key_expiry_time"]                      # Unix seconds
elif answer and answer["experimental_result_code"] == 5403:
    ...   # DIAMETER_ERROR_TRANSACTION_IDENTIFIER_INVALID: bootstrap again
```

### Zn: the BSF answers

A BSF serves Zn with `@diameter.on_request("Zn:BIR")`, which also makes the
node advertise Zn in its CEA. The handler reads the request with `get_avp`
and builds the answer with `set_avp`. A Time AVP is set from Unix seconds.

TS 29.109 clause 6.2 puts its own result codes (5401, 5402, 5403) "inside an
Experimental-Result AVP and Result-Code AVP shall be absent". Start from
`request.answer(2001)`, which does not set the error bit, remove the
Result-Code and set the group:

```python
TGPP = 10415

@diameter.on_request("Zn:BIR")
def bootstrapping_info(request):
    b_tid = request.get_avp("Transaction-Identifier")        # bytes
    naf_id = request.get_avp("NAF-Id")                       # bytes
    services = [value for code, vendor, value in request.iter_avps()
                if (code, vendor) == (403, TGPP)]            # GAA-Service-Identifier
    gba_u_aware = request.get_avp("GBA_U-Awareness-Indicator") == 1

    answer = request.answer(2001)
    answer.set_avp("Vendor-Specific-Application-Id",
                   [("Vendor-Id", TGPP), ("Auth-Application-Id", 16777220)])
    answer.set_avp("Auth-Session-State", 1)                  # NO_STATE_MAINTAINED

    session = sessions.get(b_tid)
    if session is None:
        answer.remove_avp("Result-Code")
        answer.set_avp("Experimental-Result",
                       [("Vendor-Id", TGPP), ("Experimental-Result-Code", 5403)])
        return answer

    answer.set_avp("ME-Key-Material", session.ks_naf(naf_id))
    answer.set_avp("Key-ExpiryTime", session.expires)        # Unix seconds
    answer.set_avp("BootstrapInfoCreationTime", session.created)
    answer.set_avp("GBA-UserSecSettings", session.uss_list(services))
    return answer
```

siphon carries the messages and knows the AVPs. The key derivation of
TS 33.220, the store of bootstrapping transactions and the authorisation of a
NAF are the script's.

Every message above is checked against Wireshark's Diameter dissector with
`scripts/validate_diameter_gba.sh`: the application id and command code, each
AVP's code, vendor and flags, and that nothing is malformed or unknown.
Wireshark's dictionary names AVP 402 `NAF-Hostname`; TS 29.109 names it
`NAF-Id`, and so does siphon. Not tested against an HSS.

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

`qos.media_flows_from_sdp` writes two Flow-Descriptions per sub-component,
the uplink flow first. In TS 29.214 §5.3.8 `in` is the uplink flow and `out`
the downlink flow, so the UE is the source of the `in` rule and the
destination of the `out` rule (RFC 6733 §4.3.1, TS 29.212 §5.4.2):

```text
permit in 17 from 192.0.2.2 50000 to 198.51.100.10 30000
permit out 17 from 198.51.100.10 30000 to 192.0.2.2 50000
```

Here `192.0.2.2` is the UE, on the originating and on the terminating leg
alike; `direction=` only says which of the two SDP bodies is the UE's. The
RTCP sub-component follows the same rule one port up. The same list goes to
`sbi.create_session` unchanged, where TS 29.514 defines `fDescs` by the same
clause. A script that writes its own descriptions has to follow the same
convention: siphon sends them as given.

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

### Reading AVPs: two tuple orders, and `avps()`

`get_avp` and `iter_avps` hand AVPs out as tuples, and the two shapes differ:

| Where | Shape |
|---|---|
| `iter_avps()`, each top-level AVP | `(code, vendor, value)` |
| the members of a grouped AVP, in the `value` of either call | `(code, value, vendor)` |

The second is the shape `set_avp` takes for a child, so a group read out can be
set back in. A handler that unpacks a member as `code, vendor, value` compares
a value with a vendor id, finds nothing and, typically, refuses every request.
Neither order can change without breaking scripts. `request.avps()` and
`answer.avps()` list the same AVPs as `DiameterAvp` objects instead, with the
fields by name at every level:

```python
for avp in request.avps():
    if avp.name == "Deregistration-Reason" and avp.vendor == 10415:
        reason = {member.name: member.value for member in avp.value}
```

::: siphon_sdk.mock_module.MockDiameterAvp

## `DiameterAnswer`

The value a handler returns via `request.answer(...)` / `request.reject(...)`.

::: siphon_sdk.mock_module.MockDiameterAnswer


### Credit reauthorization on a serving connection

`await diameter.reauthorize(peer, session_id, destination_host, destination_realm,
tenant="default", timeout_ms=5000)` sends RFC 8506 section 5.5 RAR on the existing
connection that carried the client's charging request. It retains the supplied
Session-Id, sets application/Auth-Application-Id 4 and AUTHORIZE_ONLY (0), and
returns the RAA Result-Code. Missing/disconnected connections and timeouts raise;
callers should persist their pending notification and retry. A 2001 or 2002 RAA
acknowledges the request; the client's subsequent CCR performs the actual credit
update. Connections are scoped by tenant, configured peer name and Origin-Host.
The weak registry does not keep disconnected peers alive or route to arbitrary
client-mode peers. A peer must first have sent a request on that connection.
