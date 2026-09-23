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
