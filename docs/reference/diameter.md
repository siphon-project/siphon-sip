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

## Rx: QoS and bearer events

`diameter.rx_aar` asks the PCRF to authorize the media of a call. With
`specific_actions` it also subscribes to IP-CAN events (TS 29.214 §5.3.13),
one Specific-Action AVP per value. The PCRF reports each event in an RAR,
which arrives at `@diameter.on_request`. The values and their names are listed
under `rx_aar` below; `0` and `5` are void in TS 29.214 and raise `ValueError`,
like any value it does not define.

```python
from siphon import diameter, qos

result = diameter.rx_aar(
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
