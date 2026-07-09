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

## `diameter` namespace

::: siphon_sdk.mock_module.MockDiameter

## `DiameterRequest`

The inbound request passed to `@diameter.on_request`.

::: siphon_sdk.mock_module.MockDiameterRequest

## `DiameterAnswer`

The value a handler returns via `request.answer(...)` / `request.reject(...)`.

::: siphon_sdk.mock_module.MockDiameterAnswer
