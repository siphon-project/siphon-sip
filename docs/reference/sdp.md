# SDP

The `sdp` namespace parses and rewrites SDP bodies — codec filtering, hold,
attribute manipulation, media-section removal — then applies the result back to
a message.

```python
from siphon import sdp

s = sdp.parse(request)
s.filter_codecs(["PCMU", "PCMA"])
s.apply(request)
```

## `sdp` namespace

::: siphon_sdk.sdp.MockSdpNamespace

## Parsed SDP body

Returned by `sdp.parse(...)`.

::: siphon_sdk.sdp.MockSdp

## Media section

An `m=` section within a parsed SDP body (iterated via `sdp.media`).

::: siphon_sdk.sdp.MockMediaSection
