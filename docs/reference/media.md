# Media

The `rtpengine` namespace controls media anchoring and injection (announcements,
DTMF, gating, subscriptions) via the RTPEngine / siphon-rtp NG control protocol.
The `qos` namespace turns an SDP offer/answer pair into the `media_components`
structure that `diameter.rx_aar` and `sbi.create_session` consume.

```python
from siphon import rtpengine

@b2bua.on_invite
async def anchor(call):
    await rtpengine.play_media(call, file="/prompts/welcome.wav")
```

## `rtpengine` namespace

::: siphon_sdk.mock_module.MockRtpEngine

## `qos` namespace

::: siphon_sdk.mock_module.MockQos
