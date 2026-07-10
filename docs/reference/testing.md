# Testing harness

The `siphon_sdk.testing` module lets you unit-test SIPhon scripts with pytest,
no Rust binary required. The harness installs the mock `siphon` module, loads
your script, feeds it simulated SIP messages, and returns a result object that
records what the handler did.

```python
from siphon_sdk.testing import SipTestHarness

def test_register_challenges_unauthenticated():
    harness = SipTestHarness()
    harness.load_script("scripts/proxy_default.py")

    result = harness.send_request("REGISTER", "sip:alice@example.com")
    assert result.action == "reply"
    assert result.status_code == 401
```

## `SipTestHarness`

::: siphon_sdk.testing.SipTestHarness

## `RequestResult`

The result of `harness.send_request(...)`.

::: siphon_sdk.testing.RequestResult

## `ReplyResult`

The result of feeding a response through `@proxy.on_reply`.

::: siphon_sdk.testing.ReplyResult

## `CallResult`

The result of driving a B2BUA call.

::: siphon_sdk.testing.CallResult

## `MockHss`

An in-process HSS stub for exercising Diameter Cx/Sh flows.

::: siphon_sdk.testing.MockHss

## `MockPcrf`

An in-process PCRF stub for exercising Diameter Rx flows.

::: siphon_sdk.testing.MockPcrf
