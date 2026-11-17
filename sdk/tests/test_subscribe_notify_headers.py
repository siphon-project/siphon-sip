"""``headers=`` on ``handle.notify()`` / ``handle.terminate()`` mirrors siphon."""
import asyncio

import pytest

from siphon_sdk.mock_module import MockSubscribeState
from siphon_sdk.request import Request

OWNED = (
    "Via", "From", "To", "Call-ID", "CSeq", "Contact", "Route", "Max-Forwards",
    "Content-Length", "Content-Type", "Event", "Subscription-State",
)
ASSERTED = {
    "P-Asserted-Identity": "<sip:group@example.com>",
    "P-Asserted-Service": "urn:urn-7:3gpp-service.ims.icsi.mcptt",
}


def run(coro):
    return asyncio.run(coro)


def accepted(state):
    return state.accept(Request(
        method="SUBSCRIBE", ruri="sip:group@example.com",
        from_uri="sip:201@example.com", to_uri="sip:group@example.com",
        from_tag="watcher", call_id="notify-headers-test",
        headers={"To": "<sip:group@example.com>", "Event": "conference",
                 "Expires": "300"},
    ))


def test_headers_are_recorded_in_order_on_notify_and_terminate():
    state = MockSubscribeState()
    handle = accepted(state)
    assert run(handle.notify(headers=ASSERTED)) is True
    assert list(state.notifies[-1]["headers"].items()) == list(ASSERTED.items())
    assert run(handle.terminate(reason="deactivated", headers=ASSERTED)) is True
    assert state.terminates[-1]["headers"] == ASSERTED
    assert state.local_count == 0


def test_no_headers_is_an_empty_mapping():
    state = MockSubscribeState()
    handle = accepted(state)
    run(handle.notify())
    assert state.notifies[-1]["headers"] == {}
    run(handle.terminate())
    assert state.terminates[-1]["headers"] == {}


@pytest.mark.parametrize("name", OWNED + ("event", "o", "i", "v", "f", "t", "m", "l", "c"))
def test_a_header_siphon_owns_is_refused_and_nothing_is_recorded(name):
    state = MockSubscribeState()
    handle = accepted(state)
    with pytest.raises(ValueError, match=name):
        handle.notify(headers={**ASSERTED, name: "value"})
    with pytest.raises(ValueError, match=name):
        handle.terminate(headers={name: "value"})
    assert state.notifies == []
    assert state.terminates == []
    assert state.local_count == 1


@pytest.mark.parametrize("headers", ({"X-Count": 5}, {5: "value"}, {"X-Raw": b"raw"}))
def test_a_name_or_value_that_is_not_a_str_raises_type_error(headers):
    state = MockSubscribeState()
    handle = accepted(state)
    with pytest.raises(TypeError, match="str header names"):
        handle.notify(headers=headers)
    with pytest.raises(TypeError, match="str header names"):
        handle.terminate(headers=headers)
    assert state.notifies == []
    assert state.local_count == 1


@pytest.mark.parametrize("headers", ([], [("X-A", "b")], "X-A: b"))
def test_headers_that_are_not_a_dict_raise_type_error(headers):
    state = MockSubscribeState()
    handle = accepted(state)
    with pytest.raises(TypeError, match="takes a dict"):
        handle.notify(headers=headers)
    with pytest.raises(TypeError, match="takes a dict"):
        handle.terminate(headers=headers)
    assert state.notifies == []
    assert state.local_count == 1


def test_a_malformed_name_or_a_line_break_in_a_value_is_refused():
    state = MockSubscribeState()
    handle = accepted(state)
    with pytest.raises(ValueError, match="not a SIP header name"):
        handle.notify(headers={"X Bad": "value"})
    with pytest.raises(ValueError, match="line break"):
        handle.notify(headers={"X-Smuggle": "one\r\nEvent: other"})
    assert state.notifies == []
