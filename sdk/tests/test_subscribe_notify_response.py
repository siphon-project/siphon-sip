"""A NOTIFY's final response decides whether its subscription stays (RFC 6665 §4.2.2)."""
import asyncio

import pytest

from siphon_sdk.mock_module import MockSubscribeState
from siphon_sdk.request import Request

RESOURCE = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"


def run(coro):
    return asyncio.run(coro)


def subscription():
    return Request(
        method="SUBSCRIBE", ruri=RESOURCE,
        from_uri="sip:watcher@example.com", to_uri=RESOURCE,
        from_tag="watcher", call_id="notify-response-test",
        headers={"To": f"<{RESOURCE}>", "Event": "reg", "Expires": "3600"},
    )


def test_a_notify_answered_200_keeps_the_subscription():
    state = MockSubscribeState()
    handle = state.accept(subscription())
    assert run(handle.notify(body="<reginfo/>")) is True
    assert run(handle.notify(body="<reginfo/>")) is True
    assert state.local_count == 1
    assert len(state.notifies) == 2


def test_a_notify_answered_481_removes_the_subscription():
    state = MockSubscribeState()
    handle = state.accept(subscription())
    state.set_notify_response(481)

    # The NOTIFY was sent: the answer is read after the awaitable resolved.
    assert run(handle.notify(body="<reginfo/>")) is True
    assert len(state.notifies) == 1

    assert state.local_count == 0
    assert state.for_resource(RESOURCE, "reg") == []
    assert run(state.get(handle.id)) is None
    assert run(handle.reload()) is False
    with pytest.raises(LookupError):
        run(handle.notify(body="<reginfo/>"))
    assert len(state.notifies) == 1, "nothing more is sent to a subscriber that is gone"


@pytest.mark.parametrize(
    "status", [None, 408, 404, 405, 410, 416, 480, 481, 482, 483, 484, 485, 489, 501, 604]
)
def test_a_timeout_and_every_listed_failure_remove_the_subscription(status):
    state = MockSubscribeState()
    handle = state.accept(subscription())
    state.set_notify_response(status)
    assert run(handle.notify()) is True
    assert state.local_count == 0


@pytest.mark.parametrize("status", [200, 202, 401, 407, 500, 503])
def test_any_other_answer_keeps_the_subscription(status):
    state = MockSubscribeState()
    handle = state.accept(subscription())
    state.set_notify_response(status)
    assert run(handle.notify()) is True
    assert state.local_count == 1
    assert handle.expires == 3600


def test_clear_restores_the_default_answer():
    state = MockSubscribeState()
    state.set_notify_response(481)
    state.clear()
    handle = state.accept(subscription())
    run(handle.notify())
    assert state.local_count == 1
