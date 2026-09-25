"""A handle's properties read local state; `reload` is the awaited re-read."""
import asyncio
import inspect

import pytest

from siphon_sdk.mock_module import MockSubscribeState
from siphon_sdk.request import Request


def run(coro):
    return asyncio.run(coro)


def subscription(tag="", expires=300):
    return Request(
        method="SUBSCRIBE", ruri="sip:201@example.com",
        from_uri="sip:201@example.com", to_uri="sip:201@example.com",
        from_tag="watcher", call_id="subscription-test",
        headers={"To": f"<sip:201@example.com>{tag}", "Event": "message-summary",
                 "Expires": str(expires)},
    )


def test_properties_are_plain_attribute_reads():
    state = MockSubscribeState()
    handle = state.accept(subscription())
    assert handle.event == "message-summary"
    assert handle.expires == 300
    assert handle.event_version == 0
    assert handle.local_tag


def test_reload_is_awaitable_and_reports_liveness():
    state = MockSubscribeState()
    handle = state.accept(subscription())
    # An awaitable mock is a plain `def` returning an inner coroutine — the
    # same shape a pymethod has — so assert on the returned object, never on
    # `iscoroutinefunction(handle.reload)`.
    assert not inspect.iscoroutinefunction(handle.reload)
    pending = handle.reload()
    assert inspect.iscoroutine(pending)
    assert run(pending) is True

    run(handle.terminate())
    assert run(handle.reload()) is False


def test_a_gone_dialog_raises_rather_than_answering_stale():
    state = MockSubscribeState()
    handle = state.accept(subscription())
    run(handle.terminate())

    for read in (lambda: handle.event, lambda: handle.expires,
                 lambda: handle.local_tag, lambda: handle.event_version,
                 handle.next_event_version):
        with pytest.raises(LookupError):
            read()
    # The id is the handle's own state, so it keeps answering.
    assert handle.id

    with pytest.raises(LookupError):
        run(handle.notify(body="x"))


def test_expires_is_a_live_read_not_a_snapshot():
    """A refresh arriving on the store is visible through the handle that was
    built before it — the property is not frozen at construction."""
    state = MockSubscribeState()
    handle = state.accept(subscription())
    assert handle.expires == 300

    refreshed = state.accept(subscription(f";tag={handle.local_tag}"), expires=600)
    assert refreshed.id == handle.id
    assert handle.expires == 600
