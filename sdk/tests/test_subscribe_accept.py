"""Notifier acceptance mirrors the native dialog lifecycle."""
from siphon_sdk.mock_module import MockSubscribeState
from siphon_sdk.request import Request


def subscription(tag="", expires=300):
    return Request(
        method="SUBSCRIBE", ruri="sip:201@example.com",
        from_uri="sip:201@example.com", to_uri="sip:201@example.com",
        from_tag="watcher", call_id="subscription-test",
        headers={"To": f"<sip:201@example.com>{tag}", "Event": "message-summary",
                 "Expires": str(expires)},
    )


def test_refresh_preserves_handle_and_version():
    state = MockSubscribeState()
    initial = state.accept(subscription())
    initial.next_event_version()
    refreshed = state.accept(subscription(f";tag={initial.local_tag}"), expires=600)
    assert refreshed.id == initial.id
    assert refreshed.event_version == 1
    assert refreshed.expires == 600
    assert state.local_count == 1


def test_unknown_dialog_is_not_created():
    state = MockSubscribeState()
    assert state.accept(subscription(";tag=unknown")) is None
    assert state.local_count == 0


def test_zero_expiry_can_be_terminated_and_does_not_leak():
    state = MockSubscribeState()
    for _ in range(200):
        handle = state.accept(subscription(expires=0))
        assert handle.expires == 0
        handle.terminate(reason="deactivated", body="Messages-Waiting: no\r\n")
        assert state.local_count == 0
