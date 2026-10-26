"""Unit tests for MockPresence.terminate and the terminated-state auto-GC.

These mirror the production behaviour added to ``src/script/api/presence.rs``:
``terminate()`` sends a final ``Subscription-State: terminated;reason=...``
NOTIFY and removes the subscription's dialog state, and ``notify()`` with a
terminated state auto-removes too — so scripts never leak dialog state and
subsequent state changes for the resource don't fan NOTIFYs out to gone
watchers (RFC 6665 §4.4.1).
"""
import asyncio
from siphon_sdk import mock_module


def run(coro):
    return asyncio.run(coro)


def _fresh_presence():
    mock_module.install()
    presence = mock_module.get_presence()
    presence.clear()
    return presence


def test_terminate_sends_terminated_notify_and_removes_dialog():
    presence = _fresh_presence()
    sub_id = presence.subscribe_dialog(
        subscriber="sip:bob@example.com",
        resource="sip:alice@example.com",
        event="reg",
        expires=3600,
        call_id="abc@bob",
        from_tag="bob-tag",
        to_tag="scscf-tag",
        route_set=["<sip:pcscf:5060;lr>"],
    )
    assert presence.subscription_count() == 1

    sent = run(presence.terminate(sub_id, reason="timeout"))
    assert sent is True

    notification = presence.notifications[-1]
    assert notification["subscription_id"] == sub_id
    assert notification["subscription_state"] == "terminated;reason=timeout"
    assert presence.subscription_count() == 0


def test_terminate_default_reason_is_noresource():
    presence = _fresh_presence()
    sub_id = presence.subscribe_dialog(
        subscriber="sip:bob@example.com",
        resource="sip:alice@example.com",
        event="reg",
        expires=3600,
        call_id="abc",
        from_tag="bt",
        to_tag="st",
    )
    run(presence.terminate(sub_id))
    assert presence.notifications[-1]["subscription_state"] \
        == "terminated;reason=noresource"


def test_terminate_unknown_subscription_returns_false_and_is_idempotent():
    presence = _fresh_presence()
    assert run(presence.terminate("sub-nonexistent")) is False
    # Second call is still safe and observably the same.
    assert run(presence.terminate("sub-nonexistent")) is False
    assert presence.notifications == []


def test_notify_with_terminated_state_auto_removes_subscription():
    """Direct notify(state='terminated;...') must also drop the dialog —
    otherwise scripts written before terminate() existed still leak."""
    presence = _fresh_presence()
    sub_id = presence.subscribe_dialog(
        subscriber="sip:bob@example.com",
        resource="sip:alice@example.com",
        event="reg",
        expires=3600,
        call_id="abc",
        from_tag="bt",
        to_tag="st",
    )
    run(presence.notify(
        sub_id,
        body="<reginfo/>",
        content_type="application/reginfo+xml",
        subscription_state="terminated;reason=deactivated",
    ))
    assert presence.subscription_count() == 0


def test_notify_with_active_state_does_not_remove():
    presence = _fresh_presence()
    sub_id = presence.subscribe_dialog(
        subscriber="sip:bob@example.com",
        resource="sip:alice@example.com",
        event="reg",
        expires=3600,
        call_id="abc",
        from_tag="bt",
        to_tag="st",
    )
    run(presence.notify(sub_id, subscription_state="active;expires=3600"))
    assert presence.subscription_count() == 1


def test_find_by_dialog_resolves_refresh_and_unsubscribe():
    """In-dialog SUBSCRIBE flow: resolve by (Call-ID, From-tag), refresh, remove."""
    presence = _fresh_presence()
    sub_id = presence.subscribe_dialog(
        subscriber="sip:alice@ims.example.com",
        resource="sip:alice@ims.example.com",
        event="reg",
        expires=3600,
        call_id="call-abc",
        from_tag="ftag-alice",
        to_tag="scscf-notif",
    )

    assert presence.find_by_dialog("call-abc", "ftag-alice") == sub_id
    # Wrong pair / unknown dialog → None.
    assert presence.find_by_dialog("call-abc", "ftag-bob") is None
    assert presence.find_by_dialog("call-xyz", "ftag-alice") is None

    # Refresh the resolved subscription.
    assert presence.refresh(sub_id, 7200) is True
    assert presence.refresh("sub-nope", 7200) is False

    # Un-SUBSCRIBE: resolve then remove.
    resolved = presence.find_by_dialog("call-abc", "ftag-alice")
    assert presence.unsubscribe(resolved) is True
    assert presence.find_by_dialog("call-abc", "ftag-alice") is None
    assert presence.subscription_count() == 0


def test_find_by_dialog_ignores_non_dialog_subscription():
    """subscribe() (no dialog state) is not findable by dialog."""
    presence = _fresh_presence()
    presence.subscribe("sip:alice@ims.example.com", "sip:alice@ims.example.com",
                       event="reg", expires=3600)
    assert presence.find_by_dialog("", "") is None


def _reg_subscription(presence):
    return presence.subscribe_dialog(
        subscriber="sip:watcher@192.0.2.7:5060",
        resource="sip:001010000000001@ims.example.com",
        event="reg",
        expires=600,
        call_id="notify-outcome",
        from_tag="ft",
        to_tag="nt",
    )


def test_notify_answered_481_removes_the_subscription():
    presence = _fresh_presence()
    sub_id = _reg_subscription(presence)
    presence.set_notify_response(481)
    status = run(presence.notify(sub_id, body="<reginfo/>", wait_for_response=True))
    assert status == 481
    assert presence.subscribers("sip:001010000000001@ims.example.com") == []


def test_notify_timeout_removes_the_subscription():
    presence = _fresh_presence()
    sub_id = _reg_subscription(presence)
    presence.set_notify_response(None)
    assert run(presence.notify(sub_id)) is None
    assert presence.subscription_count() == 0


def test_notify_200_or_5xx_keeps_the_subscription():
    presence = _fresh_presence()
    sub_id = _reg_subscription(presence)
    assert run(presence.notify(sub_id, wait_for_response=True)) == 200
    presence.set_notify_response(503)
    assert run(presence.notify(sub_id, wait_for_response=True)) == 503
    assert presence.subscription_count() == 1


def test_notify_without_waiting_resolves_to_none():
    presence = _fresh_presence()
    sub_id = _reg_subscription(presence)
    assert run(presence.notify(sub_id)) is None


def test_next_version_counts_per_subscription():
    presence = _fresh_presence()
    first = _reg_subscription(presence)
    second = presence.subscribe_dialog(
        subscriber="sip:other@192.0.2.8:5060",
        resource="sip:001010000000001@ims.example.com",
        event="reg", expires=600, call_id="other", from_tag="f2", to_tag="t2",
    )
    assert [presence.next_version(first) for _ in range(3)] == [0, 1, 2]
    assert presence.next_version(second) == 0
    assert presence.unsubscribe(first)
    assert presence.next_version(first) is None


def test_next_version_continues_from_a_rebuilt_dialog():
    presence = _fresh_presence()
    restored = presence.subscribe_dialog(
        subscriber="sip:watcher@192.0.2.7:5060",
        resource="sip:001010000000001@ims.example.com",
        event="reg", expires=600, call_id="restored", from_tag="f", to_tag="t",
        local_cseq=1792310400, version=1792310400,
    )
    assert presence.next_version(restored) == 1792310400
    assert presence.next_version(restored) == 1792310401
