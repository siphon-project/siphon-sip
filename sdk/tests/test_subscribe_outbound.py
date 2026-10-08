"""The watcher side of ``proxy.subscribe_state``: what siphon does with the
NOTIFYs of a subscription the script made with ``send()``."""

import pytest

from siphon_sdk.testing import SipTestHarness
from siphon_sdk import mock_module

SCRIPT = """
from siphon import proxy

seen = []

@proxy.on_request("MESSAGE")
async def watch(request):
    handle = await proxy.subscribe_state.send(
        "sip:001010123456789@example.com", event="reg", expires=600)
    if request.get_header("X-Unsubscribe"):
        await handle.terminate()
    request.set_reply_header("X-Subscription", handle.id)
    request.reply(200, "OK")

@proxy.on_request("NOTIFY")
def notify(request):
    handle = proxy.subscribe_state.find(
        request.call_id, request.to_tag, request.from_tag)
    if handle is None:
        request.reply(481, "Unknown To The Script")
        return
    seen.append((handle.id, handle.expires))
    request.reply(200, "OK")
"""


@pytest.fixture
def harness():
    harness = SipTestHarness(local_domains=["example.com"])
    harness.load_source(SCRIPT)
    return harness


def subscribe(harness, unsubscribe=False):
    """Run the script's ``send()`` and return the dialog it made."""
    headers = {"X-Unsubscribe": "yes"} if unsubscribe else None
    result = harness.send_request("MESSAGE", "sip:watch@example.com", headers=headers)
    assert result.status_code == 200
    state = mock_module.get_proxy().subscribe_state
    return next(dialog for dialog in state._dialogs.values() if dialog.get("is_outbound"))


def notify(harness, dialog, subscription_state, from_tag=None, event="reg"):
    return harness.send_request(
        "NOTIFY", "sip:siphon@example.com",
        call_id=dialog["call_id"],
        to_tag=dialog["local_tag"],
        from_tag=from_tag or dialog["remote_tag"],
        headers={"Event": event, "Subscription-State": subscription_state},
    )


def state():
    return mock_module.get_proxy().subscribe_state


def test_an_active_notify_reaches_the_script_and_leaves_the_subscription(harness):
    dialog = subscribe(harness)

    assert notify(harness, dialog, "active;expires=600").status_code == 200
    assert state().local_count == 1


def test_a_terminating_notify_is_found_by_the_handler_and_then_removes_it(harness):
    dialog = subscribe(harness)
    handle = state().find(dialog["call_id"], dialog["local_tag"], dialog["remote_tag"])

    result = notify(harness, dialog, "terminated;reason=timeout")

    assert result.status_code == 200, "the handler still found its subscription"
    assert state().local_count == 0
    with pytest.raises(LookupError):
        handle.expires
    # What comes after belongs to no subscription.
    assert notify(harness, dialog, "active;expires=600").status_code == 481


def test_a_notify_from_another_notifier_is_refused_without_the_script(harness):
    dialog = subscribe(harness)

    result = notify(harness, dialog, "active;expires=600", from_tag="another-fork")

    assert result.status_code == 481
    assert result.request.actions[-1].reason == "Subscription Does Not Exist"
    assert state().local_count == 1
    # And the dialog's own notifier is still heard.
    assert notify(harness, dialog, "active;expires=600").status_code == 200


def test_a_notify_for_another_event_package_is_left_to_the_script(harness):
    dialog = subscribe(harness)

    result = notify(harness, dialog, "active;expires=600", event="presence")

    # Not placed against the subscription, so the script decides: its
    # lookup is by dialog and finds it.
    assert result.status_code == 200
    assert state().local_count == 1


def test_a_notify_shortens_the_subscription_and_never_lengthens_it(harness):
    dialog = subscribe(harness)

    notify(harness, dialog, "active;expires=90")
    assert dialog["expires_secs"] == 90

    notify(harness, dialog, "active;expires=900")
    assert dialog["expires_secs"] == 90


def test_an_unsubscribed_subscription_lasts_until_its_terminating_notify(harness):
    dialog = subscribe(harness, unsubscribe=True)

    assert state().terminates[-1]["id"] == dialog["id"]
    assert state().local_count == 1, "not over until the notifier says so"
    assert dialog["expires_secs"] <= 32

    assert notify(harness, dialog, "terminated;reason=timeout").status_code == 200
    assert state().local_count == 0


def test_an_unsubscribe_no_notify_answers_ends_at_timer_n(harness):
    dialog = subscribe(harness, unsubscribe=True)

    assert state().expire_unanswered() == [dialog["id"]]
    assert state().local_count == 0
    assert state().expire_unanswered() == []


def test_timer_n_leaves_a_live_subscription_alone(harness):
    subscribe(harness)

    assert state().expire_unanswered() == []
    assert state().local_count == 1


def test_a_notifier_side_dialog_is_still_removed_at_once_on_terminate():
    import asyncio

    from siphon_sdk.mock_module import MockSubscribeState
    from siphon_sdk.request import Request

    namespace = MockSubscribeState()
    handle = namespace.accept(Request(
        method="SUBSCRIBE", ruri="sip:201@example.com",
        from_uri="sip:201@example.com", to_uri="sip:201@example.com",
        from_tag="watcher", call_id="notifier-side",
        headers={"To": "<sip:201@example.com>", "Event": "message-summary",
                 "Expires": "300"},
    ))
    asyncio.run(handle.terminate())
    assert namespace.local_count == 0
