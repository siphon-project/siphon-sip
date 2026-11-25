"""The Info-Package cookbook script, run as written.

The script is read out of docs/cookbook/info-packages.md, so the recipe and
what it is tested against cannot drift apart.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from siphon_sdk.call import Call
from siphon_sdk.reply import Reply
from siphon_sdk.testing import SipTestHarness

RECIPE = Path(__file__).resolve().parents[2] / "docs" / "cookbook" / "info-packages.md"
PACKAGE_INFO = {"Info-Package": "example-package", "Content-Disposition": "Info-Package"}


def recipe_script() -> str:
    blocks = re.findall(r"```python\n(.*?)```", RECIPE.read_text(), re.S)
    assert blocks, "the recipe has a python block"
    return blocks[0]


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    h.cache.set_data("info-state", {})
    h.load_source(recipe_script())
    yield h
    h.reset()
    h.close()


def settle(harness):
    """Let the tasks the handlers started run."""
    for _ in range(5):
        harness._loop.run_until_complete(asyncio.sleep(0))


def answered_call(harness, caller_recv_info="example-package", callee_recv_info=None):
    headers = {} if caller_recv_info is None else {"Recv-Info": caller_recv_info}
    call = Call(call_id="recipe@192.0.2.10", headers=headers)
    harness.send_invite(call)
    reply = Reply(status_code=200, call_id=call.call_id)
    if callee_recv_info is not None:
        reply.set_header("Recv-Info", callee_recv_info)
    harness.send_answer(call=call, reply=reply)
    return call, reply


def test_the_200_advertises_the_package_to_a_caller_that_offered_recv_info(harness):
    _, reply = answered_call(harness)
    assert reply.get_header("Recv-Info") == "example-package"


def test_a_caller_that_sent_no_recv_info_gets_none_back(harness):
    _, reply = answered_call(harness, caller_recv_info=None)
    assert reply.get_header("Recv-Info") is None


def test_a_package_info_from_the_caller_is_answered_here_and_a_state_info_follows(harness):
    call, _ = answered_call(harness)
    result = harness.send_info(call=call, leg="caller", headers=PACKAGE_INFO,
                               content_type="application/example+json", body="{}")
    settle(harness)
    assert result.answered and result.status_code == 200 and not result.relayed
    sent = harness.b2bua.sent_infos
    assert len(sent) == 1 and sent[0]["leg"] == "caller"
    assert sent[0]["headers"]["Info-Package"] == "example-package"


def test_an_unadvertised_package_is_a_469_listing_what_was(harness):
    call, _ = answered_call(harness)
    result = harness.send_info(call=call, leg="caller", headers={"Info-Package": "other"})
    assert result.status_code == 469
    assert ("Recv-Info", "example-package") in result.headers


def test_the_package_from_the_callee_is_a_469_because_none_was_advertised_there(harness):
    call, _ = answered_call(harness, callee_recv_info="example-package")
    result = harness.send_info(call=call, leg="callee", headers=PACKAGE_INFO)
    assert result.status_code == 469
    assert harness.b2bua.sent_infos == []


def test_a_package_info_before_the_answer_is_a_403(harness):
    call = Call(call_id="early@192.0.2.10", headers={"Recv-Info": "example-package"})
    harness.send_invite(call)
    assert harness.send_info(call=call, headers=PACKAGE_INFO).status_code == 403


def test_dtmf_is_left_to_be_relayed(harness):
    call, _ = answered_call(harness)
    result = harness.send_info(call=call, content_type="application/dtmf-relay",
                               body="Signal=5\r\nDuration=160\r\n")
    assert result.relayed


@pytest.mark.parametrize("advertised", [None, "", "other-package"])
def test_no_state_info_goes_to_a_party_that_did_not_advertise_the_package(harness, advertised):
    # The caller sent no Recv-Info (None), an empty one, or another package.
    call, _ = answered_call(harness, caller_recv_info=advertised)
    harness.cache._stores["info-state"][f"info:{call.call_id}:caller:local"] = "recv:example-package"
    result = harness.send_info(call=call, leg="caller", headers=PACKAGE_INFO)
    settle(harness)
    assert result.status_code == 200
    assert harness.b2bua.sent_infos == []


def test_the_state_is_dropped_when_the_call_ends(harness):
    call, _ = answered_call(harness)
    assert harness.cache._stores["info-state"]
    harness.send_bye(call=call)
    assert harness.cache._stores["info-state"] == {}
