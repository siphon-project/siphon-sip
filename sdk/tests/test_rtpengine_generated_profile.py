"""A generated ``base#webrtc-...`` profile name is not one a script may type.

The runtime raises ``ValueError`` naming it; the mock does the same before it
records anything, so a script that passes under the mock does not fail in
production.
"""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.testing import SipTestHarness

GENERATED = "extension#webrtc-answer"


@pytest.fixture
def engine():
    harness = SipTestHarness()
    harness.reset()
    return harness.rtpengine


def _calls(engine):
    target = ("call-1", "tag-a")
    return [
        ("offer", lambda: engine.offer(target, sdp=b"v=0\r\n", profile=GENERATED)),
        ("answer", lambda: engine.answer(target, profile=GENERATED)),
        ("answer_local", lambda: engine.answer_local(target, profile=GENERATED)),
        ("conference_join", lambda: engine.conference_join("room", target, profile=GENERATED)),
        (
            "conference_offer",
            lambda: engine.conference_offer("room", "seat-1", profile=GENERATED),
        ),
        (
            "subscribe_request",
            lambda: engine.subscribe_request("call-1", "tag-a", "tag-b", profile=GENERATED),
        ),
        (
            "subscribe_answer",
            lambda: engine.subscribe_answer(
                "call-1", "tag-a", "tag-b", b"v=0\r\n", profile=GENERATED
            ),
        ),
    ]


@pytest.mark.parametrize("index", range(7))
def test_a_generated_profile_name_is_refused_and_nothing_is_recorded(engine, index):
    name, call = _calls(engine)[index]
    with pytest.raises(ValueError, match="extension#webrtc-answer"):
        asyncio.run(call())
    assert engine.operations == [], name
