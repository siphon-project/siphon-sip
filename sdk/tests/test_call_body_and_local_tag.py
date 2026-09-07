"""Tests for ``call.set_body()`` and ``call.local_tag``.

Both exist for scripts that hand the A-leg's media off to something outside
siphon.  ``set_body()`` rewrites the captured INVITE the B-leg is built from,
which is the only place to put the result of a post-anchor SDP rewrite.
``local_tag`` exposes the UAS To-tag siphon minted, so an external media
controller keys its answer on the same dialog identity siphon put on the wire
instead of inventing one.
"""

import pytest

from siphon_sdk.call import Call
from siphon_sdk.testing import SipTestHarness


SDP = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 192.0.2.1\r\n"
    "s=-\r\n"
    "c=IN IP4 192.0.2.1\r\n"
    "t=0 0\r\n"
    "m=audio 40000 RTP/AVP 0\r\n"
)


class TestSetBody:
    def test_replaces_the_body_and_restates_content_length(self):
        call = Call()
        call.set_body(SDP, "application/sdp")
        # The B-leg INVITE is built from this message, so a stale
        # Content-Length here is a malformed INVITE on the wire.
        assert call.body == SDP.encode()
        assert call.get_header("Content-Type") == "application/sdp"
        assert call.get_header("Content-Length") == str(len(SDP))

    def test_accepts_bytes_so_a_read_modify_write_needs_no_decode(self):
        call = Call(body=SDP.encode())
        rewritten = call.body.replace(b"40000", b"40002")
        call.set_body(rewritten)
        assert call.body == rewritten
        assert call.get_header("Content-Length") == str(len(rewritten))

    def test_omitting_content_type_keeps_the_one_already_set(self):
        call = Call()
        call.set_body(SDP, "application/sdp")
        call.set_body(SDP.replace("40000", "40002"))
        # The body changed, the type did not — clearing it here would strip
        # Content-Type off an INVITE that still carries SDP.
        assert call.get_header("Content-Type") == "application/sdp"

    def test_empty_body_clears_it_and_says_zero(self):
        call = Call(body=SDP.encode())
        call.set_body("")
        # A bodiless INVITE is a legitimate state (delayed offer), so this is
        # a clear, not a refusal.
        assert call.body is None
        assert call.get_header("Content-Length") == "0"


class TestLocalTag:
    def test_a_live_call_always_has_one(self):
        # siphon mints the tag with the dialog, so it is readable from the
        # first handler onwards — before any response has gone out.
        assert Call().local_tag

    def test_is_stable_across_reads(self):
        call = Call()
        assert call.local_tag == call.local_tag

    def test_distinct_calls_get_distinct_tags(self):
        assert Call().local_tag != Call().local_tag

    def test_can_be_pinned_for_assertions(self):
        assert Call(local_tag="sb-deadbeef").local_tag == "sb-deadbeef"

    def test_none_models_a_call_that_is_no_longer_live(self):
        # The engine returns None once the call actor is gone; a script reading
        # it from a late async handler must get None, not a stale tag.
        assert Call(local_tag=None).local_tag is None


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestExternalMediaControlShape:
    def test_script_answers_with_a_body_keyed_on_the_dialog_tag(self, harness):
        # The shape both APIs exist for: anchor, rewrite the offer the anchor
        # produced, and answer with media negotiated against siphon's own
        # dialog identity.
        harness.load_source(
            """
from siphon import b2bua, rtpengine

@b2bua.on_invite
async def on_invite(call):
    await rtpengine.offer(call, profile="ivr")
    call.set_body((call.body or b"").replace(b"sendrecv", b"sendonly"),
                  "application/sdp")
    call.set_header("X-Dialog-Tag", call.local_tag or "none")
    call.answer(200, "OK", body=call.body, content_type="application/sdp")
"""
        )
        result = harness.send_invite(
            ruri="sip:echo@example.com", from_uri="sip:alice@example.com"
        )
        assert result.action == "answer"
        # The tag the script read is the one the call carries — not a fresh one.
        assert result.call.get_header("X-Dialog-Tag") == result.call.local_tag
        assert result.call.get_header("Content-Type") == "application/sdp"
