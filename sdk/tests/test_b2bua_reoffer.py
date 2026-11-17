"""Tests for the imperative b2bua.reoffer(call_id) re-INVITE.

A script tells one party something about the session it did not ask about,
RFC 7866's a=record when a recording starts or stops on its own, and learns the
final status so a crossing offer's 491 can be retried.
"""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


def test_records_the_offer_and_resolves_to_the_status(harness):
    import siphon

    status = asyncio.run(siphon.b2bua.reoffer("rec@example.com", sdp="v=0\r\na=record:off\r\n"))
    assert status == 200
    assert harness.b2bua.reoffers[-1] == {
        "call_id": "rec@example.com",
        "sdp": "v=0\r\na=record:off\r\n",
        "leg": "caller",
    }
    harness.b2bua.reoffer_status = 491
    assert asyncio.run(siphon.b2bua.reoffer("rec@example.com", leg="callee")) == 491
    assert harness.b2bua.reoffers[-1]["sdp"] is None


def test_an_unknown_leg_is_refused(harness):
    import siphon

    with pytest.raises(ValueError):
        asyncio.run(siphon.b2bua.reoffer("rec@example.com", leg="both"))


def test_the_session_in_force_is_what_the_test_set(harness):
    import siphon

    assert siphon.b2bua.session_sdp("rec@example.com") is None
    harness.b2bua.session_sdps[("rec@example.com", "caller")] = "v=0\r\n"
    assert siphon.b2bua.session_sdp("rec@example.com") == "v=0\r\n"
    assert siphon.b2bua.session_sdp("rec@example.com", leg="callee") is None


def test_a_body_and_headers_are_recorded_with_the_offer(harness):
    import siphon

    status = asyncio.run(siphon.b2bua.reoffer(
        "group@example.com",
        body="<info/>",
        content_type="application/vnd.example.info+xml",
        headers={"Resource-Priority": "example.0"},
    ))
    assert status == 200
    assert harness.b2bua.reoffers[-1] == {
        "call_id": "group@example.com",
        "sdp": None,
        "leg": "caller",
        "content_type": "application/vnd.example.info+xml",
        "body": b"<info/>",
        "headers": {"Resource-Priority": "example.0"},
    }


def test_a_body_that_is_or_carries_the_sdp_is_the_offer(harness):
    import siphon

    asyncio.run(siphon.b2bua.reoffer(
        "group@example.com", body="v=0\r\n", content_type="application/sdp"))
    assert harness.b2bua.reoffers[-1] == {
        "call_id": "group@example.com", "sdp": "v=0\r\n", "leg": "caller",
    }
    multipart = (
        "--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n\r\n"
        "--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n"
    )
    asyncio.run(siphon.b2bua.reoffer(
        "group@example.com", body=multipart, content_type="multipart/mixed;boundary=b"))
    assert harness.b2bua.reoffers[-1]["sdp"] == "v=0"
    assert harness.b2bua.reoffers[-1]["body"] == multipart.encode()


@pytest.mark.parametrize("owned", [
    "Via", "From", "To", "Call-ID", "CSeq", "Max-Forwards", "Contact", "Route",
    "Record-Route", "Content-Length", "Content-Type", "Require", "Supported",
    "Session-Expires", "Min-SE", "RAck", "RSeq", "User-Agent", "v", "k", "l",
])
def test_a_header_siphon_writes_is_refused_and_nothing_is_sent(harness, owned):
    import siphon

    with pytest.raises(ValueError, match="b2bua.reoffer"):
        asyncio.run(siphon.b2bua.reoffer("group@example.com", headers={owned: "x"}))
    assert harness.b2bua.reoffers == []


def test_what_cannot_be_sent_is_refused(harness):
    import siphon

    reoffer = siphon.b2bua.reoffer
    with pytest.raises(TypeError):
        asyncio.run(reoffer("group@example.com", headers={"X-Number": 5}))
    with pytest.raises(ValueError, match="not a SIP header name"):
        asyncio.run(reoffer("group@example.com", headers={"Not A Name": "x"}))
    with pytest.raises(ValueError, match="line break"):
        asyncio.run(reoffer("group@example.com", headers={"X-Split": "a\r\nVia: b"}))
    with pytest.raises(ValueError, match="go together"):
        asyncio.run(reoffer("group@example.com", body="<info/>"))
    with pytest.raises(ValueError, match="empty"):
        asyncio.run(reoffer("group@example.com", body=b"", content_type="text/plain"))
    with pytest.raises(ValueError, match="pass one"):
        asyncio.run(reoffer("group@example.com", sdp="v=0\r\n", body="v=0\r\n",
                            content_type="application/sdp"))
    with pytest.raises(ValueError, match="boundary"):
        asyncio.run(reoffer("group@example.com", body="--b--\r\n",
                            content_type="multipart/mixed"))
    assert harness.b2bua.reoffers == []
