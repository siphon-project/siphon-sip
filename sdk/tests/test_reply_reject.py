"""Unit tests for ``Reply.reject(code, reason)`` — the proxy-side reply-time
reject used by the IMS P-CSCF when media authorization (N5 / Rx) fails at
answer time inside ``@proxy.on_reply``.

Mirrors the Rust ``PyReply::reject`` semantics:
- Provisional (1xx): records the reject, returns ``True`` (siphon then sends the
  error upstream and CANCELs downstream).
- Final (>= 200): no-op, returns ``False`` (a proxy cannot retract a 2xx).
- Code must be in the 400–699 range.
"""
import pytest

from siphon_sdk.reply import Reply


def _provisional(code: int = 183, reason: str = "Session Progress") -> Reply:
    return Reply(
        status_code=code,
        reason=reason,
        from_uri="sip:alice@atlanta.com",
        to_uri="sip:bob@biloxi.com",
        call_id="reject-test-1",
        body=b"v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\n",
        content_type="application/sdp",
    )


def test_reject_on_provisional_records_action_and_returns_true():
    reply = _provisional()
    took = reply.reject(503, "Media Authorization Failed")
    assert took is True
    assert reply.last_action.kind == "reject"
    assert reply.last_action.status_code == 503
    assert reply.last_action.reason == "Media Authorization Failed"


def test_reject_default_reason_when_omitted():
    reply = _provisional(code=180, reason="Ringing")
    assert reply.reject(503) is True
    assert reply.last_action.reason == "Service Unavailable"


def test_reject_on_2xx_is_noop_and_returns_false():
    reply = Reply(status_code=200, reason="OK")
    took = reply.reject(503, "Service Unavailable")
    assert took is False
    # No action recorded — the script must branch on the False return.
    assert reply.actions == []


def test_reject_on_error_final_is_noop():
    reply = Reply(status_code=486, reason="Busy Here")
    assert reply.reject(503) is False
    assert reply.actions == []


@pytest.mark.parametrize("code", [100, 200, 300, 399, 700, 0])
def test_reject_rejects_out_of_range_code(code):
    reply = _provisional()
    with pytest.raises(ValueError):
        reply.reject(code)
    assert reply.actions == []


def test_reject_takes_precedence_over_relay_is_recorded_after():
    """A handler that relays then rejects records both; the dispatcher honours
    the reject. The SDK simply records the order for assertion."""
    reply = _provisional()
    reply.relay()
    assert reply.reject(503) is True
    kinds = [action.kind for action in reply.actions]
    assert kinds == ["relay", "reject"]
