"""Tests for ``call.failure_response`` in ``@b2bua.on_failure``. Mirrors the
Rust ``PyCall::failure_response`` / ``FailureResponse``.
"""

from siphon_sdk.call import Call
from siphon_sdk.types import FailureResponse


class TestFailureResponse:
    def test_none_by_default(self):
        assert Call().failure_response is None

    def test_shows_the_legs_own_response(self):
        response = FailureResponse(
            503, "Service Unavailable",
            headers={"Reason": "FAILURE_CAUSE;cause=2",
                     "X-Carrier": ["one", "two"]},
        )
        call = Call(failure_response=response)
        shown = call.failure_response
        assert shown.status_code == 503
        assert shown.reason == "Service Unavailable"
        assert shown.get_header("reason") == "FAILURE_CAUSE;cause=2"
        assert shown.get_headers("X-Carrier") == ["one", "two"]
        assert shown.get_headers("X-Absent") == []
        assert shown.get_header("X-Absent") is None
        assert shown.body is None
        assert shown.content_type is None
        assert repr(shown) == "<FailureResponse 503 Service Unavailable>"

    def test_body_and_content_type(self):
        response = FailureResponse(
            488, "Not Acceptable Here",
            headers={"Content-Type": "application/sdp"},
            body="v=0\r\nm=video 0 RTP/AVP 96\r\n",
        )
        assert response.body == b"v=0\r\nm=video 0 RTP/AVP 96\r\n"
        assert response.content_type == "application/sdp"

    def test_docstring_example_breaks_out_on_a_488_without_audio(self):
        def failed(call, code, reason):
            response = call.failure_response
            if response is None:
                return
            cause = response.get_header("Reason") or ""
            no_audio = (response.status_code == 488
                        and b"m=audio" not in (response.body or b""))
            if no_audio or (response.status_code == 500
                            and "FAILURE_CAUSE;cause=2" in cause):
                call.dial("sip:breakout@cs.example.com")

        no_audio = Call(failure_response=FailureResponse(
            488, "Not Acceptable Here", body=b"v=0\r\nm=video 0 RTP/AVP 96\r\n"))
        failed(no_audio, 488, "Not Acceptable Here")
        assert no_audio._actions[-1].kind == "dial"

        timed_out = Call()
        failed(timed_out, 408, "Request Timeout")
        assert timed_out._actions == []
