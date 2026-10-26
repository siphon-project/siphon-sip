"""
Tests for ``no_response_ms=`` on ``request.relay`` / ``request.fork``: a bound
on a branch drawing any response, below Timer B / Timer F, and for
``fork(on_reply=…, on_failure=…)``.
"""

import pytest

from siphon_sdk.request import Request


def _request(method="INVITE"):
    return Request(method=method, ruri="sip:bob@example.com")


class TestRelayNoResponse:
    def test_relay_records_the_bound(self):
        request = _request()
        request.relay("sip:next@192.0.2.20", no_response_ms=4000)
        assert request._actions[0].extras == {"no_response_ms": 4000}

    def test_relay_without_a_bound_leaves_extras_none(self):
        request = _request()
        request.relay()
        assert request._actions[0].extras is None

    def test_fork_records_the_bound_and_the_callbacks(self):
        def failed(request, code, reason):
            pass

        def replied(request, reply):
            pass

        request = _request()
        request.fork(["sip:a@host", "sip:b@host"], no_response_ms=1500,
                     on_reply=replied, on_failure=failed)
        assert request._actions[0].extras == {"no_response_ms": 1500}
        assert request._on_failure_callback is failed
        assert request._on_reply_callback is replied

    def test_just_below_the_transaction_timeout_is_accepted(self):
        _request().relay(no_response_ms=31_999)
        _request("MESSAGE").relay(no_response_ms=31_999)

    @pytest.mark.parametrize("method,timer", [("INVITE", "Timer B"), ("MESSAGE", "Timer F")])
    @pytest.mark.parametrize("bound", [32_000, 60_000])
    def test_at_or_over_the_transaction_timeout_is_refused(self, method, timer, bound):
        with pytest.raises(ValueError, match=timer):
            _request(method).relay(no_response_ms=bound)
        with pytest.raises(ValueError, match=timer):
            _request(method).fork(["sip:a@host"], no_response_ms=bound)

    @pytest.mark.parametrize("bound", [0, -1])
    def test_a_bound_that_is_not_positive_is_refused(self, bound):
        with pytest.raises(ValueError, match="positive"):
            _request().relay(no_response_ms=bound)

    def test_an_ack_is_refused(self):
        with pytest.raises(ValueError, match="ACK"):
            _request("ACK").relay(no_response_ms=1000)

    def test_a_non_integer_is_refused(self):
        with pytest.raises(TypeError):
            _request().relay(no_response_ms=1.5)
