"""
Tests for the ``send_socket=`` egress pin on ``request.relay`` / ``request.fork``
(the operator equivalent of Kamailio's ``force_send_socket()``).
"""

import pytest

from siphon_sdk.request import Request


def _request():
    return Request(method="INVITE", ruri="sip:bob@example.com")


class TestRelaySendSocket:
    def test_relay_send_socket_pin(self):
        request = _request()
        request.relay(send_socket="udp:10.0.0.1:5060")
        action = request._actions[0]
        assert action.kind == "relay"
        assert action.extras["send_socket"] == "udp:10.0.0.1:5060"

    def test_relay_without_send_socket_leaves_extras_none(self):
        request = _request()
        request.relay()
        assert request._actions[0].extras is None

    def test_relay_send_socket_malformed_raises(self):
        request = _request()
        with pytest.raises(ValueError):
            request.relay(send_socket="10.0.0.1:5060")       # no transport
        with pytest.raises(ValueError):
            request.relay(send_socket="udp:garbage")          # bad addr
        with pytest.raises(ValueError):
            request.relay(send_socket="smoke:10.0.0.1:5060")  # bad transport

    def test_fork_send_socket_pin(self):
        request = _request()
        request.fork(["sip:a@host", "sip:b@host"], send_socket="tcp:10.0.0.1:5060")
        action = request._actions[0]
        assert action.kind == "fork"
        assert action.extras["send_socket"] == "tcp:10.0.0.1:5060"

    def test_fork_send_socket_malformed_raises(self):
        request = _request()
        with pytest.raises(ValueError):
            request.fork(["sip:a@host"], send_socket="not-a-socket")

    def test_ipv6_send_socket_accepted(self):
        request = _request()
        request.relay(send_socket="tls:[2001:db8::1]:5061")
        assert request._actions[0].extras["send_socket"] == "tls:[2001:db8::1]:5061"
