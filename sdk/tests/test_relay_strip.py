"""
Tests for ``strip=`` on ``request.relay`` / ``request.fork``: header fields
left off the forwarded request only.
"""

import pytest

from siphon_sdk.request import Request


def _request():
    return Request(method="INVITE", ruri="sip:bob@example.com")


class TestRelayStrip:
    def test_relay_records_the_names(self):
        request = _request()
        request.relay(strip=[" P-Charging-Vector ", "P-Charging-Function-Addresses"])
        assert request._actions[0].extras["strip"] == [
            "P-Charging-Vector", "P-Charging-Function-Addresses"]

    def test_relay_without_strip_leaves_extras_none(self):
        request = _request()
        request.relay()
        assert request._actions[0].extras is None

    def test_fork_records_the_names_beside_send_socket(self):
        request = _request()
        request.fork(["sip:a@host"], send_socket="udp:10.0.0.1:5060",
                     strip=["P-Charging-Vector"])
        extras = request._actions[0].extras
        assert extras == {"send_socket": "udp:10.0.0.1:5060",
                          "strip": ["P-Charging-Vector"]}

    @pytest.mark.parametrize("name", ["Via", "route", "Call-ID", "CSeq", "To",
                                      "f", "Max-Forwards", "", "X: y"])
    def test_refused_names_raise(self, name):
        with pytest.raises(ValueError):
            _request().relay(strip=[name])
        with pytest.raises(ValueError):
            _request().fork(["sip:a@host"], strip=[name])

    def test_a_bare_string_is_refused(self):
        with pytest.raises(TypeError):
            _request().relay(strip="P-Charging-Vector")
