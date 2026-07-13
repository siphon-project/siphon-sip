"""
Tests for ``Call.dial`` — including the ``next_hop`` kwarg that decouples
R-URI construction from the wire-routing destination (IMS BGCF / I-CSCF
edge case).
"""

import pytest

from siphon_sdk.call import Call


class TestCallDial:
    def test_dial_basic(self):
        call = Call()
        call.dial("sip:bob@10.0.0.2:5060")
        assert len(call._actions) == 1
        action = call._actions[0]
        assert action.kind == "dial"
        assert action.targets == ["sip:bob@10.0.0.2:5060"]
        assert action.timeout == 30
        assert action.next_hop is None

    def test_dial_custom_timeout(self):
        call = Call()
        call.dial("sip:bob@10.0.0.2:5060", timeout=60)
        action = call._actions[0]
        assert action.timeout == 60
        assert action.next_hop is None

    def test_dial_next_hop_kwarg(self):
        # IMS BGCF: stamp canonical home-domain IMPU on R-URI, route via I-CSCF.
        call = Call()
        call.dial(
            "sip:1000@ims.mnc001.mcc001.3gppnetwork.org",
            next_hop="sip:192.0.2.111:4060",
        )
        action = call._actions[0]
        assert action.kind == "dial"
        # `target` is what drives the B-leg R-URI host (preserves IMPU shape).
        assert action.targets == ["sip:1000@ims.mnc001.mcc001.3gppnetwork.org"]
        # `next_hop` is what the dispatcher resolves for the wire destination.
        assert action.next_hop == "sip:192.0.2.111:4060"

    def test_dial_next_hop_with_timeout(self):
        call = Call()
        call.dial(
            "sip:1000@ims.example.org",
            timeout=15,
            next_hop="sip:icscf.ims.example.org:5060",
        )
        action = call._actions[0]
        assert action.timeout == 15
        assert action.next_hop == "sip:icscf.ims.example.org:5060"
        assert action.targets == ["sip:1000@ims.example.org"]

    def test_dial_header_policy_and_deltas(self):
        # Header policy + per-call deltas — the BGCF MT INVITE case that
        # motivated the opt-in policy work.  Verify the mock captures
        # everything the dispatcher will need to resolve.
        call = Call()
        call.dial(
            "sip:5111@ims.mnc090.mcc208.3gppnetwork.org",
            header_policy="ims-trust-domain-boundary@2026",
            copy=["X-Operator-Tag"],
            strip=["History-Info"],
            translate=[("Diversion", "rfc7044")],
        )
        action = call._actions[0]
        assert action.kind == "dial"
        assert action.extras["header_policy"] == "ims-trust-domain-boundary@2026"
        assert action.extras["copy"] == ["X-Operator-Tag"]
        assert action.extras["strip"] == ["History-Info"]
        assert action.extras["translate"] == [("Diversion", "rfc7044")]

    def test_dial_no_policy_kwargs_keeps_extras_defaulted(self):
        # Existing scripts must continue to work — calling dial() without any
        # policy kwarg should not raise and should leave reasonable defaults.
        call = Call()
        call.dial("sip:bob@10.0.0.2:5060")
        action = call._actions[0]
        assert action.extras["header_policy"] is None
        assert action.extras["copy"] == []
        assert action.extras["strip"] == []
        assert action.extras["translate"] == []
        assert action.extras["send_socket"] is None

    def test_dial_send_socket_pin(self):
        # Force-send-socket egress pin (multi-homed host).
        call = Call()
        call.dial("sip:bob@10.0.0.2:5060", send_socket="udp:10.0.0.1:5060")
        action = call._actions[0]
        assert action.extras["send_socket"] == "udp:10.0.0.1:5060"

    def test_dial_send_socket_malformed_raises(self):
        call = Call()
        with pytest.raises(ValueError):
            call.dial("sip:bob@10.0.0.2:5060", send_socket="10.0.0.1:5060")
        with pytest.raises(ValueError):
            call.dial("sip:bob@10.0.0.2:5060", send_socket="udp:not-an-addr")
        with pytest.raises(ValueError):
            call.dial("sip:bob@10.0.0.2:5060", send_socket="pigeon:10.0.0.1:5060")
        # A well-formed IPv6 pin is accepted.
        call.dial("sip:bob@10.0.0.2:5060", send_socket="tls:[2001:db8::1]:5061")
        assert call._actions[-1].extras["send_socket"] == "tls:[2001:db8::1]:5061"
