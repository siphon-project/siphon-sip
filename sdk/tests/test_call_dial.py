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
            next_hop="sip:192.0.2.178:4060",
        )
        action = call._actions[0]
        assert action.kind == "dial"
        # `target` is what drives the B-leg R-URI host (preserves IMPU shape).
        assert action.targets == ["sip:1000@ims.mnc001.mcc001.3gppnetwork.org"]
        # `next_hop` is what the dispatcher resolves for the wire destination.
        assert action.next_hop == "sip:192.0.2.178:4060"

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


class TestCallMaxDuration:
    """``timeout`` bounds the ring, ``max_duration`` bounds the talk.

    Two clocks, deliberately independent: ``timeout`` stops mattering the
    moment a 2xx lands, and before ``max_duration`` existed nothing bounded an
    answered call except a peer BYE or an RFC 4028 session timer.
    """

    def test_dial_records_max_duration_alongside_timeout(self):
        call = Call()
        call.dial("sip:bob@10.0.0.2:5060", timeout=30, max_duration=3600)
        action = call._actions[0]
        assert action.timeout == 30
        assert action.extras["max_duration"] == 3600
        assert call.max_duration == 3600

    def test_dial_without_max_duration_inherits_the_config(self):
        call = Call()
        call.dial("sip:bob@10.0.0.2:5060")
        assert call._actions[0].extras["max_duration"] is None
        assert call.max_duration is None

    def test_zero_is_an_opt_out_not_an_absent_value(self):
        # 0 is how a call escapes a configured b2bua.max_call_duration_secs,
        # so it has to survive as a value rather than collapsing into None.
        call = Call()
        call.dial("sip:bob@10.0.0.2:5060", max_duration=0)
        assert call._actions[0].extras["max_duration"] == 0
        assert call.max_duration == 0

    def test_fork_and_route_take_max_duration_too(self):
        forked = Call()
        forked.fork(["sip:bob@10.0.0.2:5060", "sip:bob@10.0.0.3:5060"],
                    timeout=20, max_duration=1800)
        assert forked._actions[0].extras["max_duration"] == 1800
        assert forked._actions[0].timeout == 20
        assert forked.max_duration == 1800

        from siphon_sdk.lcr import Route

        routed = Call()
        routed.route([Route(carrier_id="carrier-a", next_hop="sip:10.0.0.9:5060")],
                     timeout=12, max_duration=900)
        assert routed._actions[0].extras["max_duration"] == 900
        assert routed.max_duration == 900

    def test_set_max_duration_caps_a_call_that_never_dials(self):
        # A UAS-mode answer or a handover never calls dial/fork/route, so this
        # is the only per-call cap available to it.
        call = Call()
        assert call.max_duration is None
        call.set_max_duration(600)
        assert call.max_duration == 600
        call.set_max_duration(0)
        assert call.max_duration == 0
