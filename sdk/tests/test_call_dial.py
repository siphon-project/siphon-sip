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


class TestCallDialRoute:
    """``route=`` entries reach the wire as one name-addr each (RFC 3261
    §20.34), whatever form the script writes them in."""

    def _route(self, entries):
        call = Call()
        call.dial("sip:1000@ims.example.org", route=entries)
        return call._actions[0].extras["route"]

    def test_a_bare_uri_keeps_its_parameters_inside_the_brackets(self):
        assert self._route(["sip:orig@198.51.100.7:6060;lr;odi=abc"]) == [
            "<sip:orig@198.51.100.7:6060;lr;odi=abc>",
        ]

    def test_a_bracketed_uri_is_kept_as_written(self):
        assert self._route(["<sip:198.51.100.7;lr>"]) == ["<sip:198.51.100.7;lr>"]

    def test_a_name_addr_keeps_its_display_name_and_parameters(self):
        assert self._route(['"First, hop" <sip:198.51.100.7;lr>;hop=1']) == [
            '"First, hop" <sip:198.51.100.7;lr>;hop=1',
        ]

    def test_a_received_route_value_is_taken_apart_at_its_commas(self):
        assert self._route([
            "sip:[2001:db8::7]:5060;lr",
            "<sip:edge.example.com;lr>, Core <sip:1,2@core.example.com;lr>",
        ]) == [
            "<sip:[2001:db8::7]:5060;lr>",
            "<sip:edge.example.com;lr>",
            "Core <sip:1,2@core.example.com;lr>",
        ]

    def test_no_route_is_an_empty_route_set(self):
        assert self._route(None) == []
        assert self._route([]) == []

    @pytest.mark.parametrize("entry", [
        "",
        "198.51.100.7:5060;lr",
        "tel:+15550100",
        "<urn:service:sos>",
        "<sip:edge.example.com;lr",
        "<sip:edge.example.com;lr> trailing",
        "sip:edge.example.com garbage",
    ])
    def test_an_entry_that_is_no_sip_uri_raises_and_dials_nothing(self, entry):
        call = Call()
        with pytest.raises(ValueError, match="route entry|is empty"):
            call.dial("sip:1000@ims.example.org", route=["<sip:ok.example.com;lr>", entry])
        assert call._actions == []


class TestLooseRouteEntry:
    """``request.prepend_route()`` / ``add_path()`` write ``<uri;lr>`` once."""

    @pytest.mark.parametrize("given, written", [
        ("sip:proxy.example.com", "<sip:proxy.example.com;lr>"),
        ("sip:proxy.example.com;lr", "<sip:proxy.example.com;lr>"),
        ("<sip:proxy.example.com;lr>", "<sip:proxy.example.com;lr>"),
        ("<sip:proxy.example.com>", "<sip:proxy.example.com;lr>"),
        ("sip:proxy.example.com;LR;transport=tcp", "<sip:proxy.example.com;LR;transport=tcp>"),
        ("sip:proxy.example.com;lrid=1", "<sip:proxy.example.com;lrid=1;lr>"),
        ('"Edge, one" <sip:proxy.example.com:5060>;hop=1',
         '"Edge, one" <sip:proxy.example.com:5060;lr>;hop=1'),
    ])
    def test_prepend_route_and_add_path(self, given, written):
        from siphon_sdk.request import Request

        request = Request()
        request.remove_header("Route")
        request.prepend_route(given)
        assert request.get_header("Route") == written
        request.remove_header("Path")
        request.add_path(given)
        assert request.get_header("Path") == written

    def test_prepend_route_goes_in_front_of_what_is_there(self):
        from siphon_sdk.request import Request

        request = Request()
        request.set_header("Route", "<sip:second.example.com;lr>")
        request.prepend_route("sip:first.example.com")
        assert request.get_header("Route") == (
            "<sip:first.example.com;lr>, <sip:second.example.com;lr>"
        )
