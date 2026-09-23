"""Tests for IMS CSCF example scripts using MockHss and MockPcrf."""
import asyncio
from pathlib import Path
import pytest
from siphon_sdk.testing import SipTestHarness


def run(coro):
    return asyncio.run(coro)

# Resolve example script paths relative to repo root (tests run from sdk/).
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PCSCF_SCRIPT = str(_REPO_ROOT / "examples" / "ims_pcscf.py")
_ICSCF_SCRIPT = str(_REPO_ROOT / "examples" / "ims_icscf.py")
_SCSCF_SCRIPT = str(_REPO_ROOT / "examples" / "ims_scscf.py")

REALM = "ims.example.com"
SCSCF_URI = "sip:scscf.ims.example.com:6060"


# ---------------------------------------------------------------------------
# P-CSCF tests
# ---------------------------------------------------------------------------

class TestPcscf:
    """P-CSCF: relays REGISTER to S-CSCF and handles IPsec sec-agree on the
    401 reply path.  The P-CSCF itself never authenticates — that's S-CSCF's
    job — so the registration tests here assert relay behaviour, not 200.
    """

    _SECURITY_CLIENT = (
        "ipsec-3gpp;alg=hmac-sha-1-96;spi-c=1000;spi-s=1001;"
        "port-c=5064;port-s=5066"
    )

    def setup_method(self):
        self.harness = SipTestHarness(local_domains=[REALM, "192.0.2.10"])
        self.harness.auth._allow = True
        self.harness.load_script(_PCSCF_SCRIPT)

    def test_register_with_security_client_relays_to_scscf(self):
        result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            source_ip="10.0.0.1",
            headers={"Security-Client": self._SECURITY_CLIENT},
        )
        assert result.was_relayed
        assert result.record_routed

    def test_register_rejects_without_security_client(self):
        """REGISTER without Security-Client gets 421 Extension Required."""
        result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
        )
        assert result.status_code == 421
        require = result.request.get_reply_header("Require")
        assert require == "sec-agree"

    def test_register_rejects_malformed_security_client(self):
        """Security-Client without required SPIs/ports parses as empty → 421."""
        result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            headers={"Security-Client": "ipsec-3gpp;alg=hmac-sha-1-96"},
        )
        assert result.status_code == 421

    def test_401_reply_strips_ck_ik_and_injects_security_server(self):
        """The on_reply handler should consume CK/IK from S-CSCF's 401 and
        inject a Security-Server header before forwarding to the UE."""
        # First send a REGISTER so the on_reply handler has the matching
        # request context (Security-Client offers).
        request_result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            source_ip="10.0.0.1",
            call_id="alice-401-flow@10.0.0.1",
            headers={"Security-Client": self._SECURITY_CLIENT},
        )
        assert request_result.was_relayed

        # Now simulate the S-CSCF's 401 with CK/IK in WWW-Authenticate.
        ck_hex = "0123456789abcdef0123456789abcdef"
        ik_hex = "fedcba9876543210fedcba9876543210"
        www_auth = (
            f'Digest realm="{REALM}", nonce="abc", algorithm=AKAv1-MD5, '
            f'ck="{ck_hex}", ik="{ik_hex}", qop="auth"'
        )
        reply_result = self.harness.send_reply(
            request=request_result.request,
            status_code=401,
            reason="Unauthorized",
            headers={"WWW-Authenticate": www_auth},
        )
        # Verify the script forwarded the reply.
        assert any(a.kind == "relay" for a in reply_result.actions)
        # The injected Security-Server header should be present.
        security_server = reply_result.reply.get_header("Security-Server")
        assert security_server is not None
        assert "ipsec-3gpp" in security_server
        assert "hmac-sha-1-96" in security_server
        assert "port-c=5064" in security_server
        assert "port-s=5066" in security_server
        # And ck=/ik= must be gone from the upstream WWW-Authenticate.
        rewritten = reply_result.reply.get_header("WWW-Authenticate")
        assert rewritten is not None
        assert "ck=" not in rewritten
        assert "ik=" not in rewritten

    def test_options_local(self):
        result = self.harness.send_request(
            "OPTIONS", f"sip:{REALM}",
        )
        assert result.status_code == 200

    def test_invite_no_contacts_relays(self):
        """INVITE for unknown user relays toward S-CSCF."""
        result = self.harness.send_request(
            "INVITE", f"sip:bob@{REALM}",
            from_uri=f"sip:alice@{REALM}",
        )
        # No local contacts -> relay toward S-CSCF
        assert result.was_relayed
        assert result.record_routed

    def test_subscribe_relays(self):
        result = self.harness.send_request(
            "SUBSCRIBE", f"sip:alice@{REALM}",
            from_uri=f"sip:bob@{REALM}",
        )
        assert result.was_relayed


# ---------------------------------------------------------------------------
# I-CSCF tests
# ---------------------------------------------------------------------------

class TestIcscf:
    """I-CSCF: Diameter Cx UAR/LIR for S-CSCF discovery."""

    def setup_method(self):
        self.harness = SipTestHarness(local_domains=[REALM, "192.0.2.20"])
        self.hss = self.harness.hss
        self.hss.add_subscriber(
            impi=f"alice@{REALM}",
            impu=f"sip:alice@{REALM}",
            server_name=SCSCF_URI,
        )
        self.harness.load_script(_ICSCF_SCRIPT)

    def test_register_routes_to_scscf_via_uar(self):
        result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
        )
        assert result.was_relayed
        assert result.next_hop == SCSCF_URI

    def test_invite_routes_to_scscf_via_lir(self):
        result = self.harness.send_request(
            "INVITE", f"sip:alice@{REALM}",
            from_uri=f"sip:bob@{REALM}",
        )
        assert result.was_relayed
        assert result.next_hop == SCSCF_URI

    def test_options_local(self):
        result = self.harness.send_request(
            "OPTIONS", f"sip:{REALM}",
        )
        assert result.status_code == 200

    def test_max_forwards_zero(self):
        result = self.harness.send_request(
            "INVITE", f"sip:alice@{REALM}",
            from_uri=f"sip:bob@{REALM}",
            max_forwards=0,
        )
        assert result.status_code == 483

    def test_register_unknown_user_uses_fallback(self):
        """Unknown user still routes via fallback S-CSCF."""
        result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:unknown@{REALM}",
        )
        # The script has SCSCF_FALLBACK set, so even unknown users get routed
        assert result.was_relayed

    def test_uar_log_messages(self):
        """Verify UAR success is logged."""
        self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
        )
        log_messages = [msg for _, msg in self.harness.log.messages]
        assert any("UAR" in msg for msg in log_messages)


# ---------------------------------------------------------------------------
# S-CSCF tests
# ---------------------------------------------------------------------------

class TestScscf:
    """S-CSCF: auth + SAR + registrar + location lookup."""

    def setup_method(self):
        self.harness = SipTestHarness(local_domains=[REALM, "192.0.2.30"])
        self.hss = self.harness.hss
        self.hss.add_subscriber(
            impi=f"alice@{REALM}",
            impu=f"sip:alice@{REALM}",
            server_name=SCSCF_URI,
        )
        self.hss.add_subscriber(
            impi=f"bob@{REALM}",
            impu=f"sip:bob@{REALM}",
            server_name=SCSCF_URI,
        )
        self.harness.load_script(_SCSCF_SCRIPT)

    def test_register_success(self):
        result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            auth_user="alice",
        )
        assert result.status_code == 200

    def test_register_sets_service_route(self):
        result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            auth_user="alice",
        )
        assert result.status_code == 200
        service_route = result.request.get_reply_header("Service-Route")
        assert service_route is not None
        assert "orig" in service_route

    def test_register_sets_p_associated_uri(self):
        result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            auth_user="alice",
        )
        assert result.status_code == 200
        pai = result.request.get_reply_header("P-Associated-URI")
        assert pai is not None
        assert "alice" in pai

    def test_register_sends_sar(self):
        """Verify SAR is sent to HSS during registration."""
        self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            auth_user="alice",
        )
        log_messages = [msg for _, msg in self.harness.log.messages]
        assert any("SAR" in msg for msg in log_messages)

    def test_register_stores_service_routes(self):
        """Verify service routes are stored in registrar."""
        self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            auth_user="alice",
        )
        routes = self.harness.registrar.service_route(f"sip:alice@{REALM}")
        assert len(routes) > 0
        assert any("orig" in route for route in routes)

    def test_register_auth_challenge(self):
        self.harness.auth._allow = False
        result = self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
        )
        assert result.status_code == 401

    def test_invite_to_registered_user(self):
        # First register alice
        self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            auth_user="alice",
        )
        # Then INVITE alice
        result = self.harness.send_request(
            "INVITE", f"sip:alice@{REALM}",
            from_uri=f"sip:bob@{REALM}",
        )
        assert result.was_relayed or result.was_forked
        assert result.record_routed

    def test_invite_unregistered_user_404(self):
        result = self.harness.send_request(
            "INVITE", f"sip:unknown@{REALM}",
            from_uri=f"sip:bob@{REALM}",
        )
        assert result.status_code == 404

    def test_options_local(self):
        result = self.harness.send_request(
            "OPTIONS", f"sip:{REALM}",
        )
        assert result.status_code == 200

    def test_subscribe_reg_event(self):
        result = self.harness.send_request(
            "SUBSCRIBE", f"sip:alice@{REALM}",
            from_uri=f"sip:alice@{REALM}",
            event="reg",
        )
        assert result.status_code == 200

    def test_subscribe_reg_sends_initial_notify(self):
        """SUBSCRIBE for reg event should trigger initial NOTIFY with reginfo XML."""
        result = self.harness.send_request(
            "SUBSCRIBE", f"sip:alice@{REALM}",
            from_uri=f"sip:as@{REALM}",
            event="reg",
        )
        assert result.status_code == 200
        # Check that a NOTIFY was sent via proxy.send_request
        sent = self.harness.proxy.sent_requests
        assert len(sent) >= 1
        notify = sent[-1]
        assert notify["method"] == "NOTIFY"
        assert notify["headers"]["Event"] == "reg"
        assert notify["headers"]["Content-Type"] == "application/reginfo+xml"
        assert "reginfo" in notify["body"]
        assert "version" in notify["body"]

    def test_subscribe_reg_stores_subscription(self):
        """SUBSCRIBE for reg event should store subscription in presence store."""
        self.harness.send_request(
            "SUBSCRIBE", f"sip:alice@{REALM}",
            from_uri=f"sip:as@{REALM}",
            event="reg",
        )
        subs = list(self.harness.presence.subscribers(f"sip:alice@{REALM}"))
        assert len(subs) >= 1
        assert any(s.get("event") == "reg" for s in subs)

    def test_registration_change_notifies_subscribers(self):
        """When registration state changes, all reg event subscribers get NOTIFY."""
        # First subscribe an AS for reg events on alice
        self.harness.send_request(
            "SUBSCRIBE", f"sip:alice@{REALM}",
            from_uri=f"sip:as@{REALM}",
            event="reg",
        )
        initial_sent_count = len(self.harness.proxy.sent_requests)

        # Now register alice — this should trigger on_change → NOTIFY
        # to_uri must match the SUBSCRIBE AoR so on_change finds the subscriber
        self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            to_uri=f"sip:alice@{REALM}",
            auth_user="alice",
        )
        # on_change should fire and send NOTIFY to subscriber
        sent = self.harness.proxy.sent_requests[initial_sent_count:]
        notify_msgs = [s for s in sent if s["method"] == "NOTIFY"]
        assert len(notify_msgs) >= 1
        assert "reginfo" in notify_msgs[0]["body"]

    def test_reginfo_xml_contains_contacts(self):
        """registrar.reginfo_xml should reflect current contacts."""
        # Register alice (to_uri = AoR for REGISTER)
        self.harness.send_request(
            "REGISTER", f"sip:{REALM}",
            from_uri=f"sip:alice@{REALM}",
            to_uri=f"sip:alice@{REALM}",
            auth_user="alice",
        )
        xml = self.harness.registrar.reginfo_xml(f"sip:alice@{REALM}")
        assert "reginfo" in xml
        assert "active" in xml
        assert "alice" in xml

    def test_reginfo_xml_empty_aor(self):
        """reginfo_xml for unknown AoR shows terminated registration."""
        xml = self.harness.registrar.reginfo_xml(f"sip:nobody@{REALM}")
        assert "reginfo" in xml
        assert "terminated" in xml

    def test_max_forwards_zero(self):
        result = self.harness.send_request(
            "INVITE", f"sip:alice@{REALM}",
            from_uri=f"sip:bob@{REALM}",
            max_forwards=0,
        )
        assert result.status_code == 483


# ---------------------------------------------------------------------------
# MockHss tests
# ---------------------------------------------------------------------------

class TestMockHss:
    """Test the MockHss convenience class itself."""

    def setup_method(self):
        self.harness = SipTestHarness(local_domains=[REALM])

    def test_add_subscriber_configures_uar(self):
        self.harness.hss.add_subscriber(
            impi="alice", impu="sip:alice@example.com",
            server_name="sip:scscf:6060",
        )
        result = run(self.harness.diameter.cx_uar("sip:alice@example.com"))
        assert result is not None
        assert result["result_code"] == 2001
        assert result["server_name"] == "sip:scscf:6060"

    def test_add_subscriber_configures_lir(self):
        self.harness.hss.add_subscriber(
            impi="alice", impu="sip:alice@example.com",
            server_name="sip:scscf:6060",
        )
        result = run(self.harness.diameter.cx_lir("sip:alice@example.com"))
        assert result is not None
        assert result["server_name"] == "sip:scscf:6060"

    def test_add_subscriber_configures_sar(self):
        self.harness.hss.add_subscriber(
            impi="alice", impu="sip:alice@example.com",
            ifc_xml="<ServiceProfile><InitialFilterCriteria/></ServiceProfile>",
        )
        result = run(self.harness.diameter.cx_sar("sip:alice@example.com"))
        assert result is not None
        assert result["result_code"] == 2001
        assert "ServiceProfile" in result["user_data"]

    def test_add_subscriber_enables_auth(self):
        self.harness.hss.add_subscriber(
            impi="alice", impu="sip:alice@example.com",
        )
        assert self.harness.auth._allow is True

    def test_add_subscriber_adds_hss_peer(self):
        self.harness.hss.add_subscriber(
            impi="alice", impu="sip:alice@example.com",
        )
        assert self.harness.diameter.is_connected("hss1")

    def test_remove_subscriber(self):
        self.harness.hss.add_subscriber(
            impi="alice", impu="sip:alice@example.com",
            server_name="sip:scscf:6060",
        )
        self.harness.hss.remove_subscriber("sip:alice@example.com")
        # UAR should now return None (no per-user response, no default)
        result = run(self.harness.diameter.cx_uar("sip:alice@example.com"))
        assert result is None

    def test_subscriber_count(self):
        assert self.harness.hss.subscriber_count() == 0
        self.harness.hss.add_subscriber(
            impi="alice", impu="sip:alice@example.com",
        )
        assert self.harness.hss.subscriber_count() == 1

    def test_clear(self):
        self.harness.hss.add_subscriber(
            impi="alice", impu="sip:alice@example.com",
        )
        self.harness.hss.clear()
        assert self.harness.hss.subscriber_count() == 0
        assert not self.harness.diameter.is_connected("hss1")


# ---------------------------------------------------------------------------
# MockPcrf tests
# ---------------------------------------------------------------------------

class TestMockPcrf:
    """Test the MockPcrf convenience class."""

    def setup_method(self):
        self.harness = SipTestHarness(local_domains=[REALM])

    def test_accept_all(self):
        self.harness.pcrf.accept_all()
        result = run(self.harness.diameter.rx_aar())
        assert result is not None
        assert result["result_code"] == 2001

    def test_reject_all(self):
        self.harness.pcrf.reject_all(result_code=5003)
        result = run(self.harness.diameter.rx_aar())
        assert result is not None
        assert result["result_code"] == 5003

    def test_reject_session(self):
        self.harness.pcrf.accept_all()
        self.harness.pcrf.reject_session("bad-session", result_code=5003)
        # Normal session succeeds
        result = run(self.harness.diameter.rx_aar(session_id="good-session"))
        assert result["result_code"] == 2001
        # Rejected session fails
        result = run(self.harness.diameter.rx_aar(session_id="bad-session"))
        assert result["result_code"] == 5003

    def test_rx_str(self):
        self.harness.pcrf.accept_all()
        result = run(self.harness.diameter.rx_str("session-1"))
        assert result == 2001


# ---------------------------------------------------------------------------
# MockDiameter Cx methods tests
# ---------------------------------------------------------------------------

class TestMockDiameterCx:
    """Test MockDiameter Cx/Rx mock methods directly."""

    def setup_method(self):
        self.harness = SipTestHarness(local_domains=[REALM])
        self.diameter = self.harness.diameter

    def test_cx_uar_no_config_returns_none(self):
        result = run(self.diameter.cx_uar("sip:unknown@example.com"))
        assert result is None

    def test_cx_uar_with_default_server(self):
        self.diameter.set_default_server_name("sip:scscf:6060")
        result = run(self.diameter.cx_uar("sip:anyone@example.com"))
        assert result is not None
        assert result["server_name"] == "sip:scscf:6060"

    def test_cx_sar_default_success(self):
        result = run(self.diameter.cx_sar("sip:alice@example.com"))
        assert result is not None
        assert result["result_code"] == 2001
        assert result["user_data"] is None

    def test_cx_lir_per_user(self):
        self.diameter.set_lir_response(
            "sip:alice@example.com",
            server_name="sip:scscf2:6060",
        )
        result = run(self.diameter.cx_lir("sip:alice@example.com"))
        assert result["server_name"] == "sip:scscf2:6060"

    def test_rx_aar_default(self):
        result = run(self.diameter.rx_aar())
        assert result is not None
        assert result["result_code"] == 2001
        assert "session_id" in result

    def test_clear_resets_all(self):
        self.diameter.add_peer("hss1")
        self.diameter.set_default_server_name("sip:scscf:6060")
        self.diameter.set_uar_response("sip:alice@x", server_name="sip:s:6060")
        self.diameter.clear()
        assert not self.diameter.is_connected("hss1")
        assert run(self.diameter.cx_uar("sip:alice@x")) is None


# ---------------------------------------------------------------------------
# MockRegistrar service routes tests
# ---------------------------------------------------------------------------

class TestMockRegistrarServiceRoutes:
    """Test MockRegistrar set_service_routes/service_route."""

    def setup_method(self):
        self.harness = SipTestHarness(local_domains=[REALM])

    def test_set_and_get_service_routes(self):
        routes = ["sip:orig@ims.example.com;lr", "sip:pcscf@ims.example.com;lr"]
        self.harness.registrar.set_service_routes("sip:alice@ims.example.com", routes)
        result = self.harness.registrar.service_route("sip:alice@ims.example.com")
        assert result == routes

    def test_empty_routes_clears(self):
        self.harness.registrar.set_service_routes("sip:alice@x", ["sip:r;lr"])
        self.harness.registrar.set_service_routes("sip:alice@x", [])
        assert self.harness.registrar.service_route("sip:alice@x") == []

    def test_service_route_unknown_uri(self):
        assert self.harness.registrar.service_route("sip:unknown@x") == []

    def test_clear_resets_service_routes(self):
        self.harness.registrar.set_service_routes("sip:alice@x", ["sip:r;lr"])
        self.harness.registrar.clear()
        assert self.harness.registrar.service_route("sip:alice@x") == []
