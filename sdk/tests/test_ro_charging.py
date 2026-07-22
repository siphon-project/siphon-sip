"""Tests for the Ro (RFC 8506 / 3GPP TS 32.299 online charging) mock surface.

The Diameter client is async (``await diameter.ro_ccr_*`` / ``await
call.ro_authorize()``); the sync tests drive the coroutines with
``asyncio.run``.
"""

import asyncio

from siphon_sdk import mock_module
from siphon_sdk.call import Call


def run(coro):
    return asyncio.run(coro)


class TestRoMock:
    def setup_method(self):
        mock_module.install()
        mock_module.reset()
        self.diameter = mock_module.get_diameter()
        self.diameter.add_peer("ocs1", connected=True)

    def test_ccr_initial_returns_session_and_grant(self):
        from siphon import diameter
        result = run(diameter.ro_ccr_initial(
            "+310000000001",
            requested_seconds=30,
            rating_group=100,
            calling_party="sip:alice@ims.example.com",
            called_party="sip:bob@ims.example.com",
            sip_method="INVITE",
            role_of_node="originating",
            node_functionality="pcscf",
        ))
        assert result is not None
        assert result["result_code"] == 2001
        assert result["session_id"]
        assert result["request_number"] == 0
        assert result["granted_time"] == 30

    def test_scur_session_continuity(self):
        from siphon import diameter
        initial = run(diameter.ro_ccr_initial("+310000000001", requested_seconds=30))
        sid = initial["session_id"]

        update = run(diameter.ro_ccr_update(
            "+310000000001", sid, 1, used_seconds=30, requested_seconds=30
        ))
        assert update["session_id"] == sid
        assert update["request_number"] == 1

        term = run(diameter.ro_ccr_terminate("+310000000001", sid, 2, used_seconds=12))
        assert term["session_id"] == sid
        assert term["request_number"] == 2

        # All three CCRs share one Session-Id with monotonic request numbers.
        ccrs = self.diameter.captured_ccrs()
        assert [c["request_type"] for c in ccrs] == ["INITIAL", "UPDATE", "TERMINATION"]
        assert {c["session_id"] for c in ccrs} == {sid}

    def test_setup_denied_credit_limit_reached(self):
        from siphon import diameter
        self.diameter.set_ro_result_code(4012)  # DIAMETER_CREDIT_LIMIT_REACHED
        result = run(diameter.ro_ccr_initial("+310000000001", requested_seconds=30))
        assert result["result_code"] == 4012
        assert result["granted_time"] is None

    def test_final_unit_action_terminate(self):
        from siphon import diameter
        self.diameter.set_ro_final_unit_action(0)  # TERMINATE
        result = run(diameter.ro_ccr_initial("+310000000001", requested_seconds=30))
        assert result["final_unit_action"] == 0

    def test_iec_event_debit_and_deny(self):
        from siphon import diameter
        ok = run(diameter.ro_ccr_event(
            "+310000000001",
            service_context_id="32274@3gpp.org",
            originator_address="+310000000001",
            recipient_address="+310000000002",
            sm_message_type=0,
        ))
        assert ok["result_code"] == 2001

        self.diameter.set_ro_result_code(4012)
        denied = run(diameter.ro_ccr_event(
            "+310000000001", service_context_id="32274@3gpp.org"
        ))
        assert denied["result_code"] == 4012

        events = [c for c in self.diameter.captured_ccrs() if c["request_type"] == "EVENT"]
        assert len(events) == 2
        assert events[0]["requested_action"] == 0  # DIRECT_DEBITING

    def test_subscription_id_type_variants(self):
        from siphon import diameter
        run(diameter.ro_ccr_initial("001010000000001", subscription_id_type="imsi"))
        run(diameter.ro_ccr_initial("sip:alice@ims", subscription_id_type="sip"))
        types = [c.get("subscription_id_type") for c in self.diameter.captured_ccrs()]
        assert types == ["imsi", "sip"]


class TestRoAuthorizeGate:
    """The reserve-before-connect gate: grant -> dial, deny -> reject + no dial."""

    async def _on_invite(self, call):
        decision = await call.ro_authorize()
        if not decision["authorized"]:
            call.reject(402, "Payment Required")
            return
        call.dial("sip:bob@carrier.example.com")

    def test_grant_dials_bleg(self):
        call = Call(from_uri="sip:alice@ims.example.com", to_uri="sip:bob@ims.example.com")
        run(self._on_invite(call))
        kinds = [a.kind for a in call.actions]
        assert "dial" in kinds
        assert "reject" not in kinds
        # The gate was consulted exactly once before the dial.
        assert len(call.ro_authorizations) == 1

    def test_denied_rejects_and_does_not_dial(self):
        call = Call(from_uri="sip:alice@ims.example.com", to_uri="sip:bob@ims.example.com")
        call.set_ro_authorize_result(False, result_code=4012)
        run(self._on_invite(call))
        kinds = [a.kind for a in call.actions]
        assert "reject" in kinds
        assert "dial" not in kinds

    def test_authorize_records_subscription_override(self):
        call = Call()
        run(call.ro_authorize(subscription_id="sip:alice@ims", subscription_id_type="sip"))
        assert call.ro_authorizations[-1] == {
            "subscription_id": "sip:alice@ims",
            "subscription_id_type": "sip",
        }
