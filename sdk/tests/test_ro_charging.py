"""Tests for the Ro (RFC 8506 / 3GPP TS 32.299 online charging) mock surface.

The Diameter client is async (``await diameter.ro_ccr_*`` / ``await
call.ro_authorize()``); the sync tests drive the coroutines with
``asyncio.run``.
"""

import asyncio

import pytest

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
            "role_of_node": None,
        }

    def test_authorize_records_role_of_node(self):
        call = Call()
        run(call.ro_authorize(role_of_node="terminating"))
        assert call.ro_authorizations[-1]["role_of_node"] == "terminating"

    def test_authorize_rejects_a_role_release_18_does_not_have(self):
        call = Call()
        with pytest.raises(ValueError):
            run(call.ro_authorize(role_of_node="b2bua"))


class TestRoSessionMock:
    def setup_method(self):
        mock_module.install()
        mock_module.reset()
        self.diameter = mock_module.get_diameter()

    def test_two_sessions_are_independent_and_keyed(self):
        from siphon import diameter
        caller = run(diameter.ro_session("sip:+15550100001@ims.example.net",
                                         role_of_node="originating"))
        camel = run(diameter.ro_session(
            "15550100004", subscription_id_type="e164",
            additional_subscription_ids=[("001010000000004", "imsi")],
            key="dialogue-1", metering="external",
            service_context_id="32276@3gpp.org",
            role_of_node="forwarding", node_functionality="proxy",
            vcs_information={"msc_address": "51551000f9"}))
        assert caller.open and camel.open
        assert caller.session_id != camel.session_id
        assert diameter.ro_find("dialogue-1") is camel
        duplicate = run(diameter.ro_session("15550100004", key="dialogue-1"))
        assert not duplicate.authorized

        run(camel.report(30))
        run(camel.terminate(used_total=42, vcs_information={"isup_cause_value": 16}))
        assert not camel.open and caller.open
        assert diameter.ro_find("dialogue-1") is None
        ccrs = [c for c in self.diameter.captured_ccrs() if c["session_id"] == camel.session_id]
        assert [c["request_type"] for c in ccrs] == ["INITIAL", "UPDATE", "TERMINATION"]
        assert [c.get("used_seconds") for c in ccrs[1:]] == [30, 12]
        assert "isup_cause_value" not in ccrs[1]["vcs_information"]
        assert ccrs[2]["vcs_information"] == {"msc_address": "51551000f9", "isup_cause_value": 16}

    def test_an_abort_reaches_the_owner_and_ends_the_session(self):
        from siphon import diameter
        events = []
        camel = run(diameter.ro_session("15550100004", key="dialogue-2", metering="external",
                                        on_event=lambda session, event: events.append(event["event"])))
        self.diameter.trigger_ro_event(camel, "aborted")
        assert events == ["aborted"]
        assert not camel.open and diameter.ro_find("dialogue-2") is None

    def test_a_refusal_is_not_authorized(self):
        from siphon import diameter
        self.diameter.set_ro_result_code(4012)
        session = run(diameter.ro_session("15550100004"))
        assert not session.authorized and session.result_code == 4012 and not session.open
