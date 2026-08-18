"""Tests for the Rf (3GPP TS 32.299 IMS offline charging) mock surface."""

from siphon_sdk import mock_module


class TestRfMock:
    def setup_method(self):
        mock_module.install()
        mock_module.reset()
        self.diameter = mock_module.get_diameter()
        self.diameter.add_peer("cdf1", connected=True)

    def test_acr_start_returns_session_id(self):
        from siphon import diameter
        result = diameter.rf_acr_start(
            calling_party="sip:alice@ims.example.com",
            called_party="sip:bob@ims.example.com",
            sip_method="INVITE",
            role_of_node="originating",
            node_functionality="scscf",
            ims_charging_identifier="icid-1",
        )
        assert result is not None
        assert result["result_code"] == 2001
        assert result["session_id"]
        assert result["record_number"] == 0

    def test_acr_interim_passes_session_id(self):
        from siphon import diameter
        start = diameter.rf_acr_start(sip_method="INVITE")
        assert start is not None
        sid = start["session_id"]

        interim = diameter.rf_acr_interim(sid, 1, sip_method="INVITE")
        assert interim is not None
        assert interim["session_id"] == sid
        assert interim["record_number"] == 1

    def test_acr_stop_with_termination_cause(self):
        from siphon import diameter
        start = diameter.rf_acr_start(sip_method="INVITE")
        sid = start["session_id"]
        stop = diameter.rf_acr_stop(sid, 2, termination_cause=8,
                                     sip_method="BYE", cause_code=-200)
        assert stop is not None
        assert stop["session_id"] == sid

        captured = self.diameter.captured_acrs()
        assert any(
            entry["record_type"] == "STOP"
            and entry["termination_cause"] == 8
            and entry["cause_code"] == -200
            for entry in captured
        )

    def test_acr_event_one_shot(self):
        from siphon import diameter
        result = diameter.rf_acr_event(
            calling_party="sip:alice@ims.example.com",
            sip_method="REGISTER",
            role_of_node="originating",
            node_functionality="pcscf",
            cause_code=0,
        )
        assert result is not None
        captured = self.diameter.captured_acrs()
        assert len(captured) == 1
        assert captured[0]["record_type"] == "EVENT"
        assert captured[0]["sip_method"] == "REGISTER"

    def test_set_rf_result_code_propagates(self):
        from siphon import diameter
        self.diameter.set_rf_result_code(4002)  # DIAMETER_OUT_OF_SPACE
        result = diameter.rf_acr_start(sip_method="INVITE")
        assert result["result_code"] == 4002

    def test_set_rf_interim_interval_propagates(self):
        from siphon import diameter
        self.diameter.set_rf_interim_interval(600)
        result = diameter.rf_acr_start(sip_method="INVITE")
        assert result["interim_interval"] == 600

    def test_clear_captured_acrs(self):
        from siphon import diameter
        diameter.rf_acr_event(sip_method="REGISTER")
        assert len(self.diameter.captured_acrs()) == 1
        self.diameter.clear_captured_acrs()
        assert self.diameter.captured_acrs() == []

    def test_session_ids_are_unique_per_start(self):
        from siphon import diameter
        first = diameter.rf_acr_start(sip_method="INVITE")
        second = diameter.rf_acr_start(sip_method="INVITE")
        assert first["session_id"] != second["session_id"]

    def test_acr_start_carries_trunk_group_kwargs(self):
        # BGCF emit shape — Outgoing-Trunk-Group-Id (TS 32.299 §7.2.71)
        # plus Application-Server (MMTel forward).
        from siphon import diameter
        diameter.rf_acr_start(
            sip_method="INVITE",
            node_functionality="bgcf",
            outgoing_trunk_group_id="carrier-A",
            incoming_trunk_group_id="trunk-in-001",
            application_server="sip:mmtel.ims.example.com",
            application_provided_called_party_address="sip:bob@example.com",
        )
        captured = self.diameter.captured_acrs()
        assert len(captured) == 1
        entry = captured[0]
        assert entry["outgoing_trunk_group_id"] == "carrier-A"
        assert entry["incoming_trunk_group_id"] == "trunk-in-001"
        assert entry["application_server"] == "sip:mmtel.ims.example.com"
        assert (
            entry["application_provided_called_party_address"]
            == "sip:bob@example.com"
        )

    def test_acr_carries_subscription_id_for_the_served_party(self):
        """A CDR with no Subscription-Id has no billable subscriber on it —
        the collector is left resolving the IMPU against an HSS after the
        fact, which only works for locally-provisioned users."""
        from siphon import diameter
        diameter.rf_acr_start(
            sip_method="INVITE",
            calling_party="sip:alice@ims.example.com",
            subscription_id=["sip:alice@ims.example.com", "001010000000001"],
            subscription_id_type=["sip", "imsi"],
        )
        captured = self.diameter.captured_acrs()
        assert captured[-1]["subscription_id"] == [
            "sip:alice@ims.example.com",
            "001010000000001",
        ]
        assert captured[-1]["subscription_id_type"] == ["sip", "imsi"]

    def test_acr_accepts_a_single_subscription_id(self):
        from siphon import diameter
        diameter.rf_acr_event(sip_method="MESSAGE", subscription_id="+31612345678")
        assert self.diameter.captured_acrs()[-1]["subscription_id"] == "+31612345678"

    def test_acr_event_reports_a_failed_session_setup(self):
        """TS 32.260 §5.2.2.1: an unsuccessful establishment is the one record
        that carries a non-zero Cause-Code, and it must correlate by ICID with
        the rest of the attempt."""
        from siphon import diameter
        diameter.rf_acr_event(
            sip_method="INVITE",
            ims_charging_identifier="icid-failed-1",
            cause_code=-486,
        )
        captured = self.diameter.captured_acrs()[-1]
        assert captured["record_type"] == "EVENT"
        assert captured["cause_code"] == -486
        assert captured["ims_charging_identifier"] == "icid-failed-1"




class TestRequestChargingParams:
    """Test ``request.set_charging_param`` — the BGCF auto-emit
    handoff."""

    def _make_request(self):
        from siphon_sdk.request import Request
        return Request(
            method="INVITE",
            ruri="sip:bob@example.com",
            from_uri="sip:alice@example.com",
            to_uri="sip:bob@example.com",
            from_tag="a-tag",
            call_id="call-1",
            cseq=(1, "INVITE"),
        )

    def test_set_charging_param_captures_tuple(self):
        request = self._make_request()
        request.set_charging_param("outgoing-trunk-group-id", "carrier-A")
        assert request.charging_params == [("outgoing-trunk-group-id", "carrier-A")]

    def test_multiple_params_preserve_order(self):
        request = self._make_request()
        request.set_charging_param("outgoing-trunk-group-id", "carrier-A")
        request.set_charging_param("application-server", "sip:as.example.com")
        assert request.charging_params == [
            ("outgoing-trunk-group-id", "carrier-A"),
            ("application-server", "sip:as.example.com"),
        ]

    def test_unknown_param_name_still_captured(self):
        # SDK mock keeps everything; production siphon ignores unknown
        # names but doesn't error.  Tests rely on the SDK shape so they
        # can assert what the script *intended* to stamp.
        request = self._make_request()
        request.set_charging_param("future-extension", "value")
        assert ("future-extension", "value") in request.charging_params


class TestCallChargingParams:
    """Test ``call.set_charging_param`` — the BGCF/MMTel-AS B2BUA
    handoff that mirrors :class:`Request.set_charging_param`."""

    def _make_call(self):
        from siphon_sdk.call import Call
        return Call(
            call_id="call-uuid-1",
            from_uri="sip:alice@example.com",
            to_uri="sip:bob@example.com",
            ruri="sip:bob@example.com",
            source_ip="127.0.0.1",
        )

    def test_set_charging_param_captures_tuple(self):
        call = self._make_call()
        call.set_charging_param("outgoing-trunk-group-id", "carrier-A")
        assert call.charging_params == [("outgoing-trunk-group-id", "carrier-A")]

    def test_b2bua_bgcf_pattern(self):
        # Mirror the documented BGCF B2BUA flow: select a gateway,
        # stamp the trunk group, then dial.
        call = self._make_call()
        call.set_charging_param("outgoing-trunk-group-id", "carrier-A")
        call.set_charging_param("application-server", "sip:mmtel.example.com")
        assert call.charging_params == [
            ("outgoing-trunk-group-id", "carrier-A"),
            ("application-server", "sip:mmtel.example.com"),
        ]
