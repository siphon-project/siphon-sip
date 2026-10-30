"""``isc``: shared iFC sets, ORIGINATING_CDIV and the SDP body of a request
(TS 29.228 Annex B.2, E and F)."""

from __future__ import annotations

import pytest

from siphon_sdk.mock_module import MockIsc

PROFILE = """<ServiceProfile>
  <PublicIdentity><Identity>sip:alice@example.com</Identity></PublicIdentity>
  <Extension><SharedIFCSetID>7</SharedIFCSetID><SharedIFCSetID>1</SharedIFCSetID></Extension>
</ServiceProfile>"""


def test_shared_set_ids_are_kept_in_profile_order():
    isc = MockIsc()
    isc.store_profile("sip:alice@example.com", PROFILE)
    assert isc.shared_set_ids("sip:alice@example.com") == [7, 1]
    isc.remove_profile("sip:alice@example.com")
    assert isc.shared_set_ids("sip:alice@example.com") == []


def test_a_session_case_outside_the_schema_is_refused():
    isc = MockIsc()
    with pytest.raises(ValueError):
        isc.store_profile("sip:alice@example.com", "<SPT><SessionCase>9</SessionCase></SPT>")


def test_evaluate_takes_orig_cdiv_and_a_body():
    isc = MockIsc()
    isc.set_eval_results("sip:alice@example.com", [
        {"server_name": "sip:cdiv@example.com", "default_handling": 0,
         "service_info": None, "priority": 10},
        {"server_name": "sip:video@example.com", "default_handling": 0,
         "service_info": None, "priority": 20},
    ])
    matches = isc.evaluate("sip:alice@example.com", "INVITE", "sip:bob@example.com", [],
                           "orig_cdiv", start_after_priority=10, body="v=0\r\nm=video 0 RTP/AVP 96\r\n")
    assert [match["server_name"] for match in matches] == ["sip:video@example.com"]
    assert isc.evaluations[0]["session_case"] == "orig_cdiv"
    with pytest.raises(ValueError):
        isc.evaluate("sip:alice@example.com", "INVITE", "sip:bob@example.com", [], "cdiv")


def test_evaluate_results_carry_the_include_register_flags():
    isc = MockIsc()
    isc.set_eval_results("sip:alice@example.com", [
        {"server_name": "sip:a@example.com", "default_handling": 0,
         "service_info": None, "priority": 0, "include_register_request": True},
        {"server_name": "sip:b@example.com", "default_handling": 0,
         "service_info": None, "priority": 1, "include_register_response": True},
        {"server_name": "sip:c@example.com", "default_handling": 0,
         "service_info": None, "priority": 2},
    ])
    matches = isc.evaluate("sip:alice@example.com", "REGISTER", "sip:example.com", [])
    flags = [(m["include_register_request"], m["include_register_response"]) for m in matches]
    assert flags == [(True, False), (False, True), (False, False)]
