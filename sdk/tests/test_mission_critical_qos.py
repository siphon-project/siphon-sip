"""Mission critical identifiers and reservation priority on Rx and N5.

``diameter.rx_aar(mcptt_identifier=, mcvideo_identifier=, reservation_priority=)``
and ``sbi.create_session`` / ``sbi.update_session(mcptt_id=, mc_video_id=,
res_prio=)`` in the SDK mock, which refuses what siphon refuses and records
what siphon sends.
"""
import asyncio
import inspect

import pytest

from siphon_sdk import mock_module

NOTIF_URI = "http://pcscf.example.com:8080/sbi/events"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def diameter():
    return mock_module.MockDiameter()


@pytest.fixture
def sbi():
    sbi = mock_module.MockSbi()
    sbi.set_notif_uri(NOTIF_URI)
    return sbi


def test_clear_forgets_the_recorded_aars(diameter):
    run(diameter.rx_aar(mcptt_identifier="mcpttp"))
    diameter.clear()
    assert diameter.aar_requests == []


# -- Rx ---------------------------------------------------------------------

def test_rx_aar_signature_has_the_arguments_after_service_urn(diameter):
    names = list(inspect.signature(diameter.rx_aar).parameters)
    assert names[-4:] == [
        "service_urn", "mcptt_identifier", "mcvideo_identifier", "reservation_priority",
    ]


def test_rx_aar_records_the_mission_critical_arguments(diameter):
    result = run(diameter.rx_aar(
        framed_ip="192.0.2.1", mcptt_identifier="mcpttp",
        mcvideo_identifier="mcpttq", reservation_priority=5))
    assert result["result_code"] == 2001
    sent = diameter.aar_requests[-1]
    assert sent["mcptt_identifier"] == "mcpttp"
    assert sent["mcvideo_identifier"] == "mcpttq"
    assert sent["reservation_priority"] == 5
    assert sent["session_id"] is None


def test_rx_aar_takes_them_on_a_modification(diameter):
    first = run(diameter.rx_aar(framed_ip="192.0.2.1", mcptt_identifier="mcpttp",
                                reservation_priority=5))
    run(diameter.rx_aar(session_id=first["session_id"], mcptt_identifier="mcpttp",
                        reservation_priority=15))
    sent = diameter.aar_requests[-1]
    assert sent["session_id"] == first["session_id"]
    assert sent["reservation_priority"] == 15


def test_recorded_aar_keeps_what_was_sent_when_the_caller_changes_its_list(diameter):
    actions = [2]
    components = [{"number": 1, "media_type": "audio"}]
    run(diameter.rx_aar(specific_actions=actions, media_components=components))
    actions.append(9)
    components[0]["media_type"] = "video"
    sent = diameter.aar_requests[-1]
    assert sent["specific_actions"] == [2]
    assert sent["media_components"] == [{"number": 1, "media_type": "audio"}]


def test_rx_aar_without_them_sends_none(diameter):
    run(diameter.rx_aar(framed_ip="192.0.2.1"))
    run(diameter.rx_aar(framed_ip="192.0.2.1", mcptt_identifier="", mcvideo_identifier=""))
    for sent in diameter.aar_requests:
        assert sent["mcptt_identifier"] is None
        assert sent["mcvideo_identifier"] is None
        assert sent["reservation_priority"] is None


@pytest.mark.parametrize("value", range(16))
def test_rx_aar_accepts_every_priority(diameter, value):
    run(diameter.rx_aar(reservation_priority=value))
    assert diameter.aar_requests[-1]["reservation_priority"] == value


@pytest.mark.parametrize("value", [-1, 16, 255, 2**70])
def test_rx_aar_out_of_range_priority_is_a_value_error(diameter, value):
    with pytest.raises(ValueError, match="reservation_priority"):
        diameter.rx_aar(reservation_priority=value)


@pytest.mark.parametrize("value", ["7", 7.0, True, [7]])
def test_rx_aar_non_int_priority_is_a_type_error(diameter, value):
    with pytest.raises(TypeError, match="reservation_priority"):
        diameter.rx_aar(reservation_priority=value)


@pytest.mark.parametrize("name", ["mcptt_identifier", "mcvideo_identifier"])
def test_rx_aar_non_str_identifier_is_a_type_error_naming_it(diameter, name):
    with pytest.raises(TypeError, match=name):
        diameter.rx_aar(**{name: 5})


def test_rx_aar_docstring_documents_the_arguments(diameter):
    doc = type(diameter).rx_aar.__doc__
    for text in ("mcptt_identifier", "mcvideo_identifier", "reservation_priority",
                 "MCPTT-Identifier", "Reservation-Priority", "PRIO_<n+1>"):
        assert text in doc


# -- N5 ---------------------------------------------------------------------

def test_create_session_sends_the_members_by_their_ts_29_514_names(sbi):
    created = run(sbi.create_session(
        ue_ipv4="192.0.2.7", mcptt_id="mcpttp", mc_video_id="mcpttq", res_prio=15))
    session = sbi._sessions[created["app_session_id"]]
    assert session["mission_critical"] == {
        "mcpttId": "mcpttp", "mcVideoId": "mcpttq", "resPrio": "PRIO_16",
    }


@pytest.mark.parametrize("value", range(16))
def test_res_prio_int_is_one_below_the_prio_number(sbi, value):
    created = run(sbi.create_session(ue_ipv4="192.0.2.7", res_prio=value))
    sent = sbi._sessions[created["app_session_id"]]["mission_critical"]
    assert sent == {"resPrio": f"PRIO_{value + 1}"}


@pytest.mark.parametrize("value", ["PRIO_1", "PRIO_9", "PRIO_16"])
def test_res_prio_string_is_sent_as_written(sbi, value):
    created = run(sbi.create_session(ue_ipv4="192.0.2.7", res_prio=value))
    assert sbi._sessions[created["app_session_id"]]["mission_critical"] == {"resPrio": value}


def test_create_session_without_them_sends_none(sbi):
    for arguments in ({}, {"mcptt_id": "", "mc_video_id": "", "res_prio": ""}):
        created = run(sbi.create_session(ue_ipv4="192.0.2.7", **arguments))
        assert sbi._sessions[created["app_session_id"]]["mission_critical"] == {}


@pytest.mark.parametrize("value", [-1, 16, "PRIO_0", "PRIO_17", "PRIO_01", "prio_1", "15"])
def test_res_prio_out_of_range_is_a_value_error(sbi, value):
    with pytest.raises(ValueError, match="res_prio"):
        sbi.create_session(ue_ipv4="192.0.2.7", res_prio=value)
    created = run(sbi.create_session(ue_ipv4="192.0.2.7"))
    with pytest.raises(ValueError, match="res_prio"):
        sbi.update_session(created["app_session_id"], res_prio=value)


@pytest.mark.parametrize("value", [1.5, True, [1]])
def test_res_prio_of_another_type_is_a_type_error(sbi, value):
    with pytest.raises(TypeError, match="res_prio"):
        sbi.create_session(ue_ipv4="192.0.2.7", res_prio=value)


@pytest.mark.parametrize("name", ["mcptt_id", "mc_video_id"])
def test_non_str_identifier_is_a_type_error_naming_it(sbi, name):
    with pytest.raises(TypeError, match=name):
        sbi.create_session(ue_ipv4="192.0.2.7", **{name: 5})


def test_update_session_patches_the_priority_and_keeps_the_rest(sbi):
    created = run(sbi.create_session(ue_ipv4="192.0.2.7", mcptt_id="mcpttp", res_prio=5))
    session_id = created["app_session_id"]
    updated = run(sbi.update_session(session_id, res_prio=15))
    assert updated == {"app_session_id": session_id, "authorized": True}
    assert sbi._sessions[session_id]["mission_critical"] == {
        "mcpttId": "mcpttp", "resPrio": "PRIO_16",
    }
    # None leaves what the PCF holds.
    run(sbi.update_session(session_id))
    assert sbi._sessions[session_id]["mission_critical"]["resPrio"] == "PRIO_16"


def test_the_same_int_means_the_same_priority_on_both_interfaces(diameter, sbi):
    for priority in (0, 7, 15):
        run(diameter.rx_aar(reservation_priority=priority))
        created = run(sbi.create_session(ue_ipv4="192.0.2.7", res_prio=priority))
        assert diameter.aar_requests[-1]["reservation_priority"] == priority
        sent = sbi._sessions[created["app_session_id"]]["mission_critical"]["resPrio"]
        assert int(sent.removeprefix("PRIO_")) == priority + 1


def test_sbi_docstrings_document_the_arguments(sbi):
    for method in (type(sbi).create_session, type(sbi).update_session):
        for text in ("mcptt_id", "mc_video_id", "res_prio", "mcpttId", "PRIO_16"):
            assert text in method.__doc__, (method.__name__, text)
