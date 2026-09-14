"""Tests for the SDK's ``siphon.sbi`` mock: the PCF event subscription kwargs
(``events`` / ``notif_uri``) on ``create_session`` and ``update_session``.
"""
import pytest

from siphon_sdk import mock_module

mock_module.install()

from siphon import sbi  # noqa: E402  (must come after install)


NOTIF_URI = "http://pcscf.example.com:8080/sbi/events"


def setup_function(_):
    sbi.clear()


def test_create_session_with_events_and_notif_uri():
    result = sbi.create_session(
        ue_ipv4="192.0.2.7",
        notif_uri=NOTIF_URI,
        events=["FAILED_RESOURCES_ALLOCATION", "SUCCESSFUL_RESOURCES_ALLOCATION"],
    )
    assert result is not None
    assert result["app_session_id"]


def test_create_session_without_events_is_unchanged():
    assert sbi.create_session(ue_ipv4="192.0.2.7", notif_uri=NOTIF_URI) is not None


def test_create_session_events_without_notif_uri_raises():
    with pytest.raises(ValueError, match="notif_uri"):
        sbi.create_session(ue_ipv4="192.0.2.7", events=["FAILED_RESOURCES_ALLOCATION"])


def test_create_session_empty_events_raises():
    with pytest.raises(ValueError, match="events"):
        sbi.create_session(ue_ipv4="192.0.2.7", notif_uri=NOTIF_URI, events=[])


def test_create_session_events_must_be_a_list_of_strings():
    with pytest.raises(TypeError, match="events"):
        sbi.create_session(
            ue_ipv4="192.0.2.7", notif_uri=NOTIF_URI, events="FAILED_RESOURCES_ALLOCATION"
        )
    with pytest.raises(TypeError, match="events"):
        sbi.create_session(ue_ipv4="192.0.2.7", notif_uri=NOTIF_URI, events=[42])


def test_update_session_with_events_and_optional_notif_uri():
    uri = sbi.create_session(ue_ipv4="192.0.2.7")["app_session_uri"]
    assert sbi.update_session(uri, events=["QOS_NOTIF"]) is not None
    assert sbi.update_session(uri, events=["QOS_NOTIF"], notif_uri=NOTIF_URI) is not None


def test_update_session_without_events_is_unchanged():
    uri = sbi.create_session(ue_ipv4="192.0.2.7")["app_session_uri"]
    assert sbi.update_session(uri) is not None


def test_update_session_empty_events_raises():
    uri = sbi.create_session(ue_ipv4="192.0.2.7")["app_session_uri"]
    with pytest.raises(ValueError, match="events"):
        sbi.update_session(uri, events=[])


def test_update_session_notif_uri_without_events_raises():
    # notifUri only exists inside the event subscription on modify; accepting it
    # alone would send nothing.
    uri = sbi.create_session(ue_ipv4="192.0.2.7")["app_session_uri"]
    with pytest.raises(ValueError, match="events"):
        sbi.update_session(uri, notif_uri=NOTIF_URI)
