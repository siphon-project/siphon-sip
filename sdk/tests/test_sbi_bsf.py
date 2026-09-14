"""Tests for the SDK's ``siphon.sbi`` mock — Nbsf_Management discovery
(``discover_pcf_binding``) plus the per-call PCF target / ``app_session_uri``
additions to N5 ``create_session`` / ``update_session`` / ``delete_session``.
"""
import pytest

from siphon_sdk import mock_module

mock_module.install()

from siphon import sbi  # noqa: E402  (must come after install)


BINDING = {
    "supi": "imsi-001010000000001",
    "ipv4_addr": "10.45.0.7",
    "dnn": "ims",
    "snssai": {"sst": 1, "sd": "000001"},
    "pcf_fqdn": "pcf01.5gc.example.org",
    "pcf_uri": "http://pcf01.5gc.example.org",
}


def setup_function(_):
    sbi.clear()


def test_discover_404_returns_none_by_default():
    # No binding configured ⇒ BSF miss ⇒ 4G UE.
    assert sbi.discover_pcf_binding(ue_ipv4="10.45.0.7") is None


def test_discover_200_returns_binding_with_pcf_uri():
    sbi.set_binding(BINDING)
    binding = sbi.discover_pcf_binding(ue_ipv4="10.45.0.7")
    assert binding is not None
    assert binding["pcf_uri"] == "http://pcf01.5gc.example.org"
    assert binding["supi"] == "imsi-001010000000001"


def test_discover_unhealthy_raises_bsf_error():
    sbi.set_bsf_error(True)
    with pytest.raises(sbi.BsfError):
        sbi.discover_pcf_binding(ue_ipv4="10.45.0.7")


def test_bsf_error_is_runtime_error_subclass():
    # The consumer catches sbi.BsfError specifically; it is a RuntimeError.
    assert issubclass(sbi.BsfError, RuntimeError)


def test_discover_requires_exactly_one_ip():
    with pytest.raises(ValueError):
        sbi.discover_pcf_binding()
    with pytest.raises(ValueError):
        sbi.discover_pcf_binding(ue_ipv4="10.45.0.7", ue_ipv6="2001:db8::1")


def test_discover_accepts_ipv6():
    sbi.set_binding(BINDING)
    assert sbi.discover_pcf_binding(ue_ipv6="2001:db8::1") is not None


def test_create_session_returns_app_session_uri():
    result = sbi.create_session(sip_call_id="call-1", ue_ipv4="10.45.0.7")
    assert result is not None
    assert "app_session_uri" in result
    assert result["app_session_uri"].endswith(result["app_session_id"])


def test_create_session_pcf_uri_addresses_target():
    result = sbi.create_session(
        sip_call_id="call-1",
        ue_ipv4="10.45.0.7",
        pcf_uri="http://pcf01.5gc.example.org",
    )
    assert result["app_session_uri"].startswith("http://pcf01.5gc.example.org")


def test_teardown_by_absolute_uri():
    # Replica-independent teardown: delete using the absolute resource URI.
    result = sbi.create_session(ue_ipv4="10.45.0.7", pcf_uri="http://pcf01.5gc")
    uri = result["app_session_uri"]
    assert sbi.update_session(uri) is not None
    assert sbi.delete_session(uri) is True
    # Already gone: the PCF answers 404, which siphon counts as deleted.
    assert sbi.delete_session(uri) is True


def test_teardown_by_bare_id_still_works():
    result = sbi.create_session(ue_ipv4="10.45.0.7")
    session_id = result["app_session_id"]
    assert sbi.delete_session(session_id) is True


def test_delete_of_a_session_the_pcf_already_removed_is_true():
    # The on_terminate flow: the PCF has dropped the session, so the delete
    # finds nothing. The session no longer exists, which is what was asked.
    unknown = "http://pcf01.5gc.example.org/npcf-policyauthorization/v1/app-sessions/gone"
    assert sbi.delete_session(unknown) is True


def test_delete_failure_returns_false_and_keeps_the_session():
    uri = sbi.create_session(ue_ipv4="192.0.2.7")["app_session_uri"]
    sbi.set_delete_failure(True)
    assert sbi.delete_session(uri) is False
    # Still tracked: a later update finds it.
    assert sbi.update_session(uri) is not None
    sbi.set_delete_failure(False)
    assert sbi.delete_session(uri) is True


def test_clear_resets_delete_failure():
    sbi.set_delete_failure(True)
    sbi.clear()
    uri = sbi.create_session(ue_ipv4="192.0.2.7")["app_session_uri"]
    assert sbi.delete_session(uri) is True
