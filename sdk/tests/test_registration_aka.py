"""Tests for the IMS AKAv1-MD5 path of ``registration.add`` (RFC 3310 /
3GPP TS 33.203).

Mirrors the validation in the Rust binding: ``auth="aka"`` requires the
subscriber key ``k`` plus an operator key (``op`` or ``opc``); digest mode is
the default and is unaffected.

Uses the 3GPP test IMSI range (MCC 001 / MNC 01) and TS 35.208 Test Set 1
secrets — never a real subscriber.
"""
import pytest

from siphon_sdk import mock_module

AKA_AOR = "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
AKA_K = "465b5ce8b199b49faa5f0a2ee238a6bc"
AKA_OPC = "cd63cb71954a9f4e48a5994e37a02baf"
AKA_OP = "cdc202d5123e20f62b6d676ac72cb318"
PCSCF = "sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org:5060"
IMPI = "001010000000001@ims.mnc01.mcc001.3gppnetwork.org"


def _fresh_registration():
    mock_module.install()
    registration = mock_module.get_registration()
    registration._entries.clear()
    return registration


def test_add_aka_with_opc_records_aka_mode():
    registration = _fresh_registration()
    registration.add(AKA_AOR, PCSCF, user=IMPI, auth="aka", k=AKA_K, opc=AKA_OPC, amf="b9b9")
    entry = registration._entries[AKA_AOR]
    assert entry["auth"] == "aka"
    assert entry["k"] == AKA_K
    assert entry["opc"] == AKA_OPC
    assert entry["amf"] == "b9b9"
    # Defaults applied.
    assert entry["sqn"] == "000000000000"


def test_add_aka_with_op_is_accepted():
    registration = _fresh_registration()
    registration.add(AKA_AOR, PCSCF, user=IMPI, auth="aka", k=AKA_K, op=AKA_OP)
    assert registration._entries[AKA_AOR]["auth"] == "aka"


def test_add_aka_requires_k():
    registration = _fresh_registration()
    with pytest.raises(ValueError, match="requires the subscriber key"):
        registration.add(AKA_AOR, PCSCF, user=IMPI, auth="aka", opc=AKA_OPC)


def test_add_aka_requires_operator_key():
    registration = _fresh_registration()
    with pytest.raises(ValueError, match="requires either"):
        registration.add(AKA_AOR, PCSCF, user=IMPI, auth="aka", k=AKA_K)


def test_add_digest_is_default_and_needs_no_aka_params():
    registration = _fresh_registration()
    registration.add("sip:alice@carrier.com", "sip:registrar.carrier.com",
                     user="alice", password="secret")
    entry = registration._entries["sip:alice@carrier.com"]
    assert entry["auth"] == "digest"
    assert entry["k"] is None
    assert entry["ipsec"] is False


def test_add_aka_ipsec_records_ports_and_transform():
    registration = _fresh_registration()
    registration.add(AKA_AOR, PCSCF, user=IMPI, auth="aka", k=AKA_K, opc=AKA_OPC,
                     ipsec=True, ue_port_c=6100, ue_port_s=6101)
    entry = registration._entries[AKA_AOR]
    assert entry["ipsec"] is True
    assert entry["ue_port_c"] == 6100
    assert entry["ue_port_s"] == 6101
    assert entry["ipsec_alg"] == "hmac-sha-1-96"
    assert entry["ipsec_ealg"] == "null"


def test_ipsec_requires_aka():
    registration = _fresh_registration()
    with pytest.raises(ValueError, match="requires auth='aka'"):
        registration.add("sip:alice@carrier.com", PCSCF, user="alice",
                         password="x", ipsec=True, ue_port_c=6100, ue_port_s=6101)


def test_ipsec_requires_both_ports():
    registration = _fresh_registration()
    with pytest.raises(ValueError, match="ue_port_s"):
        registration.add(AKA_AOR, PCSCF, user=IMPI, auth="aka", k=AKA_K,
                         opc=AKA_OPC, ipsec=True, ue_port_c=6100)
