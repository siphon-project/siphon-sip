"""The IMS restoration surface of the mock (TS 23.380, TS 29.229):
``registrar.restore()``, the restoration keywords of ``diameter.cx_sar`` and
its answer, and ``diameter.cx_lir(user_authorization_type=)``, mirroring the
engine.
"""
import asyncio
from types import SimpleNamespace

import pytest

from siphon_sdk import mock_module

AOR = "sip:001010000000002@ims.example.net"
CONTACT = ('<sip:001010000000002@192.0.2.20:5060>;'
           '+sip.instance="<urn:gsma:imei:35145120-840600-0>";reg-id=1;'
           '+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"')
PATH = "<sip:term@pcscf.example.net;lr>"


def _registrar():
    mock_module.install()
    registrar = mock_module.get_registrar()
    registrar._store.clear()
    registrar._associated_uris.clear()
    registrar._aliases.clear()
    return registrar


def test_restore_rebuilds_the_binding():
    registrar = _registrar()
    assert registrar.restore(AOR, CONTACT, expires=1800, path=[PATH],
                             call_id="reg-7@192.0.2.20", cseq=3,
                             auth_user="001010000000002@ims.example.net",
                             aliases=["tel:+0010100002"])
    [binding] = registrar.lookup(AOR)
    assert binding.uri == "sip:001010000000002@192.0.2.20:5060"
    assert binding.path == [PATH]
    assert binding.expires == 1800
    assert binding.auth_user == "001010000000002@ims.example.net"
    assert binding.sip_instance == '"<urn:gsma:imei:35145120-840600-0>"'
    assert binding.reg_id == 1
    assert [name for name, _ in binding.params] == ["+g.3gpp.icsi-ref"]
    assert registrar.lookup("tel:+0010100002") == [binding]


def test_restore_refuses_zero_expires_and_a_non_contact():
    registrar = _registrar()
    with pytest.raises(ValueError):
        registrar.restore(AOR, CONTACT, expires=0)
    with pytest.raises(ValueError):
        registrar.restore(AOR, "", expires=600)
    assert registrar.lookup(AOR) == []


def test_save_exposes_sip_instance_and_reg_id_too():
    registrar = _registrar()
    request = SimpleNamespace(to_uri=AOR, ruri=SimpleNamespace(user="u"),
                              source_ip="192.0.2.20", method="REGISTER",
                              get_header=lambda name: CONTACT if name == "Contact" else None,
                              reply=lambda code, reason: None)
    request.get_headers = lambda name: [CONTACT] if name == "Contact" else []
    registrar.save(request)
    [binding] = registrar.lookup(AOR)
    assert binding.sip_instance == '"<urn:gsma:imei:35145120-840600-0>"'
    assert binding.reg_id == 1


def test_cx_sar_records_the_restoration_members_and_answers_the_full_shape():
    mock_module.install()
    diameter = mock_module.get_diameter()
    group = {"user_name": "001010000000002@ims.example.net",
             "restoration_info": [{"path": PATH, "contact": CONTACT}]}
    diameter.set_sar_response(AOR, 5007, "<IMSSubscription/>", experimental=True,
                              scscf_restoration_info=[group], supported_features=4)
    answer = asyncio.run(diameter.cx_sar(AOR, "sip:scscf.example.net", 3,
                                         ims_restoration=True))
    assert answer == {"result_code": 5007, "experimental_result_code": 5007,
                      "user_data": "<IMSSubscription/>",
                      "scscf_restoration_info": [group],
                      "associated_registered_identities": [],
                      "supported_features": 4}
    assert diameter.sar_requests[-1]["ims_restoration"] is True
    assert diameter.sar_requests[-1]["assignment_type"] == 3


def test_cx_lir_records_the_user_authorization_type():
    mock_module.install()
    diameter = mock_module.get_diameter()
    asyncio.run(diameter.cx_lir(AOR, user_authorization_type=2))
    assert diameter.lir_requests[-1] == {"public_identity": AOR,
                                         "user_authorization_type": 2}
