"""``registrar.network_deregister`` in ``MockRegistrar``: a P-CSCF ending a
UE's registration when it learns the access is gone (3GPP TS 24.229 clause
5.2.8) removes the bindings registered from that source, or all of them."""
import asyncio
from types import SimpleNamespace

import pytest

from siphon_sdk import mock_module


def _fresh_registrar():
    mock_module.install()
    registrar = mock_module.get_registrar()
    registrar._store.clear()
    registrar._associated_uris.clear()
    registrar._aliases.clear()
    registrar.network_deregistrations.clear()
    return registrar


def _register(user: str, source_ip: str, source_port: int):
    return SimpleNamespace(
        to_uri=f"sip:{user}@ims.example.invalid",
        ruri=SimpleNamespace(user=user),
        source_ip=source_ip,
        source_port=source_port,
        transport="udp",
        method="REGISTER",
        reply=lambda code, reason: None,
    )


def test_only_the_binding_from_the_source_goes():
    registrar = _fresh_registrar()
    registrar.save(_register("1001", "192.0.2.21", 5060), flow_token="tok-1001")
    held = registrar.lookup("sip:1001@ims.example.invalid")
    assert len(held) == 1
    source = held[0].flow.remote_addr.rsplit(":", 1)

    gone = asyncio.run(registrar.network_deregister(
        "sip:1001@ims.example.invalid", (source[0], int(source[1])), "access lost"))

    assert gone == 1
    assert not registrar.is_registered("sip:1001@ims.example.invalid")
    assert registrar.network_deregistrations[0][2] == "access lost"


def test_another_source_keeps_its_binding():
    registrar = _fresh_registrar()
    registrar.save(_register("1002", "192.0.2.22", 5060), flow_token="tok-1002")

    gone = asyncio.run(registrar.network_deregister(
        "sip:1002@ims.example.invalid", ("192.0.2.99", 5060)))

    assert gone == 0
    assert registrar.is_registered("sip:1002@ims.example.invalid")


def test_a_source_that_is_not_an_address_is_refused():
    registrar = _fresh_registrar()
    with pytest.raises(ValueError):
        asyncio.run(registrar.network_deregister(
            "sip:1003@ims.example.invalid", ("ue.example.invalid", 5060)))
