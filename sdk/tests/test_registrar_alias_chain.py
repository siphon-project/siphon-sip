"""Tests for the IMS implicit-registration-set (alias-chain) behaviour
mirrored from the production Rust registrar into ``MockRegistrar``.

The contract: ``registrar.save(request, aliases=[...])`` declares the
implicit set, and a subsequent ``registrar.lookup(any_alias)`` returns
the same contacts that ``registrar.lookup(primary)`` does.
"""
from types import SimpleNamespace

from siphon_sdk import mock_module


def _fresh_registrar():
    mock_module.install()
    registrar = mock_module.get_registrar()
    registrar._store.clear()
    registrar._associated_uris.clear()
    registrar._aliases.clear()
    return registrar


def _fake_register(to_uri: str, source_ip: str = "10.0.0.1"):
    """Minimal stand-in for a Request — enough to drive MockRegistrar.save."""
    return SimpleNamespace(
        to_uri=to_uri,
        ruri=SimpleNamespace(user="alice"),
        source_ip=source_ip,
        method="REGISTER",
        reply=lambda code, reason: None,
    )


def test_save_with_aliases_resolves_to_primary():
    registrar = _fresh_registrar()
    registrar.save(
        _fake_register("sip:alice@ims.example.com"),
        aliases=["tel:+15551234", "sip:wildcard@ims.example.com"],
    )

    by_primary = registrar.lookup("sip:alice@ims.example.com")
    assert len(by_primary) == 1

    by_tel = registrar.lookup("tel:+15551234")
    assert len(by_tel) == 1
    assert by_tel[0].uri == by_primary[0].uri

    by_wildcard = registrar.lookup("sip:wildcard@ims.example.com")
    assert len(by_wildcard) == 1
    assert by_wildcard[0].uri == by_primary[0].uri


def test_save_without_aliases_does_not_create_aliases():
    registrar = _fresh_registrar()
    registrar.save(_fake_register("sip:alice@ims.example.com"))

    assert registrar.lookup("sip:alice@ims.example.com")
    assert not registrar.lookup("tel:+15551234")
    assert registrar._aliases == {}


def test_set_associated_uris_replaces_alias_index():
    registrar = _fresh_registrar()
    registrar.save(
        _fake_register("sip:alice@ims.example.com"),
        aliases=["tel:+15550000"],
    )
    assert registrar.lookup("tel:+15550000")

    # Re-set the implicit set with a different list.
    registrar.set_associated_uris("sip:alice@ims.example.com", ["tel:+15551111"])
    assert not registrar.lookup("tel:+15550000")
    assert registrar.lookup("tel:+15551111")


def test_remove_clears_alias_index():
    registrar = _fresh_registrar()
    registrar.save(
        _fake_register("sip:alice@ims.example.com"),
        aliases=["tel:+15551234"],
    )
    assert registrar.lookup("tel:+15551234")

    registrar.remove("sip:alice@ims.example.com")
    assert not registrar.lookup("tel:+15551234")
    assert not registrar.lookup("sip:alice@ims.example.com")
