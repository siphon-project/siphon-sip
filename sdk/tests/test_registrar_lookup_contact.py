"""Tests for reverse-by-contact registrar lookup mirrored from the
production Rust registrar into ``MockRegistrar``.

Contract: a binding is keyed by the REGISTER's AoR (``user@domain``), but
a terminating INVITE a PBX loose-routes back carries the cached *contact*
(``user@source-ip``) in its Request-URI.  ``registrar.lookup`` keys on the
AoR and misses; ``registrar.lookup_contact`` matches the binding by its
stored Contact regardless of the AoR domain.
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


def _fake_register(to_uri: str, user: str, source_ip: str):
    """Minimal stand-in for a REGISTER Request driving MockRegistrar.save."""
    return SimpleNamespace(
        to_uri=to_uri,
        ruri=SimpleNamespace(user=user),
        source_ip=source_ip,
        method="REGISTER",
        reply=lambda code, reason: None,
    )


def test_lookup_contact_matches_when_lookup_by_aor_misses():
    registrar = _fresh_registrar()
    # AoR domain differs from the contact host — the PBX-in-front case.
    registrar.save(
        _fake_register("sip:1001@pbx.example", "1001", "203.0.113.7")
    )
    contact_uri = "sip:1001@203.0.113.7"

    # AoR-keyed lookup on the contact URI misses.
    assert registrar.lookup(contact_uri) == []
    assert registrar.is_registered(contact_uri) is False

    # Contact-keyed lookup recovers the binding.
    found = registrar.lookup_contact(contact_uri)
    assert len(found) == 1
    assert "1001" in found[0].uri
    assert "203.0.113.7" in found[0].uri
    assert registrar.is_registered_contact(contact_uri) is True

    # The AoR still resolves the binding by its real key.
    assert len(registrar.lookup("sip:1001@pbx.example")) == 1


def test_lookup_contact_ignores_params_and_default_port():
    registrar = _fresh_registrar()
    registrar.save(_fake_register("sip:2001@pbx.example", "2001", "203.0.113.9"))

    # Stored contact is sip:2001@203.0.113.9:5060 — default port + trailing
    # param both normalise away on the lookup side.
    assert registrar.is_registered_contact("sip:2001@203.0.113.9")
    assert registrar.is_registered_contact("sip:2001@203.0.113.9:5060")
    assert registrar.is_registered_contact("sip:2001@203.0.113.9;transport=udp")


def test_lookup_contact_wrong_user_or_host_misses():
    registrar = _fresh_registrar()
    registrar.save(_fake_register("sip:1001@pbx.example", "1001", "203.0.113.7"))

    assert not registrar.is_registered_contact("sip:9999@203.0.113.7")  # user
    assert not registrar.is_registered_contact("sip:1001@198.51.100.1")  # host
    assert len(registrar.lookup_contact("sip:1001@203.0.113.7")) == 1


def test_lookup_contact_unknown_returns_empty():
    registrar = _fresh_registrar()
    assert registrar.lookup_contact("sip:nobody@203.0.113.7") == []
    assert registrar.is_registered_contact("sip:nobody@203.0.113.7") is False
