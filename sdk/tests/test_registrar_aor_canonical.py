"""The mock registrar keys AoRs exactly as the Rust registrar does.

The table mirrors ``normalize_aor_canonical_forms`` in ``src/registrar/mod.rs``
(RFC 3261 §10.3 step 5 and §19.1.4), so a script tested against the SDK finds
the same bindings it would find on a running siphon.
"""

from __future__ import annotations

import pytest

from siphon_sdk import mock_module
from siphon_sdk.mock_module import MockRegistrar
from siphon_sdk.types import Contact


@pytest.mark.parametrize(
    "raw, canonical",
    [
        ("sip:alice@example.com", "sip:alice@example.com"),
        ("sips:alice@example.com", "sips:alice@example.com"),
        ("alice@example.com", "sip:alice@example.com"),
        ("<sip:alice@example.com>", "sip:alice@example.com"),
        ("sip:alice@example.com:5060", "sip:alice@example.com:5060"),
        ("sips:alice@example.com:5061", "sips:alice@example.com:5061"),
        ("sip:alice@example.com:5070", "sip:alice@example.com:5070"),
        ("SIP:alice@EXAMPLE.com", "sip:alice@example.com"),
        ("Sips:alice@Example.COM", "sips:alice@example.com"),
        ("sip:Alice@example.com", "sip:Alice@example.com"),
        ("sip:alice@[2001:DB8::1]:5070", "sip:alice@[2001:db8::1]:5070"),
        ("sip:%61lice@example.com", "sip:alice@example.com"),
        ("sip:alice%2dsmith@example.com", "sip:alice-smith@example.com"),
        ("sip:alice%2fbob@example.com", "sip:alice%2Fbob@example.com"),
        ("sip:alice%40bob@example.com", "sip:alice%40bob@example.com"),
        ("sip:a%00b@example.com", "sip:a%00b@example.com"),
        ("sip:a%zzb@example.com", "sip:a%zzb@example.com"),
        ("sip:ab%2@example.com", "sip:ab%2@example.com"),
        (
            "sip:+15551234567;phone-context=ims.example.com@ims.example.com;user=phone",
            "sip:+15551234567;phone-context=ims.example.com@ims.example.com",
        ),
        ("sip:alice@example.com;transport=tcp?h=1", "sip:alice@example.com"),
        ("<sip:alice@example.com:5060;transport=tcp>", "sip:alice@example.com:5060"),
        ("tel:+15551234567", "sip:tel:+15551234567"),
        ("", "sip:"),
    ],
)
def test_normalize_aor_matches_the_rust_registrar(raw: str, canonical: str) -> None:
    assert MockRegistrar._normalize_aor(raw) == canonical


def test_an_explicit_port_does_not_find_a_binding_registered_without_one() -> None:
    mock_module.install()
    registrar = mock_module.get_registrar()
    registrar.clear()
    registrar.add_contact(
        "sip:alice@example.com",
        Contact(uri="sip:alice@192.0.2.10:5062", q=1.0, expires=3600),
    )

    assert len(registrar.lookup("SIP:alice@EXAMPLE.COM")) == 1
    assert len(registrar.lookup("sip:%61lice@example.com")) == 1
    # RFC 3261 §19.1.4: the port is part of the URI, even the default one.
    assert registrar.lookup("sip:alice@example.com:5060") == []
    assert registrar.lookup("sip:alice@example.com:5070") == []
