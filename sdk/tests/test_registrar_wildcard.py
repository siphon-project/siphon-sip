"""``registrar.save()`` and the ``Contact: *`` wildcard (RFC 3261 §10.3 step 6).

``*`` removes every binding only together with ``Expires: 0`` and no other
Contact entry. Anything else is answered ``400`` and the bindings stay, as the
engine does.
"""
from typing import Optional

import pytest

from siphon_sdk import mock_module
from siphon_sdk.request import Request

AOR = "sip:001010000000001@ims.example.com"
FIRST = "<sip:001010000000001@192.0.2.10:5060>"
SECOND = "<sip:001010000000001@192.0.2.11:5060>"
THIRD = "<sip:001010000000001@192.0.2.12:5060>"


def _register(contact_lines: list[str], expires: Optional[str]) -> Request:
    headers: dict = {"Contact": list(contact_lines)}
    if expires is not None:
        headers["Expires"] = expires
    return Request(
        method="REGISTER",
        ruri="sip:ims.example.com",
        from_uri=AOR,
        to_uri=AOR,
        source_ip="192.0.2.10",
        source_port=5060,
        headers=headers,
    )


def _registered_twice():
    mock_module.reset()
    mock_module.install()
    registrar = mock_module.get_registrar()
    assert registrar.save(_register([FIRST, SECOND], "3600")) is True
    assert len(registrar.lookup(AOR)) == 2
    return registrar


def _reply(request: Request) -> tuple:
    return request.actions[-1].status_code, request.actions[-1].reason


@pytest.mark.parametrize(
    "contact_lines, expires",
    [
        (["*"], "3600"),
        (["*"], None),
        (["*"], "soon"),
        ([f"*, {THIRD}"], "0"),
        ([f"{THIRD}, *"], "0"),
        (["*", THIRD], "0"),
        ([THIRD, "*"], "0"),
        (["*", "*"], "0"),
    ],
)
@pytest.mark.parametrize("force", [False, True])
def test_an_invalid_wildcard_is_answered_400_and_keeps_the_bindings(
    contact_lines, expires, force
):
    registrar = _registered_twice()
    request = _register(contact_lines, expires)

    assert registrar.save(request, force=force) is False

    assert _reply(request) == (400, "Bad Request")
    assert len(registrar.lookup(AOR)) == 2


def test_wildcard_alone_with_expires_zero_removes_every_binding():
    registrar = _registered_twice()
    request = _register(["*"], "0")

    assert registrar.save(request) is True

    assert _reply(request) == (200, "OK")
    assert registrar.lookup(AOR) == []
