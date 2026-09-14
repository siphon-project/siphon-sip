"""``registrar.save()`` answering a REGISTER the registrar refuses.

The engine answers a refusal itself (423 + Min-Expires, 503 + Retry-After,
404), returns ``False`` and stores nothing. The mock has to do the same, and it
has to store the Contacts the request actually carries, or a script that
handles ``save()`` returning ``False`` cannot be tested at all.
"""
from siphon_sdk import mock_module
from siphon_sdk.request import Request
from siphon_sdk.testing import SipTestHarness
from siphon_sdk.types import Contact

AOR = "sip:001010000000001@ims.example.com"


def _registrar(**limits):
    mock_module.reset()
    mock_module.install()
    registrar = mock_module.get_registrar()
    if limits:
        registrar.configure(**limits)
    return registrar


def _device(host_port: str, instance: str) -> str:
    return (
        f"<sip:001010000000001@{host_port}>;+sip.instance="
        f'"<urn:uuid:00000000-0000-1000-8000-00000000000{instance}>"'
    )


def _register(*contacts: str, expires: str = "3600") -> Request:
    return Request(
        method="REGISTER",
        ruri="sip:ims.example.com",
        from_uri=AOR,
        to_uri=AOR,
        source_ip="192.0.2.10",
        source_port=5060,
        headers={"Contact": list(contacts), "Expires": expires},
    )


def _reply(request: Request) -> tuple:
    return request.actions[-1].status_code, request.actions[-1].reason


def test_save_stores_the_contact_the_request_carries():
    registrar = _registrar()
    request = _register(_device("192.0.2.10:5060", "a"))

    assert registrar.save(request) is True

    assert _reply(request) == (200, "OK")
    assert [c.uri for c in registrar.lookup(AOR)] == [
        "sip:001010000000001@192.0.2.10:5060"
    ]


def test_the_same_instance_from_a_new_port_replaces_its_binding():
    registrar = _registrar()
    registrar.save(_register(_device("192.0.2.10:5060", "a")))
    registrar.save(_register(_device("192.0.2.10:5070", "a")))

    assert [c.uri for c in registrar.lookup(AOR)] == [
        "sip:001010000000001@192.0.2.10:5070"
    ]


def test_expires_zero_removes_only_that_contact():
    registrar = _registrar()
    registrar.save(
        _register(
            "<sip:001010000000001@192.0.2.10:5060>",
            "<sip:001010000000001@192.0.2.11:5060>",
        )
    )

    registrar.save(_register("<sip:001010000000001@192.0.2.10:5060>;expires=0"))

    assert [c.uri for c in registrar.lookup(AOR)] == [
        "sip:001010000000001@192.0.2.11:5060"
    ]


def test_max_expires_caps_the_stored_lifetime():
    registrar = _registrar(max_expires=600)
    registrar.save(_register(_device("192.0.2.10:5060", "a"), expires="3600"))

    assert registrar.lookup(AOR)[0].expires == 600


def test_a_second_device_past_max_contacts_is_answered_503_with_retry_after():
    registrar = _registrar(max_contacts=1)
    registrar.save(_register(_device("192.0.2.10:5060", "a")))

    second = _register(_device("192.0.2.11:5060", "b"))
    assert registrar.save(second) is False

    assert _reply(second) == (503, "Service Unavailable")
    assert second.get_reply_header("Retry-After") == "3600"
    assert [c.uri for c in registrar.lookup(AOR)] == [
        "sip:001010000000001@192.0.2.10:5060"
    ]


def test_an_interval_below_min_expires_is_answered_423_with_min_expires():
    registrar = _registrar(min_expires=60)
    request = _register(_device("192.0.2.10:5060", "a"), expires="30")

    assert registrar.save(request) is False

    assert _reply(request) == (423, "Interval Too Brief")
    assert request.get_reply_header("Min-Expires") == "60"
    assert registrar.lookup(AOR) == []


def test_more_new_contacts_than_allowed_stores_none_of_them():
    registrar = _registrar(max_contacts=1)
    request = _register(
        _device("192.0.2.10:5060", "a"), _device("192.0.2.11:5060", "b")
    )

    assert registrar.save(request) is False

    assert _reply(request)[0] == 503
    # Nothing is held, so nothing will expire to free a slot.
    assert request.get_reply_header("Retry-After") == "7200"
    assert registrar.lookup(AOR) == []


def test_force_on_a_refused_register_keeps_the_existing_bindings():
    registrar = _registrar(max_contacts=1)
    registrar.save(_register(_device("192.0.2.10:5060", "a")))

    forced = _register(
        _device("192.0.2.11:5060", "b"), _device("192.0.2.12:5060", "c")
    )
    assert registrar.save(forced, force=True) is False

    assert [c.uri for c in registrar.lookup(AOR)] == [
        "sip:001010000000001@192.0.2.10:5060"
    ]


def test_force_replaces_the_bindings_when_accepted():
    registrar = _registrar(max_contacts=1)
    registrar.save(_register(_device("192.0.2.10:5060", "a")))

    assert registrar.save(_register(_device("192.0.2.11:5060", "b")), force=True)

    assert [c.uri for c in registrar.lookup(AOR)] == [
        "sip:001010000000001@192.0.2.11:5060"
    ]


def test_an_aor_that_is_not_a_safe_storage_key_is_answered_404():
    registrar = _registrar()
    registrar.set_associated_uris("sip:unsafe\x01key@ims.example.com", [AOR])
    request = _register(_device("192.0.2.10:5060", "a"))

    assert registrar.save(request) is False

    assert _reply(request) == (404, "Not Found")
    assert registrar._store == {}


def test_retry_after_is_clamped_to_max_expires():
    registrar = _registrar(max_contacts=1, max_expires=7200)
    registrar.add_contact(
        AOR, Contact(uri="sip:001010000000001@192.0.2.10:5060", expires=9000)
    )
    request = _register(_device("192.0.2.11:5060", "b"))

    assert registrar.save(request) is False
    assert request.get_reply_header("Retry-After") == "7200"


def test_retry_after_is_at_least_one_second():
    registrar = _registrar(max_contacts=1)
    registrar.add_contact(
        AOR, Contact(uri="sip:001010000000001@192.0.2.10:5060", expires=1)
    )
    request = _register(_device("192.0.2.11:5060", "b"))

    assert registrar.save(request) is False
    assert request.get_reply_header("Retry-After") == "1"


def test_a_refused_register_fires_no_change_event():
    registrar = _registrar(max_contacts=1)
    seen = []
    registrar.on_change(lambda aor, event, contacts: seen.append(event))
    registrar.save(_register(_device("192.0.2.10:5060", "a")))
    assert seen == ["registered"]

    registrar.save(_register(_device("192.0.2.11:5060", "b")))

    assert seen == ["registered"]


def test_a_register_without_a_contact_header_still_binds_its_source():
    """Fixtures that never modelled a Contact keep registering something."""
    registrar = _registrar()
    request = Request(
        method="REGISTER",
        ruri="sip:ims.example.com",
        from_uri=AOR,
        to_uri=AOR,
        source_ip="192.0.2.20",
    )

    assert registrar.save(request) is True
    assert len(registrar.lookup(AOR)) == 1


def test_a_script_sees_false_and_the_refusal_goes_out():
    harness = SipTestHarness(local_domains=["ims.example.com"])
    harness.load_source(
        "from siphon import proxy, registrar\n"
        "\n"
        "@proxy.on_request('REGISTER')\n"
        "def register(request):\n"
        "    if not registrar.save(request):\n"
        "        return\n"
    )
    harness.registrar.configure(max_contacts=1)

    first = harness.send_request(
        "REGISTER",
        "sip:ims.example.com",
        from_uri=AOR,
        headers={"Contact": _device("192.0.2.10:5060", "a"), "Expires": "3600"},
    )
    second = harness.send_request(
        "REGISTER",
        "sip:ims.example.com",
        from_uri=AOR,
        headers={"Contact": _device("192.0.2.11:5060", "b"), "Expires": "3600"},
    )

    assert first.status_code == 200
    assert second.status_code == 503
    assert second.request.get_reply_header("Retry-After") is not None
