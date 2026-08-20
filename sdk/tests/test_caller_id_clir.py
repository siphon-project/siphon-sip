"""Per-route caller ID, and CLIR that actually anonymises.

The presented CLI is a per-call, per-carrier decision. `number_policy` reshapes
a number's *format* but cannot substitute a different one; `call.set_from_user`
is tag-safe but identical for every carrier attempt; and a `From` in a route's
`headers` is refused because it would take the dialog tag with it.

Separately: asserting `Privacy: id` while leaving the real number in the `From`
leaks it to every carrier that renders `From` rather than `P-Asserted-Identity`,
which defeats CLIR while looking like it works. The two always move together.
"""

from siphon_sdk.call import Call
from siphon_sdk.lcr import LcrResponse, Route

ANONYMOUS = "sip:anonymous@anonymous.invalid"


def _call() -> Call:
    return Call(
        call_id="clir-1",
        from_uri="sip:+12025550100@siphon.example.com",
        headers={
            "From": '"Alice" <sip:+12025550100@siphon.example.com>;tag=a-tag',
            "P-Asserted-Identity": "<sip:+12025550100@siphon.example.com>",
        },
    )


# ── LCR contract ─────────────────────────────────────────────────────────


def test_route_caller_id_round_trips():
    route = Route(carrier_id="a", gateway_group="g", caller_id="+12025550111")

    assert route.to_dict()["caller_id"] == "+12025550111"
    assert Route.from_dict(route.to_dict()).caller_id == "+12025550111"


def test_route_presentation_round_trips():
    route = Route(carrier_id="a", gateway_group="g", caller_id_presentation="restricted")

    assert route.to_dict()["caller_id_presentation"] == "restricted"
    assert Route.from_dict(route.to_dict()).caller_id_presentation == "restricted"


def test_caller_id_fields_are_absent_from_the_wire_when_unset():
    """Additive: an API that never sets them sees no change."""
    wire = Route(carrier_id="a", gateway_group="g").to_dict()

    assert "caller_id" not in wire
    assert "caller_id_presentation" not in wire


def test_two_carriers_in_one_answer_can_present_different_clis():
    response = LcrResponse.from_dict(
        {
            "routes": [
                {"carrier_id": "a", "gateway_group": "g", "caller_id": "+12025550111"},
                {"carrier_id": "b", "gateway_group": "g", "caller_id": "+442071838750"},
            ]
        }
    )

    assert [r.caller_id for r in response.routes] == ["+12025550111", "+442071838750"]


# ── Script primitives ────────────────────────────────────────────────────


def test_set_caller_id_rewrites_from_and_keeps_the_dialog_tag():
    call = _call()
    assert call.set_caller_id("+12025550111") is True

    assert "+12025550111" in call.get_header("From")
    assert "+12025550100" not in call.get_header("From")
    assert "tag=a-tag" in call.get_header("From"), "the dialog tag must survive"


def test_set_caller_id_also_rewrites_asserted_identity():
    call = _call()
    call.set_caller_id("+12025550111")

    assert "+12025550111" in call.get_header("P-Asserted-Identity")


def test_set_caller_id_ignores_an_empty_number():
    call = _call()
    assert call.set_caller_id("") is False
    assert "+12025550100" in call.get_header("From")


def test_restrict_anonymises_from_and_asserts_privacy_id():
    call = _call()
    call.restrict_caller_id()

    from_header = call.get_header("From")
    assert ANONYMOUS in from_header
    assert "Anonymous" in from_header
    assert "+12025550100" not in from_header, "the real number must not survive in From"
    assert "tag=a-tag" in from_header, "the dialog tag must survive"
    assert call.get_header("Privacy") == "id"


def test_restrict_keeps_the_real_identity_in_pai():
    """RFC 3325 §7 — the trusted next hop still learns who is calling."""
    call = _call()
    call.restrict_caller_id()

    assert "+12025550100" in call.get_header("P-Asserted-Identity")


def test_restrict_removes_p_preferred_identity():
    call = Call(
        call_id="clir-2",
        headers={
            "From": "<sip:+12025550100@siphon.example.com>;tag=a-tag",
            "P-Preferred-Identity": "<sip:+12025550100@siphon.example.com>",
        },
    )
    call.restrict_caller_id()

    assert call.get_header("P-Preferred-Identity") is None


def test_restrict_appends_to_an_existing_privacy_value():
    call = Call(
        call_id="clir-3",
        headers={"From": "<sip:a@b>;tag=t", "Privacy": "header"},
    )
    call.restrict_caller_id()

    privacy = call.get_header("Privacy")
    assert "header" in privacy
    assert "id" in privacy


def test_restrict_is_idempotent():
    call = Call(call_id="clir-4", headers={"From": "<sip:a@b>;tag=t", "Privacy": "id"})
    call.restrict_caller_id()
    call.restrict_caller_id()

    assert call.get_header("Privacy") == "id"


def test_a_withheld_call_goes_out_anonymous_with_a_real_pai():
    """The whole point, end to end."""
    call = _call()
    call.set_caller_id("+12025550111")
    call.restrict_caller_id()

    assert ANONYMOUS in call.get_header("From")
    assert "tag=a-tag" in call.get_header("From")
    assert "+12025550111" in call.get_header("P-Asserted-Identity")
    assert call.get_header("Privacy") == "id"
