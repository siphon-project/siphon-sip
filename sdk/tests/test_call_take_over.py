"""Tests for ``call.take_over()`` — a script taking over a dialog an INVITE
names (``Target-Dialog``, RFC 4538). Mirrors the Rust ``PyCall::take_over`` /
``CallAction::TakeOver``.
"""

import pytest

from siphon_sdk.call import Call


class TestCallTakeOver:
    def test_records_the_named_dialog(self):
        call = Call()
        call.take_over("dialog@example.com", "siphon-tag", "far-tag",
                       reinvite=False)
        action = call._actions[-1]
        assert action.kind == "take_over"
        assert action.extras == {
            "call_id": "dialog@example.com",
            "local_tag": "siphon-tag",
            "remote_tag": "far-tag",
            "reinvite": False,
            "headers": {},
        }

    def test_reinvites_by_default(self):
        call = Call()
        call.take_over("dialog@example.com", "siphon-tag", "far-tag")
        assert call._actions[-1].extras["reinvite"] is True

    def test_carries_headers_for_the_200(self):
        call = Call()
        call.take_over("dialog@example.com", "siphon-tag", "far-tag",
                       headers={"P-Asserted-Identity": "<tel:+15550100001>",
                                "Feature-Caps": "*;+g.3gpp.srvcc"})
        assert call._actions[-1].extras["headers"] == {
            "P-Asserted-Identity": "<tel:+15550100001>",
            "Feature-Caps": "*;+g.3gpp.srvcc",
        }

    @pytest.mark.parametrize("owned", ["Contact", "Via", "Require", "Content-Type"])
    def test_refuses_a_header_siphon_owns(self, owned):
        call = Call()
        with pytest.raises(ValueError):
            call.take_over("dialog@example.com", "siphon-tag", "far-tag",
                           headers={owned: "x"})
        assert call._actions == []

    @pytest.mark.parametrize("names", [
        ("", "siphon-tag", "far-tag"),
        ("dialog@example.com", " ", "far-tag"),
        ("dialog@example.com", "siphon-tag", ""),
    ])
    def test_refuses_an_empty_name(self, names):
        call = Call()
        with pytest.raises(ValueError):
            call.take_over(*names)

    def test_refuses_a_non_bool_reinvite(self):
        call = Call()
        with pytest.raises(TypeError):
            call.take_over("dialog@example.com", "siphon-tag", "far-tag",
                           reinvite=1)

    def test_last_action_wins(self):
        call = Call()
        call.take_over("dialog@example.com", "siphon-tag", "far-tag")
        call.dial("sip:bob@example.com")
        assert call._actions[-1].kind == "dial"

    def test_excludes_answer_both_ways(self):
        call = Call()
        call.take_over("dialog@example.com", "siphon-tag", "far-tag")
        with pytest.raises(ValueError):
            call.answer(200, "OK")

        answered = Call()
        answered.answer(200, "OK")
        with pytest.raises(ValueError):
            answered.take_over("dialog@example.com", "siphon-tag", "far-tag")

    def test_docstring_example_reads_target_dialog(self):
        call = Call(headers={
            "Target-Dialog": "dialog@example.com;local-tag=far-tag;remote-tag=siphon-tag",
            "Require": "tdialog",
        })
        target = call.get_header("Target-Dialog")
        dialog_call_id, _, rest = target.partition(";")
        params = dict(p.strip().split("=", 1) for p in rest.split(";") if "=" in p)
        call.take_over(dialog_call_id.strip(), local_tag=params["remote-tag"],
                       remote_tag=params["local-tag"], reinvite=False)
        extras = call._actions[-1].extras
        assert extras["local_tag"] == "siphon-tag"
        assert extras["remote_tag"] == "far-tag"
