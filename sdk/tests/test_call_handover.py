"""Tests for ``call.handover()`` — the ARI-*Stasis* handoff to an out-of-process
control application. Mirrors the Rust ``PyCall::handover`` / ``CallAction::Handover``.
"""

import pytest

from siphon_sdk.call import Call


class TestCallHandover:
    def test_handover_records_action_with_full_args(self):
        call = Call()
        call.handover("ivr-app", on_lost="hangup", deadline_ms=3000,
                      vars={"queue": "support"})
        action = call._actions[-1]
        assert action.kind == "handover"
        assert action.extras["app"] == "ivr-app"
        assert action.extras["on_lost"] == "hangup"
        assert action.extras["deadline_ms"] == 3000
        assert action.extras["vars"] == {"queue": "support"}

    def test_handover_defaults(self):
        call = Call()
        call.handover("ivr-app")
        action = call._actions[-1]
        assert action.extras["on_lost"] is None
        assert action.extras["deadline_ms"] is None
        assert action.extras["vars"] == {}
        assert action.extras["answer"] is False

    def test_handover_answer_first_mode(self):
        call = Call()
        call.handover("ivr-app", answer=True)
        assert call._actions[-1].extras["answer"] is True

    def test_handover_rejects_empty_app(self):
        call = Call()
        with pytest.raises(ValueError):
            call.handover("")

    def test_handover_rejects_bad_on_lost(self):
        call = Call()
        with pytest.raises(ValueError):
            call.handover("ivr-app", on_lost="explode")

    @pytest.mark.parametrize("policy", ["hangup", "continue", "fallback"])
    def test_handover_accepts_valid_on_lost(self, policy):
        call = Call()
        call.handover("ivr-app", on_lost=policy)
        assert call._actions[-1].extras["on_lost"] == policy
