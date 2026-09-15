"""
Tests for ``Call.session_timer``, the per-call RFC 4028 session timer.
"""

import pytest

from siphon_sdk.call import Call


class TestCallSessionTimer:
    def test_defaults_mirror_the_runtime(self):
        call = Call()
        call.session_timer()
        action = call._actions[0]
        assert action.kind == "session_timer"
        assert action.extras == {"expires": 1800, "min_se": 90, "refresher": "b2bua"}

    @pytest.mark.parametrize("refresher", ["uac", "uas", "b2bua", "UAS"])
    def test_each_refresher_siphon_negotiates_is_accepted(self, refresher):
        call = Call()
        call.session_timer(900, min_se=120, refresher=refresher)
        assert call._actions[0].extras == {
            "expires": 900,
            "min_se": 120,
            "refresher": refresher.lower(),
        }

    def test_an_unknown_refresher_is_refused(self):
        call = Call()
        with pytest.raises(ValueError, match="refresher"):
            call.session_timer(1800, refresher="sometimes")
        assert call._actions == []
