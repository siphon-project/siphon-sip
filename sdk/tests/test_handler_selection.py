"""Which `@proxy.on_request` handlers run for a given method.

A filtered handler does not replace the unfiltered one — both run. That is
easy to get wrong in a script (it silently doubles a side effect: a probe that
is answered *and* relayed), and it is the opposite of the rule
`@diameter.on_request` uses, so it is pinned here rather than left to the
docstring.
"""

import pytest

from siphon_sdk.mock_module import install, reset, get_registry


@pytest.fixture(autouse=True)
def _install():
    install()
    reset()
    yield


def _matching(method):
    """The handlers siphon would run for `method`, in registration order."""
    return [fn for fn, _is_async in get_registry().get("proxy.on_request", method)]


class TestProxyOnRequestSelection:
    def test_filtered_and_unfiltered_both_run(self):
        from siphon import proxy

        @proxy.on_request("OPTIONS")
        def probe(request):
            ...

        @proxy.on_request
        def route(request):
            ...

        assert _matching("OPTIONS") == [probe, route], (
            "a filtered handler does not replace the unfiltered one"
        )

    def test_unfiltered_matches_every_method(self):
        from siphon import proxy

        @proxy.on_request
        def route(request):
            ...

        for method in ("INVITE", "REGISTER", "OPTIONS", "MESSAGE", "NOTIFY"):
            assert _matching(method) == [route]

    def test_filtered_handler_does_not_run_for_other_methods(self):
        from siphon import proxy

        @proxy.on_request("REGISTER")
        def register(request):
            ...

        assert _matching("REGISTER") == [register]
        assert _matching("INVITE") == []

    def test_pipe_separated_filter_matches_each_listed_method(self):
        from siphon import proxy

        @proxy.on_request("INVITE|SUBSCRIBE")
        def some(request):
            ...

        assert _matching("INVITE") == [some]
        assert _matching("SUBSCRIBE") == [some]
        assert _matching("MESSAGE") == []

    def test_handlers_run_in_registration_order(self):
        from siphon import proxy

        @proxy.on_request
        def first(request):
            ...

        @proxy.on_request("INVITE")
        def second(request):
            ...

        @proxy.on_request
        def third(request):
            ...

        assert _matching("INVITE") == [first, second, third]

    def test_branching_inside_one_handler_is_how_you_get_exclusivity(self):
        """The documented remedy: one handler, a branch, no second registration."""
        from siphon import proxy

        @proxy.on_request
        def route(request):
            ...

        assert _matching("OPTIONS") == [route]
        assert _matching("INVITE") == [route]


class TestStopPropagation:
    """`stop_propagation()` is the other remedy: keep two handlers, but let the
    first claim the outcome so the second cannot overwrite its action."""

    def _request(self):
        from siphon_sdk.request import Request
        return Request(method="OPTIONS", ruri="sip:siphon.test")

    def test_off_until_asked(self):
        request = self._request()
        assert not request.propagation_stopped

    def test_replying_does_not_imply_stopping(self):
        # Opt-in on purpose: a metrics handler after the reply is legitimate.
        request = self._request()
        request.reply(200, "OK")
        assert not request.propagation_stopped

    def test_stop_propagation_sets_the_flag(self):
        request = self._request()
        request.reply(200, "OK")
        request.stop_propagation()
        assert request.propagation_stopped

    def test_is_idempotent_and_keeps_the_action(self):
        request = self._request()
        request.reply(486, "Busy Here")
        request.stop_propagation()
        request.stop_propagation()
        assert request.propagation_stopped
        assert request.actions[-1].kind == "reply"
        assert request.actions[-1].status_code == 486
