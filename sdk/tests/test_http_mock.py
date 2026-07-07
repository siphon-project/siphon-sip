"""Tests for the mock ``http`` namespace + :class:`HttpTestHarness`.

The ``http`` namespace is injected at runtime by the siphon-http extension;
these tests exercise the siphon-sip mock of it (route/middleware/startup
decorators, Request/Response/Client) so HTTP scripts can be unit-tested
without binding a real listener.
"""

import pytest

from siphon_sdk.mock_module import install, reset, get_registry
from siphon_sdk.http import MockRequest, MockResponse, HttpStatusError
from siphon_sdk.http_testing import HttpTestHarness, _match_route


@pytest.fixture(autouse=True)
def _install():
    install()
    reset()
    yield


# ---------------------------------------------------------------------------
# Decorator registration
# ---------------------------------------------------------------------------

class TestDecorators:
    def test_route_records_path_and_methods(self):
        from siphon import http

        @http.route("/users/{id}", methods=["get", "post"])
        def handler(req):
            return http.Response()

        handlers = get_registry().handlers.get("http.route", [])
        assert len(handlers) == 1
        _filter, fn, _is_async, metadata = handlers[0]
        assert fn is handler
        assert metadata["path"] == "/users/{id}"
        # methods are upper-cased (mirrors python/http.py)
        assert metadata["methods"] == ["GET", "POST"]

    def test_route_defaults_to_get(self):
        from siphon import http

        @http.route("/health")
        def health(req):
            return http.Response()

        _f, _fn, _a, meta = get_registry().handlers["http.route"][0]
        assert meta["methods"] == ["GET"]

    def test_middleware_and_startup_register(self):
        from siphon import http

        @http.middleware
        def guard(req):
            return None

        @http.on_startup
        async def warm():
            pass

        assert len(get_registry().handlers.get("http.middleware", [])) == 1
        startup = get_registry().handlers.get("http.startup", [])
        assert len(startup) == 1
        assert startup[0][2]  # is_async


# ---------------------------------------------------------------------------
# Pyclasses
# ---------------------------------------------------------------------------

class TestRequest:
    def test_header_case_insensitive(self):
        req = MockRequest(headers={"Content-Type": "application/json"})
        assert req.header("content-type") == "application/json"
        assert req.header("CONTENT-TYPE") == "application/json"
        assert req.header("missing") is None

    def test_body_bytes(self):
        assert MockRequest(body="hi").body() == b"hi"
        assert MockRequest(body=b"raw").body() == b"raw"

    def test_method_uppercased(self):
        assert MockRequest(method="get").method == "GET"


class TestResponse:
    def test_body_coerced_to_bytes(self):
        assert MockResponse(body="ok").body == b"ok"
        assert MockResponse(body=b"raw").body == b"raw"

    def test_raise_for_status(self):
        MockResponse(200).raise_for_status()   # no raise
        MockResponse(204).raise_for_status()
        with pytest.raises(HttpStatusError, match="404"):
            MockResponse(404).raise_for_status()
        with pytest.raises(HttpStatusError, match="503"):
            MockResponse(503).raise_for_status()

    def test_raise_for_status_returns_self(self):
        resp = MockResponse(200, body=b"x")
        assert resp.raise_for_status() is resp


class TestRouteMatcher:
    def test_static_match(self):
        assert _match_route("/health", "/health") == {}
        assert _match_route("/health", "/other") is None

    def test_named_param(self):
        assert _match_route("/users/{id}", "/users/42") == {"id": "42"}
        assert _match_route("/users/{id}", "/users/42/extra") is None

    def test_catch_all(self):
        assert _match_route("/static/{*rest}", "/static/a/b/c") == {"rest": "a/b/c"}

    def test_multi_segment(self):
        assert _match_route("/a/{x}/b/{y}", "/a/1/b/2") == {"x": "1", "y": "2"}


# ---------------------------------------------------------------------------
# End-to-end via HttpTestHarness
# ---------------------------------------------------------------------------

class TestHarness:
    def test_route_dispatch_and_path_params(self):
        harness = HttpTestHarness()
        harness.load_source("""
from siphon import http

@http.route("/users/{id}")
def get_user(req):
    return http.Response(status=200, body=f"user {req.path_params['id']}")
""")
        resp = harness.request("GET", "/users/42")
        assert resp.status == 200
        assert resp.body == b"user 42"

    def test_method_filter_and_404(self):
        harness = HttpTestHarness()
        harness.load_source("""
from siphon import http

@http.route("/things", methods=["POST"])
def create(req):
    return http.Response(status=201)
""")
        assert harness.request("POST", "/things").status == 201
        # GET on a POST-only route → no match → 404
        assert harness.request("GET", "/things").status == 404
        # unknown path → 404
        assert harness.request("GET", "/nope").status == 404

    def test_query_params_parsed_from_path(self):
        harness = HttpTestHarness()
        harness.load_source("""
from siphon import http

@http.route("/search")
def search(req):
    return http.Response(status=200, body=req.query_params.get("q", ""))
""")
        resp = harness.request("GET", "/search?q=hello&lang=en")
        assert resp.body == b"hello"

    def test_middleware_short_circuits(self):
        harness = HttpTestHarness()
        harness.load_source("""
from siphon import http

@http.middleware
def auth(req):
    if req.header("authorization") is None:
        return http.Response(status=401, body=b"unauthorized")
    return None

@http.route("/secure")
def secure(req):
    return http.Response(status=200, body=b"secret")
""")
        assert harness.request("GET", "/secure").status == 401
        ok = harness.request("GET", "/secure", headers={"Authorization": "Bearer x"})
        assert ok.status == 200 and ok.body == b"secret"

    def test_handler_returning_non_response_is_500(self):
        harness = HttpTestHarness()
        harness.load_source("""
from siphon import http

@http.route("/broken")
def broken(req):
    return "oops"   # not a Response
""")
        assert harness.request("GET", "/broken").status == 500

    def test_outbound_client_recorded_and_canned(self):
        harness = HttpTestHarness()
        harness.add_response(MockResponse(status=200, body=b'{"ok":true}'))
        harness.load_source("""
from siphon import http

@http.route("/proxy")
async def proxy(req):
    async with http.Client("api") as c:
        upstream = await c.get("/v1/thing")
    return http.Response(status=upstream.status, body=upstream.body)
""")
        resp = harness.request("GET", "/proxy")
        assert resp.status == 200
        assert resp.body == b'{"ok":true}'
        assert len(harness.sent_requests) == 1
        sent = harness.sent_requests[0]
        assert sent["method"] == "GET"
        assert sent["path"] == "/v1/thing"
        assert sent["name"] == "api"

    def test_outbound_client_per_path_response(self):
        harness = HttpTestHarness()
        harness.set_response("/v1/thing", MockResponse(status=418))
        harness.load_source("""
from siphon import http

@http.route("/proxy")
async def proxy(req):
    async with http.Client(base_url="https://api.example.com") as c:
        upstream = await c.post("/v1/thing", body=b"x")
    return http.Response(status=upstream.status)
""")
        assert harness.request("GET", "/proxy").status == 418
        assert harness.sent_requests[0]["url"] == "https://api.example.com/v1/thing"

    def test_startup_hook_runs(self):
        harness = HttpTestHarness()
        harness.load_source("""
from siphon import http, log

@http.on_startup
async def warm():
    log.info("warmed")
""")
        harness.run_startup()
        assert any("warmed" in msg for _lvl, msg in harness.log.messages)

    def test_coexists_with_sip_and_smpp(self):
        harness = HttpTestHarness()
        harness.load_source("""
from siphon import proxy, smpp, http

@proxy.on_request
def sip(request):
    request.relay()

@smpp.on_pdu("submit_sm")
def sms(pdu, session):
    return pdu.reply()

@http.route("/health")
def health(req):
    return http.Response(status=200, body=b"ok")
""")
        assert harness.request("GET", "/health").body == b"ok"
        assert len(get_registry().handlers.get("proxy.on_request", [])) == 1
        assert len(get_registry().handlers.get("smpp.on_pdu", [])) == 1
