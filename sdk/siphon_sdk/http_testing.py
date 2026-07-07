"""
Test harness for HTTP scripts (siphon-http extension).

Mirrors :class:`siphon_sdk.testing.SipTestHarness` for the ``http`` namespace:
install the mock module, load a script (registering ``@http.route`` /
``@http.middleware`` / ``@http.on_startup``), then dispatch mock requests
through the middleware chain into the matched route and assert on the response.

Example::

    from siphon_sdk.http_testing import HttpTestHarness

    harness = HttpTestHarness()
    harness.load_source('''
    from siphon import http

    @http.route("/users/{id}")
    def get_user(req):
        return http.Response(status=200, body=f"user {req.path_params['id']}")
    ''')

    resp = harness.request("GET", "/users/42")
    assert resp.status == 200
    assert resp.body == b"user 42"
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl

from siphon_sdk import mock_module
from siphon_sdk.http import MockHttp, MockRequest, MockResponse


def _match_route(pattern: str, path: str) -> Optional[dict[str, str]]:
    """Match a concrete ``path`` against a matchit-style ``pattern``.

    Supports ``{name}`` (one segment) and ``{*rest}`` (catch-all, must be the
    last segment). Returns the extracted path-params dict, or ``None`` when the
    pattern doesn't match.
    """
    pat_parts = pattern.strip("/").split("/") if pattern.strip("/") else []
    path_parts = path.strip("/").split("/") if path.strip("/") else []

    params: dict[str, str] = {}
    for i, seg in enumerate(pat_parts):
        if seg.startswith("{*") and seg.endswith("}"):
            params[seg[2:-1]] = "/".join(path_parts[i:])
            return params
        if i >= len(path_parts):
            return None
        if seg.startswith("{") and seg.endswith("}"):
            params[seg[1:-1]] = path_parts[i]
        elif seg != path_parts[i]:
            return None
    if len(path_parts) != len(pat_parts):
        return None
    return params


class HttpTestHarness:
    """High-level test harness for HTTP scripts.

    Installs the mock ``siphon`` module, loads scripts, and dispatches mock
    HTTP requests through the registered middleware chain and route handlers.
    """

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        mock_module.reset()
        self._module = mock_module.install()
        self._loop = asyncio.new_event_loop()
        self._config = config or {}

    # -- accessors ----------------------------------------------------------

    @property
    def http(self) -> MockHttp:
        """The mock ``http`` namespace (e.g. ``harness.http.add_response(...)``)."""
        return mock_module.get_http()

    @property
    def sent_requests(self) -> list[dict[str, Any]]:
        """Recorded outbound ``http.Client`` requests."""
        return mock_module.get_http().sent_requests

    @property
    def log(self) -> Any:
        return mock_module.get_log()

    @property
    def cache(self) -> Any:
        return mock_module.get_cache()

    def reset(self) -> None:
        mock_module.reset()

    def close(self) -> None:
        self._loop.close()

    # -- outbound client canning (delegate to the namespace) ----------------

    def add_response(self, response: MockResponse) -> None:
        """Enqueue a response for the next outbound ``http.Client`` call."""
        mock_module.get_http().add_response(response)

    def set_response(self, path: str, response: MockResponse) -> None:
        """Set the response returned for outbound calls to ``path``."""
        mock_module.get_http().set_response(path, response)

    # -- script loading -----------------------------------------------------

    def load_script(self, path: str) -> None:
        script_path = Path(path).resolve()
        if not script_path.exists():
            raise FileNotFoundError(f"Script not found: {script_path}")
        script_dir = str(script_path.parent)
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        source = script_path.read_text()
        code = compile(source, str(script_path), "exec")
        exec(code, {"__name__": "__siphon_script__", "__file__": str(script_path)})

    def load_source(self, source: str, name: str = "<test>") -> None:
        code = compile(source, name, "exec")
        exec(code, {"__name__": "__siphon_script__", "__file__": name})

    # -- dispatch -----------------------------------------------------------

    def _run(self, coro_or_value: Any) -> Any:
        if asyncio.iscoroutine(coro_or_value):
            return self._loop.run_until_complete(coro_or_value)
        return coro_or_value

    def run_startup(self) -> None:
        """Run all ``@http.on_startup`` hooks to completion."""
        for _f, fn, _a, _m in mock_module.get_registry().handlers.get("http.startup", []):
            self._run(fn())

    def request(self, method: str = "GET", path: str = "/", *,
                headers: Optional[dict[str, str]] = None,
                query_params: Optional[dict[str, str]] = None,
                path_params: Optional[dict[str, str]] = None,
                body: Any = None,
                client: str = "127.0.0.1:0") -> MockResponse:
        """Dispatch a mock HTTP request: run the middleware chain, then the
        first matching route handler; return the :class:`MockResponse`.

        Semantics mirror the runtime:

        * a middleware returning a :class:`MockResponse` short-circuits;
        * an unmatched path returns ``404``;
        * a route handler returning a non-``Response`` returns ``500``.
        """
        method = method.upper()
        # Split a query string off the path if present.
        query: dict[str, str] = dict(query_params or {})
        if "?" in path:
            path, _, qs = path.partition("?")
            query.update(dict(parse_qsl(qs)))

        registry = mock_module.get_registry()

        # Resolve the route first so matched path-params are on the Request the
        # middleware chain sees.
        matched_fn = None
        matched_params: dict[str, str] = {}
        for _f, fn, _a, meta in registry.handlers.get("http.route", []):
            if method not in meta.get("methods", []):
                continue
            params = _match_route(meta.get("path", ""), path)
            if params is not None:
                matched_fn = fn
                matched_params = params
                break

        request = MockRequest(
            method=method, path=path,
            path_params=path_params if path_params is not None else matched_params,
            query_params=query, headers=headers, client=client, body=body,
        )

        # Middleware chain — first Response short-circuits.
        for _f, fn, _a, _m in registry.handlers.get("http.middleware", []):
            result = self._run(fn(request))
            if isinstance(result, MockResponse):
                return result

        if matched_fn is None:
            return MockResponse(status=404, body=b"Not Found")

        result = self._run(matched_fn(request))
        if not isinstance(result, MockResponse):
            # Runtime: a handler that doesn't return a Response is a 500.
            return MockResponse(status=500, body=b"Internal Server Error")
        return result
