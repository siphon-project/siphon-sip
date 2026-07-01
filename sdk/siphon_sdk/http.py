"""
siphon.http — mock of the HTTP server+client namespace (siphon-http extension).

At runtime the ``http`` namespace is injected by the **siphon-http** extension
(a ``siphon-bin`` build with the ``http`` feature), not by siphon-sip itself.
This module mirrors that namespace so HTTP scripts can be:

1. **Unit tested** with pytest without binding a real listener — see
   :class:`siphon_sdk.http_testing.HttpTestHarness`.
2. **Authored with LLM/IDE assistance** — the decorators and the
   ``Request`` / ``Response`` / ``Client`` pyclasses carry the same signatures
   and docstrings as the runtime.

The runtime namespace is defined by ``python/http.py`` (decorators) plus the
Rust ``Request`` / ``Response`` / ``Client`` pyclasses (``src/request.rs`` /
``response.rs`` / ``client.rs``) in the siphon-http repository. Keep this mock
in step — the siphon-http CI parity check fails if a name here drifts.

Quick start::

    from siphon import http

    @http.route("/users/{id}", methods=["GET"])
    async def get_user(req):
        uid = req.path_params["id"]
        return http.Response(status=200, body=f"user {uid}")
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Any, Callable, Optional, Union


class HttpStatusError(Exception):
    """Raised by :meth:`MockResponse.raise_for_status` for a >= 400 status —
    the mock analogue of ``reqwest``'s error-for-status."""


def _as_bytes(value: Union[str, bytes, bytearray, None]) -> bytes:
    if value is None:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


def _lower_headers(headers: Optional[dict[str, str]]) -> dict[str, str]:
    """Lowercase header keys (the runtime exposes a lowercase-keyed dict)."""
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


# ---------------------------------------------------------------------------
# Pyclasses (mirror src/request.rs / response.rs / client.rs)
# ---------------------------------------------------------------------------

class MockRequest:
    """An inbound HTTP request — the only arg passed to ``@http.route`` and
    ``@http.middleware`` handlers.

    Attributes:
        method:       ``"GET"`` / ``"PUT"`` / …
        path:         request path
        path_params:  ``dict[str, str]`` extracted from the matched route
        query_params: ``dict[str, str]``
        headers:      lowercase-keyed ``dict[str, str]``
        client:       remote socket address, ``"ip:port"``
    """

    def __init__(self, *, method: str = "GET", path: str = "/",
                 path_params: Optional[dict[str, str]] = None,
                 query_params: Optional[dict[str, str]] = None,
                 headers: Optional[dict[str, str]] = None,
                 client: str = "127.0.0.1:0",
                 body: Union[str, bytes, None] = b"") -> None:
        self.method = method.upper()
        self.path = path
        self.path_params = path_params or {}
        self.query_params = query_params or {}
        self.headers = _lower_headers(headers)
        self.client = client
        self._body = _as_bytes(body)

    def body(self) -> bytes:
        """The buffered request body as bytes."""
        return self._body

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup; ``None`` if absent."""
        return self.headers.get(name.lower())

    def __repr__(self) -> str:
        return f"Request(method={self.method}, path={self.path!r})"


class MockResponse:
    """An outbound HTTP response (route return value) or the result of an
    outbound :class:`MockClient` call.

    Construct with ``http.Response(status=200, headers={...}, body=b"...")``;
    ``body`` accepts bytes or str (UTF-8 encoded).
    """

    def __init__(self, status: int = 200,
                 headers: Optional[dict[str, str]] = None,
                 body: Union[str, bytes, None] = None) -> None:
        self.status = status
        self.headers = _lower_headers(headers)
        self._body = _as_bytes(body)

    @property
    def body(self) -> bytes:
        """The response body as bytes."""
        return self._body

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup; ``None`` if absent."""
        return self.headers.get(name.lower())

    def raise_for_status(self) -> "MockResponse":
        """Raise :class:`HttpStatusError` if ``status`` is >= 400, else return
        self (so ``resp.raise_for_status()`` can be chained)."""
        if self.status >= 400:
            raise HttpStatusError(f"HTTP status {self.status}")
        return self

    def __repr__(self) -> str:
        return f"Response(status={self.status}, body_len={len(self._body)})"


class MockClient:
    """An outbound HTTP client. In tests it **records** each request on the
    namespace's :attr:`MockHttp.sent_requests` and returns a canned
    :class:`MockResponse` (queue → per-path → default; configure via
    ``http`` harness helpers). Supports ``async with``.

    Two construction modes, mirroring the runtime::

        http.Client("api")                       # named (config clients.api)
        http.Client(base_url="https://api.example.com")
    """

    def __init__(self, name: Optional[str] = None, *, base_url: Optional[str] = None,
                 verify: Optional[str] = None,
                 cert: Optional[tuple[str, str]] = None,
                 timeout_ms: Optional[int] = None,
                 http2_prior_knowledge: bool = False) -> None:
        self.name = name
        self.base_url = base_url
        self.verify = verify
        self.cert = cert
        self.timeout_ms = timeout_ms
        self.http2_prior_knowledge = http2_prior_knowledge

    async def get(self, path: str, *, headers: Optional[dict] = None) -> MockResponse:
        return self._request("GET", path, None, headers)

    async def put(self, path: str, *, body: Any = None,
                  headers: Optional[dict] = None) -> MockResponse:
        return self._request("PUT", path, body, headers)

    async def post(self, path: str, *, body: Any = None,
                   headers: Optional[dict] = None) -> MockResponse:
        return self._request("POST", path, body, headers)

    async def patch(self, path: str, *, body: Any = None,
                    headers: Optional[dict] = None) -> MockResponse:
        return self._request("PATCH", path, body, headers)

    async def delete(self, path: str, *, headers: Optional[dict] = None) -> MockResponse:
        return self._request("DELETE", path, None, headers)

    async def __aenter__(self) -> "MockClient":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return False

    def _request(self, method: str, path: str, body: Any,
                 headers: Optional[dict]) -> MockResponse:
        ns = _active_http()
        url = f"{self.base_url.rstrip('/')}{path}" if self.base_url else path
        ns.sent_requests.append({
            "method": method, "path": path, "url": url,
            "name": self.name, "base_url": self.base_url,
            "headers": dict(headers or {}), "body": _as_bytes(body),
        })
        return ns._next_response(path)


# ---------------------------------------------------------------------------
# The http namespace
# ---------------------------------------------------------------------------

def _registry() -> Any:
    """Resolve the mock ``_siphon_registry`` (deferred import, like the runtime
    ``python/http.py``)."""
    import _siphon_registry as registry
    return registry


# Module-global handle to the active namespace, so a script-constructed
# ``http.Client(...)`` can record onto / read canned responses from it. There
# is exactly one MockHttp singleton per process (created in mock_module).
_ACTIVE: Optional["MockHttp"] = None


def _active_http() -> "MockHttp":
    if _ACTIVE is None:  # pragma: no cover - install() always creates one
        raise RuntimeError("mock http namespace not installed")
    return _ACTIVE


class MockHttp:
    """Mock ``http`` namespace — the ``route`` / ``middleware`` / ``on_startup``
    decorators plus the ``Request`` / ``Response`` / ``Client`` pyclasses.

    Outbound :class:`MockClient` calls are recorded on :attr:`sent_requests`
    and answered from a configurable response source (queue → per-path →
    default), so route logic that calls out can be tested in isolation.
    """

    # Pyclasses attached to the namespace (``http.Response(...)`` etc.).
    Request = MockRequest
    Response = MockResponse
    Client = MockClient

    def __init__(self) -> None:
        #: Recorded outbound client requests — list of dicts.
        self.sent_requests: list[dict[str, Any]] = []
        self._response_queue: deque[MockResponse] = deque()
        self._path_responses: dict[str, MockResponse] = {}
        self._default_response: Optional[MockResponse] = None
        global _ACTIVE
        _ACTIVE = self

    # -- test helpers -------------------------------------------------------

    def clear(self) -> None:
        """Reset recorded requests + canned responses (called by
        ``mock_module.reset()``)."""
        self.sent_requests.clear()
        self._response_queue.clear()
        self._path_responses.clear()
        self._default_response = None

    def add_response(self, response: MockResponse) -> None:
        """Enqueue a :class:`MockResponse` returned by the next outbound
        client call (FIFO)."""
        self._response_queue.append(response)

    def set_response(self, path: str, response: MockResponse) -> None:
        """Set the :class:`MockResponse` returned for outbound calls to
        ``path`` (used after the FIFO queue is drained)."""
        self._path_responses[path] = response

    def set_default_response(self, response: MockResponse) -> None:
        """Set the fallback :class:`MockResponse` for outbound calls with no
        queued/per-path match (default is ``200`` empty)."""
        self._default_response = response

    def _next_response(self, path: str) -> MockResponse:
        if self._response_queue:
            return self._response_queue.popleft()
        if path in self._path_responses:
            return self._path_responses[path]
        if self._default_response is not None:
            return self._default_response
        return MockResponse(200, body=b"")

    # -- decorators ---------------------------------------------------------

    def route(self, path: str, methods: Optional[list[str]] = None) -> Callable:
        """Register a route handler. ``path`` is a matchit-style pattern
        (``/users/{id}``, ``/static/{*rest}``); ``methods`` defaults to
        ``["GET"]``. The handler receives a :class:`MockRequest` and must
        return a :class:`MockResponse` (anything else is a 500)."""
        methods = [m.upper() for m in (methods or ["GET"])]

        def decorator(fn: Callable) -> Callable:
            _registry().register("http.route", None, fn,
                                 asyncio.iscoroutinefunction(fn),
                                 {"path": path, "methods": methods})
            return fn
        return decorator

    def middleware(self, fn: Callable) -> Callable:
        """Register a request-guard middleware. Middlewares run in registration
        order before the matched route handler, each receiving the
        :class:`MockRequest`; return a :class:`MockResponse` to short-circuit,
        or ``None`` to continue."""
        _registry().register("http.middleware", None, fn,
                             asyncio.iscoroutinefunction(fn), {})
        return fn

    def on_startup(self, fn: Callable) -> Callable:
        """Register a startup hook — runs once, to completion, after the script
        loads and before any listener accepts."""
        _registry().register("http.startup", None, fn,
                             asyncio.iscoroutinefunction(fn), {})
        return fn
