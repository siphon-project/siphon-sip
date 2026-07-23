"""
Mock ``siphon`` module — drop-in replacement for the Rust-injected module.

Call ``install()`` to register a fake ``siphon`` package in ``sys.modules``
so that scripts using ``from siphon import proxy, registrar, ...`` work
without the Rust binary.

The mock module records all decorator registrations and provides
configurable backends for registrar, auth, cache, etc.
"""

from __future__ import annotations

import asyncio
import ipaddress
import sys
import uuid
from types import ModuleType
from typing import Any, Callable, Optional, Union

from siphon_sdk.types import Contact, SipUri
from siphon_sdk.request import _parse_uri
from siphon_sdk.lcr import Route
from siphon_sdk.smpp import MockSmpp
from siphon_sdk.http import MockHttp


# ---------------------------------------------------------------------------
# Handler registry
# ---------------------------------------------------------------------------

class _HandlerRegistry:
    """Stores decorated handler functions, mirroring ``_siphon_registry``."""

    def __init__(self) -> None:
        self.handlers: dict[str, list[tuple[Optional[str], Callable, bool]]] = {}

    def register(self, event: str, method_filter: Optional[str],
                 fn: Callable, is_async: bool,
                 metadata: Optional[dict[str, Any]] = None) -> None:
        self.handlers.setdefault(event, []).append((method_filter, fn, is_async, metadata))

    def clear(self) -> None:
        self.handlers.clear()

    def get(self, event: str, method: Optional[str] = None
            ) -> list[tuple[Callable, bool]]:
        """Return matching handlers for an event, filtered by SIP method."""
        result = []
        for method_filter, fn, is_async, _metadata in self.handlers.get(event, []):
            if method_filter is None:
                result.append((fn, is_async))
            elif method and method in method_filter.split("|"):
                result.append((fn, is_async))
        return result


# Global registry instance
_registry = _HandlerRegistry()


def _run_async(coroutine: Any) -> Any:
    """Drive an awaitable to completion from sync code.

    Used by the mock fire-paths (``_fire_on_change`` etc.) that are
    synchronous methods but may invoke handlers registered as ``async def``.
    Reuses the running loop when one is available so the harness's loop is
    preferred; otherwise falls back to a fresh per-call loop.
    """
    if not asyncio.iscoroutine(coroutine):
        return coroutine
    try:
        # Already inside a running loop — schedule and let it complete.
        running = asyncio.get_running_loop()
        return asyncio.ensure_future(coroutine, loop=running)
    except RuntimeError:
        pass
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coroutine)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Proxy namespace
# ---------------------------------------------------------------------------

class MockProxy:
    """Mock proxy namespace with decorator registration and utility stubs.

    Decorators:
        - ``@proxy.on_request`` / ``@proxy.on_request("INVITE")``
        - ``@proxy.on_reply``
        - ``@proxy.on_failure``
        - ``@proxy.on_cancel``
        - ``@proxy.on_register_reply``

    Example::

        from siphon import proxy

        @proxy.on_request("REGISTER")
        def handle_register(request):
            request.reply(200, "OK")
    """

    def on_request(self, fn_or_filter: Union[Callable, str, None] = None) -> Any:
        """Register a handler for incoming SIP requests.

        Can be used as:
            - ``@proxy.on_request`` — handle all methods
            - ``@proxy.on_request()`` — same, explicit call
            - ``@proxy.on_request("REGISTER")`` — single method filter
            - ``@proxy.on_request("INVITE|SUBSCRIBE")`` — pipe-separated filter
        """
        if fn_or_filter is None or callable(fn_or_filter):
            fn = fn_or_filter
            if fn is not None:
                is_async = asyncio.iscoroutinefunction(fn)
                _registry.register("proxy.on_request", None, fn, is_async)
                return fn

            def decorator(fn: Callable) -> Callable:
                is_async = asyncio.iscoroutinefunction(fn)
                _registry.register("proxy.on_request", None, fn, is_async)
                return fn
            return decorator

        if isinstance(fn_or_filter, str):
            method_filter = fn_or_filter

            def decorator(fn: Callable) -> Callable:
                is_async = asyncio.iscoroutinefunction(fn)
                _registry.register("proxy.on_request", method_filter, fn, is_async)
                return fn
            return decorator

        raise TypeError(
            f"proxy.on_request expects a callable or method filter string, "
            f"got {type(fn_or_filter).__name__}"
        )

    @staticmethod
    def on_reply(fn: Callable) -> Callable:
        """Register a handler for SIP replies.

        Handler signature: ``(request, reply) -> None``
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_reply", None, fn, is_async)
        return fn

    @staticmethod
    def on_failure(fn: Callable) -> Callable:
        """Register a handler for proxy failure (all branches failed).

        Handler signature: ``(request, reply) -> None``
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_failure", None, fn, is_async)
        return fn

    @staticmethod
    def on_cancel(fn: Callable) -> Callable:
        """Register a handler for a CANCELled INVITE (RFC 3261 §9).

        Handler signature: ``(request) -> None``

        Fires once, with the original INVITE, when a relayed INVITE is
        CANCELled before any final response — the one teardown that neither
        ``on_reply`` nor ``on_failure`` delivers (the proxy answers the CANCEL
        with 487 at the transaction layer and the session is gone). Use it to
        release per-call resources that no BYE will ever clear: Diameter
        Rx / N5 QoS sessions, rtpengine media anchors, charging maps.

        Fire-and-forget — it does not gate or alter the 487 sent to the UAC.

        Example::

            @proxy.on_cancel
            async def handle_cancel(request):
                await _release_qos(request.call_id)
                await rtpengine.delete(request)
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_cancel", None, fn, is_async)
        return fn

    @staticmethod
    def on_register_reply(fn: Callable) -> Callable:
        """Register a handler for REGISTER replies.

        Handler signature: ``(request, reply) -> None``
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_register_reply", None, fn, is_async)
        return fn

    async def send_request(self, method: str, ruri: str,
                           headers: Optional[dict[str, str]] = None,
                           body: Optional[Any] = None,
                           next_hop: Optional[str] = None,
                           wait_for_response: bool = False,
                           timeout_ms: int = 2000) -> Any:
        """Originate an outbound SIP request.

        Always returns an awaitable — scripts must ``await`` it. Fire-and-forget
        by default; when ``wait_for_response=True``, the awaitable resolves to
        a configured mock ``Reply`` (or ``None`` on timeout).

        Args:
            method: SIP method name (e.g. "NOTIFY", "OPTIONS", "MESSAGE").
            ruri: Request-URI string (e.g. "sip:alice@10.0.0.1:5060").
            headers: Optional dict of header name → value to add.  When a
                ``Route`` header is supplied without ``next_hop``, the request
                is sent to the first ``Route`` entry's URI (its ``;lr``
                loose-route target) per RFC 3261 §8.1.2 — the R-URI stays in
                the Request-Line.  Use this to steer a request straight to a
                known next hop (e.g. a served IMPU's serving S-CSCF) instead of
                resolving the R-URI's home domain.
            body: Optional body — ``str`` or ``bytes``.
            next_hop: Optional next-hop URI override.  Outranks a ``Route``
                header for next-hop selection.
            wait_for_response: When ``True``, return the configured mock reply.
            timeout_ms: Response timeout (not meaningfully enforced in the mock).
        """
        record = {
            "method": method,
            "ruri": ruri,
            "headers": headers or {},
            "body": body,
            "next_hop": next_hop,
            "wait_for_response": wait_for_response,
            "timeout_ms": timeout_ms,
        }
        self._sent_requests.append(record)
        if not wait_for_response:
            return None
        key = (method, ruri)
        return self._send_request_responses.get(key)

    def set_response_for(self, method: str, ruri: str, reply: Any) -> None:
        """Test helper: configure the mock reply returned by
        ``send_request(wait_for_response=True)`` for a given (method, ruri).

        Args:
            method: SIP method (e.g. "OPTIONS").
            ruri: Request-URI the script will pass.
            reply: Any object (often a ``MockReply``) — returned to the script.
        """
        self._send_request_responses[(method, ruri)] = reply

    @property
    def sent_requests(self) -> list[dict]:
        """List of requests sent via ``send_request()`` (for test assertions)."""
        return self._sent_requests

    def __init__(self) -> None:
        self._utils = MockProxyUtils()
        self._sent_requests: list[dict] = []
        self._send_request_responses: dict[tuple[str, str], Any] = {}
        self.subscribe_state = MockSubscribeState()

    def __getattr__(self, name: str) -> Any:
        # The real `proxy` exposes its utility helpers flat
        # (``proxy.sanity_check``, ``proxy.rate_limit``, ``proxy.enum_lookup``,
        # ``proxy.memory_used_pct``); the mock keeps them on ``_utils``, so
        # delegate any otherwise-unknown attribute there. ``__getattr__`` only
        # fires when normal lookup misses, so real attributes are unaffected.
        if name != "_utils":
            utils = self.__dict__.get("_utils")
            if utils is not None and hasattr(utils, name):
                return getattr(utils, name)
        raise AttributeError(
            f"{type(self).__name__!r} object has no attribute {name!r}"
        )


# ---------------------------------------------------------------------------
# proxy.subscribe_state (managed SUBSCRIBE dialog API)
# ---------------------------------------------------------------------------

class MockSubscribeHandle:
    """Mock of the Rust ``SubscribeHandle``.

    In the mock, NOTIFY / terminate calls are recorded on the parent
    ``MockSubscribeState`` for test assertions.  No real SIP message is
    produced.
    """

    def __init__(self, parent: "MockSubscribeState", id_: str, dialog: dict) -> None:
        self._parent = parent
        self._id = id_
        self._dialog = dialog

    @property
    def id(self) -> str:
        return self._id

    @property
    def event(self) -> str:
        return self._dialog.get("event", "")

    @property
    def expires(self) -> int:
        return int(self._dialog.get("expires_secs", 0))

    @property
    def event_version(self) -> int:
        """Current event-package body version (read-only).

        Mirrors the Rust ``SubscribeHandle.event_version`` — used for
        RFC 3680 reginfo / RFC 4235 dialog-info / RFC 4575 conference
        bodies that require a monotonic ``version=`` attribute.
        """
        return int(self._dialog.get("event_version", 0))

    def next_event_version(self) -> int:
        """Atomically increment and return the next event-package body version.

        Call before building a NOTIFY body whose monotonicity matters::

            version = handle.next_event_version()
            body = registrar.reginfo_xml(aor, state="full", version=version)
            handle.notify(body=body, content_type="application/reginfo+xml")
        """
        current = int(self._dialog.get("event_version", 0))
        new_version = current + 1
        self._dialog["event_version"] = new_version
        return new_version

    def notify(self, body=None, content_type: Optional[str] = None,
               state: Optional[str] = None) -> bool:
        if self._id not in self._parent._dialogs:
            return False
        entry = {
            "id": self._id,
            "body": body,
            "content_type": content_type,
            "state": state or f"active;expires={self.expires}",
        }
        self._parent.notifies.append(entry)
        return True

    def terminate(self, reason: Optional[str] = None,
                  body=None, content_type: Optional[str] = None) -> bool:
        reason_str = reason or "noresource"
        self._parent.terminates.append({
            "id": self._id,
            "reason": reason_str,
            "body": body,
            "content_type": content_type,
        })
        self._parent._dialogs.pop(self._id, None)
        return True

    def refresh(self, expires: Optional[int] = None,
                timeout_ms: int = 2000) -> bool:
        """Mock refresh — records the call and updates the dialog's expiry.

        Tests can assert on the parent's ``refreshes`` list. Raises if
        the dialog wasn't created via ``send()`` (consistent with the
        Rust contract that refresh is only valid on outbound dialogs).
        """
        if not self._dialog.get("is_outbound"):
            raise RuntimeError(
                "refresh() is only valid on outbound dialogs (created via send())"
            )
        if not hasattr(self._parent, "refreshes"):
            self._parent.refreshes = []
        new_expires = expires if expires is not None else self.expires
        self._dialog["expires_secs"] = new_expires
        self._parent.refreshes.append({
            "id": self._id,
            "expires": new_expires,
            "timeout_ms": timeout_ms,
        })
        return True

    def __repr__(self) -> str:
        return f"MockSubscribeHandle(id={self._id!r})"


class MockSubscribeState:
    """Mock of the Rust ``proxy.subscribe_state`` namespace.

    Used from scripts under test as ``proxy.subscribe_state.create(request)``.
    Records NOTIFY and terminate invocations on ``notifies`` /
    ``terminates`` lists for test assertions.
    """

    def __init__(self) -> None:
        self._dialogs: dict[str, dict] = {}
        self.notifies: list[dict] = []
        self.terminates: list[dict] = []

    def create(self, request: Any, expires: Optional[int] = None) -> MockSubscribeHandle:
        import uuid
        event = getattr(request, "event", None) or "presence"
        expires_secs = expires if expires is not None else 3600
        handle_id = uuid.uuid4().hex
        dialog = {
            "id": handle_id,
            "event": event,
            "expires_secs": expires_secs,
            "call_id": getattr(request, "call_id", ""),
            "remote_tag": getattr(request, "from_tag", ""),
            "event_version": 0,
        }
        self._dialogs[handle_id] = dialog
        return MockSubscribeHandle(self, handle_id, dialog)

    def get(self, id: str) -> Optional[MockSubscribeHandle]:
        dialog = self._dialogs.get(id)
        if dialog is None:
            return None
        return MockSubscribeHandle(self, id, dialog)

    def send(
        self,
        ruri: str,
        event: str,
        expires: int,
        accept: Optional[str] = None,
        target_uri: Optional[str] = None,
        headers: Optional[dict] = None,
        timeout_ms: int = 2000,
    ) -> MockSubscribeHandle:
        """Mock outbound SUBSCRIBE — records the call and synthesises a dialog.

        Tests can assert on the recorded ``self.sends`` list to verify a
        script originated a SUBSCRIBE with the expected parameters.
        """
        import uuid
        if not hasattr(self, "sends"):
            self.sends = []
        handle_id = uuid.uuid4().hex
        local_tag = uuid.uuid4().hex
        remote_tag = uuid.uuid4().hex
        dialog = {
            "id": handle_id,
            "event": event,
            "expires_secs": expires,
            "call_id": f"py-sub-{uuid.uuid4().hex}",
            "local_tag": local_tag,
            "remote_tag": remote_tag,
            "event_version": 0,
            "is_outbound": True,
        }
        self._dialogs[handle_id] = dialog
        self.sends.append({
            "ruri": ruri,
            "event": event,
            "expires": expires,
            "accept": accept,
            "target_uri": target_uri,
            "headers": dict(headers or {}),
            "timeout_ms": timeout_ms,
        })
        return MockSubscribeHandle(self, handle_id, dialog)

    def find(
        self,
        call_id: str,
        local_tag: str,
        remote_tag: str,
    ) -> Optional[MockSubscribeHandle]:
        """Mock dialog lookup by tags. Returns the first live dialog
        matching all three identity fields, or ``None``."""
        for dialog_id, dialog in self._dialogs.items():
            if dialog.get("terminated"):
                continue
            if (
                dialog.get("call_id") == call_id
                and dialog.get("local_tag") == local_tag
                and dialog.get("remote_tag") == remote_tag
            ):
                return MockSubscribeHandle(self, dialog_id, dialog)
        return None

    @property
    def local_count(self) -> int:
        return len(self._dialogs)

    def clear(self) -> None:
        self._dialogs.clear()
        self.notifies.clear()
        self.terminates.clear()
        if hasattr(self, "sends"):
            self.sends.clear()


# ---------------------------------------------------------------------------
# Proxy utilities
# ---------------------------------------------------------------------------

class MockProxyUtils:
    """Mock ``proxy._utils`` namespace.

    Provides rate limiting, sanity checking, ENUM lookup, and memory stats.
    In the mock, these return configurable defaults.
    """

    def __init__(self) -> None:
        self._rate_limit_allow = True
        self._sanity_check_pass = True
        self._enum_results: dict[str, str] = {}
        self._memory_pct = 25

    def rate_limit(self, request: Any, window_secs: float,
                   max_requests: int) -> bool:
        """Check if a request is within the rate limit.

        Args:
            request: The SIP request object.
            window_secs: Sliding window duration in seconds.
            max_requests: Maximum requests allowed in the window.

        Returns:
            ``True`` if allowed, ``False`` if rate-limited.

        In the mock, returns the value of ``_rate_limit_allow`` (default ``True``).
        """
        return self._rate_limit_allow

    def sanity_check(self, request: Any) -> bool:
        """Validate request per RFC 3261 (mandatory headers, Max-Forwards, etc.).

        Returns:
            ``True`` if valid, ``False`` otherwise.

        In the mock, returns ``_sanity_check_pass`` (default ``True``).
        """
        return self._sanity_check_pass

    async def enum_lookup(self, number: str, suffix: str = "e164.arpa.",
                          service: str = "E2U+sip") -> Optional[str]:
        """DNS NAPTR lookup for phone number to SIP URI.

        Args:
            number: E.164 number (e.g. ``"+14155552671"``).
            suffix: DNS suffix (default ``"e164.arpa."``).
            service: Service type (default ``"E2U+sip"``).

        Returns:
            SIP URI string or ``None``.

        In the mock, looks up ``_enum_results`` dict.
        """
        return self._enum_results.get(number)

    def memory_used_pct(self) -> int:
        """Process RSS memory usage as percentage (0–100).

        In the mock, returns ``_memory_pct`` (default 25).
        """
        return self._memory_pct


# ---------------------------------------------------------------------------
# B2BUA namespace
# ---------------------------------------------------------------------------

class MockB2bua:
    """Mock B2BUA namespace with decorator registration.

    Decorators:
        - ``@b2bua.on_invite`` — new call
        - ``@b2bua.on_early_media`` — provisional response with SDP (183/180)
        - ``@b2bua.on_answer`` — call answered
        - ``@b2bua.on_failure`` — all B-legs failed
        - ``@b2bua.on_bye`` — call ended
        - ``@b2bua.on_refer`` — call transfer (RFC 3515)
        - ``@b2bua.on_cancel`` — unanswered call cancelled (RFC 3261 §9)

    Imperative:
        - ``b2bua.terminate(call_id)`` — end a call by SIP Call-ID from any
          context (records onto ``terminates`` for test assertions)
        - ``b2bua.refer(call_id, target)`` — transfer a call by SIP Call-ID
          from any context (records onto ``refers`` for test assertions)
    """

    def __init__(self) -> None:
        # Records b2bua.terminate(...) calls for test assertions.
        self.terminates: list[dict] = []
        # Records b2bua.refer(...) calls for test assertions.
        self.refers: list[dict] = []

    def clear(self) -> None:
        """Reset recorded imperative calls (called by ``reset()``)."""
        self.terminates.clear()
        self.refers.clear()

    def terminate(self, call_id: str, reason: str = "Normal Clearing") -> bool:
        """Imperatively end a B2BUA call by its SIP Call-ID.

        Unlike ``call.terminate()`` (deferred until its handler returns), this
        acts immediately and is keyed by SIP Call-ID, so it works from an
        out-of-band event callback (``@rtpengine.on_dtmf``,
        ``@rtpengine.on_media_timeout``), a timer, or a normal handler.

        Args:
            call_id: the SIP Call-ID of the call to end.
            reason: free-text hangup reason (RFC 3326 ``Reason`` on the BYE).

        Returns:
            bool: True if a matching call was found and torn down, False if the
            Call-ID is unknown / already gone. Never raises.

        In the mock, records ``{"call_id", "reason"}`` on ``terminates`` and
        returns True. Inspect via ``siphon.get_b2bua().terminates``.

        Usage::

            @rtpengine.on_dtmf
            def on_ivr_dtmf(call_id, from_tag, digit, duration_ms, volume):
                if digit == "#":
                    b2bua.terminate(call_id)
        """
        self.terminates.append({"call_id": call_id, "reason": reason})
        return True

    def refer(self, call_id: str, target: str,
              replaces: Optional[dict] = None) -> bool:
        """Imperatively transfer a B2BUA call by its SIP Call-ID.

        The imperative twin of :meth:`Call.refer`.  Unlike ``call.refer()``
        (a deferred call action, honoured after its handler returns), this
        acts immediately and is keyed by SIP Call-ID, so it works from an
        out-of-band event callback (``@rtpengine.on_dtmf``, a timer) where
        no ``call`` object is in scope and deferred actions are no-ops — the
        same reason :meth:`terminate` exists alongside ``call.terminate()``.

        Args:
            call_id: the SIP Call-ID of the call to transfer.
            target: the Refer-To URI (transfer destination).
            replaces: optional attended-transfer dict (RFC 3891) with
                ``call_id`` / ``from_tag`` / ``to_tag`` (and an optional
                ``early_only``); ``None`` for a blind transfer.

        Returns:
            bool: True if a matching call was found and the REFER was
            originated, False if the Call-ID is unknown / already gone.
            Never raises for a missing call.

        Raises:
            ValueError: if ``replaces`` is given but missing any of
                ``call_id`` / ``from_tag`` / ``to_tag``.

        In the mock, records ``{"call_id", "target", "replaces"}`` on
        ``refers`` and returns True. Inspect via
        ``siphon.get_b2bua().refers``.

        Usage::

            @rtpengine.on_dtmf
            def on_ivr_dtmf(call_id, from_tag, digit, duration_ms, volume):
                if digit == "*":
                    b2bua.refer(call_id, "sip:+15550142@example.com")
        """
        from siphon_sdk.call import _validate_replaces

        _validate_replaces(replaces)
        self.refers.append(
            {"call_id": call_id, "target": target, "replaces": replaces}
        )
        return True

    @staticmethod
    def on_invite(fn: Callable) -> Callable:
        """Register handler for new INVITE (new call).

        Handler signature: ``(call) -> None``
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_invite", None, fn, is_async)
        return fn

    @staticmethod
    def on_early_media(fn: Callable) -> Callable:
        """Register handler for provisional response with SDP (183/180).

        Called when the B-leg sends a provisional response containing SDP
        (early media).  Use this to process the SDP through RTPEngine so
        early media is anchored correctly.

        Handler signature: ``(call, reply) -> None``

        Example::

            @b2bua.on_early_media
            async def early_media(call, reply):
                await rtpengine.answer(reply)
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_early_media", None, fn, is_async)
        return fn

    @staticmethod
    def on_answer(fn: Callable) -> Callable:
        """Register handler for call answered (200 OK on B-leg).

        Handler signature: ``(call, reply) -> None``
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_answer", None, fn, is_async)
        return fn

    @staticmethod
    def on_failure(fn: Callable) -> Callable:
        """Register handler for B-leg failure.

        Handler signature: ``(call, code, reason) -> None``
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_failure", None, fn, is_async)
        return fn

    @staticmethod
    def on_bye(fn: Callable) -> Callable:
        """Register handler for BYE (call ended).

        Handler signature: ``(call, initiator) -> None``

        ``initiator`` is a :class:`ByeInitiator` with a ``.side`` property
        (``"a"`` or ``"b"``).
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_bye", None, fn, is_async)
        return fn

    @staticmethod
    def on_refer(fn: Callable) -> Callable:
        """Register handler for REFER (call transfer, RFC 3515).

        Handler signature is **single-arg** ``(call) -> None``.  A REFER is a
        SIP *request*, not a response, so there is **no** ``reply`` object —
        do NOT write ``(call, reply)`` and do NOT call ``rtpengine.answer()``
        here.  Read the transfer target off :attr:`Call.refer_to` (and
        :attr:`Call.refer_replaces` for an attended transfer), then decide
        with :meth:`Call.accept_refer` or :meth:`Call.reject_refer`.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                log.info(f"Transfer requested to {call.refer_to}")
                call.accept_refer()
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_refer", None, fn, is_async)
        return fn

    @staticmethod
    def on_cancel(fn: Callable) -> Callable:
        """Register handler for a CANCELled call (RFC 3261 §9).

        Handler signature: ``(call) -> None``

        Fires once, with the Call object, when an unanswered call
        (Calling/Ringing) is CANCELled — the teardown that ``on_failure``
        (B-leg error) and ``on_bye`` (answered call) never cover. A 2xx that
        wins the CANCEL/answer glare is ACK+BYE'd by the framework and never
        delivers ``on_answer``, so this hook only ever sees a genuinely
        abandoned call. Use it to release per-call resources that no BYE will
        clear: rtpengine media anchors, QoS sessions.

        Example::

            @b2bua.on_cancel
            async def handle_cancel(call):
                await rtpengine.delete(call)
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_cancel", None, fn, is_async)
        return fn


# ---------------------------------------------------------------------------
# Registrar namespace
# ---------------------------------------------------------------------------

class MockRegistrar:
    """Mock registrar with an in-memory contact store.

    Pre-populate contacts for testing::

        from siphon import registrar
        registrar.add_contact("sip:alice@example.com",
                              Contact(uri="sip:alice@192.168.1.5:5060"))

    Then your script's ``registrar.lookup()`` will find them.
    """

    def __init__(self) -> None:
        self._store: dict[str, list[Contact]] = {}
        self._asserted_identities: dict[str, str] = {}
        self._service_routes: dict[str, list[str]] = {}
        self._associated_uris: dict[str, list[str]] = {}
        # Alias AoR → primary AoR.  Derived index over ``_associated_uris``,
        # mirrors the Rust ``Registrar::aliases`` map.
        self._aliases: dict[str, str] = {}
        # Opaque flow-token → AoR.  Mirrors the Rust ``Registrar::tokens``
        # reverse index used for Path-token MT routing
        # (RFC 3327 §5 / TS 24.229 §5.2.7.2).
        self._tokens: dict[str, str] = {}
        self._on_change_callbacks: list[Callable] = []

    @staticmethod
    def _normalize_aor(uri: str) -> str:
        """Mirror of ``crate::registrar::normalize_aor``.

        Strip angle brackets, prepend ``sip:`` if no scheme, drop URI
        parameters / headers and the default port.
        """
        s = str(uri).strip().lstrip("<").rstrip(">")
        if not (s.startswith("sip:") or s.startswith("sips:")):
            s = f"sip:{s}"
        s = s.split(";", 1)[0].split("?", 1)[0]
        if s.startswith("sips:") and s.endswith(":5061"):
            s = s[:-5]
        elif s.startswith("sip:") and s.endswith(":5060"):
            s = s[:-5]
        return s

    def _resolve_alias(self, aor: str) -> str:
        return self._aliases.get(aor, aor)

    def save(
        self,
        request: Any,
        force: bool = False,
        aliases: Optional[list[str]] = None,
        flow_token: Optional[str] = None,
    ) -> bool:
        """Save contact bindings from a REGISTER request and send the 200 OK reply.

        Stores the contact bindings and automatically sends a ``200 OK`` reply
        to the REGISTER request with the granted ``Expires`` header — the script
        must **not** call ``request.reply(200, "OK")`` afterwards.

        In the mock, extracts the To URI as AoR and stores a default
        contact binding.

        Args:
            request: The REGISTER request object.
            force: If ``True``, evict all existing contacts first.
            aliases: IMS implicit registration set (3GPP TS 23.228) —
                every URI in the list becomes an alias of this AoR, so
                subsequent ``registrar.lookup(alias)`` calls resolve to
                the same contacts.  Empty / ``None`` is a no-op; clear
                an existing set with
                ``registrar.set_associated_uris(aor, [])``.
            flow_token: Opaque proxy-side token to attach to every
                contact saved by this call.  Captures the inbound flow
                so subsequent ``registrar.lookup_by_token(flow_token)``
                resolves back to this binding and the script can
                ``request.relay(flow=binding.flow)`` for P-CSCF MT
                routing (RFC 3327 §5 / TS 24.229 §5.2.7.2).

        Returns:
            ``True`` on success.

        Example::

            if request.method == "REGISTER":
                if not auth.require_digest(request, realm=DOMAIN):
                    return
                # Generate an opaque token, write it into Path so MT
                # requests come back with it on the topmost Route.
                token = secrets.token_urlsafe(16)
                request.add_pcscf_path(token)
                registrar.save(request, flow_token=token)
                return
        """
        raw_aor = str(request.to_uri) if request.to_uri else str(request.ruri)
        aor = self._resolve_alias(self._normalize_aor(raw_aor))
        if force:
            self._store.pop(aor, None)
        contacts = self._store.setdefault(aor, [])
        # Add a default contact from source IP if not already present
        default_uri = f"sip:{request.ruri.user or 'user'}@{request.source_ip}:5060"
        already_exists = any(c.uri == default_uri for c in contacts)
        if not already_exists:
            contact = Contact(uri=default_uri)
            if flow_token is not None:
                contact.flow_token = flow_token
                # Reconstitute the Flow view from request context.
                from siphon_sdk.types import Flow as _Flow
                contact.flow = _Flow(
                    transport=request.transport,
                    remote_addr=f"{request.source_ip}:{request.source_port}",
                    local_addr=getattr(request, "_local_addr", "0.0.0.0:0"),
                )
            contacts.append(contact)
            # Index for lookup_by_token.
            if flow_token is not None:
                self._tokens[flow_token] = aor
        # Fire on_change callbacks
        event_type = "refreshed" if already_exists else "registered"
        self._fire_on_change(aor, event_type)
        # Declare the implicit registration set.
        if aliases:
            self.set_associated_uris(aor, list(aliases))
        # Automatically reply 200 OK on behalf of the script — matches the
        # real Rust registrar.save() behaviour (the script must NOT also
        # call request.reply()).
        if hasattr(request, "reply"):
            request.reply(200, "OK")
        return True

    def save_proxy(
        self,
        request: Any,
        reply: Any,
        aliases: Optional[list[str]] = None,
        flow_token: Optional[str] = None,
    ) -> bool:
        """Cache a binding on a proxy after the upstream registrar accepted it.

        Use on a proxy (e.g. P-CSCF in IMS) that wants a local copy of a
        UE's binding for routing terminating requests, where the actual
        REGISTER was forwarded to a registrar of record (e.g. S-CSCF)
        and a 200 OK has just come back.

        Differs from :meth:`save` in three ways:

        1. The contact lifetime is read from the **reply's** ``Expires``
           header (the registrar's grant per RFC 3261 §10.3 step 8), not
           the request's (the UE's ask).  UEs commonly ask for
           ``600000`` s; the registrar caps to a sensible value, and
           mirroring that cap locally is incorrect — the proxy must
           trust the upstream's decision.
        2. The local ``max_expires`` cap is **not** applied.  The
           registrar of record has already capped, and a tighter local
           cap would expire the proxy cache before the upstream binding,
           opening a window where MT requests would 404 against an entry
           the registrar still considers live.
        3. No 200 OK is generated — the proxy will relay the upstream's
           response itself.

        A grace of ~32 s (RFC 3261 Timer F = 64·T1) is added on top so
        a ``NOTIFY[reg-event;state=terminated]`` from the registrar at
        expiry has a transaction-timer window to land before the proxy
        forgets.

        ``Expires: 0`` on the reply clears the binding (de-REGISTER
        path).

        Args:
            request: The original REGISTER (read for AoR + Contact list).
            reply: The upstream 200 OK (read for granted ``Expires``).
            aliases: IMS implicit registration set, same shape as
                :meth:`save` ``aliases=`` — see that method's docs.

        Raises:
            ValueError: when the reply has no parseable ``Expires``
                header (the registrar of record must include the
                granted ``Expires`` per RFC 3261 §10.3 step 8).

        Example::

            @proxy.on_reply
            def on_reply(request, reply):
                if request.method == "REGISTER" and reply.status_code == 200:
                    registrar.save_proxy(request, reply,
                                         aliases=raw_uris or [])
                reply.relay()
        """
        # Pull the granted Expires from the reply.  Mirror the Rust-side
        # validation so scripts fail identically in unit tests.
        granted_raw = None
        if hasattr(reply, "get_header"):
            granted_raw = reply.get_header("Expires")
        if granted_raw is None:
            raise ValueError(
                "save_proxy: reply has no parseable Expires header — "
                "the registrar of record must include the granted "
                "Expires per RFC 3261 §10.3 step 8"
            )
        granted = int(granted_raw)

        raw_aor = str(request.to_uri) if request.to_uri else str(request.ruri)
        aor = self._resolve_alias(self._normalize_aor(raw_aor))

        if granted == 0:
            self._store.pop(aor, None)
            return True

        contacts = self._store.setdefault(aor, [])
        default_uri = f"sip:{request.ruri.user or 'user'}@{request.source_ip}:5060"
        already_exists = any(c.uri == default_uri for c in contacts)
        if not already_exists:
            contacts.append(Contact(uri=default_uri))
        event_type = "refreshed" if already_exists else "registered"
        self._fire_on_change(aor, event_type)
        if aliases:
            self.set_associated_uris(aor, list(aliases))
        return True

    def lookup(self, uri: Union[str, SipUri]) -> list[Contact]:
        """Look up routable contacts for an address-of-record.

        Returns only UE-side bindings (``kind == "ue"``).  AS-side
        capability records — captured via :meth:`save_as_contact` —
        are excluded so a misrouted MT INVITE never goes to an AS
        (TS 24.229 §5.4.2.1.2).  See :func:`registrar.reginfo_xml` for
        the merged view that surfaces AS feature tags.

        If the URI is an alias of an IMS implicit registration set,
        resolves to the primary's contacts (matching production
        ``registrar.lookup`` behaviour).

        Args:
            uri: AoR as string or :class:`SipUri`.

        Returns:
            List of UE-side :class:`Contact` objects sorted by q-value
            (descending).  Empty list if no UE contacts registered.
        """
        key = self._resolve_alias(self._normalize_aor(str(uri)))
        contacts = [
            c for c in self._store.get(key, [])
            if getattr(c, "kind", "ue") == "ue"
        ]
        return sorted(contacts, key=lambda c: c.q, reverse=True)

    def lookup_contact(self, uri: Union[str, SipUri]) -> list[Contact]:
        """Reverse lookup by **Contact** URI.

        :meth:`lookup` resolves a *logical* address (``user@domain``);
        this resolves a *physical* one — it returns every registered
        UE-side binding whose stored Contact matches ``uri`` (user +
        host + port; URI parameters and default ports are ignored).

        Use it on the terminating edge when the only thing you have is
        the contact. A common case: a PBX in front of siphon retargets
        the INVITE straight at the cached Contact and loose-routes it
        back, so ``call.ruri`` is the contact
        (``sip:1001@203.0.113.7:17514``), not the registration AoR
        (``sip:1001@pbx.example``). ``lookup()`` keys on the AoR and
        misses; ``lookup_contact()`` matches the binding regardless of
        the AoR domain::

            @b2bua.on_invite
            def route(call):
                if not registrar.lookup_contact(str(call.ruri)):
                    call.reject(404, "No extension Found")
                    return
                call.dial(str(call.ruri))

        Args:
            uri: Contact URI as string or :class:`SipUri`.

        Returns:
            List of matching UE-side :class:`Contact` objects sorted by
            q-value (descending). AS-side capability records are
            excluded, matching :meth:`lookup`. Empty list if no binding
            has that contact.
        """
        target = self._normalize_aor(str(uri))
        matches = [
            c
            for contacts in self._store.values()
            for c in contacts
            if getattr(c, "kind", "ue") == "ue"
            and self._normalize_aor(str(c.uri)) == target
        ]
        return sorted(matches, key=lambda c: c.q, reverse=True)

    def save_as_contact(
        self,
        aor: Union[str, SipUri],
        reply: Any,
        expires_secs: Optional[int] = None,
    ) -> bool:
        """Save AS-side capability contacts from a 3PR 200 OK
        (3GPP TS 24.229 §5.4.2.1.2).

        The S-CSCF runs iFC, fires a third-party REGISTER at each
        matched AS, and receives a 200 OK whose ``Contact:`` header
        carries the AS's URI plus RFC 3840 feature tags
        (``+g.3gpp.smsip``, ``+g.3gpp.icsi-ref``, …).  Calling this from
        ``@proxy.on_reply`` (or after a
        ``proxy.send_request(..., wait_for_response=True)``) caches
        every such Contact alongside the UE's own bindings so the next
        reg-event NOTIFY surfaces them to watchers.

        AS contacts are stored with ``kind="as"`` and **excluded** from
        :meth:`lookup` — they only exist to be advertised in reg-event
        NOTIFY bodies (no MT INVITE ever routes to them).

        Args:
            aor: IMPU the AS responded for.
            reply: 200 OK from the AS.  Its ``Contact:`` headers are
                walked; ``+sip.instance`` / ``reg-id`` are NOT broken
                out (no GRUU semantic on the AS side).
            expires_secs: lifetime for the cached AS contact.  When
                ``None``, falls back to the reply's ``Expires`` header
                (raises ``ValueError`` if absent).

        Returns:
            ``True`` if at least one Contact was stored; ``False`` if
            the reply had no Contact headers, or the AoR has no UE-side
            binding (the registrar refuses to store an AS capability
            record against an unregistered user).

        Example::

            @proxy.on_reply
            def on_reply(request, reply):
                if request.method == "REGISTER" and reply.status_code == 200:
                    registrar.save_as_contact(str(request.to_uri), reply)
                reply.relay()
        """
        # Lifetime: explicit arg wins, else fall back to the reply's
        # Expires header.
        if expires_secs is None:
            if hasattr(reply, "get_header"):
                raw = reply.get_header("Expires")
            else:
                raw = None
            if raw is None:
                raise ValueError(
                    "save_as_contact: pass expires_secs= explicitly or "
                    "include an Expires header on the AS's 200 OK"
                )
            expires_secs = int(raw)

        key = self._resolve_alias(self._normalize_aor(str(aor)))
        contacts = self._store.get(key, [])
        has_ue = any(
            getattr(c, "kind", "ue") == "ue" for c in contacts
        )
        if not has_ue:
            return False

        # Walk every Contact header on the reply.  The mock keeps a
        # very simple structure — single Contact value, no NameAddr
        # parsing — so script tests should pass the AS URI directly via
        # a Contact header on the synthesized reply.
        if not hasattr(reply, "get_header"):
            return False
        contact_raw = reply.get_header("Contact")
        if contact_raw is None:
            return False

        # Minimal Contact parser sufficient for the mock: strip angle
        # brackets, split on ';' to collect params.
        raw = contact_raw.strip()
        if "<" in raw and ">" in raw:
            uri_part = raw.split("<", 1)[1].split(">", 1)[0]
            after = raw.split(">", 1)[1]
        else:
            head = raw.split(";", 1)
            uri_part = head[0].strip()
            after = ";" + head[1] if len(head) > 1 else ""
        params: list = []
        for chunk in after.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "=" in chunk:
                name, value = chunk.split("=", 1)
                name = name.strip().lower()
                if name in ("tag", "q", "expires"):
                    continue
                params.append((name, value.strip()))
            else:
                name = chunk.lower()
                if name in ("tag", "q", "expires"):
                    continue
                params.append((name, None))

        # Replace any AS contact with the same URI; never collide with
        # a UE contact even if URIs happen to match.
        retained = [
            c for c in contacts
            if not (getattr(c, "kind", "ue") == "as" and c.uri == uri_part)
        ]
        retained.append(Contact(uri=uri_part, expires=int(expires_secs)))
        retained[-1].kind = "as"
        retained[-1].params = params
        self._store[key] = retained
        return True

    def lookup_by_token(self, token: str) -> Optional[Contact]:
        """Resolve an opaque flow-token previously attached via
        ``registrar.save(flow_token=...)`` to its bound contact.

        Returns ``None`` when the token is unknown, the binding has
        expired, or no contact in the resolved AoR carries this token.

        Used by P-CSCF MT routing (RFC 3327 §5 / TS 24.229 §5.2.7.2):
        the proxy advertised a Path URI of the form
        ``<sip:TOKEN@pcscf;lr>``; on the MT request, after
        ``loose_route()`` consumed that Route,
        ``request.consumed_route_user`` exposes the token and this
        method resolves it back to the binding so the script can call
        ``request.relay(flow=binding.flow)``.

        Args:
            token: Opaque token previously passed to
                ``registrar.save(flow_token=...)``.

        Returns:
            The matching :class:`Contact` (with ``.flow`` populated)
            or ``None``.
        """
        aor = self._tokens.get(token)
        if aor is None:
            return None
        for contact in self._store.get(aor, []):
            if contact.flow_token == token:
                return contact
        return None

    def is_registered(self, uri: Union[str, SipUri]) -> bool:
        """Check if a URI has any registered UE-side contacts.

        Mirrors the Rust-side semantic — AS capability records don't
        register a user.

        Args:
            uri: AoR as string or :class:`SipUri`.
        """
        return len(self.lookup(uri)) > 0

    def is_registered_contact(self, uri: Union[str, SipUri]) -> bool:
        """Whether any registered binding has a **Contact** URI matching ``uri``.

        Contact-keyed twin of :meth:`is_registered`; see
        :meth:`lookup_contact` for when the terminating edge needs to
        match on the contact rather than the AoR.

        Args:
            uri: Contact URI as string or :class:`SipUri`.
        """
        return len(self.lookup_contact(uri)) > 0

    async def aor_count(self) -> int:
        """Number of currently registered AoRs across the deployment.

        Async — when a persistent backend (Redis, Postgres) is configured
        the Rust implementation queries the backend so the count is
        authoritative across all siphon instances sharing it.  Without a
        backend it returns the local in-memory count.

        The mock simply counts the in-memory store.

        Returns:
            Number of distinct AoRs that currently have at least one
            non-expired contact binding.

        Example::

            from siphon import registrar, metrics, timer

            gauge = metrics.gauge("siphon_aors_registered",
                                  "Currently registered AoRs")

            @timer.every(seconds=15)
            async def publish_aor_count():
                gauge.set(await registrar.aor_count())
        """
        return sum(1 for contacts in self._store.values() if contacts)

    def expire(self, uri: Union[str, SipUri]) -> None:
        """Force-expire all contacts for a URI.

        Args:
            uri: AoR to expire.
        """
        primary = self._resolve_alias(self._normalize_aor(str(uri)))
        self._store.pop(primary, None)
        self._associated_uris.pop(primary, None)
        self._service_routes.pop(primary, None)
        self._asserted_identities.pop(primary, None)
        # Drop alias entries pointing at this primary.
        self._aliases = {k: v for k, v in self._aliases.items() if v != primary}

    def remove(self, uri: Union[str, SipUri]) -> None:
        """Remove all contacts for a URI (deregistration).

        Alias for :meth:`expire` -- used from RTR handlers.

        Args:
            uri: AoR to remove.
        """
        self.expire(uri)

    def save_pending(self, request: Any) -> None:
        """Save contacts in pending state (IMS: awaiting SAR confirmation).

        Args:
            request: The REGISTER request to extract contacts from.
        """
        self.save(request)

    def confirm_pending(self, uri: Union[str, SipUri]) -> None:
        """Confirm pending contacts (IMS: SAR succeeded).

        Args:
            uri: AoR to confirm.
        """
        pass  # In mock, save_pending already saves as active

    def asserted_identity(self, uri: Union[str, SipUri]) -> Optional[str]:
        """Look up stored P-Asserted-Identity for a URI.

        Returns:
            Identity string if stored, otherwise ``None``.
        """
        return self._asserted_identities.get(str(uri))

    def set_asserted_identity(self, aor: str, identity: str) -> None:
        """Store P-Asserted-Identity for an AoR (test helper).

        Args:
            aor: Address-of-record.
            identity: P-Asserted-Identity value.
        """
        self._asserted_identities[aor] = identity

    def set_service_routes(self, aor: str, routes: list[str]) -> None:
        """Store Service-Route headers for an AoR (RFC 3608).

        Called after SAR success in the S-CSCF to record the routes that
        subsequent requests from this UE should traverse.

        Args:
            aor: Address-of-record string.
            routes: List of Route URI strings.
        """
        if routes:
            self._service_routes[str(aor)] = list(routes)
        else:
            self._service_routes.pop(str(aor), None)

    def service_route(self, uri: Union[str, SipUri]) -> list[str]:
        """Get stored Service-Route headers for a URI (RFC 3608).

        Args:
            uri: AoR as string or :class:`SipUri`.

        Returns:
            List of Route URI strings, or empty list.
        """
        return list(self._service_routes.get(str(uri), []))

    def set_associated_uris(self, aor: str, uris: list[str]) -> None:
        """Store P-Associated-URI list for an AoR and rebuild the
        derived alias index.

        Each URI in ``uris`` becomes an alias of ``aor``, so subsequent
        ``registrar.lookup(alias)`` / ``registrar.is_registered(alias)``
        calls resolve to ``aor``'s contacts.  Empty list clears both the
        AU list and every alias entry pointing at this primary.

        Args:
            aor: Address-of-record string (or any alias of it — the
                call is resolved to the primary).
            uris: List of P-Associated-URI strings.
        """
        primary = self._resolve_alias(self._normalize_aor(str(aor)))
        # Drop existing alias entries pointing at this primary.
        self._aliases = {k: v for k, v in self._aliases.items() if v != primary}
        # Re-install one entry per URI in the new list (skip self-aliases).
        for uri in uris or []:
            alias = self._normalize_aor(uri)
            if alias != primary:
                self._aliases[alias] = primary
        if uris:
            self._associated_uris[primary] = list(uris)
        else:
            self._associated_uris.pop(primary, None)

    def associated_uris(self, uri: Union[str, SipUri]) -> list[str]:
        """Get stored P-Associated-URI list for a URI.

        Args:
            uri: AoR as string or :class:`SipUri`.

        Returns:
            List of P-Associated-URI strings, or empty list.
        """
        return list(self._associated_uris.get(str(uri), []))

    @staticmethod
    def on_change(fn: Callable) -> Callable:
        """Register a handler for registration state changes.

        The handler receives ``(aor, event_type, contacts)`` where:
          - ``aor``: str — Address of Record
          - ``event_type``: str — ``"registered"``, ``"refreshed"``,
            ``"deregistered"``, or ``"expired"``
          - ``contacts``: list[Contact] — current contact bindings

        Usage::

            @registrar.on_change
            def on_reg_change(aor, event_type, contacts):
                ...
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("registrar.on_change", None, fn, is_async)
        return fn

    def reginfo_xml(self, aor: str, state: str = "full",
                    version: int = 0) -> str:
        """Generate RFC 3680 reginfo XML for an AoR.

        Returns the XML document as a string.  Includes both UE-side
        bindings and AS-side capability records (TS 24.229 §5.4.2.1.2)
        — the latter surface their RFC 3840 feature tags as
        ``<unknown-param>`` children (RFC 3680 §5.3.2).

        Registration state is ``"active"`` when at least one UE-side
        contact exists, otherwise ``"terminated"`` (AS-only AoRs don't
        register a user).

        Args:
            aor: Address of Record (e.g. ``"sip:alice@example.com"``).
            state: ``"full"`` or ``"partial"`` (default ``"full"``).
            version: reginfo version counter (default 0).

        Returns:
            XML string conforming to RFC 3680.
        """
        contacts = self._store.get(aor, [])
        has_ue = any(getattr(c, "kind", "ue") == "ue" for c in contacts)
        reg_state = "active" if has_ue else "terminated"

        def _xml_escape(value: str) -> str:
            return (
                value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;")
            )

        contacts_xml = ""
        # UE-first then AS, each sorted by q descending.
        ue = [c for c in contacts if getattr(c, "kind", "ue") == "ue"]
        as_ = [c for c in contacts if getattr(c, "kind", "ue") == "as"]
        ue.sort(key=lambda c: c.q, reverse=True)
        as_.sort(key=lambda c: c.q, reverse=True)
        for contact in (*ue, *as_):
            params_xml = ""
            for name, value in getattr(contact, "params", []) or []:
                if value is None:
                    params_xml += (
                        f'        <unknown-param name="{_xml_escape(name)}"/>\n'
                    )
                else:
                    params_xml += (
                        f'        <unknown-param name="{_xml_escape(name)}">'
                        f'{_xml_escape(value)}</unknown-param>\n'
                    )
            contacts_xml += (
                f'      <contact id="c-{hash(contact.uri) & 0xFFFF:04x}" '
                f'state="active" event="registered">\n'
                f'        <uri>{_xml_escape(contact.uri)}</uri>\n'
                f'{params_xml}'
                f'      </contact>\n'
            )

        return (
            f'<?xml version="1.0"?>\n'
            f'<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" '
            f'version="{version}" state="{state}">\n'
            f'  <registration aor="{aor}" state="{reg_state}">\n'
            f'{contacts_xml}'
            f'  </registration>\n'
            f'</reginfo>\n'
        )

    # -- Test helpers ----------------------------------------------------------

    def add_contact(self, aor: str, contact: Contact) -> None:
        """Add a contact binding directly (test helper).

        Args:
            aor: Address-of-record string (e.g. ``"sip:alice@example.com"``).
            contact: :class:`Contact` object to register.
        """
        self._store.setdefault(aor, []).append(contact)

    def clear(self) -> None:
        """Remove all registrations (test helper)."""
        aors = list(self._store.keys())
        self._store.clear()
        self._asserted_identities.clear()
        self._service_routes.clear()
        self._associated_uris.clear()
        for aor in aors:
            self._fire_on_change(aor, "deregistered")

    def _fire_on_change(self, aor: str, event_type: str) -> None:
        """Invoke all on_change handlers registered via decorator.

        Handles both sync and async handlers — async ones are driven on a
        per-call event loop so callers don't need to maintain one (matches
        how the harness drives ``@proxy.on_request`` async handlers).
        """
        contacts = self._store.get(aor, [])
        for _, fn, is_async, _meta in _registry.handlers.get("registrar.on_change", []):
            if is_async:
                _run_async(fn(aor, event_type, contacts))
            else:
                fn(aor, event_type, contacts)


# ---------------------------------------------------------------------------
# Auth namespace
# ---------------------------------------------------------------------------

class MockAuth:
    """Mock authentication namespace.

    Control auth behavior in tests::

        from siphon import auth
        auth._allow = True   # all auth checks pass
        auth._allow = False  # all auth checks fail (challenge sent)
    """

    def __init__(self) -> None:
        self._allow: bool = False
        self._credentials: dict[str, dict[str, str]] = {}

    def add_user(self, realm: str, username: str, password: str) -> None:
        """Add credentials for testing (test helper).

        Args:
            realm: Auth realm (e.g. ``"example.com"``).
            username: Username.
            password: Password.
        """
        self._credentials.setdefault(realm, {})[username] = password

    def require_www_digest(self, request: Any, realm: Optional[str] = None) -> bool:
        """Challenge with 401 WWW-Authenticate, or verify existing credentials.

        If credentials are valid: sets ``request.auth_user``, returns ``True``.
        Otherwise: sends 401 response, returns ``False``.

        Args:
            request: The SIP request.
            realm: Auth realm (e.g. ``"example.com"``).

        Returns:
            ``True`` if authenticated, ``False`` if challenge was sent.
        """
        if self._allow:
            # Derive auth_user from From URI when auto-allowing.
            user = getattr(request.from_uri, "user", None) if request.from_uri else None
            request.auth_user = user or "mock_user"
            return True
        # Check if request has Authorization header
        auth_header = request.get_header("Authorization")
        if auth_header and self._check_auth(auth_header, realm):
            request.auth_user = self._extract_username(auth_header)
            return True
        request.reply(401, "Unauthorized")
        return False

    def require_proxy_digest(self, request: Any,
                             realm: Optional[str] = None) -> bool:
        """Challenge with 407 Proxy-Authenticate.

        Same as :meth:`require_www_digest` but uses 407.

        Args:
            request: The SIP request.
            realm: Auth realm.
        """
        if self._allow:
            user = getattr(request.from_uri, "user", None) if request.from_uri else None
            request.auth_user = user or "mock_user"
            return True
        auth_header = request.get_header("Proxy-Authorization")
        if auth_header and self._check_auth(auth_header, realm):
            request.auth_user = self._extract_username(auth_header)
            return True
        request.reply(407, "Proxy Authentication Required")
        return False

    def require_digest(self, request: Any,
                       realm: Optional[str] = None) -> bool:
        """Convenience alias for :meth:`require_www_digest`."""
        return self.require_www_digest(request, realm=realm)

    def require_ims_digest(self, request: Any,
                          realm: Optional[str] = None) -> bool:
        """IMS digest authentication via Diameter Cx MAR/MAA.

        Sends a Multimedia-Auth-Request to the HSS and uses the returned
        authentication vector to challenge or verify the UE.

        Returns:
            ``True`` if credentials are valid, ``False`` if a 401 challenge was sent.
        """
        return self.require_www_digest(request, realm=realm)

    def require_aka_digest(self, request: Any,
                           realm: Optional[str] = None) -> bool:
        """IMS AKA digest authentication using local Milenage credentials.

        Uses locally-configured K/OP/AMF credentials (from ``auth.aka_credentials``
        in siphon.yaml) to generate AKA authentication vectors — no Diameter HSS
        connection needed. The nonce contains base64(RAND || AUTN) per 3GPP TS 33.203,
        and CK/IK are derived for IPsec SA creation.

        Example::

            if not auth.require_aka_digest(request, realm="ims.test"):
                log.info("sent 401 AKA challenge")
                return

        Returns:
            ``True`` if credentials are valid, ``False`` if a 401 challenge was sent.
        """
        return self.require_www_digest(request, realm=realm)

    def verify_digest(self, request: Any,
                      realm: Optional[str] = None) -> bool:
        """Verify credentials without sending a challenge.

        Returns:
            ``True`` if valid credentials are present.
        """
        if self._allow:
            return True
        auth_header = request.get_header("Authorization")
        return auth_header is not None and self._check_auth(auth_header, realm)

    def _check_auth(self, auth_header: str, realm: Optional[str]) -> bool:
        """Simple mock auth check."""
        return self._allow

    def _extract_username(self, auth_header: str) -> str:
        """Extract username from Authorization header."""
        # Parse: Digest username="alice", ...
        for part in auth_header.split(","):
            part = part.strip()
            if part.lower().startswith("username="):
                return part.split("=", 1)[1].strip('"')
        return "unknown"


# ---------------------------------------------------------------------------
# Log namespace
# ---------------------------------------------------------------------------

class MockLog:
    """Mock logging namespace — captures log messages for test assertions.

    Access captured messages via ``log.messages``::

        from siphon import log
        log.info("hello")
        assert ("info", "hello") in log.messages
    """

    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []
        """List of ``(level, message)`` tuples captured during the test."""

    def debug(self, msg: str) -> None:
        """Log at DEBUG level."""
        self.messages.append(("debug", msg))

    def info(self, msg: str) -> None:
        """Log at INFO level."""
        self.messages.append(("info", msg))

    def warn(self, msg: str) -> None:
        """Log at WARN level."""
        self.messages.append(("warn", msg))

    def warning(self, msg: str) -> None:
        """Alias for :meth:`warn`."""
        self.warn(msg)

    def error(self, msg: str) -> None:
        """Log at ERROR level."""
        self.messages.append(("error", msg))

    def clear(self) -> None:
        """Clear all captured messages (test helper)."""
        self.messages.clear()


# ---------------------------------------------------------------------------
# Cache namespace
# ---------------------------------------------------------------------------

class MockCache:
    """Mock cache namespace with an in-memory dict backend.

    Pre-populate::

        from siphon import cache
        cache.set_data("cnam", {"msisdn_display:1234": "Sales"})

    Then ``await cache.fetch("cnam", "msisdn_display:1234")`` returns ``"Sales"``.
    """

    def __init__(self) -> None:
        self._stores: dict[str, dict[str, str]] = {}

    async def fetch(self, name: str, key: str) -> Optional[str]:
        """Fetch a value from a named cache.

        Args:
            name: Cache name (from ``siphon.yaml`` ``cache:`` list).
            key: Cache key string.

        Returns:
            Cached value or ``None`` if not found.
        """
        store = self._stores.get(name)
        if store is None:
            return None
        return store.get(key)

    async def store(
        self, name: str, key: str, value: str, ttl: Optional[int] = None
    ) -> bool:
        """Store a value in a named cache with optional TTL.

        Args:
            name: Cache name.
            key: Cache key.
            value: Value to store.
            ttl: Optional TTL in seconds. Mirrors the real ``cache.store``
                signature; the mock is in-memory and does not expire keys,
                so the value is accepted and ignored.

        Returns:
            ``True`` if stored, ``False`` if cache name unknown.
        """
        if name not in self._stores:
            return False
        self._stores[name][key] = value
        return True

    def has_cache(self, name: str) -> bool:
        """Check if a named cache exists."""
        return name in self._stores

    async def delete(self, name: str, key: str) -> bool:
        """Delete a key. Returns ``True`` if the cache exists."""
        if name not in self._stores:
            return False
        self._stores[name].pop(key, None)
        return True

    async def exists(self, name: str, key: str) -> bool:
        """Check if ``key`` is present in the named cache."""
        return key in self._stores.get(name, {})

    async def list_push(self, name: str, key: str, item: str) -> Optional[int]:
        """Append ``item`` to a list under ``key``. Returns the new
        length, or ``None`` if the cache name is unknown.

        The mock stores lists as Python ``list[str]`` under the same
        keyspace as scalars — fine for tests, but a real script would
        not mix scalar and list values on the same key.
        """
        if name not in self._stores:
            return None
        existing = self._stores[name].get(key)
        if existing is None:
            new_list: list[str] = []
        elif isinstance(existing, list):
            new_list = existing
        else:
            new_list = []
        new_list.append(item)
        self._stores[name][key] = new_list  # type: ignore[assignment]
        return len(new_list)

    async def list_pop_all(self, name: str, key: str) -> list[str]:
        """Atomically read and clear a list. Returns the items in FIFO
        order, empty list when the key was absent or the cache is
        unknown."""
        store = self._stores.get(name)
        if store is None:
            return []
        existing = store.pop(key, None)
        if isinstance(existing, list):
            return list(existing)
        return []

    async def list_len(self, name: str, key: str) -> Optional[int]:
        """Return the length of the list under ``key`` (``0`` for a
        missing key), or ``None`` if the cache name is unknown."""
        store = self._stores.get(name)
        if store is None:
            return None
        existing = store.get(key)
        if isinstance(existing, list):
            return len(existing)
        return 0

    async def list_len_sum(self, name: str, prefix: str) -> Optional[int]:
        """Sum the lengths of every list whose key starts with
        ``prefix``. Returns ``0`` when nothing matches, ``None`` if the
        cache name is unknown. Raises ``ValueError`` on an empty prefix
        (which would scan the entire keyspace)."""
        if not prefix:
            raise ValueError("prefix must not be empty")
        store = self._stores.get(name)
        if store is None:
            return None
        total = 0
        for key, value in store.items():
            if key.startswith(prefix) and isinstance(value, list):
                total += len(value)
        return total

    async def expire(self, name: str, key: str, ttl: int) -> bool:
        """Mock TTL — records the call on ``self.expirations`` for
        assertions and returns ``True`` when the key currently exists
        in the cache. The mock does not actually time out entries."""
        if not hasattr(self, "expirations"):
            self.expirations = []
        self.expirations.append({"name": name, "key": key, "ttl": ttl})
        store = self._stores.get(name)
        return store is not None and key in store

    # -- Test helpers ----------------------------------------------------------

    def set_data(self, name: str, data: Optional[dict[str, str]] = None) -> None:
        """Create/replace a named cache with test data (test helper).

        Args:
            name: Cache name.
            data: Initial key-value pairs (default: empty dict).
        """
        self._stores[name] = dict(data) if data else {}

    def clear(self) -> None:
        """Remove all caches (test helper)."""
        self._stores.clear()
        if hasattr(self, "expirations"):
            self.expirations.clear()


# ---------------------------------------------------------------------------
# RTPEngine namespace
# ---------------------------------------------------------------------------

def _resolve_media_target(
    target: Any,
) -> tuple[Optional[str], Optional[str]]:
    """Resolve ``(call_id, from_tag)`` from a media-verb target.

    Mirrors the runtime's ``resolve_call_from_tag``: a media verb may be handed
    a SIP object (``Request``/``Reply``/``Call``), a ``(call_id, from_tag)``
    pair, or a bare ``call_id`` string — the latter two let an
    ``@rtpengine.on_dtmf`` handler (which receives ``call_id``/``from_tag``
    strings) drive media without a SIP message. Tolerant of ``None`` (returns
    ``(None, None)``) so existing ``play_media(None, …)`` unit tests keep working.
    """
    # Bare call_id string → empty from_tag. Checked before the pair form so a
    # 2-char id is never misread as a pair.
    if isinstance(target, str):
        return target, ""
    # (call_id, from_tag) pair of strings.
    if (
        isinstance(target, (tuple, list))
        and len(target) == 2
        and all(isinstance(item, str) for item in target)
    ):
        return target[0], target[1]
    # SIP object → best-effort from its call_id / from_tag attributes.
    return getattr(target, "call_id", None), getattr(target, "from_tag", None)


class MockRtpEngine:
    """Mock RTPEngine namespace — records media operations for assertions.

    Example::

        from siphon import rtpengine
        # After running handler:
        assert rtpengine.operations == [("offer", "srtp_to_rtp")]

    Media-injection operations (``play_media``, ``stop_media``, ``play_dtmf``,
    ``silence_media``, ``unsilence_media``, ``block_media``, ``unblock_media``,
    ``echo``) are also captured in ``operations`` as ``(name, detail)`` tuples so
    downstream apps can unit-test MMTEL announcement flows without a live
    rtpengine. Full parameter dicts are available on ``media_calls``.

    Every media verb's ``target`` accepts three forms (like the runtime's
    ``resolve_call_from_tag``): a SIP object (``Request``/``Reply``/``Call``), a
    ``(call_id, from_tag)`` pair, or a bare ``call_id`` string — so an
    ``@rtpengine.on_dtmf`` handler can drive media from the ``call_id`` /
    ``from_tag`` it was handed. The resolved ``call_id`` / ``from_tag`` are
    recorded on each ``media_calls`` entry.

    Valid profiles: ``"srtp_to_rtp"``, ``"ws_to_rtp"``, ``"wss_to_rtp"``,
    ``"rtp_passthrough"``.
    """

    def __init__(self) -> None:
        self.operations: list[tuple[str, Optional[str]]] = []
        """List of ``(operation, profile_or_detail)`` tuples recorded."""
        self.media_calls: list[dict[str, Any]] = []
        """Full parameter dicts for each media-injection call."""
        self._healthy = True
        self._play_media_duration_ms: Optional[int] = None
        self._answer_local_sdp: str = "v=0\r\nm=audio 40000 RTP/AVP 8 101\r\n"
        self._answer_local_no_codec: bool = False
        self._subscribe_request_sdp: bytes = b""
        self._subscribe_answer_sdp: bytes = b""
        self._dtmf_handlers: list[dict[str, Any]] = []
        self._media_timeout_handlers: list[dict[str, Any]] = []

    @property
    def active_sessions(self) -> int:
        """Number of active media sessions (mock: count of offer - delete)."""
        offers = sum(1 for op, _ in self.operations if op == "offer")
        deletes = sum(1 for op, _ in self.operations if op == "delete")
        return max(0, offers - deletes)

    @property
    def instance_count(self) -> int:
        """Number of configured RTPEngine instances (mock: always 1)."""
        return 1

    async def offer(self, request: Any,
                    profile: Optional[str] = None) -> bool:
        """Send ``offer`` command to RTPEngine.

        Extracts SDP from message body, sends to engine, replaces body
        with rewritten SDP.

        Args:
            request: Request or Call object with SDP body.
            profile: RTP profile name. Defaults to ``"rtp_passthrough"``.

        Returns:
            ``True`` on success.
        """
        self.operations.append(("offer", profile or "rtp_passthrough"))
        return True

    async def answer(self, reply: Any,
                     profile: Optional[str] = None,
                     call: Any = None) -> bool:
        """Send ``answer`` command to RTPEngine.

        Profile precedence (matches the real implementation):

        1. Explicit ``profile=`` argument (script override).
        2. Profile recorded by the matching ``offer`` (looked up by A-leg
           Call-ID). Lets ``@b2bua.on_answer`` / ``@b2bua.on_early_media``
           call ``rtpengine.answer(reply)`` with no ``profile=`` and still
           get the directional flags from the offer-side profile.
        3. ``"rtp_passthrough"`` when no offer was ever recorded.

        Args:
            reply: Reply or Call object with SDP body.
            profile: Optional explicit RTP profile name. When omitted, the
                     profile recorded by the matching offer is used.
            call: Optional Call object — when provided, Call-ID and
                  From-tag are taken from this object (matching the earlier
                  ``offer``), while To-tag and SDP body still come from
                  ``reply``.

        Returns:
            ``True`` on success.
        """
        if profile is None:
            # Mirror real behavior: recover from last recorded offer.
            for op, recorded in reversed(self.operations):
                if op == "offer":
                    profile = recorded
                    break
            else:
                profile = "rtp_passthrough"
        self.operations.append(("answer", profile))
        return True

    async def answer_local(
        self,
        call: Any,
        profile: Optional[str] = None,
        auto_reject: bool = True,
    ) -> Optional[str]:
        """Single-leg UAS answer — synthesise an RFC 3264 answer for the
        caller's **own** offer, with the media engine as the far side (IVR /
        echo / announcement server).

        Unlike :meth:`answer`, this takes the offer (INVITE), not a peer's
        reply: there is no far leg, so the engine picks one encodable codec
        from the offer and returns the answer SDP for the script to put in its
        own 2xx.

        Profile precedence matches :meth:`answer` (explicit ``profile=`` →
        profile recorded by a matching ``offer`` → ``"rtp_passthrough"``).

        When the offer has no encodable codec (primed in tests via
        :meth:`set_answer_local_no_codec`), the engine cannot answer:

        * with ``auto_reject=True`` (default) and a ``Call`` target, a deferred
          ``488 Not Acceptable Here`` is recorded on the call
          (``call.reject(488, "Not Acceptable Here")``) and the coroutine
          resolves to ``None``;
        * with ``auto_reject=False`` (or a non-``Call`` target) it raises
          ``ValueError`` instead.

        Native ``siphon-rtp`` backend only.

        Args:
            call: A ``Call`` (B2BUA) — or ``Request`` — carrying the INVITE
                  offer whose Call-ID / From-tag drive the single-leg answer.
            profile: Optional explicit RTP profile name. When omitted, the
                     profile recorded by a matching offer is used.
            auto_reject: When ``True`` (default) and ``call`` is a ``Call``, a
                         no-encodable-codec result records a deferred 488 and
                         returns ``None``. When ``False`` it raises
                         ``ValueError``.

        Returns:
            The answer SDP as ``str`` on success, or ``None`` when the offer had
            no encodable codec and it was auto-rejected with a 488.

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                sdp = await rtpengine.answer_local(call, profile="ivr")
                if sdp is not None:
                    call.answer(200, "OK", body=sdp, content_type="application/sdp")
                    await rtpengine.play_media(call, file="/prompts/welcome.wav")
        """
        if profile is None:
            # Mirror real behavior: recover from the last recorded offer.
            for op, recorded in reversed(self.operations):
                if op == "offer":
                    profile = recorded
                    break
            else:
                profile = "rtp_passthrough"

        if self._answer_local_no_codec:
            can_reject = auto_reject and hasattr(call, "reject")
            if can_reject:
                call.reject(488, "Not Acceptable Here")
                self.operations.append(("answer_local", None))
                self.media_calls.append({
                    "op": "answer_local",
                    "profile": profile,
                    "auto_reject": auto_reject,
                    "answered": False,
                })
                return None
            raise ValueError("no encodable codec in offer")

        self.operations.append(("answer_local", profile))
        self.media_calls.append({
            "op": "answer_local",
            "profile": profile,
            "auto_reject": auto_reject,
            "answered": True,
        })
        return self._answer_local_sdp

    async def delete(self, request: Any) -> bool:
        """Send ``delete`` command to tear down media session.

        Args:
            request: Request or Call object (uses Call-ID + From-tag).

        Returns:
            ``True`` on success.
        """
        self.operations.append(("delete", None))
        return True

    async def ping(self) -> bool:
        """Health check: ping RTPEngine instance(s).

        Returns:
            ``True`` if healthy.
        """
        return self._healthy

    async def play_media(
        self,
        target: Any,
        file: Optional[str] = None,
        blob: Optional[bytes] = None,
        db_id: Optional[int] = None,
        repeat: Optional[int] = None,
        start_ms: Optional[int] = None,
        duration_ms: Optional[int] = None,
        to_tag: Optional[str] = None,
        wait: bool = True,
    ) -> Optional[int]:
        """Inject an audio prompt into the call.

        Exactly one of ``file``/``blob``/``db_id`` must be supplied. Per
        rtpengine semantics, ``from-tag`` (derived from ``target``) selects
        the monologue whose outgoing audio is replaced by the prompt — the
        **peer** of that monologue hears it. Pass ``to_tag`` to scope to a
        specific peer in MPTY scenarios.

        Requires rtpengine built with ``--with-transcoding`` and launched
        with ``--audio-player=on-demand``. AMR-NB/WB prompts need licensed
        codec plugins; G.711 and Opus prompts work without them.

        Args:
            target: Request, Reply, or Call object.
            file: Absolute path to an audio file on the rtpengine host.
            blob: Raw audio bytes to play (e.g. TTS output).
            db_id: Reference to a prompt stored in rtpengine's prompt DB.
            repeat: Number of times to repeat the prompt.
            start_ms: Offset into the file at which to start (ms).
            duration_ms: Cap on playback length (ms).
            to_tag: Optional peer tag for MPTY scoping.
            wait: When ``True`` (default, native siphon-rtp backend), the real
                runtime blocks until the prompt finishes playing so a script can
                sequence a following action (e.g. ``echo()``) after it. The
                coroutine parks while it waits. ``wait=False`` returns as soon as
                the engine accepts the prompt (fire-and-forget). In this mock the
                call always returns immediately (the completion event is a runtime
                behavior); ``wait`` is recorded for assertions.

        Returns:
            Prompt duration in ms if rtpengine reports one (mock returns
            the value set via :meth:`set_play_media_duration`, else ``None``).

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                await rtpengine.offer(call, profile="ivr")
                call.answer(200, "OK", body=call.body, content_type="application/sdp")
                await rtpengine.play_media(call, file="/prompts/welcome.wav")  # wait=True
                await rtpengine.echo(call)                                     # after prompt
        """
        count = sum(1 for x in (file, blob, db_id) if x is not None)
        if count != 1:
            raise ValueError(
                "play_media requires exactly one of file=, blob=, or db_id="
            )
        source = "file" if file is not None else "blob" if blob is not None else "db-id"
        call_id, resolved_from_tag = _resolve_media_target(target)
        self.operations.append(("play_media", source))
        self.media_calls.append({
            "op": "play_media",
            "call_id": call_id,
            "from_tag": resolved_from_tag,
            "file": file,
            "blob": blob,
            "db_id": db_id,
            "repeat": repeat,
            "start_ms": start_ms,
            "duration_ms": duration_ms,
            "to_tag": to_tag,
            "wait": wait,
        })
        return self._play_media_duration_ms

    async def stop_media(self, target: Any) -> bool:
        """Stop any prompt currently playing on the selected monologue.

        Args:
            target: Request, Reply, or Call object.

        Returns:
            ``True`` on success.
        """
        call_id, from_tag = _resolve_media_target(target)
        self.operations.append(("stop_media", None))
        self.media_calls.append({"op": "stop_media", "call_id": call_id, "from_tag": from_tag})
        return True

    async def play_dtmf(
        self,
        target: Any,
        code: str,
        duration_ms: Optional[int] = None,
        volume_dbm0: Optional[int] = None,
        pause_ms: Optional[int] = None,
        to_tag: Optional[str] = None,
    ) -> bool:
        """Inject DTMF tone(s) into the call.

        Args:
            target: Request, Reply, or Call object.
            code: A single digit (``"0"``–``"9"``, ``"*"``, ``"#"``,
                ``"A"``–``"D"``) or a string sequence of digits.
            duration_ms: Tone duration per digit.
            volume_dbm0: Tone volume in dBm0 (typically ``-8``).
            pause_ms: Inter-tone gap when ``code`` is a sequence.
            to_tag: Optional peer tag for MPTY scoping.

        Example::

            await rtpengine.play_dtmf(call, "123#", duration_ms=100)
        """
        call_id, resolved_from_tag = _resolve_media_target(target)
        self.operations.append(("play_dtmf", code))
        self.media_calls.append({
            "op": "play_dtmf",
            "call_id": call_id,
            "from_tag": resolved_from_tag,
            "code": code,
            "duration_ms": duration_ms,
            "volume_dbm0": volume_dbm0,
            "pause_ms": pause_ms,
            "to_tag": to_tag,
        })
        return True

    async def silence_media(self, target: Any) -> bool:
        """Replace outgoing audio on the selected monologue with silence.

        Pair with :meth:`unsilence_media` to restore the original stream.
        """
        call_id, from_tag = _resolve_media_target(target)
        self.operations.append(("silence_media", None))
        self.media_calls.append({"op": "silence_media", "call_id": call_id, "from_tag": from_tag})
        return True

    async def unsilence_media(self, target: Any) -> bool:
        """Stop replacing outgoing audio with silence (undo :meth:`silence_media`)."""
        call_id, from_tag = _resolve_media_target(target)
        self.operations.append(("unsilence_media", None))
        self.media_calls.append({"op": "unsilence_media", "call_id": call_id, "from_tag": from_tag})
        return True

    async def block_media(self, target: Any) -> bool:
        """Drop outgoing packets on the selected monologue entirely.

        Pair with :meth:`unblock_media` to resume.
        """
        call_id, from_tag = _resolve_media_target(target)
        self.operations.append(("block_media", None))
        self.media_calls.append({"op": "block_media", "call_id": call_id, "from_tag": from_tag})
        return True

    async def unblock_media(self, target: Any) -> bool:
        """Resume forwarding the selected monologue's packets."""
        call_id, from_tag = _resolve_media_target(target)
        self.operations.append(("unblock_media", None))
        self.media_calls.append({"op": "unblock_media", "call_id": call_id, "from_tag": from_tag})
        return True

    async def echo(self, target: Any, enabled: bool = True) -> bool:
        """Toggle echo-test mode on a call — reflect the caller's ingress audio
        back to itself (single-leg IVR echo).

        ``enabled=False`` stops echoing. Native ``siphon-rtp`` backend only;
        DTMF and media-timeout events still fire while echoing.
        """
        call_id, from_tag = _resolve_media_target(target)
        self.operations.append(("echo", enabled))
        self.media_calls.append({
            "op": "echo",
            "enabled": enabled,
            "call_id": call_id,
            "from_tag": from_tag,
        })
        return True

    async def subscribe_request(
        self,
        call_id: str,
        from_tag: str,
        to_tag: str,
        sdp: Optional[bytes] = None,
        profile: Optional[str] = None,
    ) -> bytes:
        """Create a new subscription to an existing call's media (MPTY / MRF
        conference focus).

        Args:
            call_id: rtpengine call-id of the source session.
            from_tag: source monologue tag whose outgoing audio is subscribed.
            to_tag: subscriber tag to create.
            sdp: Optional inbound SDP for the subscriber.
            profile: RTP profile name (defaults to ``"rtp_passthrough"``).

        Returns:
            The subscriber SDP as ``bytes``.
        """
        self.operations.append(("subscribe_request", to_tag))
        self.media_calls.append({
            "op": "subscribe_request",
            "call_id": call_id,
            "from_tag": from_tag,
            "to_tag": to_tag,
            "sdp": sdp,
            "profile": profile,
        })
        return self._subscribe_request_sdp

    async def subscribe_answer(
        self,
        call_id: str,
        from_tag: str,
        to_tag: str,
        sdp: bytes,
        profile: Optional[str] = None,
    ) -> bytes:
        """Complete the SDP negotiation for a subscription created via
        :meth:`subscribe_request`.

        Returns:
            The rewritten SDP as ``bytes`` (may be empty).
        """
        self.operations.append(("subscribe_answer", to_tag))
        self.media_calls.append({
            "op": "subscribe_answer",
            "call_id": call_id,
            "from_tag": from_tag,
            "to_tag": to_tag,
            "sdp": sdp,
            "profile": profile,
        })
        return self._subscribe_answer_sdp

    async def unsubscribe(
        self,
        call_id: str,
        from_tag: str,
        to_tag: str,
    ) -> bool:
        """Tear down a subscription created via :meth:`subscribe_request`."""
        self.operations.append(("unsubscribe", to_tag))
        self.media_calls.append({
            "op": "unsubscribe",
            "call_id": call_id,
            "from_tag": from_tag,
            "to_tag": to_tag,
        })
        return True

    def on_dtmf(self, func_or_none: Any = None, *,
                call_id: Optional[str] = None,
                from_tag: Optional[str] = None) -> Any:
        """Register a handler for inbound DTMF events from rtpengine.

        Usage::

            @rtpengine.on_dtmf
            def handle_any(call_id, from_tag, digit, duration_ms, volume):
                ...

            @rtpengine.on_dtmf(call_id="abc", from_tag="ftag1")
            def handle_specific(call_id, from_tag, digit, duration_ms, volume):
                ...
        """
        def decorator(fn: Any) -> Any:
            self._dtmf_handlers.append({
                "fn": fn,
                "call_id": call_id,
                "from_tag": from_tag,
            })
            return fn
        if func_or_none is not None:
            return decorator(func_or_none)
        return decorator

    def fire_dtmf(self, call_id: str, from_tag: str, digit: str,
                  duration_ms: int = 0, volume: int = 0) -> int:
        """Test helper: fire a DTMF event.  Returns the number of handlers
        that matched (and were invoked)."""
        fired = 0
        for entry in self._dtmf_handlers:
            if entry["call_id"] is not None and entry["call_id"] != call_id:
                continue
            if entry["from_tag"] is not None and entry["from_tag"] != from_tag:
                continue
            entry["fn"](call_id, from_tag, digit, duration_ms, volume)
            fired += 1
        return fired

    def on_media_timeout(self, func_or_none: Any = None, *,
                         call_id: Optional[str] = None,
                         from_tag: Optional[str] = None) -> Any:
        """Register a handler for media-timeout events from the media engine.

        The engine reaps a call whose media went dead and pushes a
        media-timeout event; the handler releases the per-call state no BYE
        will now clear (Rx/N5 QoS, charging, dialog).

        Usage::

            @rtpengine.on_media_timeout
            def handle_any(call_id, from_tag):
                ...

            @rtpengine.on_media_timeout(call_id="abc", from_tag="ftag1")
            def handle_specific(call_id, from_tag):
                ...
        """
        def decorator(fn: Any) -> Any:
            self._media_timeout_handlers.append({
                "fn": fn,
                "call_id": call_id,
                "from_tag": from_tag,
            })
            return fn
        if func_or_none is not None:
            return decorator(func_or_none)
        return decorator

    def fire_media_timeout(self, call_id: str, from_tag: str) -> int:
        """Test helper: fire a media-timeout event.  Returns the number of
        handlers that matched (and were invoked)."""
        fired = 0
        for entry in self._media_timeout_handlers:
            if entry["call_id"] is not None and entry["call_id"] != call_id:
                continue
            if entry["from_tag"] is not None and entry["from_tag"] != from_tag:
                continue
            entry["fn"](call_id, from_tag)
            fired += 1
        return fired

    def set_subscribe_request_sdp(self, sdp: bytes) -> None:
        """Configure the SDP returned by :meth:`subscribe_request` (test helper)."""
        self._subscribe_request_sdp = sdp

    def set_subscribe_answer_sdp(self, sdp: bytes) -> None:
        """Configure the SDP returned by :meth:`subscribe_answer` (test helper)."""
        self._subscribe_answer_sdp = sdp

    def set_play_media_duration(self, duration_ms: Optional[int]) -> None:
        """Configure the duration returned by :meth:`play_media` (test helper)."""
        self._play_media_duration_ms = duration_ms

    def set_answer_local_sdp(self, sdp: str) -> None:
        """Configure the answer SDP returned by :meth:`answer_local` (test helper)."""
        self._answer_local_sdp = sdp

    def set_answer_local_no_codec(self, no_codec: bool = True) -> None:
        """Prime :meth:`answer_local` to model a no-encodable-codec offer (test
        helper) — the next ``answer_local`` records a deferred 488 (auto-reject)
        or raises ``ValueError`` (``auto_reject=False``)."""
        self._answer_local_no_codec = no_codec

    def clear(self) -> None:
        """Clear recorded operations and registered event handlers (test helper)."""
        self.operations.clear()
        self.media_calls.clear()
        self._dtmf_handlers.clear()
        self._media_timeout_handlers.clear()
        self._answer_local_no_codec = False


# ---------------------------------------------------------------------------
# Dispatcher namespace
# ---------------------------------------------------------------------------

def _ip_of_address(address: str) -> Optional[str]:
    """Extract the bare IP from a ``host:port`` (or bare-host) address string.

    Handles ``"10.0.0.1:5060"`` → ``"10.0.0.1"``, ``"[::1]:5060"`` → ``"::1"``,
    and bare literals unchanged.  Returns ``None`` only for the empty string.
    Used by :meth:`MockGateway.contains_source` to model the Rust engine's
    IP-only source membership.
    """
    if not address:
        return None
    if address.startswith("["):
        end = address.find("]")
        if end != -1:
            return address[1:end]
    # "10.0.0.1:5060" (one colon) → strip the port; a bare IPv6 (many colons,
    # no port) or a bare IPv4 is returned unchanged.
    if address.count(":") == 1:
        return address.rsplit(":", 1)[0]
    return address


class MockDestination:
    """A destination returned by ``gateway.select()`` or ``gateway.list()``.

    Attributes:
        uri: SIP URI to route to (e.g. ``"sip:gw1.carrier.com:5060"``).
        address: Socket address string (e.g. ``"10.0.0.1:5060"``).
        healthy: Whether the destination is healthy.
        weight: Weight for load balancing.
        priority: Priority tier (lower = higher priority).
        attrs: User-defined attributes dict.

    Example::

        gw = gateway.select("carriers")
        if gw:
            request.relay(gw.uri)
            print(gw.attrs.get("region"))
    """

    def __init__(
        self,
        uri: str,
        address: str = "",
        healthy: bool = True,
        weight: int = 1,
        priority: int = 1,
        attrs: Optional[dict[str, str]] = None,
    ) -> None:
        self.uri = uri
        self.address = address or uri
        self.healthy = healthy
        self.weight = weight
        self.priority = priority
        self.attrs: dict[str, str] = attrs or {}

    def __str__(self) -> str:
        return self.uri

    def __repr__(self) -> str:
        return (
            f"Destination(uri={self.uri}, healthy={self.healthy}, "
            f"weight={self.weight}, priority={self.priority})"
        )

    def __bool__(self) -> bool:
        return self.healthy


class MockGateway:
    """Mock gateway namespace — manages named groups of SIP destinations.

    Pre-populate groups for testing::

        from siphon import gateway
        gateway.add_group("carriers", [
            {"uri": "sip:gw1.carrier.com:5060", "address": "10.0.0.1:5060", "weight": 3},
            {"uri": "sip:gw2.carrier.com:5060", "address": "10.0.0.2:5060"},
        ], algorithm="weighted")

    Then in your script::

        gw = gateway.select("carriers")
        gw = gateway.select("sbc-pool", key=request.call_id)
        gw = gateway.select("carriers", attrs={"region": "us-east"})
    """

    def __init__(self) -> None:
        self._groups: dict[str, list[MockDestination]] = {}
        self._algorithms: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def select(
        self,
        group_name: str,
        /,
        key: Optional[str] = None,
        attrs: Optional[dict[str, str]] = None,
    ) -> Optional[MockDestination]:
        """Select a destination from a named group.

        Args:
            group_name: Name of the gateway group (e.g. ``"carriers"``).
            key: Optional hash key for sticky sessions (e.g. ``call_id``).
                Used by the ``"hash"`` algorithm.
            attrs: Optional dict of attribute filters. Only destinations
                matching **all** key-value pairs are considered.

        Returns:
            A :class:`MockDestination` object, or ``None`` if no healthy
            destination matches.

        Example::

            gw = gateway.select("carriers")
            gw = gateway.select("sbc-pool", key=request.call_id)
            gw = gateway.select("carriers", attrs={"region": "us-east"})
        """
        dests = self._groups.get(group_name)
        if not dests:
            return None

        candidates = [d for d in dests if d.healthy]
        if attrs:
            candidates = [
                d for d in candidates
                if all(d.attrs.get(k) == v for k, v in attrs.items())
            ]
        if not candidates:
            return None

        algorithm = self._algorithms.get(group_name, "weighted")

        if algorithm == "hash" and key is not None:
            index = hash(key) % len(candidates)
            return candidates[index]

        # round_robin / weighted — simple rotation in mock
        counter = self._counters.get(group_name, 0)
        self._counters[group_name] = counter + 1
        return candidates[counter % len(candidates)]

    def contains_source(self, group_name: str, source_ip: str) -> bool:
        """True when ``source_ip`` is a member IP of the named group.

        Mirrors the Rust ``DispatcherManager::source_in_group`` — the backing
        check for ``request.from_gateway`` / ``call.from_gateway``.  Matches on
        IP only (destination port ignored) against every destination's
        ``address``.  Returns ``False`` (never raises) for an unknown group or
        an unparseable ``source_ip``, so callers stay infallible.

        In the mock, membership is the set of destination-address IP literals
        you registered via :meth:`add_group` (no DNS is performed — give
        destinations literal IP addresses to model resolved gateways).

        Example::

            gateway.add_group("teams", [
                {"uri": "sip:sip.pstnhub.microsoft.com", "address": "203.0.113.10:5061"},
            ])
            gateway.contains_source("teams", "203.0.113.10")  # True
        """
        dests = self._groups.get(group_name)
        if not dests:
            return False
        try:
            needle = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        for dest in dests:
            host = _ip_of_address(dest.address)
            if host is None:
                continue
            try:
                if ipaddress.ip_address(host) == needle:
                    return True
            except ValueError:
                # Non-literal host (a hostname) — the mock does no DNS; skip.
                continue
        return False

    def list(self, group_name: str) -> list[MockDestination]:
        """List all destinations in a group.

        Returns:
            List of :class:`MockDestination` objects (healthy and unhealthy).
        """
        return list(self._groups.get(group_name, []))

    def status(self, group_name: str) -> list[tuple[str, bool]]:
        """Get status of all destinations in a group.

        Returns:
            List of ``(uri, is_healthy)`` tuples.
        """
        return [(d.uri, d.healthy) for d in self._groups.get(group_name, [])]

    def groups(self) -> list[str]:
        """List all group names."""
        return list(self._groups.keys())

    def add_group(
        self,
        name: str,
        destinations: list[dict[str, Any]],
        /,
        algorithm: str = "weighted",
        probe: bool = False,
    ) -> None:
        """Dynamically add a new gateway group.

        Args:
            name: Group name.
            destinations: List of dicts with keys:
                ``uri`` (required), ``address``, ``weight``, ``priority``,
                ``transport``, ``attrs``.
            algorithm: Load-balancing algorithm: ``"round_robin"``,
                ``"weighted"`` (default), ``"hash"``.
            probe: Enable health probing (ignored in mock).

        Example::

            gateway.add_group("overflow", [
                {"uri": "sip:gw3.carrier.com", "address": "10.0.0.3:5060", "weight": 2},
                {"uri": "sip:gw4.carrier.com", "address": "10.0.0.4:5060"},
            ], algorithm="weighted")
        """
        dests = []
        for d in destinations:
            dests.append(MockDestination(
                uri=d["uri"],
                address=d.get("address", d["uri"]),
                healthy=True,
                weight=d.get("weight", 1),
                priority=d.get("priority", 1),
                attrs=d.get("attrs", {}),
            ))
        self._groups[name] = dests
        self._algorithms[name] = algorithm

    def remove_group(self, name: str) -> bool:
        """Remove a group by name.

        Returns:
            ``True`` if the group existed and was removed.
        """
        if name in self._groups:
            del self._groups[name]
            self._algorithms.pop(name, None)
            self._counters.pop(name, None)
            return True
        return False

    def mark_down(self, group_name: str, uri: str) -> bool:
        """Manually mark a destination as down.

        Returns:
            ``True`` if the destination was found.
        """
        for d in self._groups.get(group_name, []):
            if d.uri == uri:
                d.healthy = False
                return True
        return False

    def mark_up(self, group_name: str, uri: str) -> bool:
        """Manually mark a destination as up.

        Returns:
            ``True`` if the destination was found.
        """
        for d in self._groups.get(group_name, []):
            if d.uri == uri:
                d.healthy = True
                return True
        return False

    def clear(self) -> None:
        """Remove all groups (test helper)."""
        self._groups.clear()
        self._algorithms.clear()
        self._counters.clear()


# ---------------------------------------------------------------------------
# CDR mock
# ---------------------------------------------------------------------------


class MockCdr:
    """Mock ``cdr`` namespace — call detail record writing from scripts.

    Usage::

        from siphon import cdr

        cdr.write(request, extra={"billing_id": "B-12345"})  # proxy handler
        cdr.write(call, extra={"billing_id": "B-12345"})     # b2bua handler
        cdr.enabled  # True if CDR system is active

    Test helper::

        from siphon_sdk.mock_module import get_cdr
        cdrs = get_cdr().records  # list of written CDR dicts
    """

    def __init__(self) -> None:
        self._enabled: bool = True
        self.records: list[dict] = []

    @property
    def enabled(self) -> bool:
        """Whether the CDR system is enabled."""
        return self._enabled

    def write(self, source: "Any", extra: "dict[str, str] | None" = None) -> bool:
        """Write a CDR for the given request or B2BUA call.

        Args:
            source: The SIP ``Request`` (proxy handlers) OR the B2BUA ``Call``
                (``@b2bua.on_answer`` / ``on_bye`` / … handlers).  Both carry
                the Call-ID, From/To/R-URI and source IP the CDR needs.
            extra: Optional dict of extra fields to include in the CDR.

        Returns:
            True if the CDR was queued successfully.

        Raises:
            TypeError: if ``source`` is neither a ``Request`` nor a ``Call``.

        Example::

            from siphon import cdr

            @proxy.on_request("INVITE")
            def route(request):
                cdr.write(request, extra={"billing_id": "B-12345"})

            @b2bua.on_answer
            def answered(call, reply):
                cdr.write(call, extra={"billing_id": "B-12345"})
        """
        # A Request exposes `.method`; a B2BUA Call does not.  The Call is
        # always INVITE-driven and its transport comes off the A-leg, mirroring
        # the engine's `cdr_method()` / `cdr_transport()` accessors.
        if hasattr(source, "method"):
            method = getattr(source, "method", "")
            transport = getattr(source, "transport", "")
        elif hasattr(source, "id") and hasattr(source, "state"):
            method = "INVITE"
            transport = getattr(source, "_transport", "udp")
        else:
            raise TypeError("cdr.write() expects a Request or Call object")

        if not self._enabled:
            return False

        record: dict = {
            "call_id": getattr(source, "call_id", ""),
            "method": method,
            "from_uri": str(getattr(source, "from_uri", "")),
            "to_uri": str(getattr(source, "to_uri", "")),
            "ruri": str(getattr(source, "ruri", "")),
            "source_ip": getattr(source, "source_ip", ""),
            "transport": transport,
        }
        if extra:
            record.update(extra)
        self.records.append(record)
        return True

    def clear(self) -> None:
        """Reset CDR records (test helper)."""
        self.records.clear()
        self._enabled = True


# ---------------------------------------------------------------------------
# LI (Lawful Intercept) namespace
# ---------------------------------------------------------------------------

class MockLi:
    """Mock ``li`` namespace — lawful intercept operations for testing.

    Pre-configure targets for testing::

        from siphon_sdk.mock_module import get_li
        li = get_li()
        li.add_target("sip:alice@example.com")

    Then in your script::

        from siphon import li
        if li.is_target(request):
            li.intercept(request)

    Test assertions::

        li = get_li()
        assert len(li.events) == 1
        assert li.events[0] == ("intercept", "sip:alice@example.com")
    """

    def __init__(self) -> None:
        self._enabled: bool = True
        self._targets: list[str] = []
        self._events: list[tuple[str, str]] = []

    @property
    def is_enabled(self) -> bool:
        """Whether the LI subsystem is enabled.

        In the mock, returns ``True`` if ``_enabled`` is set and targets
        are configured.
        """
        return self._enabled

    def is_target(self, request: Any) -> bool:
        """Check if a request matches an active intercept target.

        Matches From URI, To URI, or RURI against configured targets.

        Args:
            request: The SIP request object.

        Returns:
            ``True`` if the request matches any configured target.
        """
        if not self._enabled or not self._targets:
            return False
        uris = [
            str(getattr(request, "from_uri", "")),
            str(getattr(request, "to_uri", "")),
            str(getattr(request, "ruri", "")),
        ]
        return any(t in uris for t in self._targets)

    def intercept(self, request: Any) -> bool:
        """Trigger interception for a matching request (emit IRI-BEGIN + start media capture).

        Args:
            request: The SIP request object.

        Returns:
            ``True`` if interception was triggered for at least one matching target.
        """
        if not self._enabled:
            return False
        uris = [
            str(getattr(request, "from_uri", "")),
            str(getattr(request, "to_uri", "")),
            str(getattr(request, "ruri", "")),
        ]
        matched = [t for t in self._targets if t in uris]
        if not matched:
            return False
        for target in matched:
            self._events.append(("intercept", target))
        return True

    def record(self, target: Any) -> bool:
        """Start SIPREC recording for a request or call.

        Accepts either a ``Request`` (proxy mode) or ``Call`` (B2BUA mode).
        In B2BUA mode, the dispatcher will start SIPREC recording on answer
        using the SRS URI from ``lawful_intercept.siprec.srs_uri`` config.

        Args:
            target: A ``Request`` or ``Call`` object.

        Returns:
            ``True`` if recording was initiated.

        Example::

            @b2bua.on_invite
            def on_invite(call):
                li.record(call)       # B2BUA mode
                call.dial("sip:bob@example.com")

            @proxy.on_request("INVITE")
            def on_invite(request):
                li.record(request)    # proxy mode
                request.relay()
        """
        if not self._enabled:
            return False
        call_id = getattr(target, "call_id", "unknown")
        self._events.append(("record", call_id))
        return True

    def stop_intercept(self, request: Any) -> bool:
        """Stop interception for a request (emit IRI-END).

        Args:
            request: The SIP request object.

        Returns:
            ``True`` if a stop event was emitted for at least one matching target.
        """
        if not self._enabled:
            return False
        uris = [
            str(getattr(request, "from_uri", "")),
            str(getattr(request, "to_uri", "")),
            str(getattr(request, "ruri", "")),
        ]
        matched = [t for t in self._targets if t in uris]
        if not matched:
            return False
        for target in matched:
            self._events.append(("stop_intercept", target))
        return True

    def stop_recording(self, target: Any) -> bool:
        """Stop SIPREC recording for a request or call.

        Accepts either a ``Request`` or ``Call`` object.

        Args:
            target: A ``Request`` or ``Call`` object.

        Returns:
            ``True`` if a stop event was emitted.
        """
        if not self._enabled:
            return False
        call_id = getattr(target, "call_id", "unknown")
        self._events.append(("stop_recording", call_id))
        return True

    # -- Test helpers ----------------------------------------------------------

    def add_target(self, uri: str) -> None:
        """Add a target URI for intercept matching (test helper).

        Args:
            uri: SIP URI to match against (e.g. ``"sip:alice@example.com"``).
        """
        if uri not in self._targets:
            self._targets.append(uri)

    @property
    def events(self) -> list[tuple[str, str]]:
        """List of ``(operation, target_or_call_id)`` tuples recorded.

        Operations: ``"intercept"``, ``"record"``, ``"stop_intercept"``,
        ``"stop_recording"``.
        """
        return self._events

    @property
    def targets(self) -> list[str]:
        """List of currently configured target URIs."""
        return list(self._targets)

    def clear(self) -> None:
        """Reset targets, events, and enabled state (test helper)."""
        self._targets.clear()
        self._events.clear()
        self._enabled = True


# ---------------------------------------------------------------------------
# Registration namespace (outbound REGISTER)
# ---------------------------------------------------------------------------

class MockRegistration:
    """Mock outbound registration namespace.

    Manages outbound REGISTER bindings to upstream carriers/SBCs.

    Example::

        from siphon import registration

        registration.add("sip:bob@carrier.com", "sip:registrar.carrier.com",
                          user="bob", password="pass123", interval=3600)
        registration.remove("sip:bob@carrier.com")

        for reg in registration.list():
            log.info(f"{reg['aor']}: {reg['state']}")
    """

    def __init__(self) -> None:
        self._entries: dict[str, dict] = {}

    def add(self, aor: str, registrar: str, *, user: str, password: str = "",
            interval: Optional[int] = None, realm: Optional[str] = None,
            contact: Optional[str] = None, transport: Optional[str] = None,
            auth: Optional[str] = None, k: Optional[str] = None,
            op: Optional[str] = None, opc: Optional[str] = None,
            amf: Optional[str] = None, sqn: Optional[str] = None,
            ipsec: bool = False, ue_port_c: Optional[int] = None,
            ue_port_s: Optional[int] = None, ipsec_alg: Optional[str] = None,
            ipsec_ealg: Optional[str] = None, imei: Optional[str] = None,
            ims_features: Optional[list[str]] = None) -> None:
        """Add a new outbound registration.

        Args:
            aor: Address-of-Record (e.g. "sip:alice@carrier.com"). For IMS AKA
                this is the IMPU (e.g.
                "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org").
            registrar: Registrar URI (e.g. "sip:registrar.carrier.com:5060").
                For IMS this is the P-CSCF.
            user: Authentication username. For IMS AKA this is the IMPI.
            password: Authentication password (digest only; unused for AKA).
            interval: Registration interval in seconds.
            realm: Optional realm hint (the home domain for IMS).
            contact: Optional Contact URI.
            transport: Transport protocol: "udp" (default), "tcp", "tls".
            auth: "digest" (default) or "aka" for IMS AKAv1-MD5
                (RFC 3310 / 3GPP TS 33.203).
            k: Subscriber key K as 32 hex chars (required when auth="aka").
            op: Operator variant OP as 32 hex chars (supply op OR opc for AKA).
            opc: Pre-computed OPc as 32 hex chars (supply op OR opc for AKA).
            amf: Authentication Management Field as 4 hex chars (default "8000").
            sqn: Initial stored sequence number SQN_MS as 12 hex chars
                (default all-zeros — correct for a fresh soft-UE).
            ipsec: True to establish IPsec sec-agree with the P-CSCF
                (3GPP TS 33.203). Requires auth="aka", ue_port_c, ue_port_s.
            ue_port_c: UE protected client port (must also be a listen.udp port).
            ue_port_s: UE protected server port (must also be a listen.udp port).
            ipsec_alg: Offered integrity algorithm — "hmac-sha-1-96" (default),
                "hmac-md5-96", or "hmac-sha-256-128".
            ipsec_ealg: Offered encryption algorithm — "null" (default) or "aes-cbc".

        Raises:
            ValueError: when auth="aka" but `k` or an operator key (`op`/`opc`)
                is missing; or when ipsec=True without auth="aka" /
                ue_port_c / ue_port_s — mirroring the Rust binding.
        """
        is_aka = auth is not None and auth.lower() == "aka"
        if is_aka:
            if not k:
                raise ValueError("auth='aka' requires the subscriber key `k`")
            if not op and not opc:
                raise ValueError("auth='aka' requires either `op` or `opc`")
        if ipsec:
            if not is_aka:
                raise ValueError("ipsec=True requires auth='aka'")
            if ue_port_c is None:
                raise ValueError("ipsec=True requires ue_port_c")
            if ue_port_s is None:
                raise ValueError("ipsec=True requires ue_port_s")
        self._entries[aor] = {
            "aor": aor,
            "registrar": registrar,
            "user": user,
            "password": password,
            "interval": interval or 3600,
            "realm": realm,
            "contact": contact,
            "transport": transport or "udp",
            "auth": "aka" if is_aka else "digest",
            "k": k,
            "op": op,
            "opc": opc,
            "amf": amf or "8000",
            "sqn": sqn or "000000000000",
            "ipsec": bool(ipsec),
            "ue_port_c": ue_port_c,
            "ue_port_s": ue_port_s,
            "ipsec_alg": ipsec_alg or "hmac-sha-1-96",
            "ipsec_ealg": ipsec_ealg or "null",
            "imei": imei,
            "ims_features": list(ims_features) if ims_features else [],
            "state": "registered",
            "expires_in": interval or 3600,
            "failure_count": 0,
            # Captured from the 200 OK on a real run (IMS); empty in the mock.
            "service_route": [],
            "associated_uris": [],
        }
        self._fire_on_change(aor, "registered")

    def remove(self, aor: str) -> bool:
        """Remove an outbound registration by AoR."""
        removed = self._entries.pop(aor, None) is not None
        if removed:
            self._fire_on_change(aor, "deregistered")
        return removed

    def refresh(self, aor: str) -> bool:
        """Force an immediate re-registration for an AoR."""
        return aor in self._entries

    def list(self) -> list[dict]:
        """List all registrations with their current state.

        Returns:
            List of dicts with keys: aor, state, expires_in.
        """
        return [
            {"aor": e["aor"], "state": e["state"], "expires_in": e["expires_in"]}
            for e in self._entries.values()
        ]

    def status(self, aor: str) -> Optional[str]:
        """Get the state of a specific registration."""
        entry = self._entries.get(aor)
        return entry["state"] if entry else None

    def count(self) -> int:
        """Number of configured registrations."""
        return len(self._entries)

    def service_route(self, aor: str) -> list[str]:
        """The captured Service-Route set (RFC 3608) for an AoR — the Route a
        B2BUA prepends to MO calls so they traverse the originating S-CSCF.
        Empty in the mock unless populated on the entry dict by a test."""
        entry = self._entries.get(aor)
        return list(entry.get("service_route", [])) if entry else []

    def associated_uris(self, aor: str) -> list[str]:
        """The P-Associated-URI list (implicit registration set) for an AoR."""
        entry = self._entries.get(aor)
        return list(entry.get("associated_uris", [])) if entry else []

    def flow(self, aor: str, ue_ip: str):
        """A :class:`Flow` over the UE→P-CSCF IPsec SA for MO ``call.dial``.

        Real runtime returns ``None`` until the sec-agree handshake completes;
        the mock returns a Flow whenever the entry was added with
        ``ipsec=True`` (so MO handlers can be unit-tested), else ``None``.
        """
        entry = self._entries.get(aor)
        if not entry or not entry.get("ipsec"):
            return None
        from .types import Flow
        return Flow(
            transport="udp",
            local_addr=f"{ue_ip}:{entry.get('ue_port_c')}",
        )

    @staticmethod
    def on_change(fn: Callable) -> Callable:
        """Register a handler for outbound registration state changes.

        The handler receives ``(aor, event_type, state)`` where:
          - ``aor``: str -- Address of Record (e.g. "sip:trunk@carrier.com")
          - ``event_type``: str -- ``"registered"``, ``"refreshed"``,
            ``"failed"``, or ``"deregistered"``
          - ``state``: dict -- ``{"expires_in": int, "failure_count": int,
            "registrar": str, "status_code": int}`` (``status_code`` only
            present when ``event_type`` is ``"failed"``)

        Usage::

            @registration.on_change
            def on_trunk_change(aor, event_type, state):
                ...
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("registration.on_change", None, fn, is_async)
        return fn

    def clear(self) -> None:
        """Reset all registrations (test helper)."""
        aors = list(self._entries.keys())
        self._entries.clear()
        for aor in aors:
            self._fire_on_change(aor, "deregistered")

    def _fire_on_change(self, aor: str, event_type: str, status_code: int | None = None) -> None:
        """Invoke all on_change handlers registered via decorator."""
        entry = self._entries.get(aor)
        state = {
            "expires_in": entry["expires_in"] if entry else 0,
            "failure_count": entry.get("failure_count", 0) if entry else 0,
            "registrar": entry["registrar"] if entry else "",
        }
        if status_code is not None:
            state["status_code"] = status_code
        for _, fn, _, _meta in _registry.handlers.get("registration.on_change", []):
            fn(aor, event_type, state)


# ---------------------------------------------------------------------------
# Diameter
# ---------------------------------------------------------------------------

class MockEventSink:
    """Mock ``diameter.event_sink`` — records emitted rows for assertions."""

    def __init__(self) -> None:
        self.rows: list = []

    def emit(self, row: Any) -> None:
        self.rows.append(row)


class MockPeer:
    """A backend peer handle returned by :class:`MockPeerPool` picks."""

    def __init__(self, name: str, tenant: str, connected: bool = True) -> None:
        self.name = name
        self.tenant = tenant
        self.addr = f"{name}.example.org:3868"
        self.transport = "tcp"
        self._connected = connected

    def __bool__(self) -> bool:
        return self._connected


class MockPeerPool:
    """Mock backend pool. Picks return a :class:`MockPeer` for the first
    connected member; round-robin advances a cursor."""

    def __init__(self, diameter: "MockDiameter", tenant: str, names: list) -> None:
        self._diameter = diameter
        self._tenant = tenant
        self._names = list(names)
        self._cursor = 0
        self._sticky: dict = {}

    def _live(self) -> list:
        return [n for n in self._names if self._diameter._peers.get(n, False)]

    def pick_round_robin(self) -> Optional[MockPeer]:
        live = self._live()
        if not live:
            return None
        name = live[self._cursor % len(live)]
        self._cursor += 1
        return MockPeer(name, self._tenant)

    def pick_weighted(self, weights: dict) -> Optional[MockPeer]:
        return self.pick_round_robin()

    def pick_sticky(self, key: str, ttl_secs: float = 300.0) -> Optional[MockPeer]:
        name = self._sticky.get(key)
        if name is not None and self._diameter._peers.get(name, False):
            return MockPeer(name, self._tenant)
        peer = self.pick_round_robin()
        if peer is not None:
            self._sticky[key] = peer.name
        return peer

    @property
    def live_count(self) -> int:
        return len(self._live())


class MockDiameterAnswer:
    """Mock ``DiameterAnswer`` — the value a handler returns / forwards."""

    def __init__(self, result_code: int = 2001, command_code: int = 0,
                 avps: Optional[dict] = None) -> None:
        self.result_code = result_code
        self.command_code = command_code
        self._avps = dict(avps or {})

    @property
    def is_error(self) -> bool:
        rc = self.result_code
        return (3000 <= rc < 4000) or (5000 <= rc < 6000)

    def get_avp(self, code: int, vendor: int = 0):
        return self._avps.get((code, vendor))

    def set_avp(self, code_or_name, value, vendor: int = 0) -> None:
        self._avps[(code_or_name, vendor)] = value

    def remove_avp(self, code: int, vendor: int = 0) -> int:
        return 1 if self._avps.pop((code, vendor), None) is not None else 0

    def iter_avps(self) -> list:
        return [(code, vendor, value) for (code, vendor), value in self._avps.items()]


# ── ISDN-AddressString / TBCD (3GPP TS 29.002 §17.7.8) ──────────────────────
# Mirrors siphon's Rust codec so the mock decodes MSISDN / SC-Address /
# SGSN-Number / MME-Number-for-MT-SMS exactly like the real server path.

# (code, vendor) of the AVPs dictionary-typed ISDNAddressString — vendor 3GPP.
_ISDN_ADDRESS_AVPS = {
    (701, 10415),   # MSISDN
    (1489, 10415),  # SGSN-Number
    (1645, 10415),  # MME-Number-for-MT-SMS
    (3300, 10415),  # SC-Address
}

# International, E.164 ToN/NPI octet (bit7=ext, ToN=001, NPI=0001).
TON_NPI_INTERNATIONAL_E164 = 0x91


def _encode_tbcd_digits(digits: str) -> bytes:
    """Pack a digit string as TBCD — two digits per octet, low nibble first,
    odd length padded with 0xF (TS 29.002 §17.7.8). Non-digits are dropped."""
    nibbles = [ord(c) - ord("0") for c in digits if c.isdigit()]
    out = bytearray()
    for i in range(0, len(nibbles), 2):
        lo = nibbles[i]
        hi = nibbles[i + 1] if i + 1 < len(nibbles) else 0x0F
        out.append((hi << 4) | lo)
    return bytes(out)


def _decode_tbcd_digits(data: bytes) -> str:
    """Decode TBCD octets back to a digit string (low nibble first); nibbles
    above 9 (filler/extended) are skipped, matching the Rust decoder."""
    out = []
    for byte in data:
        lo = byte & 0x0F
        hi = (byte >> 4) & 0x0F
        if lo <= 9:
            out.append(chr(ord("0") + lo))
        if hi <= 9:
            out.append(chr(ord("0") + hi))
    return "".join(out)


def encode_isdn_address_string(digits: str, ton_npi: int = TON_NPI_INTERNATIONAL_E164) -> bytes:
    """Encode an E.164 digit string as ISDN-AddressString — one ToN/NPI octet
    then the TBCD digits. A leading ``+`` is stripped."""
    return bytes([ton_npi]) + _encode_tbcd_digits(digits)


def decode_isdn_address_string(data: bytes) -> str:
    """Decode ISDN-AddressString bytes to an E.164 digit string. Tolerates a
    missing ToN/NPI byte (bit 7 clear → treat the whole buffer as TBCD)."""
    if data and (data[0] & 0x80):
        return _decode_tbcd_digits(data[1:])
    return _decode_tbcd_digits(data)


class MockDiameterRequest:
    """Mock ``DiameterRequest`` passed to ``@diameter.on_request`` in tests.

    Construct one in your test and invoke your handler with it.
    """

    def __init__(self, *, application_name: str = "S6c", command_code: int = 0,
                 command_name: str = "", session_id: Optional[str] = None,
                 dest_realm: Optional[str] = None, dest_host: Optional[str] = None,
                 origin_host: Optional[str] = None, origin_realm: Optional[str] = None,
                 peer: Optional[MockPeer] = None, avps: Optional[dict] = None,
                 application_id: int = 0) -> None:
        self.application_id = application_id
        self.application_name = application_name
        self.command_code = command_code
        self.command_name = command_name
        self.session_id = session_id
        self.dest_realm = dest_realm
        self.dest_host = dest_host
        self.origin_host = origin_host
        self.origin_realm = origin_realm
        self.is_request = True
        self.is_proxiable = True
        self.peer = peer or MockPeer("client", "default")
        self._avps = dict(avps or {})

    def get_avp(self, code: int, vendor: int = 0):
        value = self._avps.get((code, vendor))
        # ISDNAddressString AVPs surface as a decoded E.164 digit string, like
        # the real server path. Tolerate a test storing either raw bytes or an
        # already-decoded str.
        if value is not None and (code, vendor) in _ISDN_ADDRESS_AVPS and isinstance(value, (bytes, bytearray)):
            return decode_isdn_address_string(bytes(value))
        return value

    def set_avp(self, code_or_name, value, vendor: int = 0) -> None:
        self._avps[(code_or_name, vendor)] = value

    def insert_avp(self, code_or_name, value, vendor: int = 0) -> None:
        self._avps[(code_or_name, vendor)] = value

    def remove_avp(self, code: int, vendor: int = 0) -> int:
        return 1 if self._avps.pop((code, vendor), None) is not None else 0

    def iter_avps(self) -> list:
        return [(code, vendor, value) for (code, vendor), value in self._avps.items()]

    def extract_imsi(self) -> Optional[str]:
        return self._avps.get((1, 0))

    def answer(self, result_code: int = 2001, error_message: Optional[str] = None) -> MockDiameterAnswer:
        """Build a local answer to serve this request (HSS-style). Populate it
        with :meth:`MockDiameterAnswer.set_avp`, including grouped AVPs (pass a
        list of ``(code, value[, vendor])`` child tuples as the value)."""
        return MockDiameterAnswer(result_code=result_code, command_code=self.command_code)

    def reject(self, result_code: int, error_message: Optional[str] = None) -> MockDiameterAnswer:
        return MockDiameterAnswer(result_code=result_code, command_code=self.command_code)

    async def forward_to(self, peer: MockPeer, identity=None,
                         timeout_secs: float = 10.0) -> MockDiameterAnswer:
        """Mock relay — returns a 2001 success answer (override in tests by
        monkeypatching if a different result is needed)."""
        return MockDiameterAnswer(result_code=2001, command_code=self.command_code)


class MockDiameter:
    """Mock Diameter namespace for testing scripts that use ``from siphon import diameter``.

    Exposes connection status and Cx/Rx methods matching the Rust ``DiameterNamespace``.

    Example::

        from siphon_sdk import mock_module
        mock_module.install()
        diameter = mock_module.get_diameter()
        diameter.add_peer("hss1", connected=True)
        diameter.set_default_server_name("sip:scscf.ims.example.com:6060")

        from siphon import diameter
        assert diameter.is_connected("hss1")
        result = diameter.cx_uar("sip:alice@ims.example.com")
        assert result["server_name"] == "sip:scscf.ims.example.com:6060"
    """

    def __init__(self) -> None:
        self._peers: dict[str, bool] = {}  # peer_name -> connected
        self._uar_responses: dict[str, dict] = {}  # public_identity -> response
        self._sar_responses: dict[str, dict] = {}
        self._lir_responses: dict[str, dict] = {}
        self._aar_responses: dict[str, dict] = {}  # session_id -> response
        # Sh (AS → HSS) responses, keyed by public_identity
        self._udr_responses: dict[str, dict] = {}
        self._pur_responses: dict[str, dict] = {}
        self._snr_responses: dict[str, dict] = {}
        self._default_server_name: Optional[str] = None
        self._default_rx_result_code: int = 2001
        self._default_sh_result_code: int = 2001
        # Rf (CTF → CDF) — TS 32.299 offline charging
        self._default_rf_result_code: int = 2001
        self._default_rf_interim_interval: Optional[int] = None
        self._rf_session_counter: int = 0
        self._rf_acrs: list[dict] = []  # captured ACRs for assertions
        # Ro (CTF → OCS) — RFC 8506 / TS 32.299 online charging
        self._default_ro_result_code: int = 2001
        self._default_ro_granted_time: Optional[int] = 30
        self._default_ro_validity_time: Optional[int] = None
        self._default_ro_final_unit_action: Optional[int] = None
        self._ro_session_counter: int = 0
        self._ro_ccrs: list[dict] = []  # captured CCRs for assertions

    def is_connected(self, peer_name: str) -> bool:
        """Check if a Diameter peer is connected.

        Args:
            peer_name: Name of the peer (e.g. "hss1").

        Returns:
            ``True`` if the peer was added and is marked as connected.
        """
        return self._peers.get(peer_name, False)

    def peer_count(self) -> int:
        """Get the number of connected peers.

        Returns:
            Count of peers that are marked as connected.
        """
        return sum(1 for v in self._peers.values() if v)

    # -- ISDN-AddressString helpers (3GPP TS 29.002 §17.7.8) --

    def decode_isdn_address(self, value: Union[bytes, str]) -> str:
        """Decode an ISDN-AddressString to its E.164 digit string.

        Accepts the raw AVP bytes (``0x91`` ToN/NPI + TBCD digits) **or** an
        already-decoded ``str`` — the latter is returned unchanged, so it is
        safe to call on the result of ``req.get_avp("MSISDN")`` regardless of
        the AVP's dictionary type. A missing ToN/NPI byte is tolerated.

        Args:
            value: ``bytes`` (raw ISDN-AddressString) or ``str`` (digits).

        Returns:
            The E.164 digit string (no leading ``+``).

        Example:
            >>> diameter.decode_isdn_address(req.get_avp("MSISDN"))
            '31612345678'
        """
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            return decode_isdn_address_string(bytes(value))
        raise TypeError("decode_isdn_address expects bytes or str")

    def encode_isdn_address(self, digits: str, ton_npi: int = TON_NPI_INTERNATIONAL_E164) -> bytes:
        """Encode an E.164 digit string as an ISDN-AddressString — one ToN/NPI
        octet followed by the TBCD digit string.

        Use when building a raw OctetString AVP by hand for an unknown code;
        dictionary-typed AVPs (MSISDN / SC-Address / SGSN-Number /
        MME-Number-for-MT-SMS) encode digit strings automatically. A leading
        ``+`` is stripped.

        Args:
            digits: The E.164 number as a digit string.
            ton_npi: ToN/NPI byte (default ``0x91`` = international E.164).

        Returns:
            The encoded ISDN-AddressString ``bytes``.

        Example:
            >>> diameter.encode_isdn_address("31612345678")
            b'\\x91\\x13\\x16\\x32\\x54\\x76\\xf8'
        """
        return encode_isdn_address_string(digits, ton_npi)

    # -- Cx: HSS integration (I-CSCF / S-CSCF) --

    def cx_uar(self, public_identity: str,
               visited_network_id: Optional[str] = None,
               user_auth_type: Optional[int] = None) -> Optional[dict]:
        """Send a User-Authorization-Request to discover S-CSCF assignment.

        Args:
            public_identity: User's public identity (e.g. ``"sip:alice@ims.example.com"``).
            visited_network_id: Visited network identifier.
            user_auth_type: User-Authorization-Type AVP value (3GPP TS 29.229).
                ``0`` = REGISTRATION, ``1`` = DE_REGISTRATION,
                ``2`` = REGISTRATION_AND_CAPABILITIES.  Omit to not send the AVP.

        Returns:
            Dict with ``result_code`` and ``server_name``, or ``None``.
        """
        if public_identity in self._uar_responses:
            return dict(self._uar_responses[public_identity])
        if self._default_server_name:
            return {"result_code": 2001, "server_name": self._default_server_name}
        return None

    def cx_sar(self, public_identity: str,
               server_name: Optional[str] = None,
               assignment_type: int = 1) -> Optional[dict]:
        """Send a Server-Assignment-Request after REGISTER auth.

        Args:
            public_identity: User's public identity.
            server_name: This S-CSCF's SIP URI.
            assignment_type: Server-Assignment-Type (default 1 = REGISTRATION).

        Returns:
            Dict with ``result_code`` and ``user_data`` (iFC XML), or ``None``.
        """
        if public_identity in self._sar_responses:
            return dict(self._sar_responses[public_identity])
        return {"result_code": 2001, "user_data": None}

    def cx_lir(self, public_identity: str) -> Optional[dict]:
        """Send a Location-Info-Request to find the serving S-CSCF.

        Args:
            public_identity: Target user's public identity.

        Returns:
            Dict with ``result_code`` and ``server_name``, or ``None``.
        """
        if public_identity in self._lir_responses:
            return dict(self._lir_responses[public_identity])
        if self._default_server_name:
            return {"result_code": 2001, "server_name": self._default_server_name}
        return None

    # -- Rx: PCRF integration (P-CSCF) --

    def rx_aar(self, session_id: Optional[str] = None,
               framed_ip: Optional[str] = None,
               framed_ipv6: Union[str, bytes, None] = None,
               media_components: Optional[list] = None,
               af_application_id: str = "IMS Services",
               subscription_id: Optional[tuple] = None) -> Optional[dict]:
        """Send an Rx AA-Request for QoS resource reservation.

        Args:
            session_id: Reuse an existing Rx session ID (modification AAR
                per TS 29.214 §4.4.5).  ``None`` allocates a new session.
            framed_ip: UE IPv4 address (Framed-IP-Address AVP).
            framed_ipv6: UE IPv6 address (str or bytes).
            media_components: list of media-component dicts shaped per
                TS 29.214 §5.3.7 (see project docs for the full schema).
            af_application_id: AF-Application-Identifier (default
                ``"IMS Services"``).
            subscription_id: Optional ``(data, type)`` tuple identifying
                the IMS subscriber (RFC 4006 §8.47).

        Returns:
            Dict with ``result_code`` and ``session_id``, or ``None``.
        """
        sid = session_id or f"mock-rx-{len(self._aar_responses) + 1}"
        if sid in self._aar_responses:
            return dict(self._aar_responses[sid])
        return {"result_code": self._default_rx_result_code, "session_id": sid}

    def rx_str(self, session_id: str) -> Optional[int]:
        """Send an Rx Session-Termination-Request.

        Args:
            session_id: The Rx session ID from the original AAR.

        Returns:
            Result code (int), or ``None``.
        """
        return self._default_rx_result_code

    # -- Sh: HSS integration (Application Server role) --

    def sh_udr(self, public_identity: str,
               data_reference: Union[int, list[int]],
               service_indication: Optional[str] = None) -> Optional[dict]:
        """Send a Sh User-Data-Request to fetch user profile data from the HSS.

        Args:
            public_identity: Target user's public identity.
            data_reference: Data-Reference int or list[int] (TS 29.328 §7.6).
            service_indication: e.g. ``"simservs"`` for Repository-Data.

        Returns:
            Dict with ``result_code`` and ``user_data`` (XML), or ``None``.
        """
        if public_identity in self._udr_responses:
            return dict(self._udr_responses[public_identity])
        return {"result_code": self._default_sh_result_code, "user_data": None}

    def sh_pur(self, public_identity: str,
               data_reference: int,
               xml: str,
               service_indication: Optional[str] = None) -> Optional[dict]:
        """Send a Sh Profile-Update-Request to push user profile data to the HSS.

        Args:
            public_identity: Target user's public identity.
            data_reference: Data-Reference (e.g. ``0`` = Repository-Data).
            xml: UTF-8 XML payload.
            service_indication: e.g. ``"simservs"``; required by the HSS when
                Data-Reference is Repository-Data (TS 29.328 §6.1.3).

        Returns:
            Dict with ``result_code``, or ``None``.
        """
        if public_identity in self._pur_responses:
            return dict(self._pur_responses[public_identity])
        return {"result_code": self._default_sh_result_code}

    def sh_snr(self, public_identity: str,
               data_reference: Union[int, list[int]],
               subs_req_type: int,
               service_indication: Optional[str] = None) -> Optional[dict]:
        """Send a Sh Subscribe-Notifications-Request to the HSS.

        Args:
            public_identity: Target user's public identity.
            data_reference: Data-Reference int or list[int] to subscribe to.
            subs_req_type: ``0`` = SUBSCRIBE, ``1`` = UNSUBSCRIBE.
            service_indication: e.g. ``"simservs"``; required by the HSS when
                Data-Reference is Repository-Data (TS 29.328 §6.1.4).

        Returns:
            Dict with ``result_code``, or ``None``.
        """
        if public_identity in self._snr_responses:
            return dict(self._snr_responses[public_identity])
        return {"result_code": self._default_sh_result_code}

    # -- Test helpers --

    def add_peer(self, name: str, connected: bool = True) -> None:
        """Register a mock Diameter peer (test helper).

        Args:
            name: Peer name.
            connected: Whether the peer should appear as connected.
        """
        self._peers[name] = connected

    def set_default_server_name(self, server_name: str) -> None:
        """Set a default S-CSCF name returned by UAR/LIR when no per-user response is configured.

        Args:
            server_name: S-CSCF SIP URI (e.g. ``"sip:scscf.ims.example.com:6060"``).
        """
        self._default_server_name = server_name

    def set_uar_response(self, public_identity: str,
                         result_code: int = 2001,
                         server_name: Optional[str] = None) -> None:
        """Configure a mock UAA response for a specific user (test helper).

        Args:
            public_identity: User's public identity.
            result_code: Diameter result code (default 2001 = SUCCESS).
            server_name: Assigned S-CSCF URI.
        """
        self._uar_responses[public_identity] = {
            "result_code": result_code,
            "server_name": server_name,
        }

    def set_sar_response(self, public_identity: str,
                         result_code: int = 2001,
                         user_data: Optional[str] = None) -> None:
        """Configure a mock SAA response for a specific user (test helper).

        Args:
            public_identity: User's public identity.
            result_code: Diameter result code.
            user_data: iFC XML string from user profile.
        """
        self._sar_responses[public_identity] = {
            "result_code": result_code,
            "user_data": user_data,
        }

    def set_lir_response(self, public_identity: str,
                         result_code: int = 2001,
                         server_name: Optional[str] = None) -> None:
        """Configure a mock LIA response for a specific user (test helper).

        Args:
            public_identity: User's public identity.
            result_code: Diameter result code.
            server_name: Serving S-CSCF URI.
        """
        self._lir_responses[public_identity] = {
            "result_code": result_code,
            "server_name": server_name,
        }

    def set_aar_response(self, session_id: str,
                         result_code: int = 2001) -> None:
        """Configure a mock AAA response for a specific Rx session (test helper).

        Args:
            session_id: Rx session ID.
            result_code: Diameter result code.
        """
        self._aar_responses[session_id] = {
            "result_code": result_code,
            "session_id": session_id,
        }

    # -- Rf: CDF integration (offline charging — TS 32.299) --

    def rf_acr_start(
        self,
        *,
        calling_party: Optional[str] = None,
        called_party: Optional[str] = None,
        sip_method: Optional[str] = None,
        role_of_node: Optional[str] = None,
        node_functionality: Optional[str] = None,
        ims_charging_identifier: Optional[str] = None,
        user_session_id: Optional[str] = None,
        originating_ioi: Optional[str] = None,
        terminating_ioi: Optional[str] = None,
        application_server: Optional[str] = None,
        application_provided_called_party_address: Optional[str] = None,
        incoming_trunk_group_id: Optional[str] = None,
        outgoing_trunk_group_id: Optional[str] = None,
        visited_network_id: Optional[str] = None,
        user_name: Optional[str] = None,
        cause_code: Optional[int] = None,
        service_context_id: Optional[str] = None,
        peer: Optional[str] = None,
    ) -> Optional[dict]:
        """Send Rf ACR-START to the CDF (TS 32.299 §6.2.2)."""
        return self._record_acr(
            "START",
            session_id=None,
            record_number=0,
            termination_cause=None,
            calling_party=calling_party,
            called_party=called_party,
            sip_method=sip_method,
            role_of_node=role_of_node,
            node_functionality=node_functionality,
            ims_charging_identifier=ims_charging_identifier,
            user_session_id=user_session_id,
            originating_ioi=originating_ioi,
            terminating_ioi=terminating_ioi,
            application_server=application_server,
            application_provided_called_party_address=application_provided_called_party_address,
            incoming_trunk_group_id=incoming_trunk_group_id,
            outgoing_trunk_group_id=outgoing_trunk_group_id,
            visited_network_id=visited_network_id,
            user_name=user_name,
            cause_code=cause_code,
            service_context_id=service_context_id,
            peer=peer,
        )

    def rf_acr_interim(
        self,
        session_id: str,
        record_number: int,
        *,
        calling_party: Optional[str] = None,
        called_party: Optional[str] = None,
        sip_method: Optional[str] = None,
        role_of_node: Optional[str] = None,
        node_functionality: Optional[str] = None,
        ims_charging_identifier: Optional[str] = None,
        user_session_id: Optional[str] = None,
        originating_ioi: Optional[str] = None,
        terminating_ioi: Optional[str] = None,
        application_server: Optional[str] = None,
        application_provided_called_party_address: Optional[str] = None,
        incoming_trunk_group_id: Optional[str] = None,
        outgoing_trunk_group_id: Optional[str] = None,
        visited_network_id: Optional[str] = None,
        user_name: Optional[str] = None,
        cause_code: Optional[int] = None,
        service_context_id: Optional[str] = None,
        peer: Optional[str] = None,
    ) -> Optional[dict]:
        """Send Rf ACR-INTERIM (mid-session accounting update)."""
        return self._record_acr(
            "INTERIM",
            session_id=session_id,
            record_number=record_number,
            termination_cause=None,
            calling_party=calling_party,
            called_party=called_party,
            sip_method=sip_method,
            role_of_node=role_of_node,
            node_functionality=node_functionality,
            ims_charging_identifier=ims_charging_identifier,
            user_session_id=user_session_id,
            originating_ioi=originating_ioi,
            terminating_ioi=terminating_ioi,
            application_server=application_server,
            application_provided_called_party_address=application_provided_called_party_address,
            incoming_trunk_group_id=incoming_trunk_group_id,
            outgoing_trunk_group_id=outgoing_trunk_group_id,
            visited_network_id=visited_network_id,
            user_name=user_name,
            cause_code=cause_code,
            service_context_id=service_context_id,
            peer=peer,
        )

    def rf_acr_stop(
        self,
        session_id: str,
        record_number: int,
        *,
        termination_cause: int = 1,
        calling_party: Optional[str] = None,
        called_party: Optional[str] = None,
        sip_method: Optional[str] = None,
        role_of_node: Optional[str] = None,
        node_functionality: Optional[str] = None,
        ims_charging_identifier: Optional[str] = None,
        user_session_id: Optional[str] = None,
        originating_ioi: Optional[str] = None,
        terminating_ioi: Optional[str] = None,
        application_server: Optional[str] = None,
        application_provided_called_party_address: Optional[str] = None,
        incoming_trunk_group_id: Optional[str] = None,
        outgoing_trunk_group_id: Optional[str] = None,
        visited_network_id: Optional[str] = None,
        user_name: Optional[str] = None,
        cause_code: Optional[int] = None,
        service_context_id: Optional[str] = None,
        peer: Optional[str] = None,
    ) -> Optional[dict]:
        """Send Rf ACR-STOP. ``termination_cause`` per RFC 6733 §8.15
        (1=LOGOUT, 4=ADMINISTRATIVE, 5=LINK_BROKEN, 8=SESSION_TIMEOUT)."""
        return self._record_acr(
            "STOP",
            session_id=session_id,
            record_number=record_number,
            termination_cause=termination_cause,
            calling_party=calling_party,
            called_party=called_party,
            sip_method=sip_method,
            role_of_node=role_of_node,
            node_functionality=node_functionality,
            ims_charging_identifier=ims_charging_identifier,
            user_session_id=user_session_id,
            originating_ioi=originating_ioi,
            terminating_ioi=terminating_ioi,
            application_server=application_server,
            application_provided_called_party_address=application_provided_called_party_address,
            incoming_trunk_group_id=incoming_trunk_group_id,
            outgoing_trunk_group_id=outgoing_trunk_group_id,
            visited_network_id=visited_network_id,
            user_name=user_name,
            cause_code=cause_code,
            service_context_id=service_context_id,
            peer=peer,
        )

    def rf_acr_event(
        self,
        *,
        calling_party: Optional[str] = None,
        called_party: Optional[str] = None,
        sip_method: Optional[str] = None,
        role_of_node: Optional[str] = None,
        node_functionality: Optional[str] = None,
        ims_charging_identifier: Optional[str] = None,
        user_session_id: Optional[str] = None,
        originating_ioi: Optional[str] = None,
        terminating_ioi: Optional[str] = None,
        application_server: Optional[str] = None,
        application_provided_called_party_address: Optional[str] = None,
        incoming_trunk_group_id: Optional[str] = None,
        outgoing_trunk_group_id: Optional[str] = None,
        visited_network_id: Optional[str] = None,
        user_name: Optional[str] = None,
        cause_code: Optional[int] = None,
        service_context_id: Optional[str] = None,
        peer: Optional[str] = None,
    ) -> Optional[dict]:
        """Send Rf ACR-EVENT (one-shot accounting — REGISTER/MESSAGE)."""
        return self._record_acr(
            "EVENT",
            session_id=None,
            record_number=0,
            termination_cause=None,
            calling_party=calling_party,
            called_party=called_party,
            sip_method=sip_method,
            role_of_node=role_of_node,
            node_functionality=node_functionality,
            ims_charging_identifier=ims_charging_identifier,
            user_session_id=user_session_id,
            originating_ioi=originating_ioi,
            terminating_ioi=terminating_ioi,
            application_server=application_server,
            application_provided_called_party_address=application_provided_called_party_address,
            incoming_trunk_group_id=incoming_trunk_group_id,
            outgoing_trunk_group_id=outgoing_trunk_group_id,
            visited_network_id=visited_network_id,
            user_name=user_name,
            cause_code=cause_code,
            service_context_id=service_context_id,
            peer=peer,
        )

    def _record_acr(self, record_type: str, **kwargs) -> Optional[dict]:
        """Capture an ACR for assertions and synthesize an ACA dict."""
        if record_type in ("START", "EVENT"):
            self._rf_session_counter += 1
            session_id = f"mock-cdf;rf;sess;{self._rf_session_counter}"
        else:
            session_id = kwargs.get("session_id") or "mock-cdf;rf;sess;1"
        captured = {"record_type": record_type, "session_id": session_id, **kwargs}
        self._rf_acrs.append(captured)
        return {
            "result_code": self._default_rf_result_code,
            "session_id": session_id,
            "record_number": kwargs.get("record_number") or 0,
            "interim_interval": self._default_rf_interim_interval,
        }

    # Rf test helpers

    def set_rf_result_code(self, code: int) -> None:
        """Override the Result-Code returned by every Rf ACA (default 2001)."""
        self._default_rf_result_code = code

    def set_rf_interim_interval(self, interval_secs: Optional[int]) -> None:
        """Configure the ``Acct-Interim-Interval`` returned in ACA-START."""
        self._default_rf_interim_interval = interval_secs

    def captured_acrs(self) -> list[dict]:
        """Return all ACRs the script has emitted via ``rf_acr_*``.

        Returns a fresh copy on each call.  Useful for asserting on
        accounting flows in tests.
        """
        return [dict(entry) for entry in self._rf_acrs]

    def clear_captured_acrs(self) -> None:
        """Reset the captured-ACR list between tests."""
        self._rf_acrs.clear()

    # -- Ro online charging (Credit-Control, RFC 8506 / TS 32.299) --

    async def ro_ccr_initial(
        self,
        subscription_id: str,
        *,
        subscription_id_type: Optional[str] = None,
        service_context_id: Optional[str] = None,
        requested_seconds: Optional[int] = None,
        rating_group: Optional[int] = None,
        service_identifier: Optional[int] = None,
        calling_party: Optional[str] = None,
        called_party: Optional[str] = None,
        sip_method: Optional[str] = None,
        role_of_node: Optional[str] = None,
        node_functionality: Optional[str] = None,
        ims_charging_identifier: Optional[str] = None,
        user_session_id: Optional[str] = None,
        originating_ioi: Optional[str] = None,
        terminating_ioi: Optional[str] = None,
        application_server: Optional[str] = None,
        application_provided_called_party_address: Optional[str] = None,
        incoming_trunk_group_id: Optional[str] = None,
        outgoing_trunk_group_id: Optional[str] = None,
        visited_network_id: Optional[str] = None,
        cause_code: Optional[int] = None,
        peer: Optional[str] = None,
    ) -> Optional[dict]:
        """Send a Ro CCR-INITIAL and return the CCA dict.

        Returns ``{result_code, session_id, request_number, granted_time,
        validity_time, final_unit_action}``. For SCUR, thread the returned
        ``session_id`` through :meth:`ro_ccr_update` / :meth:`ro_ccr_terminate`.

        Example:
            answer = await diameter.ro_ccr_initial(
                "+310000000001", requested_seconds=30, rating_group=100,
                calling_party="sip:alice@ims", called_party="sip:bob@ims")
            if answer["result_code"] != 2001:
                call.reject(402, "Payment Required")
        """
        return self._record_ccr(
            "INITIAL",
            request_number=0,
            subscription_id=subscription_id,
            subscription_id_type=subscription_id_type,
            service_context_id=service_context_id,
            requested_seconds=requested_seconds,
            rating_group=rating_group,
            service_identifier=service_identifier,
            calling_party=calling_party,
            called_party=called_party,
            sip_method=sip_method,
            role_of_node=role_of_node,
            node_functionality=node_functionality,
            ims_charging_identifier=ims_charging_identifier,
            user_session_id=user_session_id,
            originating_ioi=originating_ioi,
            terminating_ioi=terminating_ioi,
            application_server=application_server,
            application_provided_called_party_address=application_provided_called_party_address,
            incoming_trunk_group_id=incoming_trunk_group_id,
            outgoing_trunk_group_id=outgoing_trunk_group_id,
            visited_network_id=visited_network_id,
            cause_code=cause_code,
            peer=peer,
        )

    async def ro_ccr_update(
        self,
        subscription_id: str,
        session_id: str,
        request_number: int,
        *,
        subscription_id_type: Optional[str] = None,
        service_context_id: Optional[str] = None,
        used_seconds: Optional[int] = None,
        requested_seconds: Optional[int] = None,
        rating_group: Optional[int] = None,
        service_identifier: Optional[int] = None,
        peer: Optional[str] = None,
    ) -> Optional[dict]:
        """Send a Ro CCR-UPDATE reporting usage and requesting the next quota."""
        return self._record_ccr(
            "UPDATE",
            session_id=session_id,
            request_number=request_number,
            subscription_id=subscription_id,
            subscription_id_type=subscription_id_type,
            service_context_id=service_context_id,
            used_seconds=used_seconds,
            requested_seconds=requested_seconds,
            rating_group=rating_group,
            service_identifier=service_identifier,
            peer=peer,
        )

    async def ro_ccr_terminate(
        self,
        subscription_id: str,
        session_id: str,
        request_number: int,
        *,
        subscription_id_type: Optional[str] = None,
        service_context_id: Optional[str] = None,
        used_seconds: Optional[int] = None,
        rating_group: Optional[int] = None,
        service_identifier: Optional[int] = None,
        peer: Optional[str] = None,
    ) -> Optional[dict]:
        """Send a Ro CCR-TERMINATION closing the session with final usage."""
        return self._record_ccr(
            "TERMINATION",
            session_id=session_id,
            request_number=request_number,
            subscription_id=subscription_id,
            subscription_id_type=subscription_id_type,
            service_context_id=service_context_id,
            used_seconds=used_seconds,
            rating_group=rating_group,
            service_identifier=service_identifier,
            peer=peer,
        )

    async def ro_ccr_event(
        self,
        subscription_id: str,
        *,
        subscription_id_type: Optional[str] = None,
        service_context_id: Optional[str] = None,
        requested_action: Optional[int] = None,
        calling_party: Optional[str] = None,
        called_party: Optional[str] = None,
        node_functionality: Optional[str] = None,
        user_session_id: Optional[str] = None,
        originator_address: Optional[str] = None,
        recipient_address: Optional[str] = None,
        sm_message_type: Optional[int] = None,
        sm_service_type: Optional[int] = None,
        sms_node: Optional[int] = None,
        data_coding_scheme: Optional[int] = None,
        peer: Optional[str] = None,
    ) -> Optional[dict]:
        """Send a one-shot Ro CCR-EVENT (IEC — SMS/RCS DIRECT_DEBITING).

        Example:
            answer = await diameter.ro_ccr_event(
                "+310000000001", service_context_id="32274@3gpp.org",
                originator_address="+310000000001",
                recipient_address="+310000000002", sm_message_type=0)
            if answer["result_code"] != 2001:
                request.reply(402, "Payment Required")  # no balance
        """
        return self._record_ccr(
            "EVENT",
            request_number=0,
            subscription_id=subscription_id,
            subscription_id_type=subscription_id_type,
            service_context_id=service_context_id,
            requested_action=(
                requested_action if requested_action is not None else 0
            ),
            calling_party=calling_party,
            called_party=called_party,
            node_functionality=node_functionality,
            user_session_id=user_session_id,
            originator_address=originator_address,
            recipient_address=recipient_address,
            sm_message_type=sm_message_type,
            sm_service_type=sm_service_type,
            sms_node=sms_node,
            data_coding_scheme=data_coding_scheme,
            peer=peer,
        )

    def _record_ccr(self, request_type: str, **kwargs) -> dict:
        """Capture a CCR for assertions and synthesize a CCA dict."""
        if request_type in ("INITIAL", "EVENT"):
            self._ro_session_counter += 1
            session_id = f"mock-ocs;ro;sess;{self._ro_session_counter}"
        else:
            session_id = kwargs.get("session_id") or "mock-ocs;ro;sess;1"
        captured = {"request_type": request_type, "session_id": session_id, **kwargs}
        self._ro_ccrs.append(captured)
        success = self._default_ro_result_code == 2001
        return {
            "result_code": self._default_ro_result_code,
            "session_id": session_id,
            "request_number": kwargs.get("request_number") or 0,
            "granted_time": self._default_ro_granted_time if success else None,
            "validity_time": self._default_ro_validity_time if success else None,
            "final_unit_action": self._default_ro_final_unit_action if success else None,
        }

    # Ro test helpers

    def set_ro_result_code(self, code: int) -> None:
        """Override the Result-Code returned by every Ro CCA (default 2001)."""
        self._default_ro_result_code = code

    def set_ro_granted_time(self, seconds: Optional[int]) -> None:
        """Configure the granted CC-Time (seconds) returned in a successful CCA."""
        self._default_ro_granted_time = seconds

    def set_ro_final_unit_action(self, action: Optional[int]) -> None:
        """Configure the Final-Unit-Action (0=TERMINATE) returned in the CCA."""
        self._default_ro_final_unit_action = action

    def captured_ccrs(self) -> list[dict]:
        """Return all CCRs the script has emitted via ``ro_ccr_*`` (fresh copy)."""
        return [dict(entry) for entry in self._ro_ccrs]

    def clear_captured_ccrs(self) -> None:
        """Reset the captured-CCR list between tests."""
        self._ro_ccrs.clear()


    # -- Server-mode (accept inbound + dispatch to Python) --

    @staticmethod
    def on_inbound_cer(fn: Any) -> Any:
        """Register the server-mode CER identity callback.

        Called for an already-authenticated peer (both Rust auth gates have
        passed) with ``(peer_addr, peer_name, asserted_origin_host)``. Return
        ``(origin_host, origin_realm)`` to accept, or ``None`` to reject.

        Example::

            @diameter.on_inbound_cer
            def cer_received(peer_addr, peer_name, asserted_origin_host):
                identity = diameter.config["tenants"]["default"]["identity"]
                return identity["origin_host"], identity["origin_realm"]
        """
        return fn

    @staticmethod
    def on_request(arg: Any = None) -> Any:
        """Register the server-mode inbound-request dispatcher.

        Called for inbound requests (R-bit set). Return ``req.reject(code)``,
        ``await req.forward_to(peer, ...)``, ``req.answer(code)``, or ``None``
        (→ DIAMETER_UNABLE_TO_DELIVER, 3002).

        An optional command filter scopes the handler (mirrors
        ``@proxy.on_request("INVITE")``): bare ``@diameter.on_request`` (all),
        ``@diameter.on_request("ULR")``, ``"ULR|AIR"``, or app-qualified
        ``"S6a:ULR"``. The mock treats it as an identity decorator either way.

        Example::

            @diameter.on_request("S6a:ULR")
            async def update_location(req):
                return req.answer(2001)
        """
        # Bare form: @diameter.on_request  (arg is the handler).
        if callable(arg):
            return arg
        # Filtered form: @diameter.on_request("S6a:ULR") → returns a decorator.
        def _decorator(fn: Any) -> Any:
            return fn
        return _decorator

    @staticmethod
    def on_reply(fn: Any) -> Any:
        """Register the server-mode answer-rewrite hook.

        Called with ``(req, answer)`` on the answer an ``on_request`` handler
        produced — relayed via ``forward_to`` or built by ``answer``/``reject``
        — just before it goes back upstream. A central place to rewrite answer
        AVPs for every reply (topology hiding, Origin-Host/Result-Code mapping).
        Mutate ``answer`` in place; the return value is ignored.
        """
        return fn

    @staticmethod
    def on_request_completed(fn: Any) -> Any:
        """Register the server-mode post-answer hook.

        Called after the answer is sent upstream with
        ``(req, answer, latency_us)`` — typically to emit an event.
        """
        return fn

    def peer_pool(self, target: Any, tenant: str = "default") -> "MockPeerPool":
        """Build a mock backend peer pool. ``target`` is a peer name or list of
        names; ``tenant`` is an optional scope label (defaults to "default" —
        single-domain servers leave it unset). Register backends with
        :meth:`add_peer(connected=True)`."""
        names = [target] if isinstance(target, str) else list(target)
        return MockPeerPool(self, tenant, names)

    @staticmethod
    def ip_in_cidr(addr: str, cidr: str) -> bool:
        """Whether ``addr`` falls within ``cidr`` (mirrors the Rust helper)."""
        import ipaddress

        return ipaddress.ip_address(addr) in ipaddress.ip_network(cidr, strict=False)

    @staticmethod
    def fnmatch(value: str, pattern: str) -> bool:
        """Shell-style glob match (``*``/``?``)."""
        import fnmatch as _fnmatch

        return _fnmatch.fnmatchcase(value, pattern)

    @staticmethod
    def now_us() -> int:
        """Wall-clock microseconds since the Unix epoch."""
        import time

        return int(time.time() * 1_000_000)

    @property
    def config(self) -> dict:
        """Read-only view of the parsed ``diameter`` config (tenants/listen).

        Set it in tests with ``diameter.set_config({...})``."""
        return getattr(self, "_diameter_config", {})

    def set_config(self, config: dict) -> None:
        """Test helper: set the dict returned by :attr:`config`."""
        self._diameter_config = dict(config)

    @property
    def event_sink(self) -> "MockEventSink":
        """The generic event sink (``diameter.event_sink.emit(row)``)."""
        if not hasattr(self, "_event_sink"):
            self._event_sink = MockEventSink()
        return self._event_sink

    # -- S6a (TS 29.272) — MME ↔ HSS for LTE attach/auth --

    def s6a_air(self, imsi: str, visited_plmn_id: bytes, num_vectors: int = 1,
                immediate_response_preferred: bool = True,
                resync_info: Optional[bytes] = None,
                peer: Optional[str] = None) -> Optional[dict]:
        """Mock Authentication-Information. Returns canned E-UTRAN vectors;
        configure with :meth:`set_air_response`."""
        if getattr(self, "_air_response", None) is not None:
            return dict(self._air_response)
        return {
            "result_code": 2001,
            "vectors": [
                {
                    "rand": b"\x11" * 16,
                    "xres": b"\x22" * 8,
                    "autn": b"\x33" * 16,
                    "kasme": b"\x44" * 32,
                }
                for _ in range(num_vectors)
            ],
        }

    def set_air_response(self, *, result_code: int = 2001,
                          vectors: Optional[list] = None) -> None:
        self._air_response = {"result_code": result_code, "vectors": vectors or []}

    def s6a_ulr(self, imsi: str, visited_plmn_id: bytes, rat_type: int = 1004,
                ulr_flags: int = 0, peer: Optional[str] = None) -> Optional[dict]:
        """Mock Update-Location. Returns a 2001 with subscription data present."""
        return getattr(self, "_ulr_response", None) or {
            "result_code": 2001,
            "ula_flags": 0,
            "has_subscription_data": True,
        }

    def set_ulr_response(self, *, result_code: int = 2001,
                          ula_flags: Optional[int] = 0,
                          has_subscription_data: bool = True) -> None:
        self._ulr_response = {
            "result_code": result_code,
            "ula_flags": ula_flags,
            "has_subscription_data": has_subscription_data,
        }

    def s6a_purge_ue(self, imsi: str, pur_flags: Optional[int] = None,
                     peer: Optional[str] = None) -> Optional[dict]:
        """Mock Purge-UE. Returns a 2001."""
        return {"result_code": 2001}

    # -- S6c (TS 29.336) --

    def s6c_srr(self, msisdn: str, sc_address: str,
                sm_rp_mti: Optional[int] = None) -> Optional[dict]:
        """Mock Send-Routing-Info-for-SM. Configure responses via
        :meth:`set_srr_response`; default is a successful answer with
        an empty served-node (test scripts can detect the unset case)."""
        if not hasattr(self, "_srr_responses"):
            self._srr_responses = {}
        if msisdn in self._srr_responses:
            return dict(self._srr_responses[msisdn])
        return {
            "result_code": 2001,
            "experimental_result_code": None,
            "user_name": None,
            "sgsn_number": None,
            "mme_number_for_mt_sms": None,
        }

    def set_srr_response(self, msisdn: str, *, result_code: int = 2001,
                          user_name: Optional[str] = None,
                          sgsn_number: Optional[str] = None,
                          mme_number_for_mt_sms: Optional[str] = None,
                          experimental_result_code: Optional[int] = None) -> None:
        if not hasattr(self, "_srr_responses"):
            self._srr_responses = {}
        self._srr_responses[msisdn] = {
            "result_code": result_code,
            "experimental_result_code": experimental_result_code,
            "user_name": user_name,
            "sgsn_number": sgsn_number,
            "mme_number_for_mt_sms": mme_number_for_mt_sms,
        }

    def s6c_rsr(self, user_name: str, sc_address: str,
                delivery_outcome: int) -> Optional[dict]:
        """Mock Report-SM-Delivery-Status. Records the call on
        ``self.rsrs`` for assertions and returns a 2001."""
        if not hasattr(self, "rsrs"):
            self.rsrs = []
        self.rsrs.append({
            "user_name": user_name,
            "sc_address": sc_address,
            "delivery_outcome": delivery_outcome,
        })
        return {
            "result_code": 2001,
            "experimental_result_code": None,
            "user_name": user_name,
        }

    # -- SGd (TS 29.338) --

    def sgd_tfr(self, user_name: str, sc_address: str, sm_rp_ui: bytes,
                smsmi_correlation_id: Optional[str] = None,
                sm_rp_mti: Optional[int] = None) -> Optional[dict]:
        """Mock MT-Forward-Short-Message. Records the TPDU on ``self.tfrs``
        for assertions; returns 2001 unless overridden via
        :meth:`set_tfr_response`."""
        if not hasattr(self, "tfrs"):
            self.tfrs = []
        self.tfrs.append({
            "user_name": user_name,
            "sc_address": sc_address,
            "sm_rp_ui": bytes(sm_rp_ui),
            "smsmi_correlation_id": smsmi_correlation_id,
            "sm_rp_mti": sm_rp_mti,
        })
        if not hasattr(self, "_tfr_responses"):
            self._tfr_responses = {}
        if user_name in self._tfr_responses:
            return dict(self._tfr_responses[user_name])
        return {
            "result_code": 2001,
            "experimental_result_code": None,
            "absent_user_diagnostic": None,
        }

    def set_tfr_response(self, user_name: str, *, result_code: int = 2001,
                         absent_user_diagnostic: Optional[int] = None,
                         experimental_result_code: Optional[int] = None) -> None:
        if not hasattr(self, "_tfr_responses"):
            self._tfr_responses = {}
        self._tfr_responses[user_name] = {
            "result_code": result_code,
            "experimental_result_code": experimental_result_code,
            "absent_user_diagnostic": absent_user_diagnostic,
        }

    # -- Generic spec-name API (matches Rust `diameter.send_request` /
    # `@diameter.on_command`) --

    def send_request(self, command: str, application: str,
                     peer: Optional[str] = None,
                     timeout_ms: int = 10_000,
                     **avps: Any) -> Optional[dict]:
        """Generic Diameter request by spec name.

        Records every call on ``self.generic_requests`` for assertions.
        Returns a default 2001-success answer unless overridden via
        :meth:`set_generic_response`.
        """
        if not hasattr(self, "generic_requests"):
            self.generic_requests = []
        self.generic_requests.append({
            "command": command,
            "application": application,
            "peer": peer,
            "timeout_ms": timeout_ms,
            "avps": dict(avps),
        })
        if not hasattr(self, "_generic_responses"):
            self._generic_responses = {}
        key = (command, application)
        if key in self._generic_responses:
            return dict(self._generic_responses[key])
        return {"result_code": 2001}

    def set_generic_response(self, command: str, application: str,
                              **answer: Any) -> None:
        """Configure a mock answer for ``send_request(command, application, ...)``."""
        if not hasattr(self, "_generic_responses"):
            self._generic_responses = {}
        self._generic_responses[(command, application)] = answer


    def set_udr_response(self, public_identity: str,
                         result_code: int = 2001,
                         user_data: Optional[str] = None) -> None:
        """Configure a mock UDA response for a specific user (test helper)."""
        self._udr_responses[public_identity] = {
            "result_code": result_code,
            "user_data": user_data,
        }

    def set_pur_response(self, public_identity: str,
                         result_code: int = 2001) -> None:
        """Configure a mock PUA response for a specific user (test helper)."""
        self._pur_responses[public_identity] = {"result_code": result_code}

    def set_snr_response(self, public_identity: str,
                         result_code: int = 2001) -> None:
        """Configure a mock SNA response for a specific user (test helper)."""
        self._snr_responses[public_identity] = {"result_code": result_code}

    def clear(self) -> None:
        """Reset all mock peers and responses (test helper)."""
        self._peers.clear()
        self._uar_responses.clear()
        self._sar_responses.clear()
        self._lir_responses.clear()
        self._aar_responses.clear()
        self._udr_responses.clear()
        self._pur_responses.clear()
        self._snr_responses.clear()
        self._default_server_name = None
        self._default_rx_result_code = 2001
        self._default_sh_result_code = 2001
        self._default_rf_result_code = 2001
        self._default_rf_interim_interval = None
        self._rf_session_counter = 0
        self._rf_acrs.clear()
        self._default_ro_result_code = 2001
        self._default_ro_granted_time = 30
        self._default_ro_validity_time = None
        self._default_ro_final_unit_action = None
        self._ro_session_counter = 0
        self._ro_ccrs.clear()


# ---------------------------------------------------------------------------
# Presence namespace
# ---------------------------------------------------------------------------


def _is_terminated_subscription_state(subscription_state: str) -> bool:
    """Mirror of the production helper — recognizes RFC 6665 §4.1.3
    ``terminated`` and ``terminated;reason=...`` Subscription-State values.
    """
    trimmed = subscription_state.lstrip()
    if not trimmed.startswith("terminated"):
        return False
    rest = trimmed[len("terminated"):]
    return rest == "" or rest.startswith(";") or rest[:1].isspace()


class MockPresence:
    """Mock ``presence`` namespace — SIP presence publish/subscribe for testing.

    Manages presence documents and subscriptions in-memory.

    Example::

        from siphon_sdk import mock_module
        mock_module.install()

        from siphon import presence

        etag = presence.publish("sip:alice@example.com", "<presence/>", expires=3600)
        doc = presence.lookup("sip:alice@example.com")
        assert doc == "<presence/>"

        sub_id = presence.subscribe("sip:bob@example.com", "sip:alice@example.com")
        watchers = presence.subscribers("sip:alice@example.com")
        assert len(watchers) == 1

    Test helper::

        from siphon_sdk.mock_module import get_presence
        p = get_presence()
        p.clear()
    """

    def __init__(self) -> None:
        self._documents: dict[str, str] = {}  # entity -> pidf_xml
        self._subscriptions: dict[str, dict] = {}  # id -> {subscriber, resource, event}
        self._notifications: list[dict[str, Any]] = []  # sent NOTIFYs
        self._next_sub_id: int = 0

    def publish(self, entity: str, pidf_xml: str, expires: int = 3600) -> str:
        """Publish a presence document for a presentity.

        Args:
            entity: Presentity URI (e.g. ``"sip:alice@example.com"``).
            pidf_xml: PIDF XML body string.
            expires: Document expiry in seconds (default: 3600).

        Returns:
            An etag string assigned to the published document.

        Example::

            etag = presence.publish("sip:alice@example.com",
                                     "<presence><tuple><status><basic>open</basic></status></tuple></presence>")
        """
        self._documents[entity] = pidf_xml
        return f"etag-{hash(entity + pidf_xml) & 0xFFFFFFFF:08x}"

    def lookup(self, entity: str) -> Optional[str]:
        """Look up the current presence document for a URI.

        Args:
            entity: Presentity URI to look up.

        Returns:
            PIDF XML string, or ``None`` if not found.
        """
        return self._documents.get(entity)

    def subscribe(self, subscriber: str, resource: str,
                  event: str = "presence", expires: int = 3600) -> str:
        """Subscribe to presence for a resource.

        Creates a new subscription and returns its ID.

        Args:
            subscriber: Watcher URI (e.g. ``"sip:bob@example.com"``).
            resource: Presentity URI to watch.
            event: Event package name (default: ``"presence"``).
            expires: Subscription duration in seconds (default: 3600).

        Returns:
            Subscription ID string.
        """
        sub_id = f"sub-{self._next_sub_id}"
        self._next_sub_id += 1
        self._subscriptions[sub_id] = {
            "subscriber": subscriber,
            "resource": resource,
            "event": event,
        }
        return sub_id

    def subscribe_dialog(self, subscriber: str, resource: str,
                         event: str = "reg", expires: int = 3600,
                         call_id: str = "", from_tag: str = "",
                         to_tag: str = "", route_set: Optional[list] = None) -> str:
        """Create a subscription with dialog state for in-dialog NOTIFY.

        Args:
            subscriber: Watcher URI (Contact from the SUBSCRIBE).
            resource: Presentity URI being watched.
            event: Event package name.
            expires: Subscription duration in seconds.
            call_id: Call-ID from the SUBSCRIBE dialog.
            from_tag: From-tag from the SUBSCRIBE.
            to_tag: To-tag from the SUBSCRIBE.
            route_set: Route headers from Record-Route.

        Returns:
            Subscription ID string.
        """
        sub_id = f"sub-{self._next_sub_id}"
        self._next_sub_id += 1
        self._subscriptions[sub_id] = {
            "subscriber": subscriber,
            "resource": resource,
            "event": event,
            "call_id": call_id,
            "from_tag": from_tag,
            "to_tag": to_tag,
            "route_set": route_set or [],
        }
        return sub_id

    def unsubscribe(self, subscription_id: str) -> bool:
        """Unsubscribe by subscription ID.

        Args:
            subscription_id: The subscription ID returned by :meth:`subscribe`.

        Returns:
            ``True`` if the subscription was found and removed.
        """
        return self._subscriptions.pop(subscription_id, None) is not None

    def refresh(self, subscription_id: str, expires: int) -> bool:
        """Refresh a subscription's expiry (RFC 6665 §4.4.1 re-SUBSCRIBE).

        Resets the subscription timer to ``expires`` seconds, keeping the dialog.
        Pair with :meth:`find_by_dialog` to resolve the id from an in-dialog
        SUBSCRIBE before refreshing.

        Args:
            subscription_id: The subscription ID (from ``subscribe*`` or
                :meth:`find_by_dialog`).
            expires: New subscription duration in seconds.

        Returns:
            ``True`` if the subscription was found and refreshed.
        """
        sub = self._subscriptions.get(subscription_id)
        if sub is None:
            return False
        sub["expires"] = expires
        return True

    def find_by_dialog(self, call_id: str, from_tag: str) -> Optional[str]:
        """Resolve a subscription id from its dialog ``(Call-ID, From-tag)``.

        An in-dialog SUBSCRIBE (a refresh, or an un-SUBSCRIBE with ``Expires: 0``)
        carries the dialog's Call-ID and the subscriber's From-tag but not the
        original subscription id. This maps that pair back so a notifier
        (e.g. an S-CSCF handling reg-event) can :meth:`refresh` or
        :meth:`unsubscribe` the right dialog. Only subscriptions created with
        :meth:`subscribe_dialog` (which store dialog state) are findable.

        Args:
            call_id: Call-ID of the in-dialog SUBSCRIBE.
            from_tag: From-tag of the in-dialog SUBSCRIBE (subscriber's tag).

        Returns:
            The subscription ID string, or ``None`` if no dialog matches.
        """
        for sub_id, value in self._subscriptions.items():
            if value.get("call_id") == call_id and value.get("from_tag") == from_tag:
                return sub_id
        return None

    def subscribers(self, resource: str) -> list[dict]:
        """List subscribers (watchers) for a resource.

        Args:
            resource: Presentity URI to query.

        Returns:
            List of dicts with keys: ``id``, ``subscriber``, ``event``.
        """
        return [
            {"id": sub_id, **value}
            for sub_id, value in self._subscriptions.items()
            if value["resource"] == resource
        ]

    def subscription_count(self) -> int:
        """Get the total number of subscriptions."""
        return len(self._subscriptions)

    def document_count(self) -> int:
        """Get the total number of entities with published documents."""
        return len(self._documents)

    def notify(self, subscription_id: str, body: Optional[str] = None,
               content_type: Optional[str] = None,
               subscription_state: str = "active") -> None:
        """Send an in-dialog NOTIFY for a subscription.

        In the mock, this records the notification for test assertions.

        When ``subscription_state`` indicates a terminated subscription
        (RFC 6665 §4.1.3 — bare ``"terminated"`` or
        ``"terminated;reason=..."``) the subscription is also removed from
        the store, mirroring the production auto-GC behavior.

        Args:
            subscription_id: The subscription ID from ``subscribe_dialog()``.
            body: Optional body string (reginfo XML, PIDF XML, etc.).
            content_type: Content-Type of the body.
            subscription_state: Subscription-State header value (default ``"active"``).
        """
        self._notifications.append({
            "subscription_id": subscription_id,
            "body": body,
            "content_type": content_type,
            "subscription_state": subscription_state,
        })
        if _is_terminated_subscription_state(subscription_state):
            self._subscriptions.pop(subscription_id, None)

    def terminate(self, subscription_id: str, reason: Optional[str] = None,
                  body: Optional[str] = None,
                  content_type: Optional[str] = None) -> bool:
        """Send a terminating NOTIFY and remove the subscription (RFC 6665 §4.4.1).

        Sends an in-dialog NOTIFY with
        ``Subscription-State: terminated;reason=<reason>``, then removes
        the subscription's dialog state from the store.  Idempotent: a
        second call with the same ``subscription_id`` returns ``False``.

        Args:
            subscription_id: The subscription ID from ``subscribe_dialog()``.
            reason: Termination reason per RFC 6665 §4.2.2 — one of
                ``"deactivated"``, ``"probation"``, ``"rejected"``,
                ``"timeout"``, ``"giveup"``, ``"noresource"``,
                ``"invariant"``.  Defaults to ``"noresource"``.
            body: Optional final body.
            content_type: Content-Type of the body.

        Returns:
            ``True`` if the subscription existed and the NOTIFY was
            recorded; ``False`` if the ``subscription_id`` was unknown.

        Example::

            sub_id = presence.subscribe_dialog(...)
            ...
            presence.terminate(sub_id, reason="timeout")
        """
        if subscription_id not in self._subscriptions:
            return False
        reason_str = reason or "noresource"
        self.notify(
            subscription_id,
            body=body,
            content_type=content_type,
            subscription_state=f"terminated;reason={reason_str}",
        )
        return True

    @property
    def notifications(self) -> list:
        """List of NOTIFY messages sent (for test assertions)."""
        return self._notifications

    def parse_reginfo(self, xml: str) -> dict:
        """Parse an RFC 3680 ``application/reginfo+xml`` body for tests.

        Mirrors the Rust ``presence.parse_reginfo`` shape — returns a
        dict ``{"version": int, "state": "full"|"partial",
        "registrations": [...]}`` so tests asserting against script logic
        can use the same dict layout the production binary returns.
        """
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(xml)
        except ET.ParseError as error:
            raise ValueError(f"invalid reginfo: {error}") from error

        # Strip {namespace} from the tag for comparison.
        def local_name(tag: str) -> str:
            return tag.split("}")[-1] if "}" in tag else tag

        if local_name(root.tag) != "reginfo":
            raise ValueError("invalid reginfo: missing root <reginfo>")

        try:
            version = int(root.get("version", ""))
        except ValueError as error:
            raise ValueError(f"invalid reginfo version: {error}") from error
        state = root.get("state", "full")
        if state not in ("full", "partial"):
            raise ValueError(f"invalid reginfo state: {state!r}")

        registrations = []
        for reg in root:
            if local_name(reg.tag) != "registration":
                continue
            reg_state = reg.get("state", "active")
            contacts = []
            for contact in reg:
                if local_name(contact.tag) != "contact":
                    continue
                # URI may be on the <contact> directly, or inside <uri>.
                uri = contact.get("uri")
                if uri is None:
                    for child in contact:
                        if local_name(child.tag) == "uri":
                            uri = (child.text or "").strip()
                            break
                expires = contact.get("expires")
                q = contact.get("q")
                contacts.append({
                    "uri": uri or "",
                    "state": contact.get("state", "active"),
                    "event": contact.get("event", "registered"),
                    "expires": int(expires) if expires else None,
                    "q": float(q) if q else None,
                })
            registrations.append({
                "aor": reg.get("aor", ""),
                "id": reg.get("id", ""),
                "state": reg_state,
                "contacts": contacts,
            })

        return {
            "version": version,
            "state": state,
            "registrations": registrations,
        }

    def clear(self) -> None:
        """Reset all documents, subscriptions, and notifications (test helper)."""
        self._documents.clear()
        self._subscriptions.clear()
        self._notifications.clear()
        self._next_sub_id = 0


class MockSrs:
    """Mock ``srs`` namespace — Session Recording Server hooks for testing.

    Pre-configure accept/reject behavior::

        from siphon_sdk.mock_module import get_srs
        srs = get_srs()
        srs.accept_all = False          # reject all recordings

    Register handlers as in production::

        from siphon import srs

        @srs.on_invite
        async def on_recording(metadata):
            return True

        @srs.on_session_end
        async def on_recording_end(session):
            pass

    Inspect events after test::

        srs = get_srs()
        assert len(srs.sessions) == 1
    """

    def __init__(self) -> None:
        self._accept_all: bool = True
        self._sessions: list[dict[str, Any]] = []
        self._invite_events: list[dict[str, Any]] = []

    @property
    def accept_all(self) -> bool:
        """Whether mock auto-accepts all recordings (default ``True``)."""
        return self._accept_all

    @accept_all.setter
    def accept_all(self, value: bool) -> None:
        self._accept_all = value

    @property
    def sessions(self) -> list[dict[str, Any]]:
        """List of completed recording sessions (for test assertions)."""
        return self._sessions

    @property
    def invite_events(self) -> list[dict[str, Any]]:
        """List of on_invite calls received (for test assertions)."""
        return self._invite_events

    def on_invite(self, fn: Any) -> Any:
        """Register handler for incoming SIPREC INVITE (recording request).

        The handler receives ``(metadata,)`` where metadata is a
        :class:`~siphon_sdk.srs.RecordingMetadata` object.

        Return ``True`` to accept the recording, ``False`` to reject (403).

        Example::

            @srs.on_invite
            async def on_recording(metadata):
                log.info(f"Recording: {metadata.session_id}")
                return True
        """
        _registry.register("srs.on_invite", None, fn, asyncio.iscoroutinefunction(fn))
        return fn

    def on_session_end(self, fn: Any) -> Any:
        """Register handler for recording session completion.

        The handler receives ``(session,)`` where session is a
        :class:`~siphon_sdk.srs.SrsSession` object.

        Example::

            @srs.on_session_end
            async def on_recording_end(session):
                log.info(f"Recording {session.session_id} done")
        """
        _registry.register("srs.on_session_end", None, fn, asyncio.iscoroutinefunction(fn))
        return fn

    def record_invite(self, session_id: str, participants: list[str] | None = None) -> None:
        """Test helper: simulate an inbound SIPREC INVITE event.

        Args:
            session_id: Recording session identifier.
            participants: List of participant AoRs.
        """
        self._invite_events.append({
            "session_id": session_id,
            "participants": participants or [],
        })

    def record_session_end(
        self,
        session_id: str,
        recording_call_id: str = "",
        duration_secs: int = 0,
        recording_dir: str | None = None,
    ) -> None:
        """Test helper: simulate a completed recording session.

        Args:
            session_id: Recording session identifier.
            recording_call_id: Call-ID of the SIPREC dialog.
            duration_secs: Recording duration in seconds.
            recording_dir: Path where recordings were written.
        """
        self._sessions.append({
            "session_id": session_id,
            "recording_call_id": recording_call_id,
            "duration_secs": duration_secs,
            "recording_dir": recording_dir,
        })

    def clear(self) -> None:
        """Reset all mock state (test helper)."""
        self._accept_all = True
        self._sessions.clear()
        self._invite_events.clear()


# ---------------------------------------------------------------------------
# Timer namespace — periodic callbacks (like OpenSIPS timer_route)
# ---------------------------------------------------------------------------

class MockTimer:
    """Mock ``timer`` namespace for periodic timer callbacks.

    Timer handlers run on a Tokio interval in the Rust runtime.
    They receive no SIP request/call context but can use all other
    namespaces (registrar, cache, gateway, log, etc.).

    Example::

        from siphon import timer

        @timer.every(seconds=30)
        async def health_check():
            for dest in gateway.list("carriers"):
                if not dest.healthy:
                    log.warn(f"Gateway {dest.uri} is down")

        @timer.every(seconds=300, name="stats_push", jitter=10)
        def push_stats():
            log.info("pushing stats")
    """

    def __init__(self) -> None:
        # Scheduled one-shot timers: key -> (delay_ms, handler)
        self._one_shots: dict[str, tuple[int, Callable]] = {}

    def every(self, seconds: int, name: str | None = None,
              jitter: int = 0) -> Callable:
        """Register a periodic timer callback.

        Args:
            seconds: Interval between invocations.
            name: Optional name for logging (defaults to function name).
            jitter: Random jitter in seconds added to each interval (default 0).

        Returns:
            Decorator that registers the function as a timer handler.

        Example::

            @timer.every(seconds=60)
            def cleanup():
                presence.expire_stale()
        """
        def decorator(fn: Callable) -> Callable:
            timer_name = name if name is not None else fn.__name__
            is_async = asyncio.iscoroutinefunction(fn)
            metadata = {"seconds": seconds, "name": timer_name, "jitter": jitter}
            _registry.register("timer.every", None, fn, is_async, metadata)
            return fn
        return decorator

    def set(self, key: str, delay_ms: int, handler: Callable) -> "MockTimerHandle":
        """Schedule a one-shot callback under ``key`` to fire after ``delay_ms``.

        Setting the same key twice cancels the previous timer and reschedules.

        In the mock, no tokio runtime fires the callback — tests call
        :meth:`fire` with the key to invoke the handler manually.
        """
        self._one_shots[key] = (delay_ms, handler)
        return MockTimerHandle(self, key)

    def cancel(self, key: str) -> bool:
        """Cancel the one-shot timer registered under ``key``.  Returns
        ``True`` if a timer was cancelled, ``False`` if no timer matched."""
        return self._one_shots.pop(key, None) is not None

    def fire(self, key: str) -> None:
        """Test helper: fire the one-shot timer registered under ``key``.

        Raises ``KeyError`` if no timer matches.  Pops the timer so a
        subsequent fire for the same key raises.
        """
        delay_ms, handler = self._one_shots.pop(key)
        _ = delay_ms  # delay is cosmetic in the mock
        handler(key)

    @property
    def scheduled(self) -> dict[str, int]:
        """Map of active one-shot timer keys → scheduled delay (ms)."""
        return {key: delay for key, (delay, _) in self._one_shots.items()}


class MockTimerHandle:
    """Mock of the ``TimerHandle`` returned by ``timer.set()``."""

    def __init__(self, timer: "MockTimer", key: str) -> None:
        self._timer = timer
        self._key = key

    @property
    def key(self) -> str:
        return self._key

    def cancel(self) -> bool:
        return self._timer.cancel(self._key)

    def __repr__(self) -> str:
        return f"MockTimerHandle(key={self._key!r})"


# ---------------------------------------------------------------------------
# Module installation
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# LCR namespace — B2BUA-only Least-Cost Routing (await lcr.route(call))
# ---------------------------------------------------------------------------

class MockLcrDecision:
    """Mock of the decision returned by ``await lcr.route(call)``.

    Mirrors the Rust ``LcrDecision``: ``.routes`` is a ``list[Route]`` and
    ``.reject`` is a ``{"code": int, "reason": str}`` dict or ``None``.
    """

    def __init__(self, routes=None, reject=None) -> None:
        self.routes = list(routes) if routes else []
        self.reject = reject

    def __repr__(self) -> str:
        return f"LcrDecision(routes={len(self.routes)}, reject={self.reject is not None})"


class MockLcr:
    """Mock ``lcr`` namespace — B2BUA-only Least-Cost Routing.

    Configure the canned decision the next ``await lcr.route(call)`` returns::

        lcr = mock_module.get_lcr()
        lcr.set_routes([Route(carrier_id="a", gateway_group="pool-a", rate=0.004)])
        # or: lcr.set_reject(503, "No Route")   # API-side block
        # or: lcr.set_unavailable()             # route() returns None

    Assert on what the script asked via ``lcr.queries``.
    """

    def __init__(self) -> None:
        self._routes: list = []
        self._reject: Optional[dict] = None
        self._unavailable = False
        self.queries: list = []

    def set_routes(self, routes) -> None:
        """Canned ordered carrier routes for subsequent ``route()`` calls."""
        self._routes = list(routes)
        self._reject = None
        self._unavailable = False

    def set_reject(self, code: int, reason: str) -> None:
        """Make ``route()`` return a decision carrying an API-side reject."""
        self._reject = {"code": int(code), "reason": reason}
        self._routes = []
        self._unavailable = False

    def set_unavailable(self) -> None:
        """Make ``route()`` return ``None`` (API unreachable, no fallback)."""
        self._unavailable = True

    def clear(self) -> None:
        self._routes = []
        self._reject = None
        self._unavailable = False
        self.queries = []

    async def route(self, call, trunk_group=None, attributes=None):
        """Return the configured decision (or ``None``), recording the query."""
        try:
            dialed = call.ruri.user
        except AttributeError:
            dialed = None
        self.queries.append({
            "dialed_number": dialed,
            "trunk_group": trunk_group,
            "attributes": dict(attributes or {}),
        })
        if self._unavailable:
            return None
        return MockLcrDecision(self._routes, self._reject)


# Singleton instances
_proxy = MockProxy()
_b2bua = MockB2bua()
_registrar = MockRegistrar()
_auth = MockAuth()
_log = MockLog()
_cache = MockCache()
_rtpengine = MockRtpEngine()
_gateway = MockGateway()
_cdr = MockCdr()
_li = MockLi()
_registration = MockRegistration()
_diameter = MockDiameter()
_presence = MockPresence()
_srs = MockSrs()
_timer = MockTimer()
_lcr = MockLcr()


# ---------------------------------------------------------------------------
# Metrics namespace — custom Prometheus metrics
# ---------------------------------------------------------------------------

class _MockMetricChild:
    """Labeled child for mock counter/gauge/histogram.

    Tracks a single value for testing assertions.
    """

    def __init__(self) -> None:
        self.value: float = 0.0

    def inc(self, n: float = 1.0) -> None:
        """Increment (counter or gauge)."""
        self.value += n

    def dec(self, n: float = 1.0) -> None:
        """Decrement (gauge only)."""
        self.value -= n

    def set(self, v: float) -> None:
        """Set absolute value (gauge only)."""
        self.value = v

    def observe(self, v: float) -> None:
        """Observe a value (histogram only). Tracks sum for testing."""
        self.value += v


class MockCounter:
    """Mock Prometheus counter.

    Usage::

        from siphon import metrics

        c = metrics.counter("my_total", "My counter")
        c.inc()
        c.inc(5)

    With labels::

        c = metrics.counter("my_total", "My counter", labels=["method"])
        c.labels(method="INVITE").inc()
    """

    def __init__(self, name: str, help: str,
                 labels: "list[str] | None" = None) -> None:
        self.name = name
        self.help = help
        self.label_names: list[str] = labels or []
        self._value: float = 0.0
        self._children: dict[tuple, _MockMetricChild] = {}

    def inc(self, n: float = 1.0) -> None:
        """Increment the counter (no-label metrics only)."""
        self._value += n

    def labels(self, **kwargs: str) -> _MockMetricChild:
        """Return a labeled child counter."""
        key = tuple(kwargs.get(name, "") for name in self.label_names)
        if key not in self._children:
            self._children[key] = _MockMetricChild()
        return self._children[key]

    def clear(self) -> None:
        self._value = 0.0
        self._children.clear()


class MockGauge:
    """Mock Prometheus gauge.

    Usage::

        from siphon import metrics

        g = metrics.gauge("my_active", "Active things")
        g.inc()
        g.dec()
        g.set(42)
    """

    def __init__(self, name: str, help: str,
                 labels: "list[str] | None" = None) -> None:
        self.name = name
        self.help = help
        self.label_names: list[str] = labels or []
        self._value: float = 0.0
        self._children: dict[tuple, _MockMetricChild] = {}

    def inc(self, n: float = 1.0) -> None:
        """Increment the gauge (no-label metrics only)."""
        self._value += n

    def dec(self, n: float = 1.0) -> None:
        """Decrement the gauge (no-label metrics only)."""
        self._value -= n

    def set(self, v: float) -> None:
        """Set absolute value (no-label metrics only)."""
        self._value = v

    def labels(self, **kwargs: str) -> _MockMetricChild:
        """Return a labeled child gauge."""
        key = tuple(kwargs.get(name, "") for name in self.label_names)
        if key not in self._children:
            self._children[key] = _MockMetricChild()
        return self._children[key]

    def clear(self) -> None:
        self._value = 0.0
        self._children.clear()


class MockHistogram:
    """Mock Prometheus histogram.

    Usage::

        from siphon import metrics

        h = metrics.histogram("my_duration_seconds", "Duration",
                              buckets=[0.1, 0.5, 1.0])
        h.observe(0.3)
    """

    def __init__(self, name: str, help: str,
                 labels: "list[str] | None" = None,
                 buckets: "list[float] | None" = None) -> None:
        self.name = name
        self.help = help
        self.label_names: list[str] = labels or []
        self.buckets: list[float] = buckets or []
        self._observations: list[float] = []
        self._children: dict[tuple, _MockMetricChild] = {}

    def observe(self, v: float) -> None:
        """Observe a value (no-label metrics only)."""
        self._observations.append(v)

    def labels(self, **kwargs: str) -> _MockMetricChild:
        """Return a labeled child histogram."""
        key = tuple(kwargs.get(name, "") for name in self.label_names)
        if key not in self._children:
            self._children[key] = _MockMetricChild()
        return self._children[key]

    def clear(self) -> None:
        self._observations.clear()
        self._children.clear()


class MockMetrics:
    """Mock ``metrics`` namespace — custom Prometheus metrics from scripts.

    Usage::

        from siphon import metrics

        counter = metrics.counter("bgcf_calls_total", "Total calls",
                                  labels=["direction"])
        counter.labels(direction="outbound").inc()

        gauge = metrics.gauge("bgcf_calls_active", "Active calls")
        gauge.inc()

        hist = metrics.histogram("bgcf_setup_seconds", "Setup time",
                                 buckets=[0.1, 0.5, 1.0])
        hist.observe(0.3)

    Test helper::

        from siphon_sdk.mock_module import get_metrics
        m = get_metrics()
        c = m.counter("test_total", "Test")
        c.inc()
        assert c._value == 1.0
    """

    def __init__(self) -> None:
        self._registered: dict[str, Any] = {}

    def counter(self, name: str, help: str,
                labels: "list[str] | None" = None) -> MockCounter:
        """Create a new counter metric.

        Args:
            name: Metric name (e.g. ``"bgcf_calls_total"``).
            help: Description string.
            labels: Optional list of label names.

        Returns:
            A MockCounter handle.
        """
        if name in self._registered:
            raise ValueError(f"metric '{name}' is already registered")
        counter = MockCounter(name, help, labels)
        self._registered[name] = counter
        return counter

    def gauge(self, name: str, help: str,
              labels: "list[str] | None" = None) -> MockGauge:
        """Create a new gauge metric.

        Args:
            name: Metric name (e.g. ``"bgcf_calls_active"``).
            help: Description string.
            labels: Optional list of label names.

        Returns:
            A MockGauge handle.
        """
        if name in self._registered:
            raise ValueError(f"metric '{name}' is already registered")
        gauge = MockGauge(name, help, labels)
        self._registered[name] = gauge
        return gauge

    def histogram(self, name: str, help: str,
                  labels: "list[str] | None" = None,
                  buckets: "list[float] | None" = None) -> MockHistogram:
        """Create a new histogram metric.

        Args:
            name: Metric name (e.g. ``"bgcf_setup_seconds"``).
            help: Description string.
            labels: Optional list of label names.
            buckets: Optional list of bucket boundaries.

        Returns:
            A MockHistogram handle.
        """
        if name in self._registered:
            raise ValueError(f"metric '{name}' is already registered")
        histogram = MockHistogram(name, help, labels, buckets)
        self._registered[name] = histogram
        return histogram

    def clear(self) -> None:
        """Reset all registered metrics."""
        self._registered.clear()


_metrics = MockMetrics()


class BsfError(RuntimeError):
    """Raised by ``sbi.discover_pcf_binding()`` when the BSF is unhealthy
    (5xx / timeout / transport / malformed body).

    A 404 (no binding for the UE IP) is **not** a ``BsfError`` — it returns
    ``None`` (the 4G UE case). Mirrors the Rust ``sbi.BsfError`` exception.
    """


class MockSbi:
    """Mock SBI namespace for testing scripts that use ``from siphon import sbi``.

    Provides mock N5/Npcf policy authorization methods plus Nbsf_Management
    discovery (``discover_pcf_binding``).

    Example::

        from siphon_sdk import mock_module
        mock_module.install()

        from siphon import sbi
        result = sbi.create_session(sip_call_id="call-1", ue_ipv4="10.0.0.1")
        assert result["authorized"] is True
    """

    #: The ``sbi.BsfError`` exception type, so scripts can ``except sbi.BsfError``.
    BsfError = BsfError

    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        self._next_session_id: int = 1
        self._authorized: bool = True
        #: discover_pcf_binding result: a binding dict (5G) or None (404 / 4G).
        self._binding: Optional[dict] = None
        #: when True, discover_pcf_binding raises BsfError (BSF unhealthy).
        self._bsf_error: bool = False

    @staticmethod
    def _session_id(session_ref: str) -> str:
        """Resolve a bare id or an absolute ``app_session_uri`` to the id."""
        if session_ref.startswith(("http://", "https://")):
            return session_ref.rstrip("/").rsplit("/", 1)[-1]
        return session_ref

    def create_session(self, af_app_id: str = "IMS Services",
                       sip_call_id: Optional[str] = None,
                       supi: Optional[str] = None,
                       ue_ipv4: Optional[str] = None,
                       ue_ipv6: Optional[str] = None,
                       dnn: Optional[str] = None,
                       notif_uri: Optional[str] = None,
                       media_components: Optional[list] = None,
                       pcf_uri: Optional[str] = None) -> Optional[dict]:
        """Create an N5 app session for QoS policy authorization.

        Args:
            af_app_id: AF-Application identifier (default ``"IMS Services"``).
            sip_call_id: SIP Call-ID for correlation.
            supi: Subscription Permanent Identifier.
            ue_ipv4: UE IPv4 address.
            ue_ipv6: UE IPv6 address.
            dnn: Data Network Name.
            notif_uri: Notification URI for PCF events.
            media_components: list of media-component dicts (same shape as
                ``diameter.rx_aar``'s ``media_components``).
            pcf_uri: per-call N5 target — address this session at the given PCF
                base URL (e.g. a BSF-discovered ``pcf_uri``) instead of the
                configured ``npcf_url``. ``None`` ⇒ configured PCF.

        Returns:
            Dict with ``app_session_id``, ``authorized`` and ``app_session_uri``
            (the absolute resource URI — persist it and hand it back to
            ``update_session`` / ``delete_session`` for replica-independent
            teardown), or ``None``.
        """
        session_id = f"mock-n5-{self._next_session_id}"
        self._next_session_id += 1
        self._sessions[session_id] = {
            "sip_call_id": sip_call_id,
            "ue_ipv4": ue_ipv4,
            "pcf_uri": pcf_uri,
        }
        base = (pcf_uri or "http://mock-pcf").rstrip("/")
        app_session_uri = (
            f"{base}/npcf-policyauthorization/v1/app-sessions/{session_id}"
        )
        return {
            "app_session_id": session_id,
            "authorized": self._authorized,
            "app_session_uri": app_session_uri,
        }

    def delete_session(self, session_id: str) -> bool:
        """Delete an N5 app session.

        Args:
            session_id: The app session id from ``create_session()`` **or** the
                absolute ``app_session_uri`` (replica-independent teardown).

        Returns:
            ``True`` on success, ``False`` if session not found.
        """
        return self._sessions.pop(self._session_id(session_id), None) is not None

    def update_session(self, session_id: str,
                       media_components: Optional[list] = None) -> Optional[dict]:
        """Update an N5 app session (media renegotiation).

        Args:
            session_id: The app session id to update, or the absolute
                ``app_session_uri`` from ``create_session``.
            media_components: list of media-component dicts (same shape as
                ``create_session``).

        Returns:
            Dict with ``app_session_id`` and ``authorized``, or ``None``.
        """
        resolved = self._session_id(session_id)
        if resolved not in self._sessions:
            return None
        return {"app_session_id": resolved, "authorized": self._authorized}

    def discover_pcf_binding(self, ue_ipv4: Optional[str] = None,
                             ue_ipv6: Optional[str] = None) -> Optional[dict]:
        """Nbsf_Management discovery — look up the PCF binding for a UE IP.

        Returns a binding dict (5G; configure via ``set_binding``), ``None``
        when the BSF has no binding (404 / 4G), or raises ``sbi.BsfError`` when
        configured unhealthy via ``set_bsf_error``.

        Exactly one of ``ue_ipv4`` / ``ue_ipv6`` must be supplied.

        Args:
            ue_ipv4: UE IPv4 address (the IPsec SA peer).
            ue_ipv6: UE IPv6 address/prefix.

        Returns:
            The binding dict (incl. a ready-to-use ``pcf_uri``) or ``None``.
        """
        if (ue_ipv4 is None) == (ue_ipv6 is None):
            raise ValueError(
                "discover_pcf_binding: supply exactly one of ue_ipv4 / ue_ipv6"
            )
        if self._bsf_error:
            raise BsfError("mock BSF unhealthy")
        return self._binding

    @staticmethod
    def on_event(fn: Any) -> Any:
        """Register a handler for incoming PCF event notifications (N5).

        The handler receives the PCF's ``EventsNotification`` document
        (TS 29.514 §5.6.2.6) verbatim as a dict — every field is preserved,
        so the keys are the exact 3GPP wire names. Use ``evSubsUri`` to
        correlate the event with the app-session you created, and ``evNotifs``
        for the per-event list. Each entry's ``flows`` carries ``medCompN`` +
        ``fNums`` (not flow descriptions).

        Example::

            @sbi.on_event
            def handle_pcf_event(event):
                session_events_uri = event.get("evSubsUri")
                for notif in event.get("evNotifs", []):
                    log.info(f"PCF event: {notif['event']}")
        """
        return fn

    def set_authorized(self, authorized: bool) -> None:
        """Configure whether ``create_session`` returns authorized (test helper).

        Args:
            authorized: Whether sessions should be authorized.
        """
        self._authorized = authorized

    def set_binding(self, binding: Optional[dict]) -> None:
        """Configure what ``discover_pcf_binding`` returns (test helper).

        Args:
            binding: a binding dict (5G case) or ``None`` (404 / 4G case).
        """
        self._binding = binding

    def set_bsf_error(self, raise_error: bool) -> None:
        """Configure ``discover_pcf_binding`` to raise ``BsfError`` (test helper).

        Args:
            raise_error: when True, ``discover_pcf_binding`` raises ``BsfError``.
        """
        self._bsf_error = raise_error

    def clear(self) -> None:
        """Reset all mock sessions (test helper)."""
        self._sessions.clear()
        self._next_session_id = 1
        self._authorized = True
        self._binding = None
        self._bsf_error = False


class MockIsc:
    """Mock ISC namespace — Initial Filter Criteria evaluation for testing.

    Store per-user iFC profiles and evaluate them against requests.

    Example::

        from siphon_sdk import mock_module
        mock_module.install()

        from siphon import isc

        # Store a profile (in mock, stores raw XML string)
        count = isc.store_profile("sip:alice@example.com", ifc_xml)

        # Evaluate — returns pre-configured matches
        matches = isc.evaluate("sip:alice@example.com", "INVITE",
                               "sip:bob@example.com", [], "originating")
    """

    def __init__(self) -> None:
        self._profiles: dict[str, str] = {}  # aor -> raw XML (stored for has_profile)
        self._eval_results: dict[str, list[dict]] = {}  # aor -> list of match dicts

    def store_profile(self, aor: str, ifc_xml: str) -> int:
        """Parse and store an iFC XML profile for an AoR.

        In the mock, the XML is stored as-is (no actual parsing).
        Use ``set_eval_results()`` to configure what ``evaluate()`` returns.

        Args:
            aor: Address of Record.
            ifc_xml: Raw iFC XML string.

        Returns:
            Number of iFCs "parsed" (always 1 in mock unless configured otherwise).
        """
        self._profiles[aor] = ifc_xml
        return 1

    def remove_profile(self, aor: str) -> bool:
        """Remove a stored profile.

        Args:
            aor: Address of Record.

        Returns:
            ``True`` if a profile was removed.
        """
        removed = aor in self._profiles
        self._profiles.pop(aor, None)
        self._eval_results.pop(aor, None)
        return removed

    def has_profile(self, aor: str) -> bool:
        """Check if a profile is stored for an AoR.

        Args:
            aor: Address of Record.

        Returns:
            ``True`` if a profile exists.
        """
        return aor in self._profiles

    def evaluate(
        self,
        aor: str,
        method: str,
        ruri: str,
        headers: "list[tuple[str, str]]",
        session_case: str = "originating",
    ) -> list[dict]:
        """Evaluate iFCs for a request.

        Returns pre-configured results (via ``set_eval_results``) or an empty list.

        Args:
            aor: Address of Record.
            method: SIP method (e.g. ``"INVITE"``).
            ruri: Request-URI string.
            headers: List of (name, value) tuples.
            session_case: Session case string.

        Returns:
            List of dicts with keys: ``server_name``, ``default_handling``,
            ``service_info``, ``priority``.
        """
        return list(self._eval_results.get(aor, []))

    def profile_count(self) -> int:
        """Number of stored per-user iFC profiles."""
        return len(self._profiles)

    # -- Test helpers (not in the real Rust API) --

    def set_eval_results(self, aor: str, results: list[dict]) -> None:
        """Configure what ``evaluate()`` returns for a given AoR.

        Args:
            aor: Address of Record.
            results: List of dicts, each with keys ``server_name``,
                ``default_handling``, ``service_info``, ``priority``.

        Example::

            isc.set_eval_results("sip:alice@example.com", [
                {"server_name": "sip:as1@example.com", "default_handling": 0,
                 "service_info": None, "priority": 0},
            ])
        """
        self._eval_results[aor] = results

    def clear(self) -> None:
        """Reset all stored profiles and evaluation results."""
        self._profiles.clear()
        self._eval_results.clear()


_isc = MockIsc()
_sbi = MockSbi()


# ---------------------------------------------------------------------------
# IPsec namespace (3GPP TS 33.203 P-CSCF sec-agree primitives)
# ---------------------------------------------------------------------------


class MockSecurityOffer:
    """Mock :class:`SecurityOffer` — UE-side IPsec proposal."""

    def __init__(self, mechanism: str = "ipsec-3gpp", alg: str = "hmac-sha-1-96",
                 ealg: str = "null", spi_c: int = 1, spi_s: int = 2,
                 port_c: int = 3, port_s: int = 4, ue_addr: str = "10.0.0.1") -> None:
        self.mechanism = mechanism
        self.alg = alg
        self.ealg = ealg
        self.spi_c = spi_c
        self.spi_s = spi_s
        self.port_c = port_c
        self.port_s = port_s
        self.ue_addr = ue_addr

    def __repr__(self) -> str:
        return (f"SecurityOffer(mechanism={self.mechanism!r}, alg={self.alg!r}, "
                f"ealg={self.ealg!r}, spi_c={self.spi_c}, spi_s={self.spi_s}, "
                f"port_c={self.port_c}, port_s={self.port_s}, ue_addr={self.ue_addr!r})")


class MockTransform:
    """Mock :class:`Transform` enum — operator policy choice."""

    def __init__(self, name: str, alg: str, ealg: str = "null") -> None:
        self._name = name
        self.alg = alg
        self.ealg = ealg

    def compatible_with(self, offer: MockSecurityOffer) -> bool:
        offer_ealg = (offer.ealg or "").lower()
        want = self.ealg.lower()
        return (offer.alg.lower() == self.alg.lower()
                and (offer_ealg == want or (offer_ealg == "" and want == "null")))

    def __repr__(self) -> str:
        return f"Transform.{self._name}"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MockTransform) and self._name == other._name

    def __hash__(self) -> int:
        return hash(self._name)


class _TransformEnum:
    HmacSha1_96Null = MockTransform("HmacSha1_96Null", "hmac-sha-1-96", "null")
    HmacMd5_96Null = MockTransform("HmacMd5_96Null", "hmac-md5-96", "null")
    HmacSha256_128Null = MockTransform("HmacSha256_128Null", "hmac-sha-256-128", "null")
    HmacSha1_96AesCbc128 = MockTransform("HmacSha1_96AesCbc128", "hmac-sha-1-96", "aes-cbc")
    HmacMd5_96AesCbc128 = MockTransform("HmacMd5_96AesCbc128", "hmac-md5-96", "aes-cbc")
    HmacSha256_128AesCbc128 = MockTransform(
        "HmacSha256_128AesCbc128", "hmac-sha-256-128", "aes-cbc"
    )


class MockAuthVectorHandle:
    """Mock :class:`AuthVectorHandle` — opaque CK/IK container.

    The bytes are not exposed to Python in the real binding; the mock
    keeps them accessible via ``_ck``/``_ik`` for tests, but treats them
    as consumed after one ``allocate``.
    """

    def __init__(self, ck: bytes = b"\x01" * 16, ik: bytes = b"\x02" * 16) -> None:
        self._ck = ck
        self._ik = ik
        self._consumed = False

    def _take(self) -> tuple[bytes, bytes]:
        if self._consumed:
            raise ValueError("AuthVectorHandle already consumed")
        self._consumed = True
        return (self._ck, self._ik)

    def __repr__(self) -> str:
        return ("AuthVectorHandle(<consumed>)" if self._consumed
                else "AuthVectorHandle(<128-bit CK + 128-bit IK>)")


class MockSAHandle:
    """Mock :class:`SAHandle` — read-only view of an active SA returned by
    ``request.matched_sa``.  Tests can construct one directly and assign
    it to ``request._matched_sa``.
    """

    def __init__(self, ue_addr: str = "10.0.0.1", pcscf_addr: str = "10.0.0.10",
                 ue_port_c: int = 50000, ue_port_s: int = 50001,
                 pcscf_port_c: int = 5064, pcscf_port_s: int = 5066,
                 spi_uc: int = 1000, spi_us: int = 1001,
                 spi_pc: int = 10000, spi_ps: int = 10001,
                 alg: str = "HMAC-SHA-1-96", ealg: str = "NULL",
                 protocol: str = "udp") -> None:
        self.ue_addr = ue_addr
        self.pcscf_addr = pcscf_addr
        self.ue_port_c = ue_port_c
        self.ue_port_s = ue_port_s
        self.pcscf_port_c = pcscf_port_c
        self.pcscf_port_s = pcscf_port_s
        self.spi_uc = spi_uc
        self.spi_us = spi_us
        self.spi_pc = spi_pc
        self.spi_ps = spi_ps
        self.alg = alg
        self.ealg = ealg
        self.protocol = protocol

    def __repr__(self) -> str:
        return (f"SAHandle(ue={self.ue_addr}:{self.ue_port_c}, "
                f"pcscf={self.pcscf_addr}:{self.pcscf_port_c}, "
                f"spi_pc={self.spi_pc}, spi_ps={self.spi_ps}, "
                f"alg={self.alg!r}, ealg={self.ealg!r}, "
                f"protocol={self.protocol!r})")


class MockSecurityServerParams:
    """Mock :class:`SecurityServerParams`."""

    def __init__(self, mechanism: str, alg: str, ealg: str,
                 spi_c: int, spi_s: int, port_c: int, port_s: int,
                 protocol: str = "udp") -> None:
        self.mechanism = mechanism
        self.alg = alg
        self.ealg = ealg
        self.spi_c = spi_c
        self.spi_s = spi_s
        self.port_c = port_c
        self.port_s = port_s
        # Lower-case transport carrying ESP — "udp" or "tcp".  When non-default
        # ("tcp"), append `protocol=tcp` to the Security-Server header per RFC
        # 3329 §2.2.  Mirrors the value passed to ipsec.allocate(...).
        self.protocol = protocol

    def __repr__(self) -> str:
        return (f"SecurityServerParams(mechanism={self.mechanism!r}, "
                f"alg={self.alg!r}, ealg={self.ealg!r}, "
                f"spi_c={self.spi_c}, spi_s={self.spi_s}, "
                f"port_c={self.port_c}, port_s={self.port_s}, "
                f"protocol={self.protocol!r})")


class MockPendingSA:
    """Mock :class:`PendingSA`."""

    _next_spi = 10000

    def __init__(self, transform: MockTransform, offer: MockSecurityOffer,
                 pcscf_port_c: int, pcscf_port_s: int,
                 expires_secs: Optional[int] = None,
                 protocol: str = "udp") -> None:
        cls = type(self)
        spi_pc = cls._next_spi
        cls._next_spi += 1
        spi_ps = cls._next_spi
        cls._next_spi += 1
        self._params = MockSecurityServerParams(
            mechanism="ipsec-3gpp",
            alg=transform.alg,
            ealg=transform.ealg,
            spi_c=spi_pc,
            spi_s=spi_ps,
            port_c=pcscf_port_c,
            port_s=pcscf_port_s,
            protocol=protocol,
        )
        self._offer = offer
        self.expires_secs = expires_secs
        self.protocol = protocol
        self.is_active = False
        self.is_cleaned = False

    def security_server_params(self) -> MockSecurityServerParams:
        return self._params

    def activate(self, *, hard_lifetime_secs: Optional[int] = None) -> None:
        """Mark the SA pair active.

        ``hard_lifetime_secs`` (optional) re-pins the kernel
        hard-lifetime on all four SAs of the pair via ``XFRM_MSG_UPDSA``,
        without rekeying or disturbing selectors / SPIs.  Use on the
        path that processes the 200 OK to the auth REGISTER to tighten
        the SA expiry from the placeholder value installed at
        allocation time (typically the UE's ``Expires:`` ask) to the
        actual grant from the registrar of record (3GPP TS 33.203 §7.4
        — IPsec SA lifetime tracks SIP registration lifetime).

        ``None`` (default) preserves the original metadata-only
        transition.

        In the mock, this only updates ``self.expires_secs`` so tests
        can assert the script wired the grant through correctly.
        """
        if self.is_cleaned:
            raise ValueError("PendingSA already cleaned up")
        self.is_active = True
        if hard_lifetime_secs is not None:
            self.expires_secs = hard_lifetime_secs

    async def cleanup(self) -> None:
        self.is_cleaned = True
        self.is_active = False

    async def refresh(self, av_new: MockAuthVectorHandle) -> None:
        if self.is_cleaned:
            raise ValueError("PendingSA already cleaned up")
        av_new._take()  # consume the new AV

    def __repr__(self) -> str:
        state = ("Cleaned" if self.is_cleaned
                 else "Active" if self.is_active else "Pending")
        return f"PendingSA(state={state}, spi_pc={self._params.spi_c})"


class MockIpsec:
    """Mock :class:`Ipsec` namespace."""

    Transform = _TransformEnum

    def __init__(self) -> None:
        self.pcscf_port_c = 5064
        self.pcscf_port_s = 5066
        self._stash: dict[str, MockPendingSA] = {}
        self._allocate_should_fail: Optional[type[BaseException]] = None
        self._allocate_failure_message = "mock allocate failure"

    @property
    def stash_size(self) -> int:
        return len(self._stash)

    @property
    def active_count(self) -> int:
        return sum(1 for p in self._stash.values() if p.is_active)

    async def allocate(self, av: MockAuthVectorHandle, offer: MockSecurityOffer,
                       transform: MockTransform,
                       expires_secs: Optional[int] = None,
                       protocol: Optional[str] = None) -> MockPendingSA:
        if not transform.compatible_with(offer):
            raise ValueError(
                f"transform {transform!r} not compatible with offer alg={offer.alg!r}"
                f" ealg={offer.ealg!r}"
            )
        # Same validation as the Rust binding so scripts fail identically
        # in unit tests.
        #
        # ``protocol=None`` (default) installs an XFRM selector covering
        # both ESP-over-UDP and ESP-over-TCP under one SPI pair —
        # required by 3GPP TS 33.203 §7.2 ("the SAs shall be used to
        # protect *all* SIP signalling … including over UDP and TCP").
        # The wire-form ``protocol`` on the resulting
        # :class:`SecurityServerParams` collapses to ``"udp"`` because
        # RFC 3329 §2.2 says an absent ``protocol=`` parameter implies
        # UDP — keeps the wire shape every existing UE expects.
        #
        # Explicit ``"udp"``/``"tcp"``/``"any"`` pin the selector to
        # that one inner protocol (single-transport deployments, tests).
        if protocol is None:
            sa_protocol = "any"
            wire_protocol = "udp"
        else:
            proto_lower = protocol.lower()
            if proto_lower not in ("udp", "tcp", "any"):
                raise ValueError(
                    f"protocol must be 'udp', 'tcp', 'any', or None, got {protocol!r}"
                )
            sa_protocol = proto_lower
            wire_protocol = "udp" if proto_lower == "any" else proto_lower
        av._take()  # raises ValueError if already consumed
        if self._allocate_should_fail is not None:
            raise self._allocate_should_fail(self._allocate_failure_message)
        pending = MockPendingSA(
            transform, offer, self.pcscf_port_c, self.pcscf_port_s,
            expires_secs=expires_secs, protocol=wire_protocol,
        )
        # Surface the *internal* SA selector mode for tests that want
        # to assert multi-protocol installation specifically.  Not on
        # the Rust binding (use SAHandle.protocol for that).
        pending.sa_protocol = sa_protocol  # type: ignore[attr-defined]
        return pending

    def stash(self, call_id: str, pending: MockPendingSA) -> None:
        self._stash[call_id] = pending

    def unstash(self, call_id: str) -> Optional[MockPendingSA]:
        return self._stash.pop(call_id, None)

    # -- Test helpers -------------------------------------------------------

    def set_allocate_failure(self, exc_type: Optional[type[BaseException]],
                             message: str = "mock allocate failure") -> None:
        """Configure the next ``allocate()`` call to raise ``exc_type``.

        Pass ``None`` to clear and let ``allocate`` succeed again.
        """
        self._allocate_should_fail = exc_type
        self._allocate_failure_message = message

    def clear(self) -> None:
        self._stash.clear()
        self._allocate_should_fail = None
        MockPendingSA._next_spi = 10000


_ipsec = MockIpsec()


# ---------------------------------------------------------------------------
# STIR/SHAKEN namespace (RFC 8224/8225/8226, ATIS-1000074)
# ---------------------------------------------------------------------------

class MockStirResult:
    """Result of :meth:`MockStir.verify` — mirrors the Rust ``StirResult``.

    Attributes:
        verstat: ``"TN-Validation-Passed"`` | ``"TN-Validation-Failed"`` |
            ``"No-TN-Validation"`` (ATIS-1000074 §5.3.1).
        passed: ``True`` only when the SHAKEN PASSporT validated end to end.
        attestation: ``"A"`` / ``"B"`` / ``"C"`` from the SHAKEN PASSporT.
        origid: ``origid`` (UUID) from the SHAKEN PASSporT.
        orig_tn: originating TN from the SHAKEN PASSporT.
        reason: human-readable diagnostic / failure cause.
        passports: decoded PASSporT claim dicts.
    """

    def __init__(
        self,
        verstat: str = "No-TN-Validation",
        passed: bool = False,
        attestation: Optional[str] = None,
        origid: Optional[str] = None,
        orig_tn: Optional[str] = None,
        reason: str = "",
        passports: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        self.verstat = verstat
        self.passed = passed
        self.attestation = attestation
        self.origid = origid
        self.orig_tn = orig_tn
        self.reason = reason
        self._passports = passports or []

    @property
    def passports(self) -> list[dict[str, Any]]:
        """Decoded claim sets of every PASSporT that parsed."""
        return list(self._passports)

    def __repr__(self) -> str:
        return (
            f"StirResult(verstat={self.verstat!r}, passed={self.passed}, "
            f"attestation={self.attestation!r}, reason={self.reason!r})"
        )


class MockStir:
    """Mock ``stir`` namespace — STIR/SHAKEN signing and verification.

    Scripts use::

        from siphon import stir

        @proxy.on_request("INVITE")
        def on_invite(request):
            origid = stir.sign(request, attestation="A")   # add Identity header
            request.relay()

        @proxy.on_request("INVITE")
        def verify_inbound(request):
            result = stir.verify(request)
            if result.verstat == "TN-Validation-Failed":
                request.reply(438, "Invalid Identity Header")
                return
            stir.apply_verstat(request, result)
            request.relay()

    Test helpers: set :attr:`signing_enabled` / :attr:`verification_enabled`
    to simulate config; call :meth:`set_verify_result` to pin the next
    :meth:`verify` outcome; inspect :attr:`signed` / :attr:`applied_verstats`.
    """

    def __init__(self) -> None:
        self.signing_enabled: bool = True
        self.verification_enabled: bool = True
        self._next_result: Optional[MockStirResult] = None
        self.signed: list[dict[str, Any]] = []
        self.applied_verstats: list[str] = []

    @staticmethod
    def _uri_user(uri: Any) -> Optional[str]:
        return getattr(uri, "user", None) if uri is not None else None

    def sign(
        self,
        request: Any,
        attestation: str = "A",
        origid: Optional[str] = None,
        orig_tn: Optional[str] = None,
        dest_tn: Optional[str] = None,
    ) -> str:
        """Build a SHAKEN ``Identity`` header and add it to ``request``.

        Args:
            request: The outbound SIP request.
            attestation: ``"A"`` / ``"B"`` / ``"C"`` (full / partial / gateway).
            origid: UUID origin identifier; a fresh v4 is generated if ``None``.
            orig_tn: Originating TN; defaults to the From user part.
            dest_tn: Destination TN; defaults to the To / R-URI user part.

        Returns:
            The ``origid`` used.

        Raises:
            RuntimeError: if signing is not configured.
            ValueError: if the orig/dest TN cannot be determined.
        """
        if not self.signing_enabled:
            raise RuntimeError("STIR signing is not configured")
        if attestation.upper() not in ("A", "B", "C"):
            raise ValueError(f"invalid attestation level {attestation!r}")
        orig = orig_tn or self._uri_user(getattr(request, "from_uri", None))
        dest = dest_tn or self._uri_user(getattr(request, "to_uri", None)) \
            or self._uri_user(getattr(request, "ruri", None))
        if not orig:
            raise ValueError("could not determine originating TN (pass orig_tn=)")
        if not dest:
            raise ValueError("could not determine destination TN (pass dest_tn=)")
        used_origid = origid or str(uuid.uuid4())
        # A structurally-valid-looking (but mock) Identity header value.
        header = (
            "eyJtb2NrIjoiaGVhZGVyIn0.eyJtb2NrIjoiY2xhaW1zIn0.bW9ja3NpZw"
            ";info=<https://mock.invalid/sti.pem>;alg=ES256;ppt=shaken"
        )
        request.set_header("Identity", header)
        self.signed.append(
            {
                "attestation": attestation.upper(),
                "origid": used_origid,
                "orig_tn": orig,
                "dest_tn": dest,
                "ppt": "shaken",
            }
        )
        return used_origid

    def sign_div(
        self,
        request: Any,
        orig_tn: Optional[str] = None,
        dest_tn: Optional[str] = None,
        div_tn: Optional[str] = None,
    ) -> None:
        """Build a diverted-call (``div``) ``Identity`` header (RFC 8946).

        Args:
            request: The outbound (retargeted) SIP request.
            orig_tn: Originating TN; defaults to the From user part.
            dest_tn: New destination TN; defaults to the To / R-URI user part.
            div_tn: Diverting TN; defaults to the History-Info / Diversion user.
        """
        if not self.signing_enabled:
            raise RuntimeError("STIR signing is not configured")
        orig = orig_tn or self._uri_user(getattr(request, "from_uri", None))
        dest = dest_tn or self._uri_user(getattr(request, "to_uri", None)) \
            or self._uri_user(getattr(request, "ruri", None))
        if not orig:
            raise ValueError("could not determine originating TN")
        if not dest:
            raise ValueError("could not determine destination TN")
        if not div_tn:
            raise ValueError("could not determine diverting TN (pass div_tn=)")
        request.set_header("Identity", (
            "eyJtb2NrIjoiZGl2In0.eyJtb2NrIjoiZGl2In0.bW9ja2Rpdg"
            ";info=<https://mock.invalid/sti.pem>;alg=ES256;ppt=div"
        ))
        self.signed.append(
            {"orig_tn": orig, "dest_tn": dest, "div_tn": div_tn, "ppt": "div"}
        )

    def verify(self, request: Any) -> MockStirResult:
        """Verify the ``Identity`` header(s) on ``request``.

        Returns a :class:`MockStirResult`. By default returns a passing result
        when an ``Identity`` header is present, else ``No-TN-Validation``;
        override with :meth:`set_verify_result`.

        Raises:
            RuntimeError: if verification is not configured.
        """
        if not self.verification_enabled:
            raise RuntimeError("STIR verification is not configured")
        if self._next_result is not None:
            return self._next_result
        if request.get_header("Identity"):
            orig = self._uri_user(getattr(request, "from_uri", None))
            return MockStirResult(
                verstat="TN-Validation-Passed",
                passed=True,
                attestation="A",
                orig_tn=orig,
                reason="ok",
            )
        return MockStirResult(
            verstat="No-TN-Validation",
            passed=False,
            reason="no Identity header present",
        )

    def apply_verstat(self, request: Any, result: MockStirResult) -> None:
        """Stamp the ``verstat`` parameter onto the asserted identity
        (P-Asserted-Identity if present, else From) per ATIS-1000074 §5.3.1."""
        self.applied_verstats.append(result.verstat)

    # -- Test helpers -------------------------------------------------------

    def set_verify_result(
        self,
        verstat: str = "TN-Validation-Passed",
        passed: bool = True,
        attestation: Optional[str] = None,
        origid: Optional[str] = None,
        orig_tn: Optional[str] = None,
        reason: str = "ok",
        passports: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        """Pin the result returned by the next :meth:`verify` call(s)."""
        self._next_result = MockStirResult(
            verstat, passed, attestation, origid, orig_tn, reason, passports
        )

    def clear(self) -> None:
        self._next_result = None
        self.signed.clear()
        self.applied_verstats.clear()
        self.signing_enabled = True
        self.verification_enabled = True


_stir = MockStir()


# ---------------------------------------------------------------------------
# SDP namespace
# ---------------------------------------------------------------------------

from siphon_sdk.sdp import MockSdpNamespace

_sdp = MockSdpNamespace()


# ---------------------------------------------------------------------------
# numbers namespace — E.164 identity normalization
# ---------------------------------------------------------------------------

from siphon_sdk.numbers import MockNumbersNamespace

_numbers = MockNumbersNamespace()


# ---------------------------------------------------------------------------
# QoS namespace — SDP → IPFilterRule helper
# ---------------------------------------------------------------------------

class MockQos:
    """Mock ``qos`` namespace — turns SDP offer/answer pairs into the
    ``media_components`` structure consumed by ``diameter.rx_aar`` and
    ``sbi.create_session``.

    The mock parses SDP just enough to produce a usable
    ``media_components`` list with RTP + RTCP sub-components for each
    ``m=`` section.  Disabled streams (port 0) are skipped and
    ``a=rtcp-mux`` collapses RTCP into the RTP sub-component.

    Example::

        from siphon import qos, diameter

        components = qos.media_flows_from_sdp(
            offer=request.body, answer=reply.body, direction="orig",
        )
        diameter.rx_aar(framed_ip=request.source_ip, media_components=components)
    """

    def media_flows_from_sdp(self, *, offer: Any, answer: Any,
                             direction: str = "orig") -> list[dict]:
        """Translate an SDP offer/answer pair into a ``media_components`` list.

        Args:
            offer: the original (offer) SDP — ``str``, ``bytes``, or a
                Request/Reply/Call mock with a ``body`` attribute.
            answer: the answer SDP (typically post ``rtpengine.answer()``).
            direction: ``"orig"`` (UE is offerer — UE addr from ``offer``,
                remote from ``answer``) or ``"term"`` (UE is answerer —
                addresses flipped).

        Returns:
            list[dict]: one entry per non-disabled ``m=`` section.
        """
        if direction not in ("orig", "term", "originating", "terminating"):
            raise ValueError(
                f"direction must be 'orig' or 'term', got {direction!r}"
            )

        offer_sdp = _MiniSdp(_extract_sdp_text(offer))
        answer_sdp = _MiniSdp(_extract_sdp_text(answer))

        if len(offer_sdp.media) != len(answer_sdp.media):
            raise ValueError(
                f"offer/answer m= section count mismatch: "
                f"offer={len(offer_sdp.media)} answer={len(answer_sdp.media)}"
            )

        results: list[dict] = []
        component_number = 0
        for offer_m, answer_m in zip(offer_sdp.media, answer_sdp.media):
            if offer_m.port == 0 or answer_m.port == 0:
                continue

            offer_ip = offer_m.connection_ip or offer_sdp.connection_ip
            answer_ip = answer_m.connection_ip or answer_sdp.connection_ip
            if offer_ip is None or answer_ip is None:
                raise ValueError(
                    f"m={offer_m.media_type} {offer_m.port} missing connection address"
                )

            if direction in ("orig", "originating"):
                ue_ip, ue_port = offer_ip, offer_m.port
                remote_ip, remote_port = answer_ip, answer_m.port
                ue_media, remote_media = offer_m, answer_m
            else:
                ue_ip, ue_port = answer_ip, answer_m.port
                remote_ip, remote_port = offer_ip, offer_m.port
                ue_media, remote_media = answer_m, offer_m

            proto = _ip_proto(offer_m.protocol)

            component_number += 1
            component: dict = {
                "number": component_number,
                "media_type": _media_type_alias(offer_m.media_type),
                "flows": [
                    {
                        "number": 1,
                        "descriptions": [
                            f"permit out {proto} from {ue_ip} {ue_port} to {remote_ip} {remote_port}",
                            f"permit in {proto} from {remote_ip} {remote_port} to {ue_ip} {ue_port}",
                        ],
                    },
                ],
            }

            status = _ue_flow_status(ue_media)
            if status is not None:
                component["flow_status"] = status

            mux_agreed = "rtcp-mux" in ue_media.flags and "rtcp-mux" in remote_media.flags
            if not mux_agreed:
                ue_rtcp = ue_media.rtcp_port or ue_port + 1
                remote_rtcp = remote_media.rtcp_port or remote_port + 1
                component["flows"].append({
                    "number": 2,
                    "usage": "rtcp",
                    "descriptions": [
                        f"permit out {proto} from {ue_ip} {ue_rtcp} to {remote_ip} {remote_rtcp}",
                        f"permit in {proto} from {remote_ip} {remote_rtcp} to {ue_ip} {ue_rtcp}",
                    ],
                })

            results.append(component)

        return results


def _extract_sdp_text(source) -> str:
    if isinstance(source, str):
        return source
    if isinstance(source, (bytes, bytearray)):
        return bytes(source).decode("utf-8", errors="replace")
    # Mock Request/Reply/Call: pull `body` attribute.
    body = getattr(source, "body", None)
    if body is None:
        raise ValueError("source has no SDP body")
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", errors="replace")
    return str(body)


class _MiniSdpMedia:
    __slots__ = ("media_type", "port", "protocol", "connection_ip", "flags", "rtcp_port")

    def __init__(self, line: str) -> None:
        parts = line.split()
        # m=audio 50000 RTP/AVP 0 8 97
        self.media_type = parts[0][2:] if parts[0].startswith("m=") else parts[0]
        self.port = int(parts[1]) if len(parts) > 1 else 0
        self.protocol = parts[2] if len(parts) > 2 else "RTP/AVP"
        self.connection_ip: Optional[str] = None
        self.flags: set[str] = set()
        self.rtcp_port: Optional[int] = None


class _MiniSdp:
    """Just enough SDP parsing for the mock helper."""

    def __init__(self, text: str) -> None:
        self.connection_ip: Optional[str] = None
        self.media: list[_MiniSdpMedia] = []
        current: Optional[_MiniSdpMedia] = None
        for raw in text.splitlines():
            line = raw.rstrip("\r")
            if line.startswith("m="):
                current = _MiniSdpMedia(line)
                self.media.append(current)
            elif line.startswith("c=") and current is not None:
                current.connection_ip = _parse_c_line(line)
            elif line.startswith("c=") and current is None:
                self.connection_ip = _parse_c_line(line)
            elif line.startswith("a=") and current is not None:
                attr = line[2:]
                if ":" in attr:
                    name, value = attr.split(":", 1)
                    name = name.strip()
                    value = value.strip()
                    if name == "rtcp":
                        token = value.split()[0] if value.split() else ""
                        try:
                            current.rtcp_port = int(token)
                        except ValueError:
                            pass
                    else:
                        current.flags.add(name)
                else:
                    current.flags.add(attr.strip())


def _parse_c_line(line: str) -> Optional[str]:
    # c=IN IP4 10.0.0.1 / c=IN IP6 ::1
    parts = line[2:].split()
    if len(parts) < 3:
        return None
    addr = parts[2].split("/")[0].strip()
    return addr or None


def _ip_proto(sdp_protocol: str) -> int:
    upper = sdp_protocol.upper()
    if upper.startswith("TCP") or "/TCP/" in upper:
        return 6
    if upper.startswith("SCTP") or "/SCTP/" in upper:
        return 132
    return 17


def _media_type_alias(sdp_media_type: str) -> str:
    mapping = {
        "audio": "audio",
        "video": "video",
        "application": "application",
        "text": "text",
        "message": "message",
        "image": "data",
    }
    return mapping.get(sdp_media_type.lower(), "other")


def _ue_flow_status(media: _MiniSdpMedia) -> Optional[str]:
    if "inactive" in media.flags:
        return "disabled"
    if "sendonly" in media.flags:
        return "enabled-up"
    if "recvonly" in media.flags:
        return "enabled-down"
    return None


_qos = MockQos()


# The ``smpp`` namespace is injected at runtime by the siphon-smpp extension
# (a ``siphon-bin --features smpp`` build), not by siphon-sip itself. The mock
# is provided here so SMPP scripts can be tested/authored alongside the SIP
# ones with a single ``pip install siphon-sip``.
_smpp = MockSmpp()

# The ``http`` namespace is injected at runtime by the siphon-http extension
# (a ``siphon-bin`` build with the ``http`` feature). Mocked here so HTTP
# scripts can be tested/authored with a single ``pip install siphon-sip``.
_http = MockHttp()


def install() -> ModuleType:
    """Install the mock ``siphon`` module into ``sys.modules``.

    After calling this, ``from siphon import proxy, registrar, ...`` will
    resolve to the mock objects.  Call this before loading user scripts.

    Returns:
        The mock ``siphon`` module.
    """
    mod = ModuleType("siphon")
    mod.__doc__ = (
        "SIPhon mock module — provides the same API as the Rust-injected "
        "siphon module for testing and LLM script authoring."
    )
    mod.proxy = _proxy  # type: ignore[attr-defined]
    mod.b2bua = _b2bua  # type: ignore[attr-defined]
    mod.registrar = _registrar  # type: ignore[attr-defined]
    mod.auth = _auth  # type: ignore[attr-defined]
    mod.log = _log  # type: ignore[attr-defined]
    mod.cache = _cache  # type: ignore[attr-defined]
    mod.rtpengine = _rtpengine  # type: ignore[attr-defined]
    mod.gateway = _gateway  # type: ignore[attr-defined]
    mod.cdr = _cdr  # type: ignore[attr-defined]
    mod.li = _li  # type: ignore[attr-defined]
    mod.registration = _registration  # type: ignore[attr-defined]
    mod.diameter = _diameter  # type: ignore[attr-defined]
    mod.presence = _presence  # type: ignore[attr-defined]
    mod.srs = _srs  # type: ignore[attr-defined]
    mod.timer = _timer  # type: ignore[attr-defined]
    mod.metrics = _metrics  # type: ignore[attr-defined]
    mod.isc = _isc  # type: ignore[attr-defined]
    mod.sbi = _sbi  # type: ignore[attr-defined]
    mod.ipsec = _ipsec  # type: ignore[attr-defined]
    mod.stir = _stir  # type: ignore[attr-defined]
    mod.sdp = _sdp  # type: ignore[attr-defined]
    mod.numbers = _numbers  # type: ignore[attr-defined]
    mod.qos = _qos  # type: ignore[attr-defined]
    # LCR namespace (B2BUA-only) + the Route / LcrDecision types (mirrors the
    # Rust module.add_class::<Route>() / <LcrDecision>() top-level registration).
    mod.lcr = _lcr  # type: ignore[attr-defined]
    mod.Route = Route  # type: ignore[attr-defined]
    mod.LcrDecision = MockLcrDecision  # type: ignore[attr-defined]
    # smpp namespace — provided by the siphon-smpp extension at runtime;
    # mocked here so `from siphon import smpp` works under pytest.
    mod.smpp = _smpp  # type: ignore[attr-defined]
    # http namespace — provided by the siphon-http extension at runtime.
    mod.http = _http  # type: ignore[attr-defined]

    # IPsec types — exposed at top level so scripts can do
    # `from siphon import Transform, SecurityOffer, …` (matching the
    # Rust binding's `module.add_class::<…>()` registration).
    mod.Transform = _TransformEnum  # type: ignore[attr-defined]
    mod.SecurityOffer = MockSecurityOffer  # type: ignore[attr-defined]
    mod.AuthVectorHandle = MockAuthVectorHandle  # type: ignore[attr-defined]
    mod.PendingSA = MockPendingSA  # type: ignore[attr-defined]
    mod.SecurityServerParams = MockSecurityServerParams  # type: ignore[attr-defined]
    mod.SAHandle = MockSAHandle  # type: ignore[attr-defined]
    # Path-token MT routing (RFC 3327 §5 / TS 24.229 §5.2.7.2).
    from siphon_sdk.types import Flow as _Flow
    mod.Flow = _Flow  # type: ignore[attr-defined]

    # Also install the _siphon_registry mock
    registry_mod = ModuleType("_siphon_registry")
    registry_mod.register = _registry.register  # type: ignore[attr-defined]

    sys.modules["siphon"] = mod
    sys.modules["_siphon_registry"] = registry_mod
    return mod


def reset() -> None:
    """Reset all mock state (registrar, auth, cache, log, handlers, etc.).

    Call between tests to ensure isolation.
    """
    _registry.clear()
    _registrar.clear()
    _log.clear()
    _cache.clear()
    _rtpengine.clear()
    _gateway.clear()
    _cdr.clear()
    _li.clear()
    _registration.clear()
    _diameter.clear()
    _presence.clear()
    _srs.clear()
    _metrics.clear()
    _isc.clear()
    _ipsec.clear()
    _stir.clear()
    _numbers.clear()
    _smpp.clear()
    _http.clear()
    _lcr.clear()
    _auth._allow = False
    _auth._credentials.clear()
    _proxy._utils._rate_limit_allow = True
    _proxy._utils._sanity_check_pass = True
    _proxy._utils._enum_results.clear()
    _proxy._utils._memory_pct = 25
    _b2bua.clear()


def get_registry() -> _HandlerRegistry:
    """Access the handler registry (test helper)."""
    return _registry


def get_numbers() -> MockNumbersNamespace:
    """Access the mock numbers namespace singleton (test helper).

    Configure the home numbering plan and named policies before running a
    script under test::

        mock_module.get_numbers().configure(country_code="31")
        mock_module.get_numbers().register_policy("teams-outbound@2026", default="e164")
    """
    return _numbers


def get_smpp() -> MockSmpp:
    """Access the mock smpp namespace singleton (test helper)."""
    return _smpp


def get_lcr() -> MockLcr:
    """Access the mock lcr namespace singleton (test helper).

    Configure the decision a script's ``await lcr.route(call)`` returns::

        mock_module.get_lcr().set_routes([Route(carrier_id="a", gateway_group="pool-a")])
    """
    return _lcr


def get_http() -> MockHttp:
    """Access the mock http namespace singleton (test helper)."""
    return _http


def get_proxy() -> MockProxy:
    """Access the mock proxy singleton."""
    return _proxy


def get_b2bua() -> MockB2bua:
    """Access the mock b2bua singleton (test helper) — inspect ``.terminates``."""
    return _b2bua


def get_registrar() -> MockRegistrar:
    """Access the mock registrar singleton."""
    return _registrar


def get_auth() -> MockAuth:
    """Access the mock auth singleton."""
    return _auth


def get_log() -> MockLog:
    """Access the mock log singleton."""
    return _log


def get_cache() -> MockCache:
    """Access the mock cache singleton."""
    return _cache


def get_rtpengine() -> MockRtpEngine:
    """Access the mock rtpengine singleton."""
    return _rtpengine


def get_gateway() -> MockGateway:
    """Access the mock gateway singleton."""
    return _gateway


def get_cdr() -> MockCdr:
    """Access the mock CDR singleton."""
    return _cdr


def get_li() -> MockLi:
    """Access the mock LI singleton."""
    return _li


def get_registration() -> MockRegistration:
    """Access the mock registration singleton."""
    return _registration


def get_diameter() -> MockDiameter:
    """Access the mock Diameter singleton."""
    return _diameter


def get_presence() -> MockPresence:
    """Access the mock presence singleton."""
    return _presence


def get_srs() -> MockSrs:
    """Access the mock SRS singleton."""
    return _srs


def get_timer() -> MockTimer:
    """Access the mock timer singleton."""
    return _timer


def get_metrics() -> MockMetrics:
    """Access the mock metrics singleton."""
    return _metrics


def get_isc() -> MockIsc:
    """Access the mock ISC singleton."""
    return _isc


def get_ipsec() -> MockIpsec:
    """Access the mock IPsec singleton."""
    return _ipsec


def get_stir() -> MockStir:
    """Access the mock STIR/SHAKEN singleton."""
    return _stir
