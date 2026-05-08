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
import sys
from types import ModuleType
from typing import Any, Callable, Optional, Union

from siphon_sdk.types import Contact, SipUri
from siphon_sdk.request import _parse_uri


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
            headers: Optional dict of header name → value to add.
            body: Optional body — ``str`` or ``bytes``.
            next_hop: Optional next-hop URI override.
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
    """

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

        Handler signature: ``(call) -> None``
        """
        is_async = asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_refer", None, fn, is_async)
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

        Returns:
            ``True`` on success.

        Example::

            if request.method == "REGISTER":
                if not auth.require_digest(request, realm=DOMAIN):
                    return
                registrar.save(request, aliases=["tel:+15551234"])
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
            contacts.append(Contact(uri=default_uri))
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

    def lookup(self, uri: Union[str, SipUri]) -> list[Contact]:
        """Look up contacts for an address-of-record.

        If the URI is an alias of an IMS implicit registration set,
        resolves to the primary's contacts (matching production
        ``registrar.lookup`` behaviour).

        Args:
            uri: AoR as string or :class:`SipUri`.

        Returns:
            List of :class:`Contact` objects sorted by q-value (descending).
            Empty list if no contacts registered.
        """
        key = self._resolve_alias(self._normalize_aor(str(uri)))
        contacts = self._store.get(key, [])
        return sorted(contacts, key=lambda c: c.q, reverse=True)

    def is_registered(self, uri: Union[str, SipUri]) -> bool:
        """Check if a URI has any registered contacts.

        Args:
            uri: AoR as string or :class:`SipUri`.
        """
        return len(self.lookup(uri)) > 0

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

        Returns the XML document as a string. Used to build NOTIFY bodies
        for reg event subscriptions.

        Args:
            aor: Address of Record (e.g. ``"sip:alice@example.com"``).
            state: ``"full"`` or ``"partial"`` (default ``"full"``).
            version: reginfo version counter (default 0).

        Returns:
            XML string conforming to RFC 3680.
        """
        contacts = self._store.get(aor, [])
        reg_state = "active" if contacts else "terminated"

        contacts_xml = ""
        for contact in contacts:
            contacts_xml += (
                f'      <contact id="c-{hash(contact.uri) & 0xFFFF:04x}" '
                f'state="active" event="registered">\n'
                f'        <uri>{contact.uri}</uri>\n'
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

    async def store(self, name: str, key: str, value: str) -> bool:
        """Store a value in a named cache.

        Args:
            name: Cache name.
            key: Cache key.
            value: Value to store.

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

class MockRtpEngine:
    """Mock RTPEngine namespace — records media operations for assertions.

    Example::

        from siphon import rtpengine
        # After running handler:
        assert rtpengine.operations == [("offer", "srtp_to_rtp")]

    Media-injection operations (``play_media``, ``stop_media``, ``play_dtmf``,
    ``silence_media``, ``unsilence_media``, ``block_media``, ``unblock_media``)
    are also captured in ``operations`` as ``(name, detail_string)`` tuples so
    downstream apps can unit-test MMTEL announcement flows without a live
    rtpengine. Full parameter dicts are available on ``media_calls``.

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
        self._subscribe_request_sdp: bytes = b""
        self._subscribe_answer_sdp: bytes = b""
        self._dtmf_handlers: list[dict[str, Any]] = []

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
                    profile: str = "srtp_to_rtp") -> bool:
        """Send ``offer`` command to RTPEngine.

        Extracts SDP from message body, sends to engine, replaces body
        with rewritten SDP.

        Args:
            request: Request or Call object with SDP body.
            profile: RTP profile name.

        Returns:
            ``True`` on success.
        """
        self.operations.append(("offer", profile))
        return True

    async def answer(self, reply: Any,
                     profile: str = "srtp_to_rtp") -> bool:
        """Send ``answer`` command to RTPEngine.

        Args:
            reply: Reply or Call object with SDP body.
            profile: RTP profile name.

        Returns:
            ``True`` on success.
        """
        self.operations.append(("answer", profile))
        return True

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

        Returns:
            Prompt duration in ms if rtpengine reports one (mock returns
            the value set via :meth:`set_play_media_duration`, else ``None``).

        Example::

            dur = await rtpengine.play_media(call, file="/var/lib/siphon/prompts/cfu.wav")
            await rtpengine.play_media(call, blob=tts_bytes, to_tag=peer_tag)
        """
        count = sum(1 for x in (file, blob, db_id) if x is not None)
        if count != 1:
            raise ValueError(
                "play_media requires exactly one of file=, blob=, or db_id="
            )
        source = "file" if file is not None else "blob" if blob is not None else "db-id"
        self.operations.append(("play_media", source))
        self.media_calls.append({
            "op": "play_media",
            "file": file,
            "blob": blob,
            "db_id": db_id,
            "repeat": repeat,
            "start_ms": start_ms,
            "duration_ms": duration_ms,
            "to_tag": to_tag,
        })
        return self._play_media_duration_ms

    async def stop_media(self, target: Any) -> bool:
        """Stop any prompt currently playing on the selected monologue.

        Args:
            target: Request, Reply, or Call object.

        Returns:
            ``True`` on success.
        """
        self.operations.append(("stop_media", None))
        self.media_calls.append({"op": "stop_media"})
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
        self.operations.append(("play_dtmf", code))
        self.media_calls.append({
            "op": "play_dtmf",
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
        self.operations.append(("silence_media", None))
        self.media_calls.append({"op": "silence_media"})
        return True

    async def unsilence_media(self, target: Any) -> bool:
        """Stop replacing outgoing audio with silence (undo :meth:`silence_media`)."""
        self.operations.append(("unsilence_media", None))
        self.media_calls.append({"op": "unsilence_media"})
        return True

    async def block_media(self, target: Any) -> bool:
        """Drop outgoing packets on the selected monologue entirely.

        Pair with :meth:`unblock_media` to resume.
        """
        self.operations.append(("block_media", None))
        self.media_calls.append({"op": "block_media"})
        return True

    async def unblock_media(self, target: Any) -> bool:
        """Resume forwarding the selected monologue's packets."""
        self.operations.append(("unblock_media", None))
        self.media_calls.append({"op": "unblock_media"})
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

    def set_subscribe_request_sdp(self, sdp: bytes) -> None:
        """Configure the SDP returned by :meth:`subscribe_request` (test helper)."""
        self._subscribe_request_sdp = sdp

    def set_subscribe_answer_sdp(self, sdp: bytes) -> None:
        """Configure the SDP returned by :meth:`subscribe_answer` (test helper)."""
        self._subscribe_answer_sdp = sdp

    def set_play_media_duration(self, duration_ms: Optional[int]) -> None:
        """Configure the duration returned by :meth:`play_media` (test helper)."""
        self._play_media_duration_ms = duration_ms

    def clear(self) -> None:
        """Clear recorded operations (test helper)."""
        self.operations.clear()
        self.media_calls.clear()


# ---------------------------------------------------------------------------
# Dispatcher namespace
# ---------------------------------------------------------------------------

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

        cdr.write(request, extra={"billing_id": "B-12345"})
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

    def write(self, request: "Any", extra: "dict[str, str] | None" = None) -> bool:
        """Write a CDR for the given request.

        Args:
            request: The SIP request object.
            extra: Optional dict of extra fields to include in the CDR.

        Returns:
            True if the CDR was queued successfully.

        Example::

            from siphon import cdr
            cdr.write(request, extra={"billing_id": "B-12345", "account": "ACC-789"})
        """
        if not self._enabled:
            return False

        record: dict = {
            "call_id": getattr(request, "call_id", ""),
            "method": getattr(request, "method", ""),
            "from_uri": str(getattr(request, "from_uri", "")),
            "to_uri": str(getattr(request, "to_uri", "")),
            "ruri": str(getattr(request, "ruri", "")),
            "source_ip": getattr(request, "source_ip", ""),
            "transport": getattr(request, "transport", ""),
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

    def add(self, aor: str, registrar: str, *, user: str, password: str,
            interval: Optional[int] = None, realm: Optional[str] = None,
            contact: Optional[str] = None, transport: Optional[str] = None) -> None:
        """Add a new outbound registration.

        Args:
            aor: Address-of-Record (e.g. "sip:alice@carrier.com").
            registrar: Registrar URI (e.g. "sip:registrar.carrier.com:5060").
            user: Authentication username.
            password: Authentication password.
            interval: Registration interval in seconds.
            realm: Optional realm hint.
            contact: Optional Contact URI.
            transport: Transport protocol: "udp" (default), "tcp", "tls".
        """
        self._entries[aor] = {
            "aor": aor,
            "registrar": registrar,
            "user": user,
            "password": password,
            "interval": interval or 3600,
            "realm": realm,
            "contact": contact,
            "transport": transport or "udp",
            "state": "registered",
            "expires_in": interval or 3600,
            "failure_count": 0,
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
               media_type: str = "audio",
               framed_ip: Optional[str] = None,
               flow_description: Optional[str] = None) -> Optional[dict]:
        """Send an Rx AA-Request for QoS resource reservation.

        Args:
            session_id: Rx session identifier.
            media_type: Media type (``"audio"``, ``"video"``).
            framed_ip: UE's IP address.
            flow_description: IPFilterRule for the media flow.

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
               data_reference,
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
               data_reference,
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

    @staticmethod
    def on_rtr(fn: Any) -> Any:
        """Register a handler for incoming RTR (Registration-Termination-Request).

        Handler receives ``(public_identity, reason_code, reason_info)``.

        Reason codes: 0=PERMANENT_TERMINATION, 1=NEW_SERVER_ASSIGNED,
                      2=SERVER_CHANGE, 3=REMOVE_SCSCF.

        Example::

            @diameter.on_rtr
            def handle_rtr(public_identity, reason_code, reason_info):
                registrar.remove(public_identity)
        """
        return fn

    @staticmethod
    def on_rar(fn: Any) -> Any:
        """Register a handler for incoming RAR (Re-Auth-Request) from PCRF.

        Handler receives ``(session_id, abort_cause, specific_actions)``.
        ``specific_actions`` is a list of int values (TS 29.214 Specific-Action).

        Example::

            @diameter.on_rar
            def handle_rar(session_id, abort_cause, specific_actions):
                if 2 in specific_actions:
                    log.warn(f"Bearer lost for session {session_id}")
        """
        return fn

    @staticmethod
    def on_asr(fn: Any) -> Any:
        """Register a handler for incoming ASR (Abort-Session-Request) from PCRF.

        Handler receives ``(session_id, abort_cause, origin_host)``.

        Example::

            @diameter.on_asr
            def handle_asr(session_id, abort_cause, origin_host):
                log.info(f"Session abort from {origin_host}: {session_id}")
        """
        return fn

    @staticmethod
    def on_pnr(fn: Any) -> Any:
        """Register a handler for incoming Sh PNR (Push-Notification-Request).

        Handler receives ``(public_identity, user_data_xml)``. Siphon auto-sends
        PNA (result 2001) after the handler returns.

        Example::

            @diameter.on_pnr
            def handle_pnr(public_identity, user_data_xml):
                cache.put("simservs", public_identity, user_data_xml)
        """
        return fn

    @staticmethod
    def on_alr(fn: Any) -> Any:
        """Register a handler for incoming S6c ALR (Alert-Service-Centre).

        Handler receives ``(public_identity, msisdn)``. Siphon auto-sends
        ALA (result 2001) after the handler returns. The HSS sends ALR
        when a previously-unreachable UE has registered or moved into
        coverage — drain pending MT-SMS here.
        """
        return fn

    @staticmethod
    def on_ofr(fn: Any) -> Any:
        """Register a handler for incoming SGd OFR (MO-Forward-Short-Message).

        Handler receives ``(user_name, sc_address, sm_rp_ui)``. ``sm_rp_ui``
        is the raw SMS-SUBMIT TPDU bytes (`bytes`). Siphon auto-sends OFA
        (result 2001) after the handler returns.
        """
        return fn

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

    @staticmethod
    def on_command(command: str, application: str) -> Any:
        """Decorator factory matching Rust ``@diameter.on_command``.

        In tests, scripts can use this to mark a handler — the mock
        treats it as an identity decorator (returns the function
        unmodified). Test code can then dispatch by calling the function
        directly.
        """
        del command, application
        def _decorator(fn: Any) -> Any:
            return fn
        return _decorator

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


class MockSbi:
    """Mock SBI namespace for testing scripts that use ``from siphon import sbi``.

    Provides mock N5/Npcf policy authorization methods.

    Example::

        from siphon_sdk import mock_module
        mock_module.install()

        from siphon import sbi
        result = sbi.create_session(sip_call_id="call-1", ue_ipv4="10.0.0.1")
        assert result["authorized"] is True
    """

    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        self._next_session_id: int = 1
        self._authorized: bool = True

    def create_session(self, af_app_id: Optional[str] = None,
                       sip_call_id: Optional[str] = None,
                       supi: Optional[str] = None,
                       ue_ipv4: Optional[str] = None,
                       ue_ipv6: Optional[str] = None,
                       dnn: Optional[str] = None,
                       notif_uri: Optional[str] = None,
                       media_type: str = "AUDIO",
                       flow_status: str = "ENABLED") -> Optional[dict]:
        """Create an N5 app session for QoS policy authorization.

        Args:
            af_app_id: Application Function identifier.
            sip_call_id: SIP Call-ID for correlation.
            supi: Subscription Permanent Identifier.
            ue_ipv4: UE IPv4 address.
            ue_ipv6: UE IPv6 address.
            dnn: Data Network Name.
            notif_uri: Notification URI for PCF events.
            media_type: Media type (default ``"AUDIO"``).
            flow_status: Flow status (default ``"ENABLED"``).

        Returns:
            Dict with ``app_session_id`` and ``authorized``, or ``None``.
        """
        session_id = f"mock-n5-{self._next_session_id}"
        self._next_session_id += 1
        self._sessions[session_id] = {
            "sip_call_id": sip_call_id,
            "ue_ipv4": ue_ipv4,
        }
        return {"app_session_id": session_id, "authorized": self._authorized}

    def delete_session(self, session_id: str) -> bool:
        """Delete an N5 app session.

        Args:
            session_id: The app session ID from ``create_session()``.

        Returns:
            ``True`` on success, ``False`` if session not found.
        """
        return self._sessions.pop(session_id, None) is not None

    def update_session(self, session_id: str,
                       media_type: str = "AUDIO",
                       flow_status: str = "ENABLED") -> Optional[dict]:
        """Update an N5 app session (media renegotiation).

        Args:
            session_id: The app session ID to update.
            media_type: Media type (default ``"AUDIO"``).
            flow_status: Flow status (default ``"ENABLED"``).

        Returns:
            Dict with ``app_session_id`` and ``authorized``, or ``None``.
        """
        if session_id not in self._sessions:
            return None
        return {"app_session_id": session_id, "authorized": self._authorized}

    @staticmethod
    def on_event(fn: Any) -> Any:
        """Register a handler for incoming PCF event notifications (N5).

        Handler receives a dict with event notification data.

        Example::

            @sbi.on_event
            def handle_pcf_event(event):
                for notif in event.get("ev_notifs", []):
                    log.info(f"PCF event: {notif['event']}")
        """
        return fn

    def set_authorized(self, authorized: bool) -> None:
        """Configure whether ``create_session`` returns authorized (test helper).

        Args:
            authorized: Whether sessions should be authorized.
        """
        self._authorized = authorized

    def clear(self) -> None:
        """Reset all mock sessions (test helper)."""
        self._sessions.clear()
        self._next_session_id = 1
        self._authorized = True


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

    def activate(self) -> None:
        if self.is_cleaned:
            raise ValueError("PendingSA already cleaned up")
        self.is_active = True

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
                       protocol: str = "udp") -> MockPendingSA:
        if not transform.compatible_with(offer):
            raise ValueError(
                f"transform {transform!r} not compatible with offer alg={offer.alg!r}"
                f" ealg={offer.ealg!r}"
            )
        # Same validation as the Rust binding so scripts fail identically
        # in unit tests.  ESP-over-UDP is the default; ESP-over-TCP is
        # required for UEs that did the initial REGISTER over TCP
        # (3GPP TS 33.203 §7.2).
        proto_lower = protocol.lower()
        if proto_lower not in ("udp", "tcp"):
            raise ValueError(
                f"protocol must be 'udp' or 'tcp', got {protocol!r}"
            )
        av._take()  # raises ValueError if already consumed
        if self._allocate_should_fail is not None:
            raise self._allocate_should_fail(self._allocate_failure_message)
        return MockPendingSA(
            transform, offer, self.pcscf_port_c, self.pcscf_port_s,
            expires_secs=expires_secs, protocol=proto_lower,
        )

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
# SDP namespace
# ---------------------------------------------------------------------------

from siphon_sdk.sdp import MockSdpNamespace

_sdp = MockSdpNamespace()


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
    mod.sdp = _sdp  # type: ignore[attr-defined]

    # IPsec types — exposed at top level so scripts can do
    # `from siphon import Transform, SecurityOffer, …` (matching the
    # Rust binding's `module.add_class::<…>()` registration).
    mod.Transform = _TransformEnum  # type: ignore[attr-defined]
    mod.SecurityOffer = MockSecurityOffer  # type: ignore[attr-defined]
    mod.AuthVectorHandle = MockAuthVectorHandle  # type: ignore[attr-defined]
    mod.PendingSA = MockPendingSA  # type: ignore[attr-defined]
    mod.SecurityServerParams = MockSecurityServerParams  # type: ignore[attr-defined]
    mod.SAHandle = MockSAHandle  # type: ignore[attr-defined]

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
    _auth._allow = False
    _auth._credentials.clear()
    _proxy._utils._rate_limit_allow = True
    _proxy._utils._sanity_check_pass = True
    _proxy._utils._enum_results.clear()
    _proxy._utils._memory_pct = 25


def get_registry() -> _HandlerRegistry:
    """Access the handler registry (test helper)."""
    return _registry


def get_proxy() -> MockProxy:
    """Access the mock proxy singleton."""
    return _proxy


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
