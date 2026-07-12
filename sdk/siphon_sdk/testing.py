"""
Test harness for SIPhon scripts.

Provides :class:`SipTestHarness` — a high-level API for loading scripts,
sending mock SIP messages, and asserting on the results.

Example::

    from siphon_sdk.testing import SipTestHarness

    harness = SipTestHarness()
    harness.load_script("scripts/proxy_default.py")

    # Pre-populate registrar
    harness.registrar.add_contact(
        "sip:alice@example.com",
        Contact(uri="sip:alice@192.168.1.5:5060"),
    )

    # Send INVITE and check result
    result = harness.send_request("INVITE", "sip:alice@example.com")
    assert result.action == "fork"
    assert "sip:alice@192.168.1.5:5060" in result.targets
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from siphon_sdk.types import Action, ByeInitiator, Contact, SipUri
from siphon_sdk.request import Request, _parse_uri
from siphon_sdk.reply import Reply
from siphon_sdk.call import Call
from siphon_sdk import mock_module


@dataclass
class RequestResult:
    """Result of sending a request through the harness.

    Provides convenient access to the primary action the handler took,
    plus the full list of actions and the request/reply objects.
    """

    request: Request
    """The request object that was passed to the handler."""

    actions: list[Action] = field(default_factory=list)
    """All actions the handler took (reply, relay, fork, etc.)."""

    @property
    def action(self) -> str:
        """The primary action kind (last action), or ``"silent_drop"``."""
        if not self.actions:
            return "silent_drop"
        return self.actions[-1].kind

    @property
    def status_code(self) -> Optional[int]:
        """Status code from the last reply/reject action, or ``None``."""
        for a in reversed(self.actions):
            if a.status_code is not None:
                return a.status_code
        return None

    @property
    def reason(self) -> Optional[str]:
        """Reason phrase from the last reply/reject action."""
        for a in reversed(self.actions):
            if a.reason is not None:
                return a.reason
        return None

    @property
    def targets(self) -> Optional[list[str]]:
        """Fork/dial targets from the last fork action."""
        for a in reversed(self.actions):
            if a.targets is not None:
                return a.targets
        return None

    @property
    def strategy(self) -> Optional[str]:
        """Fork strategy from the last fork action."""
        for a in reversed(self.actions):
            if a.strategy is not None:
                return a.strategy
        return None

    @property
    def next_hop(self) -> Optional[str]:
        """Next-hop from the last relay action."""
        for a in reversed(self.actions):
            if a.kind == "relay":
                return a.next_hop
        return None

    @property
    def was_relayed(self) -> bool:
        """``True`` if the handler called ``relay()``."""
        return any(a.kind == "relay" for a in self.actions)

    @property
    def was_forked(self) -> bool:
        """``True`` if the handler called ``fork()``."""
        return any(a.kind == "fork" for a in self.actions)

    @property
    def was_dropped(self) -> bool:
        """``True`` if the handler returned without any terminal action
        (silent drop semantics)."""
        return self.action == "silent_drop"

    @property
    def record_routed(self) -> bool:
        """``True`` if ``record_route()`` was called."""
        return any(a.kind == "record_route" for a in self.actions)


@dataclass
class ReplyResult:
    """Result of sending a reply through the harness."""

    reply: Reply
    """The reply object passed to the handler."""

    actions: list[Action] = field(default_factory=list)

    @property
    def action(self) -> str:
        if not self.actions:
            return "silent_drop"
        return self.actions[-1].kind

    @property
    def was_relayed(self) -> bool:
        return any(a.kind == "relay" for a in self.actions)


@dataclass
class CallResult:
    """Result of sending a B2BUA event through the harness."""

    call: Call
    """The call object passed to the handler."""

    actions: list[Action] = field(default_factory=list)

    @property
    def action(self) -> str:
        if not self.actions:
            return "silent_drop"
        return self.actions[-1].kind

    @property
    def status_code(self) -> Optional[int]:
        for a in reversed(self.actions):
            if a.status_code is not None:
                return a.status_code
        return None

    @property
    def targets(self) -> Optional[list[str]]:
        for a in reversed(self.actions):
            if a.targets is not None:
                return a.targets
        return None

    @property
    def was_rejected(self) -> bool:
        return any(a.kind == "reject" for a in self.actions)

    @property
    def was_terminated(self) -> bool:
        return any(a.kind == "terminate" for a in self.actions)


class SipTestHarness:
    """High-level test harness for SIPhon scripts.

    Usage::

        harness = SipTestHarness(local_domains=["example.com"])
        harness.load_script("scripts/proxy_default.py")

        result = harness.send_request("REGISTER", "sip:alice@example.com",
                                      from_uri="sip:alice@example.com")
        assert result.status_code == 401

    The harness:
    1. Installs the mock ``siphon`` module
    2. Loads and executes user scripts (registering their decorators)
    3. Dispatches mock SIP messages to registered handlers
    4. Returns structured results for assertion
    """

    def __init__(
        self,
        local_domains: Optional[list[str]] = None,
    ) -> None:
        """Create a new test harness.

        Args:
            local_domains: List of domains considered local (for
                           ``request.ruri.is_local``).  Default: ``["example.com"]``.
        """
        self._local_domains = local_domains or ["example.com"]
        # Start from a clean slate so handlers from a previous harness /
        # previous test don't accumulate across ``load_script`` calls.
        mock_module.reset()
        self._module = mock_module.install()
        self._loop = asyncio.new_event_loop()
        self._hss: Optional[MockHss] = None
        self._pcrf: Optional[MockPcrf] = None

    @property
    def registrar(self) -> mock_module.MockRegistrar:
        """Access the mock registrar to pre-populate contacts."""
        return mock_module._registrar

    @property
    def auth(self) -> mock_module.MockAuth:
        """Access the mock auth to control authentication behavior."""
        return mock_module._auth

    @property
    def log(self) -> mock_module.MockLog:
        """Access captured log messages."""
        return mock_module._log

    @property
    def cache(self) -> mock_module.MockCache:
        """Access the mock cache to pre-populate data."""
        return mock_module._cache

    @property
    def rtpengine(self) -> mock_module.MockRtpEngine:
        """Access the mock RTPEngine to inspect operations."""
        return mock_module._rtpengine

    @property
    def proxy(self) -> mock_module.MockProxy:
        """Access the mock proxy namespace (e.g. for _utils config)."""
        return mock_module._proxy

    @property
    def b2bua(self) -> mock_module.MockB2bua:
        """Access the mock b2bua namespace to inspect ``terminates``."""
        return mock_module._b2bua

    @property
    def presence(self) -> mock_module.MockPresence:
        """Access the mock presence store."""
        return mock_module._presence

    def reset(self) -> None:
        """Reset all mock state between tests.

        Clears: handlers, registrar, auth, cache, log, rtpengine.
        """
        mock_module.reset()

    def load_script(self, path: str) -> None:
        """Load and execute a SIPhon script, registering its handlers.

        Args:
            path: Path to the Python script file.

        Raises:
            FileNotFoundError: If the script file doesn't exist.
        """
        script_path = Path(path).resolve()
        if not script_path.exists():
            raise FileNotFoundError(f"Script not found: {script_path}")

        # Add script directory to sys.path so relative imports work
        script_dir = str(script_path.parent)
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)

        source = script_path.read_text()
        code = compile(source, str(script_path), "exec")
        exec(code, {"__name__": "__siphon_script__", "__file__": str(script_path)})

    def load_source(self, source: str, name: str = "<test>") -> None:
        """Load a script from a string (useful for inline test scripts).

        Args:
            source: Python source code.
            name: Module name for error messages.
        """
        code = compile(source, name, "exec")
        exec(code, {"__name__": "__siphon_script__", "__file__": name})

    def send_request(
        self,
        method: str = "INVITE",
        ruri: Union[str, SipUri] = "sip:bob@example.com",
        *,
        from_uri: Union[str, SipUri, None] = "sip:alice@example.com",
        to_uri: Union[str, SipUri, None] = None,
        from_tag: Optional[str] = None,
        to_tag: Optional[str] = None,
        call_id: Optional[str] = None,
        cseq: Optional[tuple[int, str]] = None,
        max_forwards: int = 70,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        transport: str = "udp",
        source_ip: str = "127.0.0.1",
        user_agent: Optional[str] = None,
        auth_user: Optional[str] = None,
        contact_expires: Optional[int] = None,
        event: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> RequestResult:
        """Send a mock SIP request and return the handler's result.

        Dispatches to handlers registered via ``@proxy.on_request``.

        Args:
            method: SIP method (e.g. ``"INVITE"``, ``"REGISTER"``).
            ruri: Request-URI.
            from_uri: From header URI.
            to_uri: To header URI (defaults to ``ruri``).
            from_tag: From-tag (auto-generated if ``None``).
            to_tag: To-tag (``None`` for initial requests).
            call_id: Call-ID (auto-generated if ``None``).
            cseq: CSeq tuple (auto-generated if ``None``).
            max_forwards: Max-Forwards value.
            body: Message body bytes.
            content_type: Content-Type header.
            transport: Transport protocol.
            source_ip: Source IP address.
            user_agent: User-Agent header.
            auth_user: Pre-authenticated username.
            contact_expires: Contact expires value.
            event: Event header value.
            headers: Additional headers dict.

        Returns:
            :class:`RequestResult` with action details and assertions.
        """
        parsed_ruri = _parse_uri(ruri) or SipUri()
        # Mark as local if domain matches
        if parsed_ruri.host in self._local_domains:
            parsed_ruri._is_local = True

        # For REGISTER, the To header is the AoR being registered — by
        # convention the same as From (RFC 3261 §10.2).  For other methods
        # the default is the R-URI (the callee).
        default_to_uri = from_uri if method == "REGISTER" else ruri

        request = Request(
            method=method,
            ruri=parsed_ruri,
            from_uri=from_uri,
            to_uri=to_uri or default_to_uri,
            from_tag=from_tag,
            to_tag=to_tag,
            call_id=call_id,
            cseq=cseq,
            max_forwards=max_forwards,
            body=body,
            content_type=content_type,
            transport=transport,
            source_ip=source_ip,
            user_agent=user_agent,
            auth_user=auth_user,
            contact_expires=contact_expires,
            event=event,
            headers=headers,
        )

        # --- Test harness only: simulate Rust dispatcher pre-checks ---
        # In production these never reach Python — the Rust transaction
        # layer handles them before script dispatch.  We replicate the
        # behaviour here so SDK tests can assert on the expected outcome.
        if request.max_forwards == 0:
            request.reply(483, "Too Many Hops")
            return RequestResult(request=request, actions=list(request.actions))

        if method == "CANCEL":
            request.relay()
            return RequestResult(request=request, actions=list(request.actions))

        registry = mock_module.get_registry()
        handlers = registry.get("proxy.on_request", method)

        for fn, is_async in handlers:
            if is_async:
                self._loop.run_until_complete(fn(request))
            else:
                fn(request)

        return RequestResult(request=request, actions=list(request.actions))

    def send_reply(
        self,
        request: Optional[Request] = None,
        status_code: int = 200,
        reason: str = "OK",
        *,
        from_uri: Union[str, SipUri, None] = None,
        to_uri: Union[str, SipUri, None] = None,
        call_id: Optional[str] = None,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> ReplyResult:
        """Send a mock SIP reply and return the handler's result.

        Dispatches to handlers registered via ``@proxy.on_reply``.

        Args:
            request: Original request (auto-created if ``None``).
            status_code: SIP status code (e.g. 200, 404).
            reason: Reason phrase.
            from_uri: From URI.
            to_uri: To URI.
            call_id: Call-ID.
            body: Response body.
            content_type: Content-Type.
            headers: Additional headers.

        Returns:
            :class:`ReplyResult` with action details.
        """
        if request is None:
            request = Request()

        reply = Reply(
            status_code=status_code,
            reason=reason,
            from_uri=from_uri or request.from_uri,
            to_uri=to_uri or request.to_uri,
            call_id=call_id or request.call_id,
            body=body,
            content_type=content_type,
            headers=headers,
        )

        registry = mock_module.get_registry()
        handlers = registry.get("proxy.on_reply")

        for fn, is_async in handlers:
            if is_async:
                self._loop.run_until_complete(fn(request, reply))
            else:
                fn(request, reply)

        return ReplyResult(reply=reply, actions=list(reply.actions))

    def send_cancel(self, request: Optional[Request] = None, **kwargs: Any) -> RequestResult:
        """Dispatch a CANCEL teardown to ``@proxy.on_cancel`` handlers.

        Simulates a relayed INVITE being CANCELled before any final response.
        The handler receives the original INVITE ``request``. Fire-and-forget:
        there is no reply/relay gating — assert on side effects (e.g.
        ``harness.rtpengine`` deletes, ``harness.diameter`` Rx STR).

        Args:
            request: Original INVITE (auto-created with ``method="INVITE"`` if
                ``None``).
            **kwargs: Passed to the :class:`Request` constructor when
                auto-creating.
        """
        if request is None:
            request = Request(method="INVITE", **kwargs)

        registry = mock_module.get_registry()
        handlers = registry.get("proxy.on_cancel")

        for fn, is_async in handlers:
            if is_async:
                self._loop.run_until_complete(fn(request))
            else:
                fn(request)

        return RequestResult(request=request, actions=list(request.actions))

    def send_invite(self, call: Optional[Call] = None, **kwargs: Any) -> CallResult:
        """Send a B2BUA INVITE event.

        Args:
            call: Call object (auto-created if ``None``).
            **kwargs: Passed to :class:`Call` constructor.

        Returns:
            :class:`CallResult` with action details.
        """
        if call is None:
            call = Call(**kwargs)

        registry = mock_module.get_registry()
        handlers = registry.get("b2bua.on_invite")

        for fn, is_async in handlers:
            if is_async:
                self._loop.run_until_complete(fn(call))
            else:
                fn(call)

        return CallResult(call=call, actions=list(call.actions))

    def send_answer(self, call: Optional[Call] = None, **kwargs: Any) -> CallResult:
        """Send a B2BUA answer event."""
        if call is None:
            call = Call(state="answered", **kwargs)

        from siphon_sdk.reply import Reply
        import inspect

        answer_reply = Reply(
            status_code=200,
            from_uri=call.from_uri,
            to_uri=call.to_uri,
            call_id=call.call_id,
        )

        registry = mock_module.get_registry()
        handlers = registry.get("b2bua.on_answer")

        for fn, is_async in handlers:
            sig = inspect.signature(fn)
            args = (call, answer_reply) if len(sig.parameters) >= 2 else (call,)
            if is_async:
                self._loop.run_until_complete(fn(*args))
            else:
                fn(*args)

        return CallResult(call=call, actions=list(call.actions))

    def send_failure(
        self,
        call: Optional[Call] = None,
        code: int = 486,
        reason: str = "Busy Here",
        **kwargs: Any,
    ) -> CallResult:
        """Send a B2BUA failure event.

        Args:
            call: Call object.
            code: Failure status code.
            reason: Failure reason phrase.
        """
        if call is None:
            call = Call(**kwargs)

        registry = mock_module.get_registry()
        handlers = registry.get("b2bua.on_failure")

        for fn, is_async in handlers:
            if is_async:
                self._loop.run_until_complete(fn(call, code, reason))
            else:
                fn(call, code, reason)

        return CallResult(call=call, actions=list(call.actions))

    def send_bye(
        self,
        call: Optional[Call] = None,
        initiator_side: str = "a",
        **kwargs: Any,
    ) -> CallResult:
        """Send a B2BUA BYE event.

        Args:
            call: Call object.
            initiator_side: ``"a"`` (caller) or ``"b"`` (callee).
        """
        if call is None:
            call = Call(state="answered", **kwargs)

        initiator = ByeInitiator(side=initiator_side)
        registry = mock_module.get_registry()
        handlers = registry.get("b2bua.on_bye")

        for fn, is_async in handlers:
            if is_async:
                self._loop.run_until_complete(fn(call, initiator))
            else:
                fn(call, initiator)

        return CallResult(call=call, actions=list(call.actions))

    def send_call_cancel(self, call: Optional[Call] = None, **kwargs: Any) -> CallResult:
        """Dispatch a CANCEL teardown to ``@b2bua.on_cancel`` handlers.

        Simulates an unanswered call (Calling/Ringing) being CANCELled. The
        handler receives the :class:`Call`. Fire-and-forget — assert on side
        effects (e.g. ``harness.rtpengine`` deletes).

        Args:
            call: Call object (auto-created in ``state="ringing"`` if ``None``).
            **kwargs: Passed to the :class:`Call` constructor when
                auto-creating.
        """
        if call is None:
            call = Call(state="ringing", **kwargs)

        registry = mock_module.get_registry()
        handlers = registry.get("b2bua.on_cancel")

        for fn, is_async in handlers:
            if is_async:
                self._loop.run_until_complete(fn(call))
            else:
                fn(call)

        return CallResult(call=call, actions=list(call.actions))

    @property
    def diameter(self) -> mock_module.MockDiameter:
        """Access the mock Diameter namespace (Cx/Rx operations)."""
        return mock_module._diameter

    @property
    def gateway(self) -> mock_module.MockGateway:
        """Access the mock gateway namespace."""
        return mock_module._gateway

    @property
    def li(self) -> mock_module.MockLi:
        """Access the mock lawful intercept namespace."""
        return mock_module._li

    @property
    def hss(self) -> MockHss:
        """Access a convenience MockHss wired to this harness.

        Lazily created on first access.
        """
        if self._hss is None:
            self._hss = MockHss(self)
        return self._hss

    @property
    def pcrf(self) -> MockPcrf:
        """Access a convenience MockPcrf wired to this harness.

        Lazily created on first access.
        """
        if self._pcrf is None:
            self._pcrf = MockPcrf(self)
        return self._pcrf

    def close(self) -> None:
        """Clean up the event loop."""
        self._loop.close()

    def __enter__(self) -> SipTestHarness:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# MockHss — convenience mock for IMS HSS (Diameter Cx)
# ---------------------------------------------------------------------------

class MockHss:
    """High-level mock HSS for IMS script testing.

    Combines subscriber data management with automated Diameter Cx response
    generation.  Wires into ``MockDiameter`` and ``MockAuth`` so test scripts
    get realistic IMS registration and routing flows.

    Usage::

        harness = SipTestHarness(local_domains=["ims.example.com"])
        hss = harness.hss

        hss.add_subscriber(
            impi="alice@ims.example.com",
            impu="sip:alice@ims.example.com",
            server_name="sip:scscf.ims.example.com:6060",
        )
        harness.load_script("examples/ims_icscf.py")

        result = harness.send_request("REGISTER", "sip:ims.example.com",
                                       from_uri="sip:alice@ims.example.com")
        assert result.was_relayed
        assert result.next_hop == "sip:scscf.ims.example.com:6060"
    """

    def __init__(self, harness: SipTestHarness) -> None:
        self._harness = harness
        self._diameter = mock_module._diameter
        self._auth = mock_module._auth
        self._subscribers: dict[str, dict] = {}  # impu -> subscriber data

    def add_subscriber(
        self,
        impi: str,
        impu: str,
        server_name: Optional[str] = None,
        ifc_xml: Optional[str] = None,
    ) -> None:
        """Register a subscriber in the mock HSS.

        This configures the mock Diameter Cx responses so that:
        - ``diameter.cx_uar(impu)`` returns the assigned ``server_name``
        - ``diameter.cx_lir(impu)`` returns the serving ``server_name``
        - ``diameter.cx_sar(impu)`` returns success with ``ifc_xml``
        - ``auth.require_aka_digest()`` / ``auth.require_ims_digest()``
          auto-passes (returns ``True``)

        Args:
            impi: IMS Private Identity (e.g. ``"alice@ims.example.com"``).
            impu: IMS Public Identity (e.g. ``"sip:alice@ims.example.com"``).
            server_name: Assigned S-CSCF URI.
            ifc_xml: Initial Filter Criteria XML for the user profile.
        """
        self._subscribers[impu] = {
            "impi": impi,
            "server_name": server_name,
            "ifc_xml": ifc_xml,
        }

        # Configure Diameter Cx responses
        if server_name:
            self._diameter.set_uar_response(impu, result_code=2001,
                                            server_name=server_name)
            self._diameter.set_lir_response(impu, result_code=2001,
                                            server_name=server_name)
        self._diameter.set_sar_response(impu, result_code=2001,
                                        user_data=ifc_xml)

        # Ensure at least one HSS peer appears connected
        self._diameter.add_peer("hss1", connected=True)

        # Auto-pass authentication challenges
        self._auth._allow = True

    def remove_subscriber(self, impu: str) -> None:
        """Remove a subscriber from the mock HSS.

        Args:
            impu: IMS Public Identity to remove.
        """
        self._subscribers.pop(impu, None)
        self._diameter._uar_responses.pop(impu, None)
        self._diameter._sar_responses.pop(impu, None)
        self._diameter._lir_responses.pop(impu, None)

    def set_auth_failure(self, impu: str) -> None:
        """Configure authentication to fail for a subscriber.

        Args:
            impu: IMS Public Identity.
        """
        self._auth._allow = False

    def subscriber_count(self) -> int:
        """Number of registered subscribers."""
        return len(self._subscribers)

    def clear(self) -> None:
        """Remove all subscribers and reset Diameter/auth state."""
        self._subscribers.clear()
        self._diameter.clear()
        self._auth._allow = False


# ---------------------------------------------------------------------------
# MockPcrf — convenience mock for IMS PCRF (Diameter Rx)
# ---------------------------------------------------------------------------

class MockPcrf:
    """High-level mock PCRF for IMS P-CSCF testing.

    Simulates a Policy and Charging Rules Function for Rx interface testing.
    Configures ``MockDiameter`` Rx responses for QoS resource operations.

    Usage::

        harness = SipTestHarness(local_domains=["ims.example.com"])
        pcrf = harness.pcrf

        # PCRF will accept all AAR requests
        pcrf.accept_all()

        # Or reject specific sessions
        pcrf.reject_session("rx-sess-1", result_code=5003)
    """

    def __init__(self, harness: SipTestHarness) -> None:
        self._harness = harness
        self._diameter = mock_module._diameter

    def accept_all(self) -> None:
        """Configure the PCRF to accept all Rx AAR requests with 2001."""
        self._diameter._default_rx_result_code = 2001
        self._diameter.add_peer("pcrf1", connected=True)

    def reject_all(self, result_code: int = 5003) -> None:
        """Configure the PCRF to reject all Rx AAR requests.

        Args:
            result_code: Diameter result code for rejection (default 5003 =
                         DIAMETER_AUTHORIZATION_REJECTED).
        """
        self._diameter._default_rx_result_code = result_code

    def reject_session(self, session_id: str, result_code: int = 5003) -> None:
        """Reject a specific Rx session.

        Args:
            session_id: Rx session ID to reject.
            result_code: Diameter result code.
        """
        self._diameter.set_aar_response(session_id, result_code=result_code)

    def clear(self) -> None:
        """Reset PCRF mock state."""
        self._diameter._aar_responses.clear()
        self._diameter._default_rx_result_code = 2001
