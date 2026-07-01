"""
Test harness for SMPP scripts (siphon-smpp extension).

Mirrors :class:`siphon_sdk.testing.SipTestHarness` for the ``smpp`` namespace:
install the mock module, load a script (registering its ``@smpp.*``
decorators), then drive binds / PDUs / lifecycle events into the registered
handlers and assert on the returned replies and recorded outbound sends.

Example::

    from siphon_sdk.smpp_testing import SmppTestHarness

    harness = SmppTestHarness()
    harness.load_source('''
    from siphon import smpp

    @smpp.on_bind
    def authorise(bind):
        return bind.accept() if bind.password == "s3cret" else bind.reject("ESME_RINVPASWD")

    @smpp.on_pdu("submit_sm")
    def on_submit(pdu, session):
        return pdu.reply(message_id="msg-1")
    ''')

    assert harness.bind("esme1", password="s3cret")
    reply = harness.submit_sm(source_addr="15550100", destination_addr="15550101",
                              short_message=b"hi")
    assert reply.ok and reply.message_id == "msg-1"
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Optional, Union

from siphon_sdk import mock_module
from siphon_sdk.smpp import (
    MockAlertNotification,
    MockBind,
    MockBindResult,
    MockPdu,
    MockPduReply,
    MockSession,
    MockSmpp,
)


class SmppTestHarness:
    """High-level test harness for SMPP scripts.

    Installs the mock ``siphon`` module, loads scripts, and dispatches mock
    binds / PDUs / session events to the handlers registered via
    ``@smpp.on_bind`` / ``@smpp.on_pdu(...)`` / ``@smpp.on_session(...)``.
    """

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        """Create a harness.

        Args:
            config: Optional ``smpp`` config dict (shape mirrors
                ``src/install.rs::build_config_dict`` — ``server`` / ``binds``
                / ``routing``). Drives ``smpp.config()`` / ``smpp.binds()`` /
                ``smpp.bind_address()`` / ``smpp.routing_rules()``.
        """
        mock_module.reset()
        self._module = mock_module.install()
        self._loop = asyncio.new_event_loop()
        if config is not None:
            mock_module.get_smpp().set_config(config)

    # -- accessors ----------------------------------------------------------

    @property
    def smpp(self) -> MockSmpp:
        """The mock ``smpp`` namespace (e.g. ``harness.smpp.set_query_result(...)``)."""
        return mock_module.get_smpp()

    @property
    def sent(self) -> list[tuple[str, dict[str, Any]]]:
        """Recorded outbound/inbound sends — ``(op, kwargs)`` tuples."""
        return mock_module.get_smpp().sent

    @property
    def log(self) -> Any:
        """Captured log messages (``harness.log.messages``)."""
        return mock_module.get_log()

    @property
    def cache(self) -> Any:
        """The mock cache (pre-populate with ``harness.cache.set_data(...)``)."""
        return mock_module.get_cache()

    def reset(self) -> None:
        """Reset all mock state between tests."""
        mock_module.reset()

    def close(self) -> None:
        """Close the harness event loop."""
        self._loop.close()

    # -- script loading -----------------------------------------------------

    def load_script(self, path: str) -> None:
        """Load and execute an SMPP script file, registering its handlers."""
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
        """Load an SMPP script from a string (inline test scripts)."""
        code = compile(source, name, "exec")
        exec(code, {"__name__": "__siphon_script__", "__file__": name})

    # -- dispatch -----------------------------------------------------------

    def _run(self, coro_or_value: Any) -> Any:
        if asyncio.iscoroutine(coro_or_value):
            return self._loop.run_until_complete(coro_or_value)
        return coro_or_value

    def bind(self, system_id: str, *, password: str = "",
             client_addr: str = "203.0.113.5:5000"
             ) -> Union[MockBindResult, bool]:
        """Dispatch a ``bind_transceiver`` to the ``@smpp.on_bind`` handler.

        Returns the handler's result (a :class:`MockBindResult`, or a bare
        truthy/falsy). With no handler, returns a reject
        :class:`MockBindResult` — binds are closed by default.
        """
        bind_obj = MockBind(system_id=system_id, password=password,
                            client_addr=client_addr)
        handlers = mock_module.get_registry().handlers.get("smpp.on_bind", [])
        if not handlers:
            return MockBindResult(accept=False, status="ESME_RBINDFAIL",
                                  reason="no @smpp.on_bind handler")
        _filter, fn, _is_async, _meta = handlers[-1]
        return self._run(fn(bind_obj))

    def _dispatch_pdu(self, command: str, pdu: MockPdu,
                      session: MockSession) -> Optional[MockPduReply]:
        result: Optional[MockPduReply] = None
        ran = False
        for _filter, fn, _is_async, meta in \
                mock_module.get_registry().handlers.get("smpp.on_pdu", []):
            if not meta or meta.get("command") != command:
                continue
            ran = True
            result = self._run(fn(pdu, session))
        if not ran:
            return None
        # None from a handler == a default ESME_ROK reply (runtime semantics).
        return result if result is not None else MockPduReply()

    def _session(self, kind: str, session_id: str, system_id: str,
                 client_addr: str) -> MockSession:
        return MockSession(kind=kind, session_id=session_id,
                           system_id=system_id, client_addr=client_addr)

    def submit_sm(self, *, session_id: str = "esme-1", system_id: str = "esme1",
                  client_addr: str = "203.0.113.5:5000",
                  **fields: Any) -> Optional[MockPduReply]:
        """Dispatch an inbound ``submit_sm`` to ``@smpp.on_pdu("submit_sm")``."""
        pdu = MockPdu(command="submit_sm", **fields)
        return self._dispatch_pdu("submit_sm", pdu,
                                  self._session("esme", session_id, system_id, client_addr))

    def submit_sm_multi(self, *, session_id: str = "esme-1", system_id: str = "esme1",
                        client_addr: str = "203.0.113.5:5000",
                        **fields: Any) -> Optional[MockPduReply]:
        """Dispatch an inbound ``submit_sm_multi`` (destinations in ``fields``)."""
        pdu = MockPdu(command="submit_sm_multi", **fields)
        return self._dispatch_pdu("submit_sm_multi", pdu,
                                  self._session("esme", session_id, system_id, client_addr))

    def deliver_sm(self, *, session_id: str = "bind-1", system_id: str = "carrier",
                   client_addr: str = "198.51.100.7:2775",
                   **fields: Any) -> Optional[MockPduReply]:
        """Dispatch an outbound-bind ``deliver_sm`` (MT/MO/DLR) to
        ``@smpp.on_pdu("deliver_sm")``. Set ``esm_class=0x04`` + a receipt body
        for a DLR (``pdu.is_dlr`` / ``pdu.receipt``)."""
        pdu = MockPdu(command="deliver_sm", **fields)
        return self._dispatch_pdu("deliver_sm", pdu,
                                  self._session("bind", session_id, system_id, client_addr))

    def data_sm(self, *, kind: str = "esme", session_id: str = "esme-1",
                system_id: str = "esme1", client_addr: str = "203.0.113.5:5000",
                **fields: Any) -> Optional[MockPduReply]:
        """Dispatch a ``data_sm`` to ``@smpp.on_pdu("data_sm")``."""
        pdu = MockPdu(command="data_sm", **fields)
        return self._dispatch_pdu("data_sm", pdu,
                                  self._session(kind, session_id, system_id, client_addr))

    def cancel_sm(self, *, message_id: str, session_id: str = "esme-1",
                  system_id: str = "esme1", client_addr: str = "203.0.113.5:5000",
                  **fields: Any) -> Optional[MockPduReply]:
        """Dispatch an inbound ``cancel_sm`` to ``@smpp.on_pdu("cancel_sm")``."""
        pdu = MockPdu(command="cancel_sm", message_id=message_id, **fields)
        return self._dispatch_pdu("cancel_sm", pdu,
                                  self._session("esme", session_id, system_id, client_addr))

    def query_sm(self, *, message_id: str, session_id: str = "esme-1",
                 system_id: str = "esme1", client_addr: str = "203.0.113.5:5000",
                 **fields: Any) -> Optional[MockPduReply]:
        """Dispatch an inbound ``query_sm`` to ``@smpp.on_pdu("query_sm")``
        (reply via ``pdu.reply_query(...)``)."""
        pdu = MockPdu(command="query_sm", message_id=message_id, **fields)
        return self._dispatch_pdu("query_sm", pdu,
                                  self._session("esme", session_id, system_id, client_addr))

    def replace_sm(self, *, message_id: str, session_id: str = "esme-1",
                   system_id: str = "esme1", client_addr: str = "203.0.113.5:5000",
                   **fields: Any) -> Optional[MockPduReply]:
        """Dispatch an inbound ``replace_sm`` to ``@smpp.on_pdu("replace_sm")``."""
        pdu = MockPdu(command="replace_sm", message_id=message_id, **fields)
        return self._dispatch_pdu("replace_sm", pdu,
                                  self._session("esme", session_id, system_id, client_addr))

    def alert_notification(self, *, session_id: str = "bind-1",
                           system_id: str = "carrier",
                           client_addr: str = "198.51.100.7:2775",
                           **fields: Any) -> Optional[MockPduReply]:
        """Dispatch an ``alert_notification`` to
        ``@smpp.on_pdu("alert_notification")``. The handler's first arg is a
        :class:`MockAlertNotification`."""
        alert = MockAlertNotification(**fields)
        session = self._session("bind", session_id, system_id, client_addr)
        result: Optional[MockPduReply] = None
        for _filter, fn, _is_async, meta in \
                mock_module.get_registry().handlers.get("smpp.on_pdu", []):
            if not meta or meta.get("command") != "alert_notification":
                continue
            result = self._run(fn(alert, session))
        return result

    def session_event(self, event: str, *, kind: str = "esme",
                      session_id: str = "esme-1", system_id: str = "esme1",
                      client_addr: str = "203.0.113.5:5000") -> None:
        """Fire a ``@smpp.on_session(event)`` lifecycle hook (``event`` is
        ``"bound"`` or ``"unbound"``)."""
        session = self._session(kind, session_id, system_id, client_addr)
        for method_filter, fn, _is_async, meta in \
                mock_module.get_registry().handlers.get("smpp.on_session", []):
            hook_event = (meta or {}).get("event", method_filter)
            if hook_event != event:
                continue
            self._run(fn(session))
