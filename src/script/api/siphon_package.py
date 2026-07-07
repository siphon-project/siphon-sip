"""
siphon — Python scripting API for SIPhon.

This module is injected into sys.modules by the Rust engine before any user
script runs.  It exposes the decorator-based API that scripts use:

    from siphon import proxy, registrar, b2bua, auth, log, cache
"""
import asyncio as _asyncio
import sys as _sys

# Ensure the registry is available.
import _siphon_registry as _registry


# ---------------------------------------------------------------------------
# Proxy namespace
# ---------------------------------------------------------------------------

class _ProxyNamespace:
    """Namespace for stateful/stateless proxy event handlers.

    Decorator methods (on_request, on_reply, etc.) are defined here.
    Utility methods (send_request, rate_limit, sanity_check, etc.) live
    on the Rust-backed ``_utils`` attribute, injected at startup.
    ``__getattr__`` delegates unknown attributes to ``_utils`` so that
    ``proxy.send_request(...)`` works transparently.
    """

    def __init__(self):
        # Placeholder for proxy.subscribe_state — replaced at startup by the
        # Rust-backed SubscribeStateNamespace.  Keeps decorator-time access
        # from AttributeError-ing before the Rust namespace is installed.
        self.subscribe_state = _SubscribeStateStub()

    def __getattr__(self, name):
        utils = object.__getattribute__(self, "__dict__").get("_utils")
        if utils is not None:
            return getattr(utils, name)
        raise AttributeError(f"proxy.{name}() not available — proxy utils not initialized")

    def on_request(self, fn_or_filter=None):
        """
        Register a handler for incoming SIP requests.

        Usage:
            @proxy.on_request              # all methods
            @proxy.on_request("REGISTER")  # single method
            @proxy.on_request("INVITE|SUBSCRIBE")  # pipe-separated
        """
        if fn_or_filter is None or callable(fn_or_filter):
            # @proxy.on_request or @proxy.on_request without parens
            fn = fn_or_filter
            if fn is not None:
                is_async = _asyncio.iscoroutinefunction(fn)
                _registry.register("proxy.on_request", None, fn, is_async)
                return fn
            # @proxy.on_request() — called with no args, return decorator
            def decorator(fn):
                is_async = _asyncio.iscoroutinefunction(fn)
                _registry.register("proxy.on_request", None, fn, is_async)
                return fn
            return decorator

        if isinstance(fn_or_filter, str):
            # @proxy.on_request("REGISTER")
            method_filter = fn_or_filter
            def decorator(fn):
                is_async = _asyncio.iscoroutinefunction(fn)
                _registry.register("proxy.on_request", method_filter, fn, is_async)
                return fn
            return decorator

        raise TypeError(
            f"proxy.on_request expects a callable or method filter string, "
            f"got {type(fn_or_filter).__name__}"
        )

    @staticmethod
    def on_reply(fn):
        """
        Register a handler for SIP replies (responses).

        Usage:
            @proxy.on_reply
            def handle_reply(request, reply):
                ...
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_reply", None, fn, is_async)
        return fn

    @staticmethod
    def on_failure(fn):
        """
        Register a handler for proxy failure (all branches failed).

        Usage:
            @proxy.on_failure
            def failure_route(request, reply):
                ...
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_failure", None, fn, is_async)
        return fn

    @staticmethod
    def on_cancel(fn):
        """
        Register a handler for a CANCELled INVITE (RFC 3261 §9).

        Fires once, with the original INVITE, when a relayed INVITE is
        CANCELled before any final response — the one teardown that
        neither ``on_reply`` nor ``on_failure`` ever delivers (the proxy
        answers the CANCEL with 487 at the transaction layer and the call
        is gone). Use it to release per-call resources that no BYE will
        ever clear: Diameter Rx / N5 QoS sessions, rtpengine media
        anchors, charging correlation maps.

        It is fire-and-forget cleanup — it does not gate or alter the 487
        sent to the UAC, so there is no ``relay()``/``reply()`` decision.

        Usage:
            @proxy.on_cancel
            async def handle_cancel(request):
                await _release_qos(request.call_id)
                await rtpengine.delete(request)
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_cancel", None, fn, is_async)
        return fn

    @staticmethod
    def on_register_reply(fn):
        """
        Register a handler for REGISTER replies.

        Usage:
            @proxy.on_register_reply
            def handle_register_reply(request, reply):
                ...
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("proxy.on_register_reply", None, fn, is_async)
        return fn


# ---------------------------------------------------------------------------
# B2BUA namespace
# ---------------------------------------------------------------------------

class _B2buaNamespace:
    """Namespace for B2BUA call event handlers."""

    @staticmethod
    def on_invite(fn):
        """Register handler for new INVITE (new call)."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_invite", None, fn, is_async)
        return fn

    @staticmethod
    def on_early_media(fn):
        """Register handler for provisional response with SDP (183/180).

        Called when the B-leg sends a provisional response containing SDP
        (early media).  Use this to process the SDP through RTPEngine so
        early media is anchored correctly.

        Usage:
            @b2bua.on_early_media
            async def early_media(call, reply):
                await rtpengine.answer(reply)
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_early_media", None, fn, is_async)
        return fn

    @staticmethod
    def on_answer(fn):
        """Register handler for call answered (200 OK on B leg)."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_answer", None, fn, is_async)
        return fn

    @staticmethod
    def on_failure(fn):
        """Register handler for B leg failure."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_failure", None, fn, is_async)
        return fn

    @staticmethod
    def on_bye(fn):
        """Register handler for BYE (call ended)."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_bye", None, fn, is_async)
        return fn

    @staticmethod
    def on_refer(fn):
        """Register handler for REFER (call transfer, RFC 3515)."""
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_refer", None, fn, is_async)
        return fn

    @staticmethod
    def on_cancel(fn):
        """Register handler for a CANCELled call (RFC 3261 §9).

        Fires once, with the Call object, when an unanswered call
        (Calling/Ringing) is CANCELled — the teardown that ``on_failure``
        (B-leg error) and ``on_bye`` (answered call) never cover. A 2xx
        that wins the CANCEL/answer glare is ACK+BYE'd by the framework
        and never delivers ``on_answer``, so this hook only ever sees a
        genuinely abandoned call. Use it to release per-call resources
        that no BYE will clear: rtpengine media anchors, QoS sessions.

        Usage:
            @b2bua.on_cancel
            async def handle_cancel(call):
                await rtpengine.delete(call)
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("b2bua.on_cancel", None, fn, is_async)
        return fn


# ---------------------------------------------------------------------------
# Registrar namespace (stubs — wired to Rust in Phase 4)
# ---------------------------------------------------------------------------

class _RegistrarNamespace:
    """Namespace for registrar operations."""

    def save(self, request, force=False):
        raise NotImplementedError("registrar.save() not yet wired to Rust backend")

    def lookup(self, uri):
        raise NotImplementedError("registrar.lookup() not yet wired to Rust backend")

    def is_registered(self, uri):
        raise NotImplementedError("registrar.is_registered() not yet wired to Rust backend")

    def remove(self, uri):
        raise NotImplementedError("registrar.remove() not yet wired to Rust backend")

    @staticmethod
    def on_change(fn):
        """Register a handler for registration state changes.

        The handler receives (aor, event_type, contacts) where:
          - aor: str — Address of Record (e.g. "sip:alice@example.com")
          - event_type: str — "registered", "refreshed", "deregistered", or "expired"
          - contacts: list[Contact] — current contact bindings

        Usage:
            @registrar.on_change
            def on_reg_change(aor, event_type, contacts):
                ...
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("registrar.on_change", None, fn, is_async)
        return fn


# ---------------------------------------------------------------------------
# Auth namespace (stubs — wired to Rust in Phase 4)
# ---------------------------------------------------------------------------

class _AuthNamespace:
    """Namespace for authentication operations."""

    def require_www_digest(self, request, realm=None):
        raise NotImplementedError("auth.require_www_digest() not yet wired")

    def require_proxy_digest(self, request, realm=None):
        raise NotImplementedError("auth.require_proxy_digest() not yet wired")

    def require_digest(self, request, realm=None):
        """Convenience: same as require_www_digest (backward compat)."""
        return self.require_www_digest(request, realm=realm)

    def verify_digest(self, request, realm=None):
        raise NotImplementedError("auth.verify_digest() not yet wired")


# ---------------------------------------------------------------------------
# Log namespace
# ---------------------------------------------------------------------------

class _LogNamespace:
    """Logging — bridges to Rust tracing."""

    def debug(self, msg):
        print(f"[DEBUG] {msg}")

    def info(self, msg):
        print(f"[INFO] {msg}")

    def warn(self, msg):
        print(f"[WARN] {msg}")

    def error(self, msg):
        print(f"[ERROR] {msg}")


# ---------------------------------------------------------------------------
# Cache namespace (stub)
# ---------------------------------------------------------------------------

class _CacheNamespace:
    """Named cache connections (stub — wired to Redis in later phase)."""

    async def fetch(self, name, key):
        raise NotImplementedError("cache.fetch() not yet wired to Redis backend")


# ---------------------------------------------------------------------------
# RTPEngine namespace (stub — replaced by Rust when media.rtpengine configured)
# ---------------------------------------------------------------------------

class _RtpEngineNamespace:
    """RTPEngine media proxy operations (stub)."""

    async def offer(self, request, profile=None):
        raise NotImplementedError("rtpengine.offer() not available — no media.rtpengine in config")

    async def answer(self, reply, profile=None):
        raise NotImplementedError("rtpengine.answer() not available — no media.rtpengine in config")

    async def delete(self, request):
        raise NotImplementedError("rtpengine.delete() not available — no media.rtpengine in config")

    async def ping(self):
        raise NotImplementedError("rtpengine.ping() not available — no media.rtpengine in config")

    async def subscribe_request(self, call_id, from_tag, to_tag, sdp=None, profile=None):
        raise NotImplementedError("rtpengine.subscribe_request() not available — no media.rtpengine in config")

    async def subscribe_answer(self, call_id, from_tag, to_tag, sdp, profile=None):
        raise NotImplementedError("rtpengine.subscribe_answer() not available — no media.rtpengine in config")

    async def unsubscribe(self, call_id, from_tag, to_tag):
        raise NotImplementedError("rtpengine.unsubscribe() not available — no media.rtpengine in config")

    def on_dtmf(self, func_or_none=None, *, call_id=None, from_tag=None):
        """Register a handler for inbound DTMF events from rtpengine.

        Usage:
            @rtpengine.on_dtmf
            def handle_any(call_id, from_tag, digit, duration_ms, volume):
                ...

            @rtpengine.on_dtmf(call_id="abc")
            def handle_specific(call_id, from_tag, digit, duration_ms, volume):
                ...
        """
        def decorator(fn):
            is_async = _asyncio.iscoroutinefunction(fn)
            metadata = {"call_id": call_id, "from_tag": from_tag}
            _registry.register("rtpengine.on_dtmf", None, fn, is_async, metadata)
            return fn
        if func_or_none is not None:
            return decorator(func_or_none)
        return decorator

    def on_media_timeout(self, func_or_none=None, *, call_id=None, from_tag=None):
        """Register a handler for media-timeout events from the media engine.

        The engine reaps a call whose media went dead and pushes a media-timeout
        event; the handler releases the per-call state no BYE will now clear
        (Rx/N5 QoS, charging, dialog).

        Usage:
            @rtpengine.on_media_timeout
            def handle_any(call_id, from_tag):
                ...

            @rtpengine.on_media_timeout(call_id="abc")
            def handle_specific(call_id, from_tag):
                ...
        """
        def decorator(fn):
            is_async = _asyncio.iscoroutinefunction(fn)
            metadata = {"call_id": call_id, "from_tag": from_tag}
            _registry.register("rtpengine.on_media_timeout", None, fn, is_async, metadata)
            return fn
        if func_or_none is not None:
            return decorator(func_or_none)
        return decorator


# ---------------------------------------------------------------------------
# Gateway namespace (stub — replaced by Rust when gateway is configured)
# ---------------------------------------------------------------------------

class _GatewayNamespace:
    """Gateway dispatcher operations (stub)."""

    def select(self, group, key=None, attrs=None):
        raise NotImplementedError("gateway.select() not available — no gateway in config")

    def list(self, group):
        raise NotImplementedError("gateway.list() not available — no gateway in config")

    def groups(self):
        raise NotImplementedError("gateway.groups() not available — no gateway in config")

    def add_group(self, name, destinations, algorithm="weighted"):
        raise NotImplementedError("gateway.add_group() not available — no gateway in config")

    def remove_group(self, name):
        raise NotImplementedError("gateway.remove_group() not available — no gateway in config")

    def mark_down(self, group, uri):
        raise NotImplementedError("gateway.mark_down() not available — no gateway in config")

    def mark_up(self, group, uri):
        raise NotImplementedError("gateway.mark_up() not available — no gateway in config")

    def status(self, group):
        raise NotImplementedError("gateway.status() not available — no gateway in config")


# ---------------------------------------------------------------------------
# LI namespace (stub — replaced by Rust when lawful_intercept is configured)
# ---------------------------------------------------------------------------

class _LiNamespace:
    """Lawful Intercept operations (stub)."""

    def is_target(self, request):
        raise NotImplementedError("li.is_target() not available — no lawful_intercept in config")

    def intercept(self, request):
        raise NotImplementedError("li.intercept() not available — no lawful_intercept in config")

    def record(self, request):
        raise NotImplementedError("li.record() not available — no lawful_intercept in config")

    def stop_intercept(self, request):
        raise NotImplementedError("li.stop_intercept() not available — no lawful_intercept in config")

    def stop_recording(self, request):
        raise NotImplementedError("li.stop_recording() not available — no lawful_intercept in config")

    @property
    def is_enabled(self):
        return False


# ---------------------------------------------------------------------------
# Registration namespace (stub — replaced by Rust when registrant is configured)
# ---------------------------------------------------------------------------

class _RegistrationNamespace:
    """Outbound registration operations (stub).

    Replaced by the Rust-backed namespace when a ``registrant:`` block is
    configured. NOTE: that replacement happens at server init AFTER the script
    module is first loaded, so calling ``registration.add(...)`` at script
    *top level* always lands on this stub — declare registrations in YAML
    (``registrant.entries``) or call ``registration.add`` from a runtime
    handler/timer instead.
    """

    def add(self, aor, registrar, *, user, password="", interval=None, realm=None,
            contact=None, transport=None, auth=None, k=None, op=None, opc=None,
            amf=None, sqn=None, ipsec=False, ue_port_c=None, ue_port_s=None,
            ipsec_alg=None, ipsec_ealg=None, imei=None, ims_features=None):
        raise NotImplementedError("registration.add() not available — no registrant in config")

    def remove(self, aor):
        raise NotImplementedError("registration.remove() not available — no registrant in config")

    def refresh(self, aor):
        raise NotImplementedError("registration.refresh() not available — no registrant in config")

    def list(self):
        raise NotImplementedError("registration.list() not available — no registrant in config")

    def status(self, aor):
        raise NotImplementedError("registration.status() not available — no registrant in config")

    def count(self):
        raise NotImplementedError("registration.count() not available — no registrant in config")

    def service_route(self, aor):
        raise NotImplementedError("registration.service_route() not available — no registrant in config")

    def associated_uris(self, aor):
        raise NotImplementedError("registration.associated_uris() not available — no registrant in config")

    def flow(self, aor, ue_ip):
        raise NotImplementedError("registration.flow() not available — no registrant in config")

    @staticmethod
    def on_change(fn):
        """Register a handler for outbound registration state changes.

        The handler receives (aor, event_type, state) where:
          - aor: str — Address of Record (e.g. "sip:trunk@carrier.com")
          - event_type: str — "registered", "refreshed", "failed", or "deregistered"
          - state: dict — {"expires_in": int, "failure_count": int, "registrar": str,
            "status_code": int (only present when event_type is "failed")}

        Usage:
            @registration.on_change
            def on_trunk_change(aor, event_type, state):
                ...
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("registration.on_change", None, fn, is_async)
        return fn


class _SubscribeStateStub:
    """Pre-startup stub for ``proxy.subscribe_state``.

    The real, Rust-backed namespace is installed onto ``proxy`` by
    ``install_siphon_module()`` before any user handler runs.  If a
    handler ever lands on this stub it means the singleton wasn't
    registered before the script was loaded — every method below raises
    a self-describing :class:`NotImplementedError` so the failure points
    at the cause instead of an opaque ``AttributeError``.
    """

    _ERROR = (
        "proxy.subscribe_state.{name}() not available — the Rust "
        "namespace was not installed before the script was loaded. "
        "This is a siphon startup-ordering bug; the subscribe_state "
        "singleton must be registered before ScriptEngine::new()."
    )

    def create(self, request, expires=None):
        raise NotImplementedError(self._ERROR.format(name="create"))

    def get(self, id):
        raise NotImplementedError(self._ERROR.format(name="get"))

    def find(self, call_id, local_tag, remote_tag):
        raise NotImplementedError(self._ERROR.format(name="find"))

    def send(
        self,
        ruri,
        event,
        expires,
        accept=None,
        target_uri=None,
        headers=None,
        timeout_ms=2000,
    ):
        raise NotImplementedError(self._ERROR.format(name="send"))

    @property
    def local_count(self):
        raise NotImplementedError(self._ERROR.format(name="local_count"))


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

proxy = _ProxyNamespace()
registrar = _RegistrarNamespace()
b2bua = _B2buaNamespace()
auth = _AuthNamespace()
log = _LogNamespace()
cache = _CacheNamespace()
rtpengine = _RtpEngineNamespace()
gateway = _GatewayNamespace()
registration = _RegistrationNamespace()
li = _LiNamespace()


# ---------------------------------------------------------------------------
# Presence namespace (stub — replaced by Rust when presence store is active)
# ---------------------------------------------------------------------------

class _PresenceNamespace:
    """Namespace for SIP presence operations (stub)."""

    def publish(self, entity, pidf_xml, expires=3600):
        raise NotImplementedError("presence.publish() not available — presence store not initialized")

    def lookup(self, entity):
        raise NotImplementedError("presence.lookup() not available — presence store not initialized")

    def subscribe(self, subscriber, resource, event="presence", expires=3600):
        raise NotImplementedError("presence.subscribe() not available — presence store not initialized")

    def subscribe_dialog(self, subscriber, resource, event, expires, call_id, from_tag, to_tag, route_set=None):
        raise NotImplementedError("presence.subscribe_dialog() not available — presence store not initialized")

    def unsubscribe(self, subscription_id):
        raise NotImplementedError("presence.unsubscribe() not available — presence store not initialized")

    def subscribers(self, resource):
        raise NotImplementedError("presence.subscribers() not available — presence store not initialized")

    def notify(self, subscription_id, body=None, content_type=None, subscription_state="active"):
        raise NotImplementedError("presence.notify() not available — presence store not initialized")


presence = _PresenceNamespace()


# ---------------------------------------------------------------------------
# Diameter namespace (stub — replaced by Rust when diameter: is configured)
# ---------------------------------------------------------------------------

class _DiameterNamespace:
    """Stub diameter namespace with decorator support.

    When ``diameter:`` is configured, the Rust DiameterNamespace replaces this.
    The ``@on_rtr`` decorator still needs to be available for registration even
    before the Rust instance is injected (decorators run at import time).
    """

    @staticmethod
    def on_rtr(fn):
        """Register handler for incoming RTR (Registration-Termination-Request).

        Handler receives (public_identity, reason_code, reason_info).
        Siphon auto-sends RTA (result 2001) after the handler returns.

        Reason codes: 0=PERMANENT_TERMINATION, 1=NEW_SERVER_ASSIGNED,
                      2=SERVER_CHANGE, 3=REMOVE_SCSCF

        Usage:
            @diameter.on_rtr
            def handle_rtr(public_identity, reason_code, reason_info):
                registrar.remove(public_identity)
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("diameter.on_rtr", None, fn, is_async)
        return fn

    @staticmethod
    def on_rar(fn):
        """Register handler for incoming RAR (Re-Auth-Request) from PCRF.

        Handler receives (session_id, abort_cause, specific_actions).
        Siphon auto-sends RAA (result 2001) after the handler returns.

        specific_actions is a list of int values (TS 29.214 Specific-Action):
            1=CHARGING_CORRELATION_EXCHANGE
            2=INDICATION_OF_LOSS_OF_BEARER
            3=INDICATION_OF_RECOVERY_OF_BEARER
            4=INDICATION_OF_RELEASE_OF_BEARER
            6=INDICATION_OF_ESTABLISHMENT_OF_BEARER
            7=IP_CAN_CHANGE

        Usage:
            @diameter.on_rar
            def handle_rar(session_id, abort_cause, specific_actions):
                if 2 in specific_actions:
                    log.warn(f"Bearer lost for session {session_id}")
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("diameter.on_rar", None, fn, is_async)
        return fn

    @staticmethod
    def on_asr(fn):
        """Register handler for incoming ASR (Abort-Session-Request) from PCRF.

        Handler receives (session_id, abort_cause, origin_host).
        Siphon auto-sends ASA (result 2001) after the handler returns.

        abort_cause values (TS 29.214):
            0=BEARER_RELEASED
            1=INSUFFICIENT_SERVER_RESOURCES
            2=INSUFFICIENT_BEARER_RESOURCES

        Usage:
            @diameter.on_asr
            def handle_asr(session_id, abort_cause, origin_host):
                log.info(f"Session abort from {origin_host}: {session_id}")
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("diameter.on_asr", None, fn, is_async)
        return fn

    @staticmethod
    def on_pnr(fn):
        """Register handler for incoming Sh PNR (Push-Notification-Request) from HSS.

        Handler receives (public_identity, user_data_xml).
        Siphon auto-sends PNA (result 2001) after the handler returns.

        The HSS sends PNR when a user's profile changes (simservs edit,
        iFC update, etc.) after the AS subscribed via ``diameter.sh_snr``.

        Usage:
            @diameter.on_pnr
            def handle_pnr(public_identity, user_data_xml):
                cache.put("simservs", public_identity, user_data_xml)
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("diameter.on_pnr", None, fn, is_async)
        return fn


diameter = _DiameterNamespace()


# ---------------------------------------------------------------------------
# SBI namespace (5G Service Based Interfaces — N5/Npcf policy authorization)
# ---------------------------------------------------------------------------

class BsfError(RuntimeError):
    """Raised by ``sbi.discover_pcf_binding()`` when the BSF is unhealthy
    (5xx / timeout / transport / malformed body).

    A 404 (no binding for the UE IP) is **not** a ``BsfError`` — it returns
    ``None`` (the 4G UE case).  This Python class is only a pre-injection
    fallback so ``except sbi.BsfError`` resolves before the Rust singleton is
    wired; once ``sbi._inner`` is injected, ``sbi.BsfError`` forwards to the
    Rust exception type (which is what ``discover_pcf_binding`` actually
    raises).
    """


class _SbiNamespace:
    """SBI namespace façade.

    Data methods (``create_session``, ``discover_pcf_binding``, …) forward to
    the Rust-backed singleton, injected at startup as ``self._inner`` — the
    same pattern ``_ProxyNamespace`` uses for ``_utils``.  Forwarding (rather
    than replacing the module attribute) means a script that did
    ``from siphon import sbi`` before the singleton was wired still reaches the
    Rust impl, and the Python ``@on_event`` decorator (which the Rust namespace
    does not implement) keeps working.

    ``__getattr__`` delegates any other attribute (notably ``BsfError``) to the
    injected singleton so ``except sbi.BsfError`` catches the actual Rust
    exception type once wired.
    """

    def __init__(self):
        # Replaced at startup by the Rust SbiNamespace (set_sbi_singleton /
        # install_siphon_module).  None until then.
        self._inner = None

    def __getattr__(self, name):
        inner = object.__getattribute__(self, "__dict__").get("_inner")
        if inner is not None:
            return getattr(inner, name)
        if name == "BsfError":
            # Pre-injection fallback so `except sbi.BsfError` resolves.
            return BsfError
        raise AttributeError(
            f"sbi.{name} not available — sbi: not configured "
            "(needs npcf_url and/or bsf_url)"
        )

    def create_session(self, *args, **kwargs):
        """Create an N5 app session for QoS policy authorization.

        Requires ``sbi:`` configuration with ``npcf_url``.

        Args:
            af_app_id: AF-Application identifier (default "IMS Services").
            sip_call_id: SIP Call-ID for correlation.
            supi: Subscription Permanent Identifier.
            ue_ipv4: UE IPv4 address.
            ue_ipv6: UE IPv6 address.
            dnn: Data Network Name.
            notif_uri: Notification URI for PCF events.
            media_components: list of media-component dicts.  See the
                project docs for the full shape (mirrors
                ``diameter.rx_aar``).
            pcf_uri: per-call N5 target — the discovered PCF.  In ``indirect``
                communication mode it becomes the ``3gpp-Sbi-Target-apiRoot``
                routed via the SCP; in ``direct`` mode it is the POST base.

        Returns:
            Dict with ``app_session_id``, ``authorized`` and
            ``app_session_uri``, or None.
        """
        inner = self.__dict__.get("_inner")
        if inner is None:
            raise NotImplementedError(
                "sbi.create_session() requires sbi: with npcf_url in config"
            )
        return inner.create_session(*args, **kwargs)

    def delete_session(self, *args, **kwargs):
        """Delete an N5 app session.

        Args:
            session_id: The app session id from create_session(), or the
                absolute ``app_session_uri`` for replica-independent teardown.

        Returns:
            True on success, False on failure.
        """
        inner = self.__dict__.get("_inner")
        if inner is None:
            raise NotImplementedError(
                "sbi.delete_session() requires sbi: with npcf_url in config"
            )
        return inner.delete_session(*args, **kwargs)

    def update_session(self, *args, **kwargs):
        """Update an N5 app session (media renegotiation).

        Args:
            session_id: The app session id to update, or the absolute
                ``app_session_uri``.
            media_components: list of media-component dicts (same shape as
                ``create_session``).

        Returns:
            Dict with ``app_session_id`` and ``authorized``, or None.
        """
        inner = self.__dict__.get("_inner")
        if inner is None:
            raise NotImplementedError(
                "sbi.update_session() requires sbi: with npcf_url in config"
            )
        return inner.update_session(*args, **kwargs)

    def discover_pcf_binding(self, *args, **kwargs):
        """Nbsf_Management discovery — look up the PCF binding for a UE IP.

        Returns a binding dict (BSF 200, 5G; incl. a ready-to-use ``pcf_uri``),
        ``None`` (BSF 404, 4G), or raises ``sbi.BsfError`` (BSF unhealthy).
        Requires ``sbi:`` configuration with ``bsf_url``.

        Args:
            ue_ipv4: UE IPv4 address (the IPsec SA peer).
            ue_ipv6: UE IPv6 address/prefix.  Exactly one of ue_ipv4 / ue_ipv6.
        """
        inner = self.__dict__.get("_inner")
        if inner is None:
            raise NotImplementedError(
                "sbi.discover_pcf_binding() requires sbi: with bsf_url in config"
            )
        return inner.discover_pcf_binding(*args, **kwargs)

    @staticmethod
    def on_event(fn):
        """Register handler for incoming PCF event notifications (N5).

        Handler receives a dict with event notification data.

        Usage:
            @sbi.on_event
            def handle_pcf_event(event):
                for notif in event.get("ev_notifs", []):
                    if notif["event"] == "UP_PATH_CH_EVENT":
                        log.warn("Bearer path changed")
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("sbi.on_event", None, fn, is_async)
        return fn


sbi = _SbiNamespace()


# ---------------------------------------------------------------------------
# SRS namespace (Session Recording Server — accepts SIPREC INVITEs)
# ---------------------------------------------------------------------------

class _SrsNamespace:
    """Namespace for SRS (Session Recording Server) event handlers."""

    @staticmethod
    def on_invite(fn):
        """Register handler for incoming SIPREC INVITE (recording request).

        The handler receives (request, metadata) where:
          - request: Request object (the SIPREC INVITE)
          - metadata: RecordingMetadata (parsed XML — participants, streams, session_id)

        Return True to accept the recording, False to reject (403).

        Usage:
            @srs.on_invite
            async def on_recording(request, metadata):
                log.info(f"Recording: {metadata.session_id}")
                return True
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("srs.on_invite", None, fn, is_async)
        return fn

    @staticmethod
    def on_session_end(fn):
        """Register handler called when a recording session ends.

        The handler receives (session,) where:
          - session: SrsSession (session_id, participants, duration, recording_dir)

        Usage:
            @srs.on_session_end
            async def on_recording_end(session):
                log.info(f"Recording {session.session_id} done, {session.duration}s")
        """
        is_async = _asyncio.iscoroutinefunction(fn)
        _registry.register("srs.on_session_end", None, fn, is_async)
        return fn


srs = _SrsNamespace()


# ---------------------------------------------------------------------------
# Timer namespace — periodic callbacks (like OpenSIPS timer_route)
# ---------------------------------------------------------------------------

class _TimerNamespace:
    """Namespace for periodic timer callbacks.

    Timer handlers run on a Tokio interval in the Rust runtime.
    They receive no SIP request/call context but can use all other
    namespaces (registrar, cache, gateway, log, etc.).
    """

    def every(self, seconds, name=None, jitter=0):
        """Register a periodic timer callback.

        Usage:
            @timer.every(seconds=30)
            async def health_check():
                ...

            @timer.every(seconds=300, name="stats", jitter=10)
            def push_stats():
                ...

        Args:
            seconds: Interval between invocations.
            name: Optional name for logging (defaults to function name).
            jitter: Random jitter in seconds added to each interval (default 0).
        """
        def decorator(fn):
            timer_name = name if name is not None else fn.__name__
            is_async = _asyncio.iscoroutinefunction(fn)
            metadata = {"seconds": seconds, "name": timer_name, "jitter": jitter}
            _registry.register("timer.every", None, fn, is_async, metadata)
            return fn
        return decorator


timer = _TimerNamespace()


# ---------------------------------------------------------------------------
# Metrics namespace (stub — replaced by Rust at startup)
# ---------------------------------------------------------------------------

class _MetricsNamespace:
    """Custom Prometheus metrics from Python scripts (stub).

    Usage:
        from siphon import metrics

        counter = metrics.counter("my_total", "My counter")
        counter.inc()
    """

    def counter(self, name, help, labels=None):
        raise NotImplementedError("metrics.counter() not available — metrics not initialized")

    def gauge(self, name, help, labels=None):
        raise NotImplementedError("metrics.gauge() not available — metrics not initialized")

    def histogram(self, name, help, labels=None, buckets=None):
        raise NotImplementedError("metrics.histogram() not available — metrics not initialized")


metrics = _MetricsNamespace()


# ---------------------------------------------------------------------------
# ISC namespace (stub — replaced by Rust at startup)
# ---------------------------------------------------------------------------

class _IscNamespace:
    """Initial Filter Criteria evaluation for ISC routing (stub).

    Used by the S-CSCF to determine which Application Servers a SIP
    request must be routed through, based on the subscriber's service
    profile received from the HSS via Diameter Cx SAR.

    Usage:
        from siphon import isc

        # Store per-user iFC profile (from Cx SAR user_data XML)
        count = isc.store_profile("sip:alice@ims.example.com", ifc_xml)

        # Evaluate iFCs for a request
        matches = isc.evaluate("sip:alice@ims.example.com", "INVITE",
                               "sip:bob@example.com", headers, "originating")
    """

    def store_profile(self, aor, ifc_xml):
        raise NotImplementedError("isc.store_profile() not available — ISC not initialized")

    def remove_profile(self, aor):
        raise NotImplementedError("isc.remove_profile() not available — ISC not initialized")

    def has_profile(self, aor):
        raise NotImplementedError("isc.has_profile() not available — ISC not initialized")

    def evaluate(self, aor, method, ruri, headers, session_case="originating"):
        raise NotImplementedError("isc.evaluate() not available — ISC not initialized")

    def profile_count(self):
        raise NotImplementedError("isc.profile_count() not available — ISC not initialized")


isc = _IscNamespace()


# ---------------------------------------------------------------------------
# SDP namespace (stub — replaced by Rust at startup)
# ---------------------------------------------------------------------------

class _SdpNamespace:
    """SDP parser and manipulator (stub).

    Usage:
        from siphon import sdp

        s = sdp.parse(request)
        s.get_attr("group")
        s.media[0].set_attr("des", "qos optional local sendrecv")
        s.apply(request)
    """

    def parse(self, source):
        raise NotImplementedError("sdp.parse() not available — SDP namespace not initialized")


sdp = _SdpNamespace()


# ---------------------------------------------------------------------------
# QoS namespace (stub — replaced by Rust at startup)
# ---------------------------------------------------------------------------

class _QosNamespace:
    """SDP → IPFilterRule helper (stub).

    Usage:
        from siphon import qos

        components = qos.media_flows_from_sdp(
            offer=request.body, answer=reply.body, direction="orig",
        )
        diameter.rx_aar(framed_ip=request.source_ip, media_components=components)
    """

    def media_flows_from_sdp(self, *, offer, answer, direction="orig"):
        raise NotImplementedError(
            "qos.media_flows_from_sdp() not available — QoS namespace not initialized"
        )


qos = _QosNamespace()
