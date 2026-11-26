"""
Mock of the **split bridge**: ``rtpengine.attach_ws_split`` /
``detach_ws_split`` and the ``on_ws_split_started`` / ``on_ws_split_ended``
events.

Both legs of an answered two-party call are streamed to one duplex stereo
WebSocket, and the two parties are isolated from each other for as long as it
is attached: channel 0 is the offerer (the party whose tag is the call's
``from_tag``), channel 1 the answerer, and what the server sends on a channel
is played to that party only. It is the shape of live translation.

The mock does not record a call and answer yes. It holds the same state the
engine does and refuses what the engine refuses (an unknown call, a call
nobody answered, one the engine answered itself, a seated leg, a call that
already has a split, a rate the engine does not serve), so a script that
attaches where the engine would not fails in its test too. The lifecycle
events the engine sends because of a script's own action are delivered the
same way: ``started`` on attach, ``ended`` with ``detached`` on detach and with
``call_deleted`` on delete. The ones it sends on its own (the server closed
the socket, a failure, a re-offer it could not follow) are fired by the test:
:meth:`~_WsSplitMixin.fire_ws_split_ended`.

**After any end other than ``detached`` and ``call_deleted`` the call stays
isolated and silent until the script detaches it**, whatever the reason; the
mock keeps it held until :meth:`~_WsSplitMixin.detach_ws_split`.

Example::

    from siphon import rtpengine

    @rtpengine.on_ws_split_ended
    async def split_down(call_id, from_tag, stream_id, reason):
        if reason not in ("detached", "call_deleted"):
            await rtpengine.detach_ws_split((call_id, from_tag))

    # In a test:
    harness.rtpengine.anchor_call("call-1@example.com")
    await rtpengine.attach_ws_split(("call-1@example.com", "tag-a"),
                                    "wss://translate.internal/call")
    harness.rtpengine.fire_ws_split_ended("call-1@example.com", "tag-a",
                                          reason="ws_error")
    assert harness.rtpengine.splits == {}   # the handler detached it
"""

from __future__ import annotations

import inspect
from typing import Any, Optional

#: The L16 wire rates the engine serves for a split, in Hz.
WS_SPLIT_SAMPLE_RATES = (8000, 16000, 24000, 48000)

#: The ends that give the parties their direct audio back.
_RESTORING_REASONS = ("detached", "call_deleted")


def _refusal(verb: str, token: Optional[str], reason: str) -> RuntimeError:
    """A ``RuntimeError`` as the script gets one: the verb's name, the engine's
    reason, and the refusal token as ``.token`` (``None`` when it has none)."""
    if token is None:
        message = f"rtpengine.{verb} failed: RTPEngine returned error: {reason}"
    else:
        message = (
            f"rtpengine.{verb} failed: RTPEngine returned error: {verb}: {token}: {reason}"
        )
    error = RuntimeError(message)
    error.token = token  # type: ignore[attr-defined]
    return error


class _WsSplitMixin:
    """The split bridge's half of :class:`MockRtpEngine`."""

    def _ws_split_init(self) -> None:
        self.splits: dict[str, dict[str, Any]] = {}
        """Splits the engine holds, by SIP Call-ID.

        Each entry is ``{"from_tag", "stream_id", "ws_uri", "sample_rate",
        "offerer_profile", "answerer_profile", "isolated", "ended",
        "end_reason"}``. ``isolated`` is ``True`` for as long as the entry
        exists: a split whose end was reported (``ended``) is still held, and
        the parties still cut off from each other, until it is detached.
        """
        self._ws_split_started_handlers: list[dict[str, Any]] = []
        self._ws_split_ended_handlers: list[dict[str, Any]] = []
        self._ws_split_supported = True
        self._ws_split_refusals: list[str] = []
        # The engine keys a call by its Call-ID and, for a leg a proxy
        # anchored under a per-call scope, the scope as well.
        self._admitted_calls: set[str] = set()
        self._answered_calls: set[str] = set()
        self._answered_locally: set[str] = set()
        self._takeovers: set[str] = set()

    @staticmethod
    def _call_key(call_id: Optional[str], scope: Optional[str]) -> str:
        """The engine's key for a call: the Call-ID, with the scope after a
        ``;`` for a leg anchored under one (the ``splits`` key too)."""
        return f"{call_id};{scope}" if scope is not None else (call_id or "")

    # -- the engine's view of a call ------------------------------------

    def anchor_call(self, call_id: str, answered_locally: bool = False,
                    scope: Optional[str] = None) -> None:
        """Test helper: the engine holds ``call_id`` as an answered two-party
        call, as an ``offer`` and its ``answer`` leave it. With
        ``answered_locally`` it is a call the engine answered itself
        (``answer_local``), which has no second party to split. With ``scope``
        it is the leg a proxy anchored under that per-call scope."""
        key = self._call_key(call_id, scope)
        self._admitted_calls.add(key)
        self._answered_calls.add(key)
        if answered_locally:
            self._answered_locally.add(key)

    def _track_answered(self, call_id: Optional[str], locally: bool = False,
                        scope: Optional[str] = None) -> None:
        """What ``answer`` / ``answer_local`` leave the engine holding."""
        if not call_id:
            return
        key = self._call_key(call_id, scope)
        self._answered_calls.add(key)
        if locally:
            self._answered_locally.add(key)

    def _engine_holds(self, call_id: Optional[str], scope: Optional[str]) -> bool:
        key = self._call_key(call_id, scope)
        return bool(call_id) and (
            key in self._admitted_calls
            or key in self._answered_calls
            or scope in self._anchored_legs.get(call_id, set())  # type: ignore[attr-defined]
        )

    def _forget_call(self, call_id: Optional[str], scope: Optional[str]) -> None:
        """A delete ends what the engine held for the call (every leg without
        a scope): its split, its takeover and the call itself."""
        for key in [key for key in self._known_keys() if self._of_call(key, call_id, scope)]:
            split = self.splits.pop(key, None)
            self._admitted_calls.discard(key)
            self._answered_calls.discard(key)
            self._answered_locally.discard(key)
            self._takeovers.discard(key)
            if split is not None and not split["ended"]:
                self._deliver_ws_split_ended(
                    split["call_id"], split["from_tag"], split["stream_id"],
                    "call_deleted", split["scope"],
                )

    def _known_keys(self) -> set[str]:
        return (
            set(self.splits) | self._admitted_calls | self._answered_calls
            | self._answered_locally | self._takeovers
        )

    @staticmethod
    def _of_call(key: str, call_id: Optional[str], scope: Optional[str]) -> bool:
        if scope is not None:
            return key == f"{call_id};{scope}"
        return key == call_id or key.startswith(f"{call_id};")

    def _record_takeover(self, call_id: Optional[str], scope: Optional[str],
                         attached: bool) -> None:
        """``attach_ws_bridge`` / ``detach_ws_bridge`` leave a takeover the
        engine refuses a split over."""
        key = self._call_key(call_id, scope)
        if attached:
            self._takeovers.add(key)
        else:
            self._takeovers.discard(key)

    # -- test knobs -------------------------------------------------------

    def set_ws_split_supported(self, supported: bool = True) -> None:
        """Model an engine that does (or, with ``False``, does not) list
        ``ws_split`` in its ``node_info`` features: ``attach_ws_split`` and
        ``detach_ws_split`` then raise ``RuntimeError`` before anything is sent
        (test helper)."""
        self._ws_split_supported = supported

    def refuse_next_ws_split(self, token: str = "ws-split-renegotiation") -> None:
        """Prime the engine to refuse the next ``attach_ws_split`` with
        ``token`` (``ws-split-renegotiation``, ``ws-split-profile``, ...), once
        (test helper)."""
        self._ws_split_refusals.append(token)

    def _ws_split_clear(self) -> None:
        self.splits.clear()
        self._ws_split_started_handlers.clear()
        self._ws_split_ended_handlers.clear()
        self._ws_split_supported = True
        self._ws_split_refusals.clear()
        self._admitted_calls.clear()
        self._answered_calls.clear()
        self._answered_locally.clear()
        self._takeovers.clear()

    # -- verbs ------------------------------------------------------------

    async def attach_ws_split(
        self,
        target: Any,
        ws_uri: str,
        sample_rate: Optional[int] = None,
        offerer_profile: Optional[str] = None,
        answerer_profile: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> bool:
        """Attach a **split bridge** to a live, answered two-party call: both
        legs are streamed to one duplex stereo WebSocket and the two parties
        are isolated from each other for as long as it is attached.

        The engine dials ``ws_uri`` once for the call. Channel 0 of the stream
        is the offerer (the party whose tag is the call's ``from_tag``) and
        channel 1 the answerer, in both directions: what the server sends on
        channel 0 is played to the offerer only, what it sends on channel 1 to
        the answerer only. A channel the server leaves silent plays silence.
        This is the shape of live translation: each party hears a bot, not the
        other.

        Resolves when the engine has **accepted** the attach, which is before
        ``on_ws_split_started`` fires and does not mean the bot connected: a bot
        that drops during the handshake gives a successful attach, then
        ``started``, then ``on_ws_split_ended`` with ``ws_error`` (and the call
        isolated), so always register ``on_ws_split_ended``. The engine ignores
        the call's ``from_tag`` when it picks the parties: channel 0 is always
        the offerer and channel 1 the answerer. Raises ``RuntimeError`` when the
        engine refuses,
        leaving the call as it was; the exception's ``token`` attribute carries
        the engine's refusal token so a script branches on it without parsing
        the text: ``ws-split-not-answered``, ``ws-split-answer-local``,
        ``ws-split-seated``, ``ws-split-already-bridged``,
        ``ws-split-secondary-source``, ``ws-split-renegotiation``,
        ``ws-split-profile``, ``ws-split-sample-rate``. ``token`` is ``None``
        for any other failure (an unknown call, an engine that does not list
        ``ws_split``).

        **After the split ends for any reason but** :meth:`detach_ws_split` **or
        the call going, the call stays isolated and silent in both directions**
        until the script detaches it; see :meth:`on_ws_split_ended`.

        Requires ``media.backend: siphon-rtp``.

        Args:
            target: Request, Reply or Call, a ``(call_id, from_tag)`` pair, or
                a bare ``call_id``.
            ws_uri: ``ws://`` or ``wss://`` URI the engine dials as a client,
                templated as for :meth:`attach_ws_tee`.
            sample_rate: L16 wire rate in Hz, both ways: 8000, 16000, 24000 or
                48000. ``None`` is the engine's default (16000). Anything else
                raises ``ValueError``.
            offerer_profile: Name of a media profile whose ``answer`` half sets
                what runs on the offerer's uplink. The engine applies only
                ``noise_suppression`` and refuses a profile that asks for more
                (echo cancellation, ``ws_vad*``, ``ws_uri``) with
                ``ws-split-profile``.
            answerer_profile: The same for the answerer's uplink.
            scope: The leg's per-call scope, as for :meth:`play_media`.

        Returns:
            ``True`` on success.

        Example::

            try:
                await rtpengine.attach_ws_split(
                    call, "wss://translate.internal/session",
                    sample_rate=16000, offerer_profile="denoise")
            except RuntimeError as exc:
                if exc.token == "ws-split-not-answered":
                    ...   # try again once the call is answered
                else:
                    raise
        """
        from siphon_sdk.mock_module import _resolve_media_target

        ws_uri = self._expand_ws_uri(ws_uri, target)  # type: ignore[attr-defined]
        call_id, from_tag = _resolve_media_target(target)
        # What the script layer refuses before anything is sent.
        if sample_rate is not None and sample_rate not in WS_SPLIT_SAMPLE_RATES:
            raise ValueError(
                f"sample_rate: ws split sample_rate {sample_rate} Hz is not one of "
                "8000, 16000, 24000 or 48000"
            )
        scope = self._leg_scope(scope, target, call_id, "attach_ws_split")  # type: ignore[attr-defined]
        key = self._call_key(call_id, scope)
        if not self._ws_split_supported:
            raise _refusal_unsupported("attach_ws_split")
        if self._ws_split_refusals:
            token = self._ws_split_refusals.pop(0)
            raise _refusal("attach_ws_split", token, "refused for the test")
        if not self._engine_holds(call_id, scope):
            raise _refusal("attach_ws_split", None, f"unknown call: {call_id}")
        # The engine's order: a seat, a call it answered itself, a call that
        # already has a split or a takeover, then one nobody has answered.
        if self.conference_seat(call_id or "") is not None:  # type: ignore[attr-defined]
            raise _refusal(
                "attach_ws_split", "ws-split-seated",
                "the call's leg is seated in a conference room",
            )
        if key in self._answered_locally:
            raise _refusal(
                "attach_ws_split", "ws-split-answer-local",
                "the engine answered this call itself",
            )
        if key in self.splits or key in self._takeovers:
            raise _refusal(
                "attach_ws_split", "ws-split-already-bridged",
                "the call already has a WebSocket takeover or a split",
            )
        offered_only = (
            scope in self._anchored_legs.get(call_id, set())  # type: ignore[attr-defined]
            and key not in self._answered_calls
            and key not in self._admitted_calls
        )
        if offered_only:
            raise _refusal(
                "attach_ws_split", "ws-split-not-answered",
                "the call has no far party answered yet",
            )

        rate = 16000 if sample_rate is None else sample_rate
        self.splits[key] = {
            "call_id": call_id,
            "scope": scope,
            "from_tag": from_tag,
            "stream_id": f"split-{call_id}",
            "ws_uri": ws_uri,
            "sample_rate": rate,
            "offerer_profile": offerer_profile,
            "answerer_profile": answerer_profile,
            "isolated": True,
            "ended": False,
            "end_reason": None,
        }
        self.operations.append(("attach_ws_split", ws_uri))  # type: ignore[attr-defined]
        self.media_calls.append({  # type: ignore[attr-defined]
            "op": "attach_ws_split",
            "call_id": call_id,
            "from_tag": from_tag,
            "ws_uri": ws_uri,
            "sample_rate": sample_rate,
            "offerer_profile": offerer_profile,
            "answerer_profile": answerer_profile,
        })
        self._deliver_ws_split_started(
            call_id, from_tag, f"split-{call_id}", ws_uri, rate, scope  # type: ignore[arg-type]
        )
        return True

    async def detach_ws_split(self, target: Any, scope: Optional[str] = None) -> bool:
        """Detach a call's **split bridge**, putting the direct path back
        between the two parties without a re-INVITE.

        Idempotent: a call with no split is not an error. This is the way out
        of a split that ended on its own: after any ``on_ws_split_ended`` reason
        but ``detached`` and ``call_deleted`` the call stays isolated and silent
        until this is called. To reconnect to a different server, detach and
        attach again.

        Requires ``media.backend: siphon-rtp``; an engine that does not list
        ``ws_split`` raises ``RuntimeError``.

        Args:
            target: Request, Reply or Call, a ``(call_id, from_tag)`` pair, or
                a bare ``call_id``.
            scope: The leg's per-call scope, as for :meth:`play_media`.

        Returns:
            ``True`` on success.

        Example::

            await rtpengine.detach_ws_split(call)   # parties hear each other again
        """
        from siphon_sdk.mock_module import _resolve_media_target

        call_id, from_tag = _resolve_media_target(target)
        scope = self._leg_scope(scope, target, call_id, "detach_ws_split")  # type: ignore[attr-defined]
        key = self._call_key(call_id, scope)
        if not self._ws_split_supported:
            raise _refusal_unsupported("detach_ws_split")
        if not self._engine_holds(call_id, scope) and key not in self.splits:
            raise _refusal("detach_ws_split", None, f"unknown call: {call_id}")
        self.operations.append(("detach_ws_split", None))  # type: ignore[attr-defined]
        self.media_calls.append({  # type: ignore[attr-defined]
            "op": "detach_ws_split",
            "call_id": call_id,
            "from_tag": from_tag,
        })
        split = self.splits.pop(key, None)
        if split is not None and not split["ended"]:
            # An end already reported is not reported twice.
            self._deliver_ws_split_ended(
                call_id, split["from_tag"], split["stream_id"], "detached", scope  # type: ignore[arg-type]
            )
        return True

    # -- events -----------------------------------------------------------

    def on_ws_split_started(self, func_or_none: Any = None, *,
                            call_id: Optional[str] = None,
                            from_tag: Optional[str] = None) -> Any:
        """Register a handler for **split bridge started** events.

        Fires once the engine has dialled the split's WebSocket server and
        isolated the two parties of the call from each other. Channel 0 of the
        stream is the offerer (the party whose tag is ``from_tag``), channel 1
        the answerer. ``stream_id`` is the correlator between this event and
        the ``start`` frame on the socket. ``call_id`` is the SIP Call-ID of the
        offerer's dialog.

        Delivered by the native **siphon-rtp** backend only. In the mock it is
        delivered when :meth:`attach_ws_split` succeeds, or by
        :meth:`fire_ws_split_started`.

        Usage::

            @rtpengine.on_ws_split_started
            def split_up(call_id, from_tag, stream_id, ws_uri, sample_rate):
                log.info(f"split {stream_id} @ {sample_rate}Hz -> {ws_uri}")
        """
        def decorator(fn: Any) -> Any:
            self._ws_split_started_handlers.append(
                {"fn": fn, "call_id": call_id, "from_tag": from_tag}
            )
            return fn
        if func_or_none is not None:
            return decorator(func_or_none)
        return decorator

    def on_ws_split_ended(self, func_or_none: Any = None, *,
                          call_id: Optional[str] = None,
                          from_tag: Optional[str] = None) -> Any:
        """Register a handler for **split bridge ended** events.

        Fires exactly once per started split, for any reason. ``reason`` is
        one of ``detached``, ``ws_closed``, ``ws_stopped``, ``ws_error``,
        ``call_deleted``, ``renegotiated`` or ``restored``. With the control
        protocol of siphon-rtp 0.29 an end carrying any other reason cannot be
        decoded and is not delivered.

        **After any end other than ``detached`` and ``call_deleted`` the call
        is still isolated and silent in both directions**, whatever the reason:
        the engine lifts a split's isolation on a ``detach_ws_split`` you sent
        and on nothing else, not the server going away, a re-offer, a failure
        or a failover. The handler is where to act: ``detach_ws_split`` for
        direct audio, or detach and attach again for a new server.

        An ``async def`` handler is awaited to completion, so it may detach
        from inside the hook.

        Delivered by the native **siphon-rtp** backend only. In the mock it is
        delivered on :meth:`detach_ws_split` (``detached``), on a delete
        (``call_deleted``), or by :meth:`fire_ws_split_ended` for the ends the
        engine sends on its own.

        Usage::

            @rtpengine.on_ws_split_ended
            async def split_down(call_id, from_tag, stream_id, reason):
                if reason not in ("detached", "call_deleted"):
                    await rtpengine.detach_ws_split((call_id, from_tag))
        """
        def decorator(fn: Any) -> Any:
            self._ws_split_ended_handlers.append(
                {"fn": fn, "call_id": call_id, "from_tag": from_tag}
            )
            return fn
        if func_or_none is not None:
            return decorator(func_or_none)
        return decorator

    def _run_ws_split_handlers(self, handlers: list[dict[str, Any]], call_id: str,
                               from_tag: str, arguments: tuple,
                               scope: Optional[str] = None) -> int:
        from siphon_sdk.mock_module import _call_media_handler, _run_to_completion

        fired = 0
        for entry in list(handlers):
            if entry["call_id"] is not None and entry["call_id"] != call_id:
                continue
            if entry["from_tag"] is not None and entry["from_tag"] != from_tag:
                continue
            result = _call_media_handler(entry["fn"], arguments, scope)
            if inspect.isawaitable(result):
                _run_to_completion(result)
            fired += 1
        return fired

    def _deliver_ws_split_started(self, call_id: str, from_tag: str, stream_id: str,
                                  ws_uri: str, sample_rate: int,
                                  scope: Optional[str] = None) -> int:
        return self._run_ws_split_handlers(
            self._ws_split_started_handlers, call_id, from_tag,
            (call_id, from_tag, stream_id, ws_uri, sample_rate), scope,
        )

    def _deliver_ws_split_ended(self, call_id: str, from_tag: str, stream_id: str,
                                reason: str, scope: Optional[str] = None) -> int:
        return self._run_ws_split_handlers(
            self._ws_split_ended_handlers, call_id, from_tag,
            (call_id, from_tag, stream_id, reason), scope,
        )

    def fire_ws_split_started(self, call_id: str, from_tag: str, stream_id: str,
                              ws_uri: str, sample_rate: int = 16000,
                              scope: Optional[str] = None) -> int:
        """Test helper: the engine reports a split started that this mock did
        not attach (a controller's ``stream_start``, say). The call is then
        held isolated as the engine would hold it. Returns the number of
        handlers that matched (and were invoked). ``scope`` is the per-call
        scope of the leg, for a proxy that anchored two legs of one Call-ID."""
        key = self._call_key(call_id, scope)
        self.splits[key] = {
            "call_id": call_id,
            "scope": scope,
            "from_tag": from_tag,
            "stream_id": stream_id,
            "ws_uri": ws_uri,
            "sample_rate": sample_rate,
            "offerer_profile": None,
            "answerer_profile": None,
            "isolated": True,
            "ended": False,
            "end_reason": None,
        }
        return self._deliver_ws_split_started(
            call_id, from_tag, stream_id, ws_uri, sample_rate, scope
        )

    def fire_ws_split_ended(self, call_id: str, from_tag: str, stream_id: Optional[str] = None,
                            reason: str = "ws_closed", scope: Optional[str] = None) -> int:
        """Test helper: the engine reports the split on ``call_id`` ended for
        ``reason``. Returns the number of handlers that matched (and were
        invoked).

        The mock keeps what the engine keeps. After ``detached`` and
        ``call_deleted`` the parties have their direct audio back and the split
        is gone; after **any other** reason, including one this mock has never
        heard of, the call stays held and isolated (``splits[call_id]["isolated"]``)
        until the script calls :meth:`detach_ws_split`. An end is reported once
        per started split, and only after its start: a second end, or one for a
        call with no split, raises ``RuntimeError``.

        Args:
            call_id: The SIP Call-ID of the offerer's dialog.
            from_tag: The offerer's tag.
            stream_id: The split's stream id; the one it started with by default.
            reason: ``detached``, ``ws_closed``, ``ws_stopped``, ``ws_error``,
                ``call_deleted``, ``renegotiated`` or ``restored``. (With
                siphon-rtp-proto 0.29 a reason outside this list never reaches a
                script: the engine's event fails to decode.)
            scope: The per-call scope of the leg, when it has one.
        """
        key = self._call_key(call_id, scope)
        split = self.splits.get(key)
        if split is None:
            raise RuntimeError(
                f"no split is held on {call_id}: an end is only reported for a split "
                "that started (attach_ws_split or fire_ws_split_started first)"
            )
        if split["ended"]:
            raise RuntimeError(
                f"the split on {call_id} already ended ({split['end_reason']}); "
                "the engine reports one end per split"
            )
        stream_id = stream_id or split["stream_id"]
        if reason in _RESTORING_REASONS:
            self.splits.pop(key)
        else:
            split["ended"] = True
            split["end_reason"] = reason
        return self._deliver_ws_split_ended(call_id, from_tag, stream_id, reason, scope)


def _refusal_unsupported(verb: str) -> RuntimeError:
    error = RuntimeError(
        f"rtpengine.{verb} failed: {verb} is not supported by the siphon-rtp "
        "(needs an engine that lists ws_split) media backend"
    )
    error.token = None  # type: ignore[attr-defined]
    return error
