"""
Mock ``Reoffer``: an in-dialog offer on a bridged B2BUA call.

``@b2bua.on_reoffer`` is called with ``(call, offer)`` when either party of a
bridged call sends a re-INVITE or an UPDATE (RFC 3311), before siphon relays
it to the other party. ``@b2bua.on_reoffer_answered`` is called with the same
``(call, offer)`` once the offerer has its final response, whoever gave it.

The offer is read against the session in force, the description the sending
party last gave on its dialog, so a script can tell a hold (RFC 3264 §8.4,
TS 24.610 §4.5.2) from its resume and from a session refresh (RFC 4028 §10,
which on a held call repeats ``sendonly`` and is no second hold).

Example::

    from siphon import b2bua, rtpengine

    @b2bua.on_reoffer
    def hold(call, offer):
        # Answer the hold here and keep the callee on the line.
        if offer.kind == "hold" and offer.side == "a":
            offer.answer()

    @b2bua.on_reoffer_answered
    async def held(call, offer):
        if offer.kind == "hold" and offer.side == "a" and offer.status_code == 200:
            await rtpengine.play_media(call, file="/srv/moh.wav",
                                       repeat="inf", wait=False)
"""

from __future__ import annotations

import re
from typing import Optional, Union

from siphon_sdk.call import _uas_response_headers
from siphon_sdk.request import Request

_DIRECTIONS = ("sendrecv", "sendonly", "recvonly", "inactive")


def _sections(sdp: str) -> tuple[list[str], list[list[str]]]:
    session: list[str] = []
    media: list[list[str]] = []
    for raw in sdp.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("m="):
            media.append([line])
        elif media:
            media[-1].append(line)
        else:
            session.append(line)
    return session, media


def _attribute(lines: list[str]) -> Optional[str]:
    for line in lines:
        if line[2:] in _DIRECTIONS and line.startswith("a="):
            return line[2:]
    return None


def _connection(lines: list[str]) -> Optional[str]:
    for line in lines:
        if line.startswith("c="):
            return line[2:].strip()
    return None


def _streams(sdp: str) -> list[tuple]:
    session, media = _sections(sdp)
    session_direction = _attribute(session)
    session_connection = _connection(session)
    streams = []
    for section in media:
        fields = section[0][2:].split()
        port = int(fields[1].split("/")[0]) if len(fields) > 1 else 0
        stated = _attribute(section[1:]) or session_direction or "sendrecv"
        send = stated in ("sendrecv", "sendonly")
        receive = stated in ("sendrecv", "recvonly")
        connection = _connection(section[1:]) or session_connection
        if connection and len(connection.split()) > 2 and connection.split()[2] == "0.0.0.0":
            receive = False
        streams.append((
            fields[0].lower() if fields else "",
            port,
            fields[2].upper() if len(fields) > 2 else "",
            fields[3:],
            connection,
            (send, receive),
        ))
    return streams


def direction_of(sdp: Optional[str]) -> Optional[str]:
    """Which way ``sdp`` has media flow, over the streams it does not reject.

    ``0.0.0.0`` as the connection address receives nothing (RFC 3264 §8.4).
    ``None`` for no SDP or one without a live stream.
    """
    if not sdp:
        return None
    active = [stream for stream in _streams(sdp) if stream[1] != 0]
    if not active:
        return None
    send = any(stream[5][0] for stream in active)
    receive = any(stream[5][1] for stream in active)
    return {
        (True, True): "sendrecv",
        (True, False): "sendonly",
        (False, True): "recvonly",
        (False, False): "inactive",
    }[(send, receive)]


#: Attributes whose change renegotiates a stream rather than repeating it: a
#: key exchange, an ICE restart, a grouping. A trickled candidate is not one.
_RENEGOTIATING = ("crypto", "key-mgmt", "fingerprint", "setup", "ice-ufrag",
                  "ice-pwd", "group", "mid")


def _renegotiating(sdp: str) -> list[str]:
    lines = []
    for line in sdp.replace("\r\n", "\n").split("\n"):
        if not line.startswith("a="):
            continue
        name = line[2:].split(":", 1)[0].strip().lower()
        if name in _RENEGOTIATING:
            lines.append(line[2:].strip())
    return lines


def classify(offer: Optional[str], in_force: Optional[str]) -> str:
    """What ``offer`` does to ``in_force``: hold, resume, refresh or change.

    Keeping the streams but restarting ICE, re-keying or regrouping them is a
    change: the session in force is not an answer to it."""
    if not offer:
        return "refresh"

    def receives(sdp: str) -> bool:
        direction = direction_of(sdp)
        return direction is not None and direction.endswith("recv")

    if not in_force:
        return "change" if receives(offer) else "hold"
    if _streams(offer) == _streams(in_force) and _renegotiating(offer) == _renegotiating(in_force):
        return "refresh"
    was, now = receives(in_force), receives(offer)
    if was and not now:
        return "hold"
    if now and not was:
        return "resume"
    return "change"


_BOUNDARY = re.compile(r'boundary=(?:"([^"]*)"|([^;,\s]*))', re.IGNORECASE)


def _media_type(content_type: str) -> str:
    return content_type.split(";")[0].strip().lower()


def _sdp_part(content_type: str, body: bytes, method: str = "offer.answer") -> Optional[str]:
    """The ``application/sdp`` part of a multipart body, checked the way
    siphon checks one it is to put the SDP part in."""
    match = _BOUNDARY.search(content_type)
    boundary = (match.group(1) or match.group(2)) if match else ""
    if not boundary:
        raise ValueError(
            f"{method}(): multipart body cannot take the SDP: "
            "missing boundary parameter in Content-Type"
        )
    delimiter = b"--" + boundary.encode()
    sections = body.split(delimiter)
    if len(sections) < 2 or not any(
        line.startswith(delimiter) for line in body.splitlines()
    ):
        raise ValueError(
            f"{method}(): multipart body cannot take the SDP: no part "
            f"delimited by its boundary '{boundary}'"
        )
    for section in sections[1:]:
        if section.startswith(b"--"):
            break
        head, separator, content = section.partition(b"\r\n\r\n")
        if not separator:
            head, separator, content = section.partition(b"\n\n")
        for line in head.splitlines():
            name, _, value = line.decode("utf-8", "replace").partition(":")
            if name.strip().lower() == "content-type" and _media_type(value) == "application/sdp":
                return content.decode("utf-8", "replace").rstrip("\r\n")
    return None


def sdp_and_body(
    method: str,
    sdp: Optional[str],
    body: Optional[Union[str, bytes]],
    content_type: Optional[str],
) -> tuple[Optional[str], Optional[tuple[str, bytes]]]:
    """Sort the ``sdp``, ``body`` and ``content_type`` of ``offer.answer()``
    or ``b2bua.reoffer()`` into the SDP and the body sent beside it, the way
    siphon does: a body that is the SDP, or a multipart body with an SDP
    part, gives the SDP itself.

    Raises:
        ValueError: ``body`` without ``content_type`` or the reverse, an
            empty ``body``, a ``content_type`` with a line break, an SDP
            given both ways, or a ``multipart/*`` body without a
            ``boundary`` or a part delimited by it.
        TypeError: a ``body`` that is neither ``str`` nor ``bytes``.
    """
    if (body is None) != (content_type is None):
        raise ValueError(f"{method}(body=…) and content_type=… go together")
    if body is None or content_type is None:
        return sdp, None
    if not isinstance(body, (str, bytes)):
        raise TypeError("body must be str or bytes")
    raw = body.encode() if isinstance(body, str) else body
    if any(character in content_type for character in "\r\n\0"):
        raise ValueError(f"{method}(): content_type contains a line break or NUL")
    if not raw:
        raise ValueError(f"{method}(): body is empty")
    twice = f"{method}(): the body carries the SDP and sdp= gives another: pass one"
    media_type = _media_type(content_type)
    if media_type == "application/sdp":
        if sdp is not None:
            raise ValueError(twice)
        return raw.decode("utf-8", "replace"), None
    if media_type.startswith("multipart/"):
        part = _sdp_part(content_type, raw, method)
        if part is not None:
            if sdp is not None:
                raise ValueError(twice)
            sdp = part
    return sdp, (content_type, raw)


class Reoffer:
    """An in-dialog offer from one party of a bridged call.

    Handed to ``@b2bua.on_reoffer`` before the offer is relayed and to
    ``@b2bua.on_reoffer_answered`` with the final response.
    """

    def __init__(
        self,
        sdp: Optional[str] = None,
        previous_sdp: Optional[str] = None,
        method: str = "INVITE",
        side: str = "a",
        early: bool = False,
        request: Optional[Request] = None,
        session_sdp: Optional[str] = None,
    ) -> None:
        self._sdp = sdp or None
        self._session_sdp = session_sdp or None
        self._method = method
        self._side = side
        self._early = early
        self._direction = direction_of(self._sdp)
        self._previous_direction = direction_of(previous_sdp)
        self._kind = classify(self._sdp, previous_sdp)
        if request is None:
            request = Request(
                method=method,
                body=self._sdp.encode() if self._sdp else None,
                content_type="application/sdp" if self._sdp else None,
            )
        self._request: Optional[Request] = request
        self._decision: tuple = ("relay",)
        self._answer_extras: Optional[dict] = None
        self._status_code: Optional[int] = None
        self._answer_sdp: Optional[str] = None
        self._answered_locally = False
        self._answered = False

    # -- the offer --------------------------------------------------------

    @property
    def method(self) -> str:
        """``"INVITE"`` for a re-INVITE, ``"UPDATE"`` for an UPDATE (RFC 3311)."""
        return self._method

    @property
    def side(self) -> str:
        """Which party sent the offer: ``"a"`` (caller) or ``"b"`` (callee)."""
        return self._side

    @property
    def request(self) -> Optional[Request]:
        """The re-INVITE or UPDATE as it arrived, for its headers.

        Only in ``@b2bua.on_reoffer``. A header or body set on it is on the
        request relayed to the other party. Decide the offer with
        :meth:`reject` or :meth:`answer`, not ``request.reply()``.
        """
        return None if self._answered else self._request

    @property
    def sdp(self) -> Optional[str]:
        """The offer as the party sent it; ``None`` for an offerless re-INVITE
        (the other party's 2xx then carries the offer) or an UPDATE without one."""
        return self._sdp

    @property
    def direction(self) -> Optional[str]:
        """``"sendrecv"``, ``"sendonly"``, ``"recvonly"`` or ``"inactive"`` for the
        offer, with ``0.0.0.0`` counted as receiving nothing (RFC 3264 §8.4)."""
        return self._direction

    @property
    def previous_direction(self) -> Optional[str]:
        """The same for the session in force before this offer, or ``None``."""
        return self._previous_direction

    @property
    def kind(self) -> str:
        """``"hold"``, ``"resume"``, ``"refresh"`` or ``"change"``, read against
        the session in force stream by stream (a refresh on a held call that
        repeats ``sendonly`` is ``"refresh"``, not a second hold). An ICE
        restart, new keys or a new grouping make it ``"change"``; an attribute
        that renegotiates nothing, such as ``a=recordpref``, does not."""
        return self._kind

    @property
    def session_sdp(self) -> Optional[str]:
        """The description siphon last sent the offering party, the session in
        force toward it; ``None`` before siphon has sent it one.

        What :meth:`answer` answers from, and what a script edits when its
        answer differs in one attribute only (RFC 7866's ``a=record``) on a
        stream :meth:`answer` cannot answer for itself (keyed, ICE, grouped).
        Repeating it answers only an offer that renegotiates nothing, which is
        what a ``"refresh"`` is."""
        return self._session_sdp

    @property
    def early(self) -> bool:
        """Whether it is an UPDATE between early dialogs (RFC 3311 §5.1)."""
        return self._early

    # -- the final response (on_reoffer_answered) --------------------------

    @property
    def status_code(self) -> Optional[int]:
        """The final response's status, ``None`` before it."""
        return self._status_code

    @property
    def answer_sdp(self) -> Optional[str]:
        """The SDP the offerer was sent in the final response, if any."""
        return self._answer_sdp

    @property
    def answer_direction(self) -> Optional[str]:
        """Which way :attr:`answer_sdp` has media flow (``None`` after a refusal)."""
        return direction_of(self._answer_sdp)

    @property
    def answered_locally(self) -> bool:
        """Whether siphon answered the offer itself rather than the other party."""
        return self._answered_locally

    # -- decisions (on_reoffer) --------------------------------------------

    def reject(
        self,
        code: int,
        reason: str,
        body: Optional[Union[str, bytes]] = None,
        content_type: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        """Refuse the offer with ``code`` (300-699); nothing is relayed and the
        session stays as it was (RFC 3261 §14.2).

        ``body`` with its ``content_type`` goes on the refusal as given, for a
        service that says why in a document of its own (an MCPTT controlling
        function's ``application/vnd.3gpp.mcptt-info+xml``, TS 24.379
        §6.3.3.1.14). ``headers`` is added to the refusal, in its order, such
        as ``Warning`` (RFC 3261 §20.43) or ``Retry-After``; the headers
        siphon owns on a response it sends are refused, as on
        :meth:`answer`.

        Example::

            @b2bua.on_reoffer
            def upgrade(call, offer):
                if not may_upgrade(call):
                    offer.reject(403, "Forbidden",
                                 body=refusal_info_xml,
                                 content_type="application/vnd.example.info+xml",
                                 headers={"Warning": '399 example.com "not allowed"'})

        Raises:
            ValueError: for a code outside 300-699, an owned header, ``body``
                without ``content_type`` or the reverse, or an empty ``body``.
            TypeError: for a header name or value that is not a ``str``, or a
                ``body`` that is neither ``str`` nor ``bytes``.
            RuntimeError: in ``@b2bua.on_reoffer_answered``.

        Nothing is decided when it raises.
        """
        self._still_open("reject")
        if not 300 <= code <= 699:
            raise ValueError(f"offer.reject() takes a final non-2xx status, 300-699, not {code}")
        checked = _uas_response_headers("offer.reject", headers)
        if (body is None) != (content_type is None):
            raise ValueError("offer.reject(body=…) and content_type=… go together")
        raw = None
        if body is not None and content_type is not None:
            if not isinstance(body, (str, bytes)):
                raise TypeError("body must be str or bytes")
            if any(character in content_type for character in "\r\n\0"):
                raise ValueError("offer.reject(): content_type contains a line break or NUL")
            raw = body.encode() if isinstance(body, str) else body
            if not raw:
                raise ValueError("offer.reject(): body is empty")
        self._decision = ("reject", code, reason)
        self._answer_extras = None if raw is None and not checked else {
            "content_type": content_type if raw is not None else None,
            "body": raw,
            "headers": checked,
        }

    def answer(
        self,
        sdp: Optional[str] = None,
        body: Optional[Union[str, bytes]] = None,
        content_type: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        """Answer the offer here and relay nothing.

        Without ``sdp`` siphon answers from the session in force toward the
        offerer (the media engine's on an anchored call), with the direction
        the offer leaves (a ``sendonly`` hold is answered ``recvonly``). The
        media engine is not told, so the other party can be played an
        announcement. Streams that are keyed, use ICE or are grouped
        (DTLS-SRTP, SDES, BUNDLE) are answered this way only for an offer
        that asks for none of it again (the same streams, addresses, keys,
        ICE credentials and grouping, any direction); an ICE restart, a
        re-key or a moved stream is refused ``488``. On a call the media
        engine answered itself, the engine answers the offer. ``sdp`` is sent
        as the answer instead.

        ``body`` with its ``content_type`` is sent with the answer, for a
        service that carries a document of its own beside the session
        description (RFC 5621 §3):

        - a single part of any type goes out as the second part of a
          ``multipart/mixed`` body after the SDP, under a boundary siphon
          draws;
        - a ``multipart/*`` body without an ``application/sdp`` part gets
          the SDP part first, under its own boundary (build this one to give
          a part its own headers);
        - a ``multipart/*`` body with an ``application/sdp`` part, or an
          ``application/sdp`` body, gives the answer itself, as ``sdp`` does.

        A 200 that carries no SDP (an UPDATE without an offer) carries
        ``body`` as it was given.

        ``headers`` is added to the 200, in its order. The headers siphon
        owns on a response it sends are refused, as on ``call.answer()``:
        ``Via``, ``From``, ``To``, ``Call-ID``, ``CSeq``, ``Max-Forwards``,
        ``Contact``, ``Record-Route``, ``Route``, ``Content-Length``,
        ``Content-Type``, ``RSeq``, ``RAck``, ``Require``, ``Supported``,
        ``Session-Expires`` and ``Min-SE``.

        Example::

            @b2bua.on_reoffer
            def upgrade(call, offer):
                if offer.request.get_header("Resource-Priority"):
                    offer.answer(body=service_info_xml,
                                 content_type="application/vnd.example.info+xml",
                                 headers={"Resource-Priority": "example.0"})

        Raises:
            RuntimeError: in ``@b2bua.on_reoffer_answered``.
            ValueError: for an owned header, ``body`` without
                ``content_type`` or the reverse, an empty ``body``, an answer
                given both in ``sdp`` and in the body, or a ``multipart/*``
                body without a ``boundary`` or a part delimited by it.
            TypeError: for a header name or value that is not a ``str``.

        Nothing is decided when it raises.
        """
        self._still_open("answer")
        checked = _uas_response_headers("offer.answer", headers)
        sdp, extras_body = sdp_and_body("offer.answer", sdp, body, content_type)
        self._decision = ("answer", sdp)
        self._answer_extras = {
            "content_type": extras_body[0] if extras_body else None,
            "body": extras_body[1] if extras_body else None,
            "headers": checked,
        }

    @property
    def decision(self) -> tuple:
        """Mock-only: ``("relay",)``, ``("reject", code, reason)`` or
        ``("answer", sdp)``."""
        return self._decision

    @property
    def answer_extras(self) -> Optional[dict]:
        """Mock-only: what ``offer.answer()`` put beside the answer, as
        ``{"content_type": str | None, "body": bytes | None, "headers":
        dict}``; ``None`` unless the decision is an answer."""
        return self._answer_extras

    def _still_open(self, what: str) -> None:
        if self._answered:
            raise RuntimeError(
                f"offer.{what}() decides an offer before it is relayed; in "
                "@b2bua.on_reoffer_answered the offer has been answered already"
            )

    def _complete(self, status_code: int, answer_sdp: Optional[str], locally: bool) -> None:
        self._answered = True
        self._status_code = status_code
        self._answer_sdp = answer_sdp
        self._answered_locally = locally

    def __repr__(self) -> str:
        return (
            f"<Reoffer {self._method} from {self._side} kind={self._kind} "
            f"direction={self._direction or 'none'}>"
        )
