"""
Mock SDP parser — mirrors the Rust ``PySdpNamespace``, ``PySdp``,
``PyMediaSection`` types.

Usage::

    from siphon import sdp

    s = sdp.parse(request)            # from a SIP message
    s = sdp.parse("v=0\\r\\n...")     # from a raw string
    s = sdp.parse(b"v=0\\r\\n...")    # from bytes

    # Session-level properties
    s.origin                          # str | None
    s.session_name                    # str | None
    s.connection                      # str | None

    # Session-level attribute API
    s.get_attr("group")               # "BUNDLE audio video"
    s.set_attr("group", "BUNDLE audio")
    s.remove_attr("ice-lite")
    s.has_attr("ice-lite")            # bool
    s.attrs                           # list[str] — all a= values

    # Media sections
    for m in s.media:
        m.media_type                  # "audio"
        m.port                        # int (r/w)
        m.protocol                    # "RTP/AVP"
        m.codecs                      # ["PCMU", "PCMA"]
        m.connection                  # str | None
        m.get_attr("des")             # "qos mandatory local sendrecv"
        m.set_attr("des", "qos optional local sendrecv")
        m.remove_attr("des")
        m.has_attr("sendrecv")

    # Codec filtering (RTP sections only)
    s.filter_codecs(["PCMU", "PCMA"])
    s.remove_codecs(["G729"])

    # Remove media sections by type
    s.remove_media("video")

    # Apply back to message
    s.apply(request)                  # sets body + content_type
    str(s)                            # serialize
    bytes(s)                          # serialize

Formats that are not RTP payload types (``t38``, ``webrtc-datachannel``,
``*``), their ``a=fmtp:`` lines and a ``port/count`` survive a parse and
serialize unchanged (RFC 8866 §5.14).
"""

from __future__ import annotations

from typing import Callable, Optional, Union

# Well-known static payload type names (RFC 3551).
_STATIC_CODEC_NAMES: dict[int, str] = {
    0: "PCMU", 3: "GSM", 4: "G723", 5: "DVI4", 6: "DVI4",
    7: "LPC", 8: "PCMA", 9: "G722", 10: "L16", 11: "L16",
    12: "QCELP", 13: "CN", 14: "MPA", 15: "G728", 18: "G729",
    25: "CelB", 26: "JPEG", 28: "nv", 31: "H261", 32: "MPV",
    33: "MP2T", 34: "H263",
}


def _attr_matches_name(attr_value: str, name: str) -> bool:
    """Check if an attribute value (after ``a=``) matches the given name."""
    attr_name = attr_value.split(":", 1)[0]
    return attr_name == name


def _attr_extract_value(attr_value: str) -> str:
    """Extract the value portion of an attribute (after the first ``:``)."""
    parts = attr_value.split(":", 1)
    return parts[1] if len(parts) > 1 else ""


def _parse_u16(text: str) -> Optional[int]:
    """The 16-bit unsigned number *text* is, or ``None``."""
    digits = text[1:] if text.startswith("+") else text
    if not digits or not digits.isascii() or not digits.isdigit():
        return None
    value = int(digits)
    return value if value <= 0xFFFF else None


def _codec_name(rtpmap: list[tuple[int, str]], fmt: str) -> Optional[str]:
    """The codec an RTP format names: its rtpmap encoding, else its static name.

    ``None`` for a format that is not a payload type number or names nothing
    known.
    """
    payload_type = _parse_u16(fmt)
    if payload_type is None:
        return None
    for mapped, encoding in rtpmap:
        if mapped == payload_type:
            return encoding.split("/")[0]
    return _STATIC_CODEC_NAMES.get(payload_type)


class MockMediaSection:
    """A single media section within a parsed SDP body.

    Shares state with the parent ``MockSdp`` — mutations are immediately
    visible from either side.

    Example::

        s = sdp.parse(request)
        m = s.media[0]
        m.port = 0              # hold
        m.set_attr("ptime", "30")
        s.apply(request)
    """

    def __init__(
        self,
        media_type: str,
        port: int,
        protocol: str,
        formats: list[str],
        rtpmap: list[tuple[int, str]],
        fmtp: list[tuple[str, str]],
        other_attrs: list[str],
        port_count: Optional[int] = None,
    ) -> None:
        self._media_type = media_type
        self.port = port
        self._port_count = port_count
        self._protocol = protocol
        self._formats = formats
        self._rtpmap = rtpmap
        self._fmtp = fmtp
        self._other_attrs = other_attrs

    @property
    def media_type(self) -> str:
        """Media type: ``"audio"``, ``"video"``, ``"application"``, etc."""
        return self._media_type

    @property
    def protocol(self) -> str:
        """Protocol: ``"RTP/AVP"``, ``"RTP/SAVPF"``, ``"udptl"``, etc.

        ``""`` when the ``m=`` line has none.
        """
        return self._protocol

    @property
    def codecs(self) -> list[str]:
        """Codec names derived from rtpmap and static payload types.

        Only an RTP section has codecs. In any other section (T.38 ``udptl``,
        WebRTC ``UDP/DTLS/SCTP``, ``TCP/MSRP``) the formats are not payload
        types, so this is ``[]``.

        Example::

            m.codecs  # ["PCMU", "PCMA", "opus"]
        """
        if not self._is_rtp():
            return []
        names: list[str] = []
        for fmt in self._formats:
            name = _codec_name(self._rtpmap, fmt)
            if name is not None:
                names.append(name)
        return names

    @property
    def connection(self) -> Optional[str]:
        """Media-level connection (``c=``), or ``None``.

        Example::

            m.connection  # "IN IP4 192.168.1.1"
        """
        for line in self._other_attrs:
            if line.startswith("c="):
                return line[2:]
        return None

    @property
    def attrs(self) -> list[str]:
        """All ``a=`` attribute values for this media section.

        Returns the part after ``a=``. Excludes ``rtpmap`` and ``fmtp``
        (which are stored separately), except an ``rtpmap`` line whose payload
        type is not a number or an ``fmtp`` line without parameters, which
        stay here as they arrived.

        Example::

            m.attrs  # ["sendrecv", "ptime:20", "des:qos mandatory local sendrecv"]
        """
        return [line[2:] for line in self._other_attrs if line.startswith("a=")]

    @attrs.setter
    def attrs(self, values: list[str]) -> None:
        """Replace all ``a=`` lines. Non-``a=`` lines (``c=``, ``b=``) are preserved.

        Example::

            m.attrs = ["sendonly", "ptime:30"]
        """
        self._other_attrs = [
            line for line in self._other_attrs if not line.startswith("a=")
        ]
        for value in values:
            self._other_attrs.append(f"a={value}")

    def get_attr(self, name: str) -> Optional[str]:
        """Get the value of the first ``a=`` attribute matching *name*.

        For ``a=des:qos mandatory local sendrecv``, ``get_attr("des")``
        returns ``"qos mandatory local sendrecv"``.
        For flag attributes like ``a=sendrecv``, returns ``""``.
        Returns ``None`` if not found.

        Args:
            name: Attribute name (part before the first ``:``, or the flag name).

        Example::

            m.get_attr("ptime")       # "20"
            m.get_attr("sendrecv")    # ""
            m.get_attr("nonexistent") # None
        """
        for line in self._other_attrs:
            if line.startswith("a="):
                attr = line[2:]
                if _attr_matches_name(attr, name):
                    return _attr_extract_value(attr)
        return None

    def set_attr(self, name: str, value: str = "") -> None:
        """Set (replace first or append) a media-level attribute.

        ``set_attr("des", "qos optional local sendrecv")`` produces
        ``a=des:qos optional local sendrecv``.
        ``set_attr("sendrecv")`` produces ``a=sendrecv`` (flag).

        Args:
            name: Attribute name.
            value: Attribute value (empty string for flags).

        Example::

            m.set_attr("ptime", "30")
            m.set_attr("sendrecv")    # flag
        """
        new_line = f"a={name}" if not value else f"a={name}:{value}"
        for i, line in enumerate(self._other_attrs):
            if line.startswith("a=") and _attr_matches_name(line[2:], name):
                self._other_attrs[i] = new_line
                return
        self._other_attrs.append(new_line)

    def remove_attr(self, name: str) -> None:
        """Remove all ``a=`` attributes matching *name*.

        Args:
            name: Attribute name to remove.

        Example::

            m.remove_attr("des")  # removes all a=des:... lines
        """
        self._other_attrs = [
            line for line in self._other_attrs
            if not (line.startswith("a=") and _attr_matches_name(line[2:], name))
        ]

    def has_attr(self, name: str) -> bool:
        """Check whether an ``a=`` attribute with *name* exists.

        Args:
            name: Attribute name to check.

        Example::

            m.has_attr("sendrecv")  # True
        """
        for line in self._other_attrs:
            if line.startswith("a=") and _attr_matches_name(line[2:], name):
                return True
        return False

    def _is_rtp(self) -> bool:
        """Whether the section carries RTP, so its formats are payload types."""
        return any(part.lower() == "rtp" for part in self._protocol.split("/"))

    def _retain_codecs(self, keep: Callable[[Optional[str]], bool]) -> None:
        """Keep the formats whose codec *keep* accepts, in an RTP section only.

        A section left with no format is rejected instead: port 0 and its
        first format kept, because an ``m=`` line needs one (RFC 3264 §6).
        """
        if not self._is_rtp():
            return
        if any(keep(_codec_name(self._rtpmap, fmt)) for fmt in self._formats):
            self._formats = [
                fmt for fmt in self._formats
                if keep(_codec_name(self._rtpmap, fmt))
            ]
        elif self._formats:
            self._formats = self._formats[:1]
            self.port = 0
            self._port_count = None
        payload_types = {_parse_u16(fmt) for fmt in self._formats}
        self._rtpmap = [(pt, c) for pt, c in self._rtpmap if pt in payload_types]
        self._fmtp = [(fmt, p) for fmt, p in self._fmtp if fmt in self._formats]

    def __repr__(self) -> str:
        return (
            f"<MediaSection type={self._media_type!r} "
            f"port={self.port} protocol={self._protocol!r}>"
        )


class MockSdp:
    """Parsed SDP body with structured access to session and media attributes.

    Example::

        s = sdp.parse(request)
        s.get_attr("group")            # "BUNDLE audio video"
        for m in s.media:
            m.set_attr("ptime", "30")
        s.apply(request)
    """

    def __init__(
        self,
        session_lines: list[str],
        media_sections: list[MockMediaSection],
    ) -> None:
        self._session_lines = session_lines
        self._media_sections = media_sections

    # -----------------------------------------------------------------
    # Session-level properties
    # -----------------------------------------------------------------

    @property
    def origin(self) -> Optional[str]:
        """Origin line value (``o=``), or ``None``.

        Example::

            s.origin  # "alice 2890844526 2890844526 IN IP4 10.0.0.1"
        """
        for line in self._session_lines:
            if line.startswith("o="):
                return line[2:]
        return None

    @property
    def session_name(self) -> Optional[str]:
        """Session name (``s=``), or ``None``.

        Example::

            s.session_name  # "SIPhon"
        """
        for line in self._session_lines:
            if line.startswith("s="):
                return line[2:]
        return None

    @property
    def connection(self) -> Optional[str]:
        """Session-level connection (``c=``), or ``None``.

        Example::

            s.connection  # "IN IP4 10.0.0.1"
        """
        for line in self._session_lines:
            if line.startswith("c="):
                return line[2:]
        return None

    # -----------------------------------------------------------------
    # Session-level attribute API
    # -----------------------------------------------------------------

    @property
    def attrs(self) -> list[str]:
        """All session-level ``a=`` values as a list of strings.

        Example::

            s.attrs  # ["group:BUNDLE audio video", "ice-lite"]
        """
        return [line[2:] for line in self._session_lines if line.startswith("a=")]

    @attrs.setter
    def attrs(self, values: list[str]) -> None:
        """Replace all session-level ``a=`` lines.

        Non-``a=`` lines (``v=``, ``o=``, ``s=``, ``c=``, ``t=``) are preserved.

        Example::

            s.attrs = ["tool:SIPhon", "recvonly"]
        """
        self._session_lines = [
            line for line in self._session_lines if not line.startswith("a=")
        ]
        for value in values:
            self._session_lines.append(f"a={value}")

    def get_attr(self, name: str) -> Optional[str]:
        """Get the value of the first session-level attribute matching *name*.

        For ``a=group:BUNDLE audio video``, ``get_attr("group")`` returns
        ``"BUNDLE audio video"``.
        For flag attributes like ``a=ice-lite``, returns ``""``.
        Returns ``None`` if not found.

        Args:
            name: Attribute name.

        Example::

            s.get_attr("group")      # "BUNDLE audio video"
            s.get_attr("ice-lite")   # ""
        """
        for line in self._session_lines:
            if line.startswith("a="):
                attr = line[2:]
                if _attr_matches_name(attr, name):
                    return _attr_extract_value(attr)
        return None

    def set_attr(self, name: str, value: str = "") -> None:
        """Set (replace or append) a session-level attribute.

        Args:
            name: Attribute name.
            value: Attribute value (empty string for flags).

        Example::

            s.set_attr("group", "BUNDLE audio")
            s.set_attr("ice-lite")    # flag
        """
        new_line = f"a={name}" if not value else f"a={name}:{value}"
        for i, line in enumerate(self._session_lines):
            if line.startswith("a=") and _attr_matches_name(line[2:], name):
                self._session_lines[i] = new_line
                return
        self._session_lines.append(new_line)

    def remove_attr(self, name: str) -> None:
        """Remove all session-level attributes matching *name*.

        Args:
            name: Attribute name to remove.

        Example::

            s.remove_attr("ice-lite")
        """
        self._session_lines = [
            line for line in self._session_lines
            if not (line.startswith("a=") and _attr_matches_name(line[2:], name))
        ]

    def has_attr(self, name: str) -> bool:
        """Check whether a session-level attribute with *name* exists.

        Args:
            name: Attribute name.

        Example::

            s.has_attr("ice-lite")  # True
        """
        for line in self._session_lines:
            if line.startswith("a=") and _attr_matches_name(line[2:], name):
                return True
        return False

    # -----------------------------------------------------------------
    # Media sections
    # -----------------------------------------------------------------

    @property
    def media(self) -> list[MockMediaSection]:
        """List of media sections.

        Example::

            for m in s.media:
                print(m.media_type, m.port)
        """
        return self._media_sections

    # -----------------------------------------------------------------
    # Codec filtering
    # -----------------------------------------------------------------

    def filter_codecs(self, keep: list[str]) -> None:
        """Keep only codecs whose names match the given list (case-insensitive).

        Applies to RTP sections only. Any other section (T.38 ``udptl``,
        WebRTC ``UDP/DTLS/SCTP``, ``TCP/MSRP``) is left as it is, because its
        formats are not codecs. An RTP section left with none of the codecs is
        rejected rather than emptied: its port becomes 0 and its first format
        stays, since an ``m=`` line needs at least one (RFC 3264 §6).

        Args:
            keep: List of codec names to keep (e.g. ``["PCMU", "PCMA"]``).

        Example::

            s.filter_codecs(["PCMU", "PCMA"])
        """
        keep_lower = {name.lower() for name in keep}
        for media in self._media_sections:
            media._retain_codecs(
                lambda name: name is not None and name.lower() in keep_lower
            )

    def remove_codecs(self, remove: list[str]) -> None:
        """Remove codecs by name (case-insensitive).

        Applies to RTP sections only, like ``filter_codecs``. Removing every
        codec of a stream rejects it the same way: port 0, first format kept.

        Args:
            remove: List of codec names to remove (e.g. ``["G729"]``).

        Example::

            s.remove_codecs(["telephone-event"])
        """
        remove_lower = {name.lower() for name in remove}
        for media in self._media_sections:
            media._retain_codecs(
                lambda name: name is None or name.lower() not in remove_lower
            )

    # -----------------------------------------------------------------
    # Media section removal
    # -----------------------------------------------------------------

    def remove_media(self, media_type: str) -> None:
        """Remove all media sections with the given type.

        Args:
            media_type: Media type to remove (e.g. ``"video"``).

        Example::

            s.remove_media("video")
        """
        self._media_sections = [
            m for m in self._media_sections if m._media_type != media_type
        ]

    # -----------------------------------------------------------------
    # Apply / serialization
    # -----------------------------------------------------------------

    def apply(self, target: object) -> None:
        """Write the SDP back into a Request/Reply/Call message.

        Sets the body, updates ``Content-Type`` to ``application/sdp``.

        Args:
            target: A ``Request``, ``Reply``, or ``Call`` mock object.

        Example::

            s = sdp.parse(request)
            s.media[0].set_attr("ptime", "30")
            s.apply(request)
        """
        serialized = str(self).encode("utf-8")
        target._body = serialized  # type: ignore[attr-defined]
        target._content_type = "application/sdp"  # type: ignore[attr-defined]
        if hasattr(target, "_headers"):
            target._headers["Content-Length"] = str(len(serialized))  # type: ignore[attr-defined]

    def __str__(self) -> str:
        """Serialize to SDP string.

        Example::

            sdp_text = str(s)
        """
        lines: list[str] = []
        for line in self._session_lines:
            lines.append(f"{line}\r\n")
        for media in self._media_sections:
            m_line = f"m={media._media_type} {media.port}"
            if media._port_count is not None:
                m_line += f"/{media._port_count}"
            if media._protocol:
                m_line += f" {media._protocol}"
            for fmt in media._formats:
                m_line += f" {fmt}"
            lines.append(f"{m_line}\r\n")
            for attr in media._other_attrs:
                lines.append(f"{attr}\r\n")
            for pt, codec in media._rtpmap:
                lines.append(f"a=rtpmap:{pt} {codec}\r\n")
            for fmt, params in media._fmtp:
                lines.append(f"a=fmtp:{fmt} {params}\r\n")
        return "".join(lines)

    def __bytes__(self) -> bytes:
        """Serialize to SDP bytes.

        Example::

            sdp_bytes = bytes(s)
        """
        return str(self).encode("utf-8")

    def __repr__(self) -> str:
        name = self.session_name or "-"
        return f"<Sdp session_name={name!r} media_sections={len(self._media_sections)}>"


class MockSdpNamespace:
    """Mock ``sdp`` namespace — SDP parser and manipulator.

    Usage::

        from siphon import sdp

        s = sdp.parse(request)
        s.media[0].set_attr("des", "qos optional local sendrecv")
        s.apply(request)
    """

    def parse(self, source: Union[str, bytes, object]) -> MockSdp:
        """Parse SDP from a Request/Reply/Call message, a string, or bytes.

        Parsing does not reject SDP it cannot fully read: whatever it does not
        break out is kept and written back as it arrived.

        Args:
            source: A ``Request``, ``Reply``, ``Call``, ``str``, or ``bytes``
                containing SDP.

        Returns:
            An ``Sdp`` object for structured inspection and manipulation.

        Raises:
            ValueError: If the message has no body or the body is invalid.
            TypeError: If the source type is unsupported.

        Example::

            s = sdp.parse(request)
            s = sdp.parse("v=0\\r\\n...")
            s = sdp.parse(b"v=0\\r\\n...")
        """
        if isinstance(source, str):
            return _parse_sdp_string(source)
        if isinstance(source, bytes):
            text = source.decode("utf-8")
            return _parse_sdp_string(text)
        # Try message object (Request/Reply/Call) — must have _body or body attr.
        if not hasattr(source, "_body") and not hasattr(source, "body"):
            raise TypeError(
                "sdp.parse() expects a Request, Reply, Call, str, or bytes"
            )
        body = getattr(source, "_body", None)
        if body is None:
            body = getattr(source, "body", None)
        if not body:
            raise ValueError("message has no SDP body")
        if isinstance(body, bytes):
            text = body.decode("utf-8")
        elif isinstance(body, str):
            text = body
        else:
            raise TypeError(
                "sdp.parse() expects a Request, Reply, Call, str, or bytes"
            )
        return _parse_sdp_string(text)

    def __repr__(self) -> str:
        return "<SdpNamespace>"


def _parse_port(field: str) -> tuple[int, Optional[int]]:
    """Split an ``m=`` port field, ``49170`` or ``49170/2``, into port and count."""
    port_text, _, count_text = field.partition("/")
    port = _parse_u16(port_text)
    count = _parse_u16(count_text) if count_text else None
    return (port if port is not None else 0), count


def _parse_rtpmap(line: str) -> Optional[tuple[int, str]]:
    """``a=rtpmap:97 opus/48000/2`` → ``(97, "opus/48000/2")``, else ``None``."""
    payload_type, space, encoding = line[len("a=rtpmap:"):].partition(" ")
    value = _parse_u16(payload_type)
    if not space or value is None:
        return None
    return value, encoding


def _parse_fmtp(line: str) -> Optional[tuple[str, str]]:
    """``a=fmtp:97 minptime=10`` → ``("97", "minptime=10")``, else ``None``."""
    fmt, space, parameters = line[len("a=fmtp:"):].partition(" ")
    if not space:
        return None
    return fmt, parameters


def _parse_sdp_string(sdp_text: str) -> MockSdp:
    """Parse an SDP string into a ``MockSdp`` object."""
    session_lines: list[str] = []
    media_sections: list[MockMediaSection] = []
    current_media: Optional[dict] = None

    for raw_line in sdp_text.split("\n"):
        line = raw_line.rstrip("\r")

        if line.startswith("m="):
            # Save previous media section.
            if current_media is not None:
                media_sections.append(_build_media_section(current_media))
            # Parse new m= line: every format is kept as the token it is.
            parts = line[2:].split()
            port, port_count = _parse_port(parts[1]) if len(parts) > 1 else (0, None)
            current_media = {
                "media_type": parts[0] if parts else "",
                "port": port,
                "port_count": port_count,
                "protocol": parts[2] if len(parts) > 2 else "",
                "formats": parts[3:],
                "rtpmap": [],
                "fmtp": [],
                "other_attrs": [],
            }
        elif current_media is not None:
            rtpmap = _parse_rtpmap(line) if line.startswith("a=rtpmap:") else None
            fmtp = _parse_fmtp(line) if line.startswith("a=fmtp:") else None
            if rtpmap is not None:
                current_media["rtpmap"].append(rtpmap)
            elif fmtp is not None:
                current_media["fmtp"].append(fmtp)
            elif line:
                current_media["other_attrs"].append(line)
        elif line:
            session_lines.append(line)

    # Save last media section.
    if current_media is not None:
        media_sections.append(_build_media_section(current_media))

    return MockSdp(session_lines, media_sections)


def _build_media_section(data: dict) -> MockMediaSection:
    """Create a ``MockMediaSection`` from parsed data."""
    return MockMediaSection(
        media_type=data["media_type"],
        port=data["port"],
        protocol=data["protocol"],
        formats=data["formats"],
        rtpmap=data["rtpmap"],
        fmtp=data["fmtp"],
        other_attrs=data["other_attrs"],
        port_count=data["port_count"],
    )
