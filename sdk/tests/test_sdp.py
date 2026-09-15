"""
Tests for the SDP manipulation namespace (``from siphon import sdp``).

Covers parsing, attribute get/set/remove, codec filtering, media section
removal, apply-back to messages, and serialization roundtrips.
"""

import pytest
from siphon_sdk.sdp import MockSdpNamespace, MockSdp
from siphon_sdk.testing import SipTestHarness


SAMPLE_SDP = (
    "v=0\r\n"
    "o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n"
    "s=SIPhon\r\n"
    "c=IN IP4 10.0.0.1\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE audio video\r\n"
    "a=ice-lite\r\n"
    "m=audio 49170 RTP/AVP 0 8 97 101\r\n"
    "c=IN IP4 192.168.1.1\r\n"
    "a=sendrecv\r\n"
    "a=des:qos mandatory local sendrecv\r\n"
    "a=ptime:20\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:97 opus/48000/2\r\n"
    "a=fmtp:97 minptime=10;useinbandfec=1\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-16\r\n"
    "m=video 49172 RTP/AVP 96\r\n"
    "a=sendonly\r\n"
    "a=rtpmap:96 H264/90000\r\n"
)


@pytest.fixture
def ns():
    return MockSdpNamespace()


@pytest.fixture
def sdp(ns):
    return ns.parse(SAMPLE_SDP)


class TestParse:
    """Parsing from strings, bytes, and message objects."""

    def test_parse_string(self, ns):
        s = ns.parse(SAMPLE_SDP)
        assert s.session_name == "SIPhon"
        assert len(s.media) == 2

    def test_parse_bytes(self, ns):
        s = ns.parse(SAMPLE_SDP.encode("utf-8"))
        assert s.origin == "alice 2890844526 2890844526 IN IP4 10.0.0.1"

    def test_parse_empty_raises(self, ns):
        # Dummy object with no body.
        class NoBody:
            _body = None
            body = None
        with pytest.raises(ValueError, match="no SDP body"):
            ns.parse(NoBody())

    def test_parse_unsupported_type_raises(self, ns):
        with pytest.raises(TypeError, match="expects a Request"):
            ns.parse(12345)

    def test_parse_empty_string(self, ns):
        s = ns.parse("")
        assert len(s.media) == 0
        assert s.origin is None

    def test_parse_empty_bytes(self, ns):
        s = ns.parse(b"")
        assert len(s.media) == 0

    def test_parse_body_attr_fallback(self, ns):
        """Objects with ``body`` (not ``_body``) are also supported."""
        class MsgWithBody:
            body = SAMPLE_SDP.encode("utf-8")
        s = ns.parse(MsgWithBody())
        assert s.session_name == "SIPhon"

    def test_parse_falsy_body(self, ns):
        """Empty bytes body (falsy) should raise ValueError, not fall through."""
        class EmptyBody:
            _body = b""
            body = None
        with pytest.raises(ValueError, match="no SDP body"):
            ns.parse(EmptyBody())


class TestSessionProperties:
    """Session-level read-only properties."""

    def test_origin(self, sdp):
        assert sdp.origin == "alice 2890844526 2890844526 IN IP4 10.0.0.1"

    def test_session_name(self, sdp):
        assert sdp.session_name == "SIPhon"

    def test_connection(self, sdp):
        assert sdp.connection == "IN IP4 10.0.0.1"

    def test_missing_properties(self, ns):
        s = ns.parse("v=0\r\nt=0 0\r\n")
        assert s.origin is None
        assert s.session_name is None
        assert s.connection is None


class TestSessionAttrs:
    """Session-level a= attribute API."""

    def test_get_attr_with_value(self, sdp):
        assert sdp.get_attr("group") == "BUNDLE audio video"

    def test_get_attr_flag(self, sdp):
        assert sdp.get_attr("ice-lite") == ""

    def test_get_attr_missing(self, sdp):
        assert sdp.get_attr("nonexistent") is None

    def test_has_attr(self, sdp):
        assert sdp.has_attr("group")
        assert sdp.has_attr("ice-lite")
        assert not sdp.has_attr("sendrecv")

    def test_set_attr_replace(self, sdp):
        sdp.set_attr("group", "BUNDLE audio")
        assert sdp.get_attr("group") == "BUNDLE audio"
        assert len(sdp.attrs) == 2  # no duplication

    def test_set_attr_append(self, sdp):
        sdp.set_attr("msid-semantic", "WMS *")
        assert sdp.get_attr("msid-semantic") == "WMS *"
        assert len(sdp.attrs) == 3

    def test_set_attr_flag(self, sdp):
        sdp.set_attr("ice-options")
        assert sdp.has_attr("ice-options")

    def test_remove_attr(self, sdp):
        sdp.remove_attr("ice-lite")
        assert not sdp.has_attr("ice-lite")
        assert sdp.has_attr("group")

    def test_attrs_list(self, sdp):
        attrs = sdp.attrs
        assert "group:BUNDLE audio video" in attrs
        assert "ice-lite" in attrs

    def test_set_attrs_bulk(self, sdp):
        sdp.attrs = ["tool:SIPhon", "recvonly"]
        assert len(sdp.attrs) == 2
        assert sdp.get_attr("tool") == "SIPhon"
        # Non-a= lines preserved.
        assert sdp.origin is not None


class TestMediaProperties:
    """Media section properties."""

    def test_media_type(self, sdp):
        assert sdp.media[0].media_type == "audio"
        assert sdp.media[1].media_type == "video"

    def test_port(self, sdp):
        assert sdp.media[0].port == 49170
        assert sdp.media[1].port == 49172

    def test_port_setter(self, sdp):
        sdp.media[0].port = 0
        assert sdp.media[0].port == 0
        assert "m=audio 0 RTP/AVP" in str(sdp)

    def test_protocol(self, sdp):
        assert sdp.media[0].protocol == "RTP/AVP"

    def test_codecs(self, sdp):
        assert sdp.media[0].codecs == ["PCMU", "PCMA", "opus", "telephone-event"]
        assert sdp.media[1].codecs == ["H264"]

    def test_connection(self, sdp):
        assert sdp.media[0].connection == "IN IP4 192.168.1.1"
        assert sdp.media[1].connection is None


class TestMediaAttrs:
    """Media-level a= attribute API."""

    def test_get_attr_value(self, sdp):
        assert sdp.media[0].get_attr("des") == "qos mandatory local sendrecv"
        assert sdp.media[0].get_attr("ptime") == "20"

    def test_get_attr_flag(self, sdp):
        assert sdp.media[0].get_attr("sendrecv") == ""

    def test_get_attr_missing(self, sdp):
        assert sdp.media[0].get_attr("nonexistent") is None

    def test_set_attr_replace(self, sdp):
        sdp.media[0].set_attr("ptime", "30")
        assert sdp.media[0].get_attr("ptime") == "30"

    def test_set_attr_append(self, sdp):
        sdp.media[0].set_attr("maxptime", "60")
        assert sdp.media[0].get_attr("maxptime") == "60"

    def test_remove_attr(self, sdp):
        sdp.media[0].remove_attr("des")
        assert not sdp.media[0].has_attr("des")
        assert sdp.media[0].has_attr("sendrecv")

    def test_has_attr(self, sdp):
        assert sdp.media[0].has_attr("sendrecv")
        assert sdp.media[0].has_attr("des")
        assert not sdp.media[0].has_attr("rtcp")

    def test_attrs_list(self, sdp):
        attrs = sdp.media[0].attrs
        assert "sendrecv" in attrs
        assert "des:qos mandatory local sendrecv" in attrs
        assert "ptime:20" in attrs

    def test_set_attrs_bulk(self, sdp):
        sdp.media[0].attrs = ["sendonly", "ptime:30"]
        attrs = sdp.media[0].attrs
        assert len(attrs) == 2
        assert "sendonly" in attrs
        # Non-a= lines (c=) preserved.
        assert sdp.media[0].connection is not None


class TestCodecFiltering:
    """Codec filtering operations."""

    def test_filter_codecs(self, sdp):
        sdp.filter_codecs(["PCMU", "PCMA"])
        assert sdp.media[0].codecs == ["PCMU", "PCMA"]
        # H264 is not in the keep list, so the video stream is rejected
        # rather than left with an m= line that has no format.
        assert sdp.media[1].port == 0
        assert "m=video 0 RTP/AVP 96\r\n" in str(sdp)

    def test_filter_codecs_case_insensitive(self, sdp):
        sdp.filter_codecs(["pcmu", "Opus"])
        codecs = sdp.media[0].codecs
        assert "PCMU" in codecs
        assert "opus" in codecs

    def test_remove_codecs(self, sdp):
        sdp.remove_codecs(["telephone-event"])
        codecs = sdp.media[0].codecs
        assert "telephone-event" not in codecs
        assert "PCMU" in codecs

    def test_filter_rejects_a_stream_left_with_no_codec(self, ns):
        s = ns.parse(
            "v=0\r\n"
            "m=audio 49170 RTP/AVP 0 8\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
        )
        s.filter_codecs(["G722"])
        # RFC 3264 §6: port 0 rejects the stream, and the m= line keeps one
        # format because SDP requires at least one.
        assert str(s) == (
            "v=0\r\n"
            "m=audio 0 RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )

    def test_removing_every_codec_rejects_the_stream(self, ns):
        s = ns.parse("v=0\r\nm=audio 49170/2 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
        s.remove_codecs(["PCMA"])
        assert str(s) == "v=0\r\nm=audio 0 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"


# Every format below except the audio stream's is a token rather than an RTP
# payload type number (RFC 8866 §5.14): T.38 fax, a WebRTC data channel, MSRP,
# and a floor-control stream whose format also keys an fmtp line.
MIXED_FORMATS_SDP = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 192.0.2.10\r\n"
    "s=-\r\n"
    "c=IN IP4 192.0.2.10\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 8 101\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-15\r\n"
    "m=image 49172 udptl t38\r\n"
    "a=T38FaxVersion:0\r\n"
    "a=T38FaxRateManagement:transferredTCF\r\n"
    "m=application 49174 UDP/DTLS/SCTP webrtc-datachannel\r\n"
    "a=sctp-port:5000\r\n"
    "m=message 49176 TCP/MSRP *\r\n"
    "a=accept-types:message/cpim text/plain\r\n"
    "m=application 49178 udp MCPTT\r\n"
    "a=fmtp:MCPTT mc_queueing;mc_priority=5\r\n"
)


class TestFormatTokens:
    """Formats that are not RTP payload types survive parsing and filtering."""

    def test_round_trip_is_lossless(self, ns):
        assert str(ns.parse(MIXED_FORMATS_SDP)) == MIXED_FORMATS_SDP

    def test_filter_leaves_sections_that_are_not_rtp_alone(self, ns):
        s = ns.parse(MIXED_FORMATS_SDP)
        s.filter_codecs(["PCMA"])
        output = str(s)
        assert "m=audio 49170 RTP/AVP 8\r\n" in output
        assert "telephone-event" not in output
        assert "m=image 49172 udptl t38\r\n" in output
        assert "m=application 49174 UDP/DTLS/SCTP webrtc-datachannel\r\n" in output
        assert "m=message 49176 TCP/MSRP *\r\n" in output
        assert "m=application 49178 udp MCPTT\r\n" in output
        assert "a=fmtp:MCPTT mc_queueing;mc_priority=5\r\n" in output

    def test_sections_that_are_not_rtp_have_no_codecs(self, ns):
        s = ns.parse(MIXED_FORMATS_SDP)
        assert s.media[0].codecs == ["PCMA", "telephone-event"]
        assert [m.codecs for m in s.media[1:]] == [[], [], [], []]

    def test_port_count_is_kept(self, ns):
        body = "v=0\r\nm=video 49170/2 RTP/AVP 31\r\n"
        s = ns.parse(body)
        assert s.media[0].port == 49170
        assert str(s) == body

    def test_unreadable_rtpmap_and_fmtp_lines_are_kept(self, ns):
        body = (
            "v=0\r\n"
            "m=audio 49170 RTP/AVP 97\r\n"
            "a=rtpmap:dynamic opus/48000/2\r\n"
            "a=fmtp:97\r\n"
        )
        assert str(ns.parse(body)) == body

    def test_m_line_without_protocol_is_not_given_one(self, ns):
        body = "v=0\r\nm=audio 5060\r\n"
        s = ns.parse(body)
        assert s.media[0].protocol == ""
        assert str(s) == body


class TestMediaRemoval:
    """Media section removal."""

    def test_remove_video(self, sdp):
        sdp.remove_media("video")
        assert len(sdp.media) == 1
        assert sdp.media[0].media_type == "audio"

    def test_remove_nonexistent(self, sdp):
        sdp.remove_media("application")
        assert len(sdp.media) == 2


class TestSerialization:
    """Serialization and roundtrip."""

    def test_str_output(self, sdp):
        output = str(sdp)
        assert "v=0\r\n" in output
        assert "m=audio 49170 RTP/AVP" in output
        assert "a=sendrecv\r\n" in output
        assert "a=rtpmap:0 PCMU/8000\r\n" in output

    def test_bytes_output(self, sdp):
        output = bytes(sdp)
        assert b"v=0\r\n" in output

    def test_roundtrip(self, ns, sdp):
        """Parse → mutate → serialize → reparse → verify."""
        sdp.media[0].set_attr("des", "qos optional local sendrecv")
        output = str(sdp)
        reparsed = ns.parse(output)
        assert reparsed.media[0].get_attr("des") == "qos optional local sendrecv"
        assert reparsed.media[0].get_attr("ptime") == "20"
        assert reparsed.session_name == "SIPhon"

    def test_repr(self, sdp):
        assert "Sdp" in repr(sdp)
        assert "SIPhon" in repr(sdp)
        assert "MediaSection" in repr(sdp.media[0])

    def test_namespace_repr(self, ns):
        assert repr(ns) == "<SdpNamespace>"


class TestApply:
    """Applying SDP back to mock message objects."""

    def test_apply_updates_body(self, ns):
        class MockMsg:
            _body = SAMPLE_SDP.encode("utf-8")
            _content_type = "application/sdp"
            _headers = {}

        msg = MockMsg()
        s = ns.parse(msg)
        s.media[0].set_attr("ptime", "30")
        s.apply(msg)

        assert b"a=ptime:30" in msg._body
        assert msg._content_type == "application/sdp"

    def test_apply_updates_content_length(self, ns):
        class MockMsg:
            _body = SAMPLE_SDP.encode("utf-8")
            _content_type = "application/sdp"
            _headers = {}

        msg = MockMsg()
        s = ns.parse(msg)
        s.apply(msg)

        assert "Content-Length" in msg._headers
        assert msg._headers["Content-Length"] == str(len(msg._body))

    def test_apply_overwrites_content_type(self, ns):
        """apply() always sets Content-Type to application/sdp."""
        class MockMsg:
            _body = SAMPLE_SDP.encode("utf-8")
            _content_type = "multipart/mixed;boundary=abc"
            _headers = {}

        msg = MockMsg()
        s = ns.parse(msg)
        s.apply(msg)

        assert msg._content_type == "application/sdp"


class TestQosPreconditionRewrite:
    """The motivating use-case: rewriting QoS preconditions."""

    def test_mandatory_to_optional(self, ns):
        s = ns.parse(SAMPLE_SDP)
        for m in s.media:
            val = m.get_attr("des")
            if val and "mandatory" in val:
                m.set_attr("des", val.replace("mandatory", "optional"))

        audio = s.media[0]
        assert audio.get_attr("des") == "qos optional local sendrecv"
        output = str(s)
        assert "mandatory" not in output
        assert "optional" in output


class TestScriptIntegration:
    """Test SDP manipulation through a loaded script."""

    def test_sdp_rewrite_in_script(self):
        harness = SipTestHarness(local_domains=["example.com"])
        try:
            harness.load_source("""
from siphon import proxy, sdp

@proxy.on_request("INVITE")
def route(request):
    if request.has_body("application/sdp"):
        s = sdp.parse(request)
        for m in s.media:
            val = m.get_attr("des")
            if val and "mandatory" in val:
                m.set_attr("des", val.replace("mandatory", "optional"))
        s.apply(request)
    request.reply(200, "OK")
""")
            sdp_body = (
                "v=0\r\n"
                "o=- 0 0 IN IP4 0.0.0.0\r\n"
                "s=-\r\n"
                "t=0 0\r\n"
                "m=audio 5004 RTP/AVP 0\r\n"
                "a=des:qos mandatory local sendrecv\r\n"
                "a=rtpmap:0 PCMU/8000\r\n"
            )
            result = harness.send_request(
                "INVITE",
                "sip:bob@example.com",
                body=sdp_body.encode("utf-8"),
                content_type="application/sdp",
            )
            assert result.status_code == 200
        finally:
            harness.close()
