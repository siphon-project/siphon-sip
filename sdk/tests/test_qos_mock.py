"""Tests for the SDK's ``siphon.qos`` mock — the SDP→IPFilterRule helper that
P-CSCF scripts call to build the ``media_components`` list for Rx AAR / N5
Npcf_PolicyAuthorization.
"""
import pytest

from siphon_sdk import mock_module

mock_module.install()

from siphon import qos  # noqa: E402  (must come after install)


OFFER = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 192.0.2.2\r\n"
    "s=-\r\n"
    "c=IN IP4 192.0.2.2\r\n"
    "t=0 0\r\n"
    "m=audio 50000 RTP/AVP 0 8\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n"
)

ANSWER = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 198.51.100.10\r\n"
    "s=-\r\n"
    "c=IN IP4 198.51.100.10\r\n"
    "t=0 0\r\n"
    "m=audio 30000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n"
)


def test_orig_emits_full_five_tuple_with_rtcp():
    components = qos.media_flows_from_sdp(
        offer=OFFER, answer=ANSWER, direction="orig",
    )
    assert len(components) == 1
    component = components[0]
    assert component["media_type"] == "audio"
    flows = component["flows"]
    assert len(flows) == 2

    rtp_descs = flows[0]["descriptions"]
    assert rtp_descs == [
        "permit in 17 from 192.0.2.2 50000 to 198.51.100.10 30000",
        "permit out 17 from 198.51.100.10 30000 to 192.0.2.2 50000",
    ]
    assert flows[1]["usage"] == "rtcp"
    rtcp_descs = flows[1]["descriptions"]
    assert rtcp_descs == [
        "permit in 17 from 192.0.2.2 50001 to 198.51.100.10 30001",
        "permit out 17 from 198.51.100.10 30001 to 192.0.2.2 50001",
    ]


def test_term_flips_ue_and_remote():
    components = qos.media_flows_from_sdp(
        offer=OFFER, answer=ANSWER, direction="term",
    )
    rtp_descs = components[0]["flows"][0]["descriptions"]
    assert rtp_descs[0] == "permit in 17 from 198.51.100.10 30000 to 192.0.2.2 50000"
    assert rtp_descs[1] == "permit out 17 from 192.0.2.2 50000 to 198.51.100.10 30000"


def _audio_sdp(address_type, address, port):
    return (
        "v=0\r\n"
        f"o=- 1 1 IN {address_type} {address}\r\n"
        "s=-\r\n"
        f"c=IN {address_type} {address}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 0\r\n"
    )


@pytest.mark.parametrize("address_type,offerer,answerer", [
    ("IP4", "192.0.2.2", "198.51.100.10"),
    ("IP6", "2001:db8:1::2", "2001:db8:2::10"),
])
@pytest.mark.parametrize("leg", ["orig", "term"])
def test_ue_is_source_of_in_and_destination_of_out(address_type, offerer, answerer, leg):
    """TS 29.214 clause 5.3.8: "in" is uplink, "out" is downlink, so the UE
    is the source of the "in" rule and the destination of the "out" rule,
    for RTP and RTCP alike, as siphon builds them."""
    components = qos.media_flows_from_sdp(
        offer=_audio_sdp(address_type, offerer, 50000),
        answer=_audio_sdp(address_type, answerer, 30000),
        direction=leg,
    )
    if leg == "orig":
        ue, ue_port, remote, remote_port = offerer, 50000, answerer, 30000
    else:
        ue, ue_port, remote, remote_port = answerer, 30000, offerer, 50000

    flows = components[0]["flows"]
    assert len(flows) == 2
    for offset, flow in enumerate(flows):  # RTP, then RTCP one port up
        uplink, downlink = (rule.split() for rule in flow["descriptions"])
        assert uplink[:2] == ["permit", "in"]
        assert uplink[3:] == ["from", ue, str(ue_port + offset),
                              "to", remote, str(remote_port + offset)]
        assert downlink[:2] == ["permit", "out"]
        assert downlink[3:] == ["from", remote, str(remote_port + offset),
                                "to", ue, str(ue_port + offset)]


def test_rtcp_mux_collapses_to_single_flow():
    mux_offer = (
        "v=0\r\n"
        "o=- 1 1 IN IP4 100.65.0.2\r\n"
        "s=-\r\n"
        "c=IN IP4 100.65.0.2\r\n"
        "t=0 0\r\n"
        "m=audio 50000 RTP/AVP 0\r\n"
        "a=rtcp-mux\r\n"
    )
    mux_answer = (
        "v=0\r\n"
        "o=- 1 1 IN IP4 100.64.0.10\r\n"
        "s=-\r\n"
        "c=IN IP4 100.64.0.10\r\n"
        "t=0 0\r\n"
        "m=audio 30000 RTP/AVP 0\r\n"
        "a=rtcp-mux\r\n"
    )
    components = qos.media_flows_from_sdp(
        offer=mux_offer, answer=mux_answer, direction="orig",
    )
    assert len(components[0]["flows"]) == 1


def test_rtcp_attr_overrides_port():
    custom_offer = (
        "v=0\r\n"
        "o=- 1 1 IN IP4 100.65.0.2\r\n"
        "s=-\r\n"
        "c=IN IP4 100.65.0.2\r\n"
        "t=0 0\r\n"
        "m=audio 50000 RTP/AVP 0\r\n"
        "a=rtcp:59999\r\n"
    )
    components = qos.media_flows_from_sdp(
        offer=custom_offer, answer=ANSWER, direction="orig",
    )
    rtcp_descs = components[0]["flows"][1]["descriptions"]
    assert " 100.65.0.2 59999 " in rtcp_descs[0]


def _sdp(address, session_attrs, media):
    text = (
        "v=0\r\n"
        f"o=- 1 1 IN IP4 {address}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {address}\r\n"
        "t=0 0\r\n"
    )
    text += "".join(f"a={attr}\r\n" for attr in session_attrs)
    for section in media:
        text += "".join(f"{line}\r\n" for line in section.split("|"))
    return text


def _statuses(offer, answer, direction):
    return [
        (component["number"], component["media_type"], component["flow_status"],
         len(component["flows"]))
        for component in qos.media_flows_from_sdp(
            offer=offer, answer=answer, direction=direction)
    ]


def _flow_status(offer_media, answer_media, direction):
    return _statuses(_sdp("192.0.2.2", [], [offer_media]),
                     _sdp("198.51.100.10", [], [answer_media]), direction)[0][2]


AUDIO_OFFER = "m=audio 50000 RTP/AVP 0"
AUDIO_ANSWER = "m=audio 30000 RTP/AVP 0"


@pytest.mark.parametrize("offer_attr,answer_attr,direction,expected", [
    # TS 29.213 table 6.2.1: the answer's attribute, read against the
    # direction of the SDP carrying it (NOTE 5, NOTE 8).
    ("sendonly", "recvonly", "orig", "enabled-up"),
    ("sendonly", "recvonly", "term", "enabled-down"),
    ("recvonly", "sendonly", "orig", "enabled-down"),
    ("recvonly", "sendonly", "term", "enabled-up"),
    ("sendrecv", "inactive", "orig", "disabled"),
    ("sendrecv", "inactive", "term", "disabled"),
    ("sendrecv", "sendrecv", "orig", "enabled"),
    ("sendrecv", "sendrecv", "term", "enabled"),
    # NOTE 5: a=inactive in the offer wins.
    ("inactive", "sendrecv", "orig", "disabled"),
    ("inactive", "sendrecv", "term", "disabled"),
    ("sendonly", "sendrecv", "orig", "enabled"),
])
def test_table_6_2_1_direction_rows(offer_attr, answer_attr, direction, expected):
    assert _flow_status(f"{AUDIO_OFFER}|a={offer_attr}",
                        f"{AUDIO_ANSWER}|a={answer_attr}", direction) == expected


@pytest.mark.parametrize("direction", ["orig", "term"])
def test_no_direction_attribute_names_enabled(direction):
    assert _flow_status(AUDIO_OFFER, AUDIO_ANSWER, direction) == "enabled"


@pytest.mark.parametrize("offer_session,answer_session,answer_media,direction,expected", [
    (["sendonly"], ["recvonly"], AUDIO_ANSWER, "orig", "enabled-up"),
    (["sendonly"], ["recvonly"], AUDIO_ANSWER, "term", "enabled-down"),
    (["inactive"], [], AUDIO_ANSWER, "term", "disabled"),
    ([], ["sendonly"], f"{AUDIO_ANSWER}|a=sendrecv", "term", "enabled"),
])
def test_session_level_direction(offer_session, answer_session, answer_media,
                                 direction, expected):
    statuses = _statuses(_sdp("192.0.2.2", offer_session, [AUDIO_OFFER]),
                         _sdp("198.51.100.10", answer_session, [answer_media]),
                         direction)
    assert statuses[0][2] == expected


@pytest.mark.parametrize("direction", ["orig", "term"])
@pytest.mark.parametrize("offer_attr,answer_attr", [
    ("sendonly", "recvonly"), ("recvonly", "sendonly"), ("sendrecv", "inactive"),
])
def test_rtcp_mux_forces_enabled(direction, offer_attr, answer_attr):
    assert _flow_status(f"{AUDIO_OFFER}|a=rtcp-mux|a={offer_attr}",
                        f"{AUDIO_ANSWER}|a=rtcp-mux|a={answer_attr}",
                        direction) == "enabled"


def test_rtcp_mux_not_accepted_leaves_direction():
    assert _flow_status(f"{AUDIO_OFFER}|a=rtcp-mux|a=sendonly",
                        f"{AUDIO_ANSWER}|a=recvonly", "orig") == "enabled-up"


@pytest.mark.parametrize("protocol", ["TCP", "TCP/MSRP", "UDP/DTLS/SCTP"])
@pytest.mark.parametrize("direction", ["orig", "term"])
def test_tcp_transport_is_enabled(protocol, direction):
    assert _flow_status(f"m=message 50000 {protocol} *|a=sendonly",
                        f"m=message 30000 {protocol} *|a=recvonly",
                        direction) == "enabled"


@pytest.mark.parametrize("direction", ["orig", "term"])
def test_port_zero_is_removed_and_numbering_is_stable(direction):
    offer = _sdp("192.0.2.2", [], [
        "m=video 0 RTP/AVP 96", "m=audio 50000 RTP/AVP 0", "m=video 50002 RTP/AVP 96"])
    answer = _sdp("198.51.100.10", [], [
        "m=video 0 RTP/AVP 96", "m=audio 30000 RTP/AVP 0", "m=video 0 RTP/AVP 96"])
    assert _statuses(offer, answer, direction) == [
        (1, "video", "removed", 0),
        (2, "audio", "enabled", 2),
        (3, "video", "removed", 0),
    ]


def test_sendonly_yields_uplink_status():
    hold = (
        "v=0\r\n"
        "o=- 1 1 IN IP4 100.65.0.2\r\n"
        "s=-\r\n"
        "c=IN IP4 100.65.0.2\r\n"
        "t=0 0\r\n"
        "m=audio 50000 RTP/AVP 0\r\n"
        "a=sendonly\r\n"
    )
    # RFC 3264 6.1: the answer to a sendonly stream is recvonly.
    components = qos.media_flows_from_sdp(
        offer=hold, answer=ANSWER.replace("a=sendrecv", "a=recvonly"),
        direction="orig",
    )
    assert components[0]["flow_status"] == "enabled-up"


def test_mismatched_m_counts_errors():
    one = (
        "v=0\r\n"
        "o=- 1 1 IN IP4 100.65.0.2\r\n"
        "s=-\r\n"
        "c=IN IP4 100.65.0.2\r\n"
        "t=0 0\r\n"
        "m=audio 50000 RTP/AVP 0\r\n"
    )
    two = (
        "v=0\r\n"
        "o=- 1 1 IN IP4 100.64.0.10\r\n"
        "s=-\r\n"
        "c=IN IP4 100.64.0.10\r\n"
        "t=0 0\r\n"
        "m=audio 30000 RTP/AVP 0\r\n"
        "m=video 30002 RTP/AVP 96\r\n"
    )
    import pytest

    with pytest.raises(ValueError):
        qos.media_flows_from_sdp(offer=one, answer=two, direction="orig")
