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


def test_disabled_stream_skipped():
    offer = (
        "v=0\r\n"
        "o=- 1 1 IN IP4 100.65.0.2\r\n"
        "s=-\r\n"
        "c=IN IP4 100.65.0.2\r\n"
        "t=0 0\r\n"
        "m=video 0 RTP/AVP 96\r\n"
        "m=audio 50000 RTP/AVP 0\r\n"
    )
    answer = (
        "v=0\r\n"
        "o=- 1 1 IN IP4 100.64.0.10\r\n"
        "s=-\r\n"
        "c=IN IP4 100.64.0.10\r\n"
        "t=0 0\r\n"
        "m=video 0 RTP/AVP 96\r\n"
        "m=audio 30000 RTP/AVP 0\r\n"
    )
    components = qos.media_flows_from_sdp(
        offer=offer, answer=answer, direction="orig",
    )
    assert len(components) == 1
    assert components[0]["media_type"] == "audio"


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
    components = qos.media_flows_from_sdp(
        offer=hold, answer=ANSWER, direction="orig",
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
