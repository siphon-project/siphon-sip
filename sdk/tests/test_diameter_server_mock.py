"""Tests for the server-mode Diameter mocks in siphon_sdk."""

import asyncio

from siphon_sdk import mock_module


def _fresh_diameter():
    mock_module.install()
    diameter = mock_module.get_diameter()
    diameter._peers.clear()
    return diameter


def test_on_inbound_cer_and_config():
    diameter = _fresh_diameter()
    diameter.set_config(
        {
            "tenants": {
                "default": {
                    "identity": {
                        "origin_host": "diam.epc.example.org",
                        "origin_realm": "epc.example.org",
                    },
                    "clients": [{"name": "mme", "allowed_ips": ["10.0.0.0/24"]}],
                }
            }
        }
    )

    from siphon import diameter as d

    @d.on_inbound_cer
    def cer_received(peer_addr, peer_name, asserted_origin_host):
        identity = d.config["tenants"]["default"]["identity"]
        return identity["origin_host"], identity["origin_realm"]

    result = cer_received("10.0.0.5", "mme", "mme.epc.example.org")
    assert result == ("diam.epc.example.org", "epc.example.org")


def test_peer_pool_round_robin_and_liveness():
    diameter = _fresh_diameter()
    diameter.add_peer("hss-a", connected=True)
    diameter.add_peer("hss-b", connected=True)
    diameter.add_peer("hss-dead", connected=False)

    from siphon import diameter as d

    pool = d.peer_pool(["hss-a", "hss-b", "hss-dead"])
    assert pool.live_count == 2
    picked = {pool.pick_round_robin().name for _ in range(2)}
    assert picked == {"hss-a", "hss-b"}

    empty = d.peer_pool(["hss-dead"])
    assert empty.pick_round_robin() is None


def test_on_request_forward_and_reject():
    diameter = _fresh_diameter()
    diameter.add_peer("hss", connected=True)

    from siphon import diameter as d

    @d.on_request
    async def handle(req):
        pool = d.peer_pool(["hss"])
        peer = pool.pick_round_robin()
        if peer is None:
            return req.reject(3002)
        return await req.forward_to(peer)

    req = mock_module.MockDiameterRequest(
        application_name="S6c",
        command_name="SRR",
        session_id="mme;1;1",
        peer=mock_module.MockPeer("mme", "default"),
    )
    answer = asyncio.run(handle(req))
    assert answer.result_code == 2001
    assert not answer.is_error

    # No live backend → reject 3002.
    diameter._peers["hss"] = False
    answer = asyncio.run(handle(req))
    assert answer.result_code == 3002
    assert answer.is_error


def test_event_sink_and_completed_hook():
    diameter = _fresh_diameter()

    from siphon import diameter as d

    @d.on_request_completed
    def completed(req, answer, latency_us):
        d.event_sink.emit(
            {"app": req.application_name, "rc": answer.result_code, "us": latency_us}
        )

    req = mock_module.MockDiameterRequest(application_name="Rx")
    answer = mock_module.MockDiameterAnswer(result_code=2001)
    completed(req, answer, 1234)
    assert d.event_sink.rows == [{"app": "Rx", "rc": 2001, "us": 1234}]


def test_s6a_air_ulr_purge():
    _fresh_diameter()
    from siphon import diameter as d

    air = d.s6a_air("001010000000001", b"\x00\xf1\x10", num_vectors=2)
    assert air["result_code"] == 2001
    assert len(air["vectors"]) == 2
    assert air["vectors"][0]["kasme"] == b"\x44" * 32

    ula = d.s6a_ulr("001010000000001", b"\x00\xf1\x10", rat_type=1004)
    assert ula["result_code"] == 2001
    assert ula["has_subscription_data"] is True

    pua = d.s6a_purge_ue("001010000000001")
    assert pua["result_code"] == 2001


def test_server_answer_with_grouped_avp():
    # siphon transports; the script builds the answer (incl. grouped AVPs).
    req = mock_module.MockDiameterRequest(
        application_name="S6a", command_name="AIR", session_id="mme;1;1"
    )
    answer = req.answer(2001)
    assert answer.result_code == 2001
    assert not answer.is_error
    # Build Authentication-Info -> E-UTRAN-Vector -> {RAND,...} as nested tuples.
    answer.set_avp(
        "Authentication-Info",
        [("E-UTRAN-Vector", [("RAND", b"\x11" * 16), ("KASME", b"\x44" * 32)])],
        vendor=10415,
    )
    stored = answer.get_avp("Authentication-Info", 10415)
    assert stored[0][0] == "E-UTRAN-Vector"


def test_on_reply_rewrites_answer():
    """@diameter.on_reply gets (req, answer) and rewrites AVPs in place."""
    diameter = _fresh_diameter()

    @diameter.on_reply
    def hide_topology(req, answer):
        # Topology hiding: replace the backend's Origin-Host before it goes
        # back upstream. siphon re-serializes the mutated answer.
        answer.set_avp("Origin-Host", b"diam.example.net")

    # The decorator returns the handler unchanged.
    assert hide_topology.__name__ == "hide_topology"

    req = mock_module.MockDiameterRequest(application_name="S6a", command_name="ULR")
    answer = req.answer(2001)
    hide_topology(req, answer)
    assert answer.get_avp("Origin-Host") == b"diam.example.net"


def test_peer_pool_tenant_defaults_to_single_domain():
    """peer_pool(target) works without a tenant arg (single-domain server)."""
    diameter = _fresh_diameter()
    diameter.add_peer("backend", connected=True)
    pool = diameter.peer_pool("backend")
    assert pool.pick_round_robin().name == "backend"


def test_ip_in_cidr_and_fnmatch_helpers():
    from siphon import diameter as d

    assert d.ip_in_cidr("10.0.0.42", "10.0.0.0/24")
    assert not d.ip_in_cidr("10.0.1.1", "10.0.0.0/24")
    assert d.fnmatch("epc.mnc001.mcc001.3gppnetwork.org", "epc.*.3gppnetwork.org")
    assert not d.fnmatch("ims.example.org", "epc.*")
    assert isinstance(d.now_us(), int)
