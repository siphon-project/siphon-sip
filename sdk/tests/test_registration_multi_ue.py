"""Tests for the per-entry address surface of the ``registration`` mock: one
process registering many IMS UEs, each from its own address.

Covers ``local_addr`` / ``require_local_addr`` / ``refresh_window`` on
``registration.add``, ``set_local_addr``, ``find_by_local``, ``counts``, the
extended ``list()`` keys, ``flow()`` defaulting its ``ue_ip``, and the
``"awaiting_address"`` state and ``on_change`` event. Mirrors the Rust binding.

Addresses are RFC 5737, identities the 3GPP test range (MCC 001 / MNC 01).
"""
import pytest

from siphon_sdk import mock_module

PCSCF = "sip:198.51.100.10:5060"
DOMAIN = "ims.mnc01.mcc001.3gppnetwork.org"
AKA_K = "465b5ce8b199b49faa5f0a2ee238a6bc"
AKA_OPC = "cd63cb71954a9f4e48a5994e37a02baf"


def impu(index: int) -> str:
    return f"sip:00101000000000{index}@{DOMAIN}"


def impi(index: int) -> str:
    return f"00101000000000{index}@{DOMAIN}"


@pytest.fixture
def registration():
    mock_module.reset()
    mock_module.install()
    yield mock_module.get_registration()
    mock_module.reset()


@pytest.fixture
def events(registration):
    seen = []

    @registration.on_change
    def record(aor, event_type, state):
        seen.append((aor, event_type, state["state"]))

    return seen


def add_ue(registration, index: int, **kwargs) -> None:
    arguments = dict(
        user=impi(index), auth="aka", k=AKA_K, opc=AKA_OPC,
        ipsec=True, ue_port_c=6100, ue_port_s=6101,
        imei=f"01234567-00000{index}-0",
    )
    arguments.update(kwargs)
    registration.add(impu(index), PCSCF, **arguments)


# --- add(local_addr=, require_local_addr=, refresh_window=) -----------------

def test_add_with_local_addr_stores_and_lists_it(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    [listed] = registration.list()
    assert listed["local_addr"] == "192.0.2.77"
    assert listed["state"] == "registered"
    assert registration._entries[impu(1)]["require_local_addr"] is True


def test_add_local_addr_is_normalised(registration):
    add_ue(registration, 1, local_addr=" 2001:db8:0::1 ")
    assert registration.list()[0]["local_addr"] == "2001:db8::1"


def test_add_rejects_local_addr_that_is_not_an_ip(registration):
    with pytest.raises(ValueError, match="is not an IP address"):
        add_ue(registration, 1, local_addr="ue1.example.com")
    with pytest.raises(ValueError, match="is not an IP address"):
        add_ue(registration, 1, local_addr="192.0.2.77:5060")
    assert registration.count() == 0


@pytest.mark.parametrize("transport", ["tls", "TLS"])
def test_add_rejects_local_addr_on_tls(registration, transport):
    with pytest.raises(ValueError, match="needs transport udp or tcp"):
        registration.add("sip:trunk@carrier.example", PCSCF, user="trunk",
                         transport=transport, local_addr="192.0.2.77")
    assert registration.count() == 0


def test_add_takes_local_addr_on_tcp(registration):
    add_ue(registration, 1, local_addr="192.0.2.77", transport="tcp")
    assert registration.list()[0]["local_addr"] == "192.0.2.77"
    assert registration.flow(impu(1)).transport == "tcp"


def test_two_ipsec_ues_share_an_address_with_distinct_ports(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    add_ue(registration, 2, local_addr="192.0.2.77", ue_port_c=6200, ue_port_s=6201)
    assert registration.count() == 2


def test_same_address_and_ue_port_c_is_refused(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    with pytest.raises(ValueError, match="ue_port_c 6100 is already used by"):
        add_ue(registration, 2, local_addr="192.0.2.77", ue_port_s=6301)
    assert registration.count() == 1


def test_protected_ports_repeat_across_addresses(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    add_ue(registration, 2, local_addr="192.0.2.78")
    assert registration.count() == 2


def test_two_plain_entries_cannot_share_an_address(registration):
    registration.add("sip:a@carrier.example", PCSCF, user="a", local_addr="192.0.2.5")
    with pytest.raises(ValueError, match="local_addr 192.0.2.5 is already used by sip:a@"):
        registration.add("sip:b@carrier.example", PCSCF, user="b", local_addr="192.0.2.5")


def test_re_adding_the_same_aor_replaces_it_without_a_clash(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    add_ue(registration, 1, local_addr="192.0.2.77", interval=600)
    assert registration.count() == 1
    assert registration._entries[impu(1)]["interval"] == 600


def test_require_local_addr_without_address_awaits(registration, events):
    add_ue(registration, 1, require_local_addr=True)
    assert registration.status(impu(1)) == "awaiting_address"
    assert registration.list()[0]["local_addr"] is None
    assert events == [(impu(1), "awaiting_address", "awaiting_address")]


def test_add_without_address_or_requirement_uses_process_address(registration, events):
    add_ue(registration, 1)
    assert registration.status(impu(1)) == "registered"
    assert registration.list()[0]["local_addr"] is None
    assert events == [(impu(1), "registered", "registered")]


def test_refresh_window_is_stored(registration):
    add_ue(registration, 1, local_addr="192.0.2.77", refresh_window=(0.4, 0.6))
    assert registration._entries[impu(1)]["refresh_window"] == (0.4, 0.6)


@pytest.mark.parametrize("window", [(0.0, 0.5), (0.5, 1.0), (0.7, 0.3),
                                    (float("nan"), 0.5), (-0.1, 0.5)])
def test_bad_refresh_window_is_refused(registration, window):
    with pytest.raises(ValueError, match="0 < low <= high < 1"):
        add_ue(registration, 1, refresh_window=window)
    assert registration.count() == 0


def test_refresh_window_must_be_a_pair_tuple(registration):
    with pytest.raises(TypeError):
        add_ue(registration, 1, refresh_window=[0.4, 0.6])


# --- set_local_addr ---------------------------------------------------------

def test_set_local_addr_unknown_aor_returns_false(registration):
    assert registration.set_local_addr(impu(9), "192.0.2.77") is False


def test_set_local_addr_same_address_is_a_no_op(registration, events):
    add_ue(registration, 1, local_addr="192.0.2.77")
    events.clear()
    assert registration.set_local_addr(impu(1), "192.0.2.77") is True
    assert registration.status(impu(1)) == "registered"
    assert events == []


def test_set_local_addr_move_resets_to_unregistered(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    entry = registration._entries[impu(1)]
    entry["service_route"] = [f"<sip:orig@scscf.{DOMAIN};lr>"]
    entry["failure_count"] = 2
    entry["last_failure_status"] = 403
    assert registration.set_local_addr(impu(1), "192.0.2.78") is True
    [listed] = registration.list()
    assert listed["local_addr"] == "192.0.2.78"
    assert listed["state"] == "unregistered"
    assert listed["failure_count"] == 0
    assert listed["last_failure_status"] is None
    assert registration.service_route(impu(1)) == []


def test_set_local_addr_none_awaits_once_it_had_an_address(registration, events):
    add_ue(registration, 1, local_addr="192.0.2.77")
    events.clear()
    assert registration.set_local_addr(impu(1), None) is True
    assert registration.status(impu(1)) == "awaiting_address"
    assert events == [(impu(1), "awaiting_address", "awaiting_address")]


def test_set_local_addr_none_falls_back_when_never_required(registration, events):
    add_ue(registration, 1)
    events.clear()
    # Already on the process's address: nothing changes.
    assert registration.set_local_addr(impu(1), None) is True
    assert registration.status(impu(1)) == "registered"
    assert events == []


def test_setting_an_address_marks_the_entry_as_requiring_one(registration):
    add_ue(registration, 1)
    registration.set_local_addr(impu(1), "192.0.2.77")
    assert registration.status(impu(1)) == "unregistered"
    registration.set_local_addr(impu(1), None)
    assert registration.status(impu(1)) == "awaiting_address"


def test_awaiting_entry_leaves_the_state_when_given_an_address(registration):
    add_ue(registration, 1, require_local_addr=True)
    registration.set_local_addr(impu(1), "192.0.2.77")
    assert registration.status(impu(1)) == "unregistered"
    assert registration.list()[0]["local_addr"] == "192.0.2.77"


def test_set_local_addr_refuses_a_taken_pair(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    add_ue(registration, 2, local_addr="192.0.2.78")
    with pytest.raises(ValueError, match="already used by"):
        registration.set_local_addr(impu(2), "192.0.2.77")
    assert registration.list()[1]["local_addr"] == "192.0.2.78"


def test_set_local_addr_refuses_a_bad_ip(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    with pytest.raises(ValueError, match="is not an IP address"):
        registration.set_local_addr(impu(1), "not-an-address")


def test_set_local_addr_refuses_a_tls_entry(registration):
    registration.add("sip:trunk@carrier.example", PCSCF, user="trunk", transport="tls")
    with pytest.raises(ValueError, match="needs transport udp or tcp"):
        registration.set_local_addr("sip:trunk@carrier.example", "192.0.2.77")


def test_set_local_addr_moves_a_tcp_entry(registration):
    registration.add("sip:trunk@carrier.example", PCSCF, user="trunk", transport="tcp")
    assert registration.set_local_addr("sip:trunk@carrier.example", "192.0.2.77") is True


# --- find_by_local ----------------------------------------------------------

def test_find_by_local_by_ip_and_by_owned_ports(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    add_ue(registration, 2, local_addr="192.0.2.77", ue_port_c=6200, ue_port_s=6201)
    assert registration.find_by_local("192.0.2.77") == impu(1)
    assert registration.find_by_local("192.0.2.77:6101") == impu(1)
    assert registration.find_by_local("192.0.2.77:6100") == impu(1)
    assert registration.find_by_local("192.0.2.77:6201") == impu(2)
    assert registration.find_by_local("192.0.2.77:6200") == impu(2)
    # The plain port is shared on the address: the first entry owns it.
    assert registration.find_by_local("192.0.2.77:5060") == impu(1)


def test_find_by_local_misses(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    add_ue(registration, 2)   # process address: never matched
    assert registration.find_by_local("192.0.2.77:7000") is None
    assert registration.find_by_local("192.0.2.99") is None
    assert registration.find_by_local("203.0.113.1:5060") is None


def test_find_by_local_ipv6_forms(registration):
    add_ue(registration, 1, local_addr="2001:db8::7")
    assert registration.find_by_local("2001:db8::7") == impu(1)
    assert registration.find_by_local("[2001:db8::7]") == impu(1)
    assert registration.find_by_local("[2001:db8::7]:6101") == impu(1)
    assert registration.find_by_local("[2001:db8::7]:9") is None


def test_find_by_local_plain_entry_only_owns_plain_port(registration):
    registration.add("sip:a@carrier.example", PCSCF, user="a", local_addr="192.0.2.5")
    assert registration.find_by_local("192.0.2.5:5060") == "sip:a@carrier.example"
    assert registration.find_by_local("192.0.2.5:6100") is None


def test_find_by_local_accepts_a_flow_local_addr(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    flow = registration.flow(impu(1))
    assert registration.find_by_local(flow.local_addr) == impu(1)


@pytest.mark.parametrize("bad", ["", "ue1.example.com", "192.0.2.77:port",
                                 "192.0.2.77:70000", "[2001:db8::7", "2001:db8::7]:5"])
def test_find_by_local_rejects_unparseable(registration, bad):
    with pytest.raises(ValueError, match="is not an IP address or IP:port"):
        registration.find_by_local(bad)


# --- counts / list ----------------------------------------------------------

def test_counts_has_every_state_even_when_empty(registration):
    assert registration.counts() == {
        "unregistered": 0, "registering": 0, "challenging": 0,
        "registered": 0, "failed": 0, "awaiting_address": 0,
    }


def test_counts_tallies_states(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    add_ue(registration, 2, local_addr="192.0.2.78")
    add_ue(registration, 3, require_local_addr=True)
    registration.set_local_addr(impu(2), "192.0.2.79")
    counts = registration.counts()
    assert counts["registered"] == 1
    assert counts["unregistered"] == 1
    assert counts["awaiting_address"] == 1
    assert sum(counts.values()) == registration.count()


def test_list_has_the_extended_keys(registration):
    registration.add("sip:trunk@carrier.example", PCSCF, user="trunk")
    [listed] = registration.list()
    assert set(listed) == {"aor", "state", "expires_in", "local_addr",
                           "failure_count", "last_failure_status"}
    assert listed["local_addr"] is None
    assert listed["failure_count"] == 0
    assert listed["last_failure_status"] is None


# --- flow -------------------------------------------------------------------

def test_flow_defaults_ue_ip_to_local_addr(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    flow = registration.flow(impu(1))
    assert flow is not None
    assert flow.local_addr == "192.0.2.77:6100"


def test_flow_explicit_ue_ip_still_wins(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    assert registration.flow(impu(1), "198.51.100.5").local_addr == "198.51.100.5:6100"


def test_flow_ipv6_local_addr_is_bracketed(registration):
    add_ue(registration, 1, local_addr="2001:db8::7")
    assert registration.flow(impu(1)).local_addr == "[2001:db8::7]:6100"


def test_flow_unknown_aor_is_none(registration):
    assert registration.flow(impu(9)) is None


def test_flow_without_local_addr_needs_ue_ip(registration):
    add_ue(registration, 1)
    with pytest.raises(ValueError, match="pass ue_ip"):
        registration.flow(impu(1))
    assert registration.flow(impu(1), "192.0.2.10").local_addr == "192.0.2.10:6100"


def test_flow_rejects_a_bad_ue_ip(registration):
    add_ue(registration, 1, local_addr="192.0.2.77")
    with pytest.raises(ValueError, match="ue_ip"):
        registration.flow(impu(1), "nowhere")


def test_flow_non_ipsec_entry_is_none(registration):
    registration.add("sip:a@carrier.example", PCSCF, user="a", local_addr="192.0.2.5")
    assert registration.flow("sip:a@carrier.example") is None


# --- many UEs end to end ----------------------------------------------------

def test_many_ues_each_from_its_own_address(registration):
    for index in range(1, 10):
        add_ue(registration, index, local_addr=f"192.0.2.{100 + index}")
    assert registration.counts()["registered"] == 9
    for index in range(1, 10):
        assert registration.find_by_local(f"192.0.2.{100 + index}:6101") == impu(index)
