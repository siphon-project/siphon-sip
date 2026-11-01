"""registration.add(ims_features=["mcptt"], register_body=, register_headers=)."""

import pytest

from siphon_sdk import mock_module

IMPU = "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
K = "465b5ce8b199b49faa5f0a2ee238a6bc"
OPC = "cd63cb71954a9f4e48a5994e37a02baf"
MIME = "application/vnd.3gpp.mcptt-info+xml"


def make_registration():
    mock_module.install()
    registration = mock_module.get_registration()
    registration._entries.clear()
    return registration


def add(registration, **kwargs):
    registration.add(IMPU, "sip:198.51.100.10:5060", user="001010000000001",
                     auth="aka", k=K, opc=OPC, **kwargs)
    return registration._entries[IMPU]


def test_mcptt_feature_is_stored_lower_case():
    entry = add(make_registration(), ims_features=["MCPTT", "mmtel"])
    assert entry["ims_features"] == ["mcptt", "mmtel"]


def test_unknown_feature_is_refused():
    with pytest.raises(ValueError, match="mcptx"):
        add(make_registration(), ims_features=["mcptx"])


def test_body_and_headers_are_kept_in_order():
    entry = add(
        make_registration(),
        register_body=(MIME, "<mcpttinfo/>"),
        register_headers={"P-Preferred-Service": "urn:urn-7:3gpp-service.ims.icsi.mcptt",
                          "X-Second": "2"},
    )
    assert entry["register_body"] == (MIME, b"<mcpttinfo/>")
    assert [name for name, _ in entry["register_headers"]] == [
        "P-Preferred-Service", "X-Second"]


def test_bytes_body_is_kept_verbatim():
    entry = add(make_registration(), register_body=(MIME, b"\x00\xff"))
    assert entry["register_body"] == (MIME, b"\x00\xff")


@pytest.mark.parametrize("name", [
    "Via", "from", "To", "Call-ID", "CSeq", "Contact", "Expires", "Max-Forwards",
    "Route", "Content-Type", "Content-Length", "Authorization",
    "Security-Client", "Security-Verify", "Require", "Supported", "m", "l",
])
def test_headers_siphon_owns_are_refused(name):
    with pytest.raises(ValueError, match="siphon owns it"):
        add(make_registration(), register_headers={name: "x"})


def test_line_break_in_a_header_or_a_bad_content_type_is_refused():
    with pytest.raises(ValueError):
        add(make_registration(), register_headers={"X-A": "a\r\nVia: b"})
    with pytest.raises(ValueError):
        add(make_registration(), register_body=("xml", "<a/>"))


def test_entry_without_the_options_has_none():
    entry = add(make_registration())
    assert entry["register_body"] is None
    assert entry["register_headers"] == []
