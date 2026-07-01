"""Tests for the mock ``smpp`` namespace + :class:`SmppTestHarness`.

The ``smpp`` namespace is injected at runtime by the siphon-smpp extension;
these tests exercise the siphon-sip mock of it (decorators, pyclasses, send
helpers) so SMPP scripts can be unit-tested without a running SMSC.
"""

import pytest

from siphon_sdk.mock_module import install, reset, get_registry
from siphon_sdk.smpp import (
    MockBind, MockBindResult, MockPdu, MockQueryResp, SMPP_STATUSES, _parse_receipt,
)
from siphon_sdk.smpp_testing import SmppTestHarness


@pytest.fixture(autouse=True)
def _install():
    """Install + reset the mock module before every test (function and method)."""
    install()
    reset()
    yield


# ---------------------------------------------------------------------------
# Decorator registration
# ---------------------------------------------------------------------------

class TestDecorators:
    def test_on_bind_registers(self):
        from siphon import smpp

        @smpp.on_bind
        def authorise(bind):
            return bind.accept()

        handlers = get_registry().handlers.get("smpp.on_bind", [])
        assert len(handlers) == 1
        method_filter, fn, is_async, metadata = handlers[0]
        assert fn is authorise
        assert not is_async
        assert method_filter is None

    def test_on_pdu_records_command_metadata(self):
        from siphon import smpp

        @smpp.on_pdu("submit_sm")
        def on_submit(pdu, session):
            return pdu.reply()

        handlers = get_registry().handlers.get("smpp.on_pdu", [])
        assert len(handlers) == 1
        _filter, fn, _is_async, metadata = handlers[0]
        assert fn is on_submit
        assert metadata == {"command": "submit_sm"}

    def test_on_session_records_event_metadata(self):
        from siphon import smpp

        @smpp.on_session("bound")
        def on_bound(session):
            pass

        handlers = get_registry().handlers.get("smpp.on_session", [])
        _filter, _fn, _is_async, metadata = handlers[0]
        assert _filter == "bound"
        assert metadata == {"event": "bound"}

    def test_async_handler_detected(self):
        from siphon import smpp

        @smpp.on_pdu("deliver_sm")
        async def on_deliver(pdu, session):
            return pdu.reply()

        _filter, fn, is_async, _meta = \
            get_registry().handlers["smpp.on_pdu"][0]
        assert is_async

    def test_coexists_with_proxy_handlers(self):
        from siphon import proxy, smpp

        @proxy.on_request
        def route(request):
            pass

        @smpp.on_pdu("submit_sm")
        def on_submit(pdu, session):
            pass

        assert len(get_registry().get("proxy.on_request")) == 1
        assert len(get_registry().handlers.get("smpp.on_pdu", [])) == 1


# ---------------------------------------------------------------------------
# Pyclasses
# ---------------------------------------------------------------------------

class TestPdu:
    def test_reply_defaults_to_ok(self):
        pdu = MockPdu(command="submit_sm")
        reply = pdu.reply()
        assert reply.command_status == "ESME_ROK"
        assert reply.ok
        assert reply.message_id is None

    def test_reply_with_message_id(self):
        reply = MockPdu().reply(message_id="msg-42")
        assert reply.message_id == "msg-42"
        assert reply.ok

    def test_reply_reject_status(self):
        reply = MockPdu().reply(command_status="ESME_RSUBMITFAIL")
        assert reply.command_status == "ESME_RSUBMITFAIL"
        assert not reply.ok

    def test_reply_unknown_status_raises(self):
        with pytest.raises(ValueError, match="unknown SMPP status"):
            MockPdu().reply(command_status="ESME_BOGUS")

    def test_reply_query_defaults_message_id_to_queried(self):
        pdu = MockPdu(command="query_sm", message_id="qid-7")
        reply = pdu.reply_query(message_state=2, final_date="2401011200")
        assert reply.message_state == 2
        assert reply.message_id == "qid-7"   # defaults to queried id
        assert reply.final_date == "2401011200"

    def test_reply_query_explicit_message_id(self):
        pdu = MockPdu(command="query_sm", message_id="qid-7")
        reply = pdu.reply_query(message_state=7, message_id="other", error_code=9)
        assert reply.message_id == "other"
        assert reply.error_code == 9

    def test_is_tpdu_reflects_udhi_bit(self):
        assert MockPdu(esm_class=0x40).is_tpdu
        assert MockPdu(esm_class=0xC0).is_tpdu
        assert not MockPdu(esm_class=0x00).is_tpdu
        assert not MockPdu(esm_class=0x01).is_tpdu

    def test_is_dlr_reflects_receipt_bit(self):
        assert MockPdu(esm_class=0x04).is_dlr
        assert MockPdu(esm_class=0x44).is_dlr
        assert not MockPdu(esm_class=0x00).is_dlr
        assert not MockPdu(esm_class=0x40).is_dlr

    def test_receipt_only_for_dlr(self):
        # receipt-shaped body but not flagged as a DLR → None
        pdu = MockPdu(esm_class=0x00, short_message=b"id:1 stat:DELIVRD")
        assert pdu.receipt is None
        # flagged DLR → parsed dict
        dlr = MockPdu(esm_class=0x04, short_message=b"id:1 stat:DELIVRD err:000")
        assert dlr.receipt["id"] == "1"
        assert dlr.receipt["stat"] == "DELIVRD"

    def test_short_message_coerced_to_bytes(self):
        assert MockPdu(short_message="hello").short_message == b"hello"
        assert MockPdu(short_message=b"raw").short_message == b"raw"


class TestBind:
    def test_accept(self):
        result = MockBind(system_id="esme1").accept()
        assert result.accept
        assert bool(result)
        assert result.status == "ESME_ROK"

    def test_reject_with_status_and_reason(self):
        result = MockBind().reject("ESME_RINVPASWD", "bad password")
        assert not result.accept
        assert not bool(result)
        assert result.status == "ESME_RINVPASWD"
        assert result.reason == "bad password"

    def test_reject_default_status(self):
        result = MockBind().reject()
        assert result.status == "ESME_RBINDFAIL"
        assert result.reason == ""

    def test_reject_unknown_status_raises(self):
        with pytest.raises(ValueError, match="unknown SMPP status"):
            MockBind().reject("ESME_BOGUS")


class TestResponses:
    def test_smpp_resp_ok(self):
        from siphon_sdk.smpp import MockSmppResp
        assert MockSmppResp(command_status="ESME_ROK").ok
        assert not MockSmppResp(command_status="ESME_RSUBMITFAIL").ok

    def test_query_resp_fields(self):
        resp = MockQueryResp(message_id="m1", message_state=2, final_date="x", error_code=3)
        assert resp.ok
        assert resp.message_state == 2
        assert resp.error_code == 3

    def test_alert_notification_command(self):
        from siphon_sdk.smpp import MockAlertNotification
        alert = MockAlertNotification(source_addr="15550100", esme_addr="esme1")
        assert alert.command == "alert_notification"


class TestReceiptParser:
    def test_canonical_form(self):
        body = (b"id:0a1b2c3d sub:001 dlvrd:001 submit date:2401011200 "
                b"done date:2401011201 stat:DELIVRD err:000 text:Hello world")
        r = _parse_receipt(body)
        assert r["id"] == "0a1b2c3d"
        assert r["submit_date"] == "2401011200"
        assert r["done_date"] == "2401011201"
        assert r["stat"] == "DELIVRD"
        assert r["err"] == "000"
        assert r["text"] == "Hello world"

    def test_minimal(self):
        r = _parse_receipt(b"id:XYZ stat:EXPIRED")
        assert r["id"] == "XYZ"
        assert r["stat"] == "EXPIRED"
        assert "sub" not in r

    def test_non_receipt_is_none(self):
        assert _parse_receipt(b"hey are we still on for lunch?") is None


def test_status_set_matches_expected_size():
    # Guard the mirror of parse_smpp_status — 41 statuses (SMPP 3.4 + query).
    assert "ESME_ROK" in SMPP_STATUSES
    assert "ESME_RQUERYFAIL" in SMPP_STATUSES
    assert len(SMPP_STATUSES) == 41


# ---------------------------------------------------------------------------
# Send helpers (recorded on smpp.sent)
# ---------------------------------------------------------------------------

class TestSendHelpers:
    def test_submit_via_records_and_returns_message_id(self):
        harness = SmppTestHarness()
        harness.load_source("""
from siphon import smpp

@smpp.on_pdu("submit_sm")
async def route(pdu, session):
    resp = await smpp.submit_via(bind="carrier", source_addr=pdu.source_addr,
                                 destination_addr=pdu.destination_addr,
                                 short_message=pdu.short_message)
    return pdu.reply(message_id=resp.message_id)
""")
        reply = harness.submit_sm(source_addr="15550100",
                                  destination_addr="15550101", short_message=b"hi")
        assert reply.ok and reply.message_id
        op, kwargs = harness.sent[0]
        assert op == "submit_via"
        assert kwargs["bind"] == "carrier"
        assert kwargs["destination_addr"] == "15550101"

    def test_query_via_result_is_configurable(self):
        harness = SmppTestHarness()
        harness.smpp.set_query_result(MockQueryResp(message_id="m1", message_state=2))
        harness.load_source("""
from siphon import smpp

@smpp.on_pdu("query_sm")
async def route(pdu, session):
    resp = await smpp.query_via(bind="carrier", message_id=pdu.message_id)
    return pdu.reply_query(message_state=resp.message_state)
""")
        reply = harness.query_sm(message_id="m1")
        assert reply.message_state == 2


# ---------------------------------------------------------------------------
# End-to-end via SmppTestHarness
# ---------------------------------------------------------------------------

class TestHarness:
    def _gateway(self, harness):
        harness.load_source("""
from siphon import smpp, log

@smpp.on_bind
def authorise(bind):
    if bind.password != "s3cret":
        return bind.reject("ESME_RINVPASWD", "bad password")
    return bind.accept()

@smpp.on_pdu("submit_sm")
def on_submit(pdu, session):
    if not pdu.destination_addr:
        return pdu.reply(command_status="ESME_RINVDSTADR")
    return pdu.reply(message_id="msg-1")

@smpp.on_pdu("deliver_sm")
async def on_deliver(pdu, session):
    if pdu.is_dlr:
        await smpp.deliver_to(session_id="esme-1", source_addr=pdu.source_addr,
                              destination_addr=pdu.destination_addr,
                              short_message=pdu.short_message, esm_class=0x04)
    return pdu.reply()

@smpp.on_session("bound")
def on_bound(session):
    log.info(f"bound: {session.system_id}")
""")

    def test_bind_accept_and_reject(self):
        harness = SmppTestHarness()
        self._gateway(harness)
        assert harness.bind("esme1", password="s3cret")
        rejected = harness.bind("esme1", password="wrong")
        assert not rejected
        assert rejected.status == "ESME_RINVPASWD"

    def test_bind_default_reject_without_handler(self):
        harness = SmppTestHarness()
        harness.load_source("from siphon import smpp\n")
        result = harness.bind("esme1")
        assert isinstance(result, MockBindResult)
        assert not result

    def test_submit_sm_success_and_reject(self):
        harness = SmppTestHarness()
        self._gateway(harness)
        ok = harness.submit_sm(source_addr="15550100",
                               destination_addr="15550101", short_message=b"hi")
        assert ok.ok and ok.message_id == "msg-1"
        bad = harness.submit_sm(source_addr="15550100",
                                destination_addr="", short_message=b"hi")
        assert bad.command_status == "ESME_RINVDSTADR"

    def test_deliver_dlr_routes_back_to_esme(self):
        harness = SmppTestHarness()
        self._gateway(harness)
        reply = harness.deliver_sm(
            source_addr="15550101", destination_addr="15550100",
            esm_class=0x04, short_message=b"id:msg-1 stat:DELIVRD err:000")
        assert reply.ok
        op, kwargs = harness.sent[0]
        assert op == "deliver_to"
        assert kwargs["session_id"] == "esme-1"

    def test_no_handler_returns_none(self):
        harness = SmppTestHarness()
        harness.load_source("from siphon import smpp\n")
        assert harness.submit_sm(source_addr="1", destination_addr="2",
                                 short_message=b"x") is None

    def test_session_event_fires(self):
        harness = SmppTestHarness()
        self._gateway(harness)
        harness.session_event("bound", system_id="esme1")
        assert any("bound: esme1" in msg for _lvl, msg in harness.log.messages)

    def test_query_sm_reply_query(self):
        harness = SmppTestHarness()
        harness.load_source("""
from siphon import smpp

@smpp.on_pdu("query_sm")
def on_query(pdu, session):
    return pdu.reply_query(message_state=2, final_date="2401011200")
""")
        reply = harness.query_sm(message_id="msg-1")
        assert reply.message_state == 2
        assert reply.message_id == "msg-1"


class TestConfigReadouts:
    def test_config_readouts(self):
        harness = SmppTestHarness(config={
            "server": {"bind_address": "10.0.0.1", "port": 2775},
            "binds": [{"name": "carrier", "host": "smsc.example", "port": 2775,
                       "system_id": "sysid", "bind_type": "transceiver"}],
            "routing": {"default_chain": ["carrier"], "rules": []},
        })
        harness.load_source("""
from siphon import smpp, log

@smpp.on_pdu("submit_sm")
def on_submit(pdu, session):
    log.info(smpp.bind_address())
    log.info(str(len(smpp.binds())))
    default_chain, rules = smpp.routing_rules()
    log.info(",".join(default_chain))
    return pdu.reply()
""")
        harness.submit_sm(source_addr="1", destination_addr="2", short_message=b"x")
        msgs = [msg for _lvl, msg in harness.log.messages]
        assert "10.0.0.1:2775" in msgs
        assert "1" in msgs
        assert "carrier" in msgs
