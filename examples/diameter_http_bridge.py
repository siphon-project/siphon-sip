"""Diameter -> HTTP bridge: a standalone siphon instance that fronts a plain
HTTP billing/balance API as a Diameter Online Charging System (OCS).

Run this as its OWN siphon process (see diameter_http_bridge.yaml). Another
siphon acting as the CTF (the `ro:` block) — or any 3GPP node — sends CCR to
this instance over Diameter Ro; this script translates each CCR into an async
HTTP call to your existing REST API and answers with a spec-correct CCA.

Why a separate instance: it keeps the credit-control policy (your HTTP backend)
decoupled from the call-processing siphon, and lets you put the OCS wherever the
billing API lives. siphon owns the Diameter transport + CER/DWR/framing; this
script owns only the translation.

Everything I/O is async: the handler `await`s the HTTP backend, so one slow
backend request never blocks the Diameter reader — siphon runs each handler on
its asyncio driver pool.

    HTTP contract this bridge expects (adapt to yours):
      POST {BILLING_API}/reserve   {"account","session","seconds"} -> {"granted_seconds": N}   (0 = no balance)
      POST {BILLING_API}/report    {"account","session","seconds"}  -> 200
      POST {BILLING_API}/debit     {"account","units","kind"}        -> {"ok": true|false}

Requires an async HTTP client. `pip install httpx` (or swap in aiohttp).
"""

import asyncio
import os

import httpx

from siphon import diameter, log

BILLING_API = os.environ.get("BILLING_API", "http://127.0.0.1:8080")
# Fail-closed by default: if the HTTP backend is unreachable we deny rather than
# give away free service. Set BRIDGE_FAIL_OPEN=1 to allow-uncharged instead.
FAIL_OPEN = os.environ.get("BRIDGE_FAIL_OPEN", "0") == "1"
HTTP_TIMEOUT_S = float(os.environ.get("BRIDGE_HTTP_TIMEOUT", "3.0"))
DEFAULT_GRANT_S = int(os.environ.get("BRIDGE_DEFAULT_GRANT", "30"))

# CC-Request-Type (RFC 8506 §8.3).
INITIAL, UPDATE, TERMINATION, EVENT = 1, 2, 3, 4

# Result-Code (RFC 8506 §9.1).
SUCCESS = 2001
UNABLE_TO_DELIVER = 3002
CREDIT_LIMIT_REACHED = 4012

# AVP codes we read out of grouped AVPs (a grouped AVP surfaces to Python as a
# list of (code, value, vendor) tuples).
SUBSCRIPTION_ID_DATA = 444
CC_TIME = 420
GRANTED_SERVICE_UNIT = 431
REQUESTED_SERVICE_UNIT = 437
USED_SERVICE_UNIT = 446
MULTIPLE_SERVICES_CREDIT_CONTROL = 456
RO_APPLICATION_ID = 4

# One shared connection pool for the whole process — a resource, not per-request
# state. Created lazily so import never blocks.
_client: httpx.AsyncClient | None = None


def _http() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(base_url=BILLING_API, timeout=HTTP_TIMEOUT_S)
    return _client


def _grouped_child(grouped, want_code: int):
    """Pull a child value out of a grouped AVP (list of (code, value, vendor))."""
    if not isinstance(grouped, list):
        return None
    for item in grouped:
        try:
            code, value, _vendor = item
        except (TypeError, ValueError):
            continue
        if code == want_code:
            return value
    return None


def _account(req) -> str | None:
    """Charged party: Subscription-Id-Data, falling back to User-Name."""
    sub = req.get_avp("Subscription-Id")
    data = _grouped_child(sub, SUBSCRIPTION_ID_DATA)
    if data:
        return str(data)
    user_name = req.get_avp("User-Name")
    return str(user_name) if user_name else None


def _unit_seconds(req, wrapper_code: int, default: int | None) -> int | None:
    """CC-Time from a service-unit AVP (Requested/Used), MSCC-nested or command-level."""
    mscc = req.get_avp("Multiple-Services-Credit-Control")
    su = _grouped_child(mscc, wrapper_code)
    secs = _grouped_child(su, CC_TIME) if su is not None else None
    if secs is None:
        # Command-level (single-service) fallback.
        name = "Requested-Service-Unit" if wrapper_code == REQUESTED_SERVICE_UNIT else "Used-Service-Unit"
        su = req.get_avp(name)
        secs = _grouped_child(su, CC_TIME) if su is not None else None
    return int(secs) if secs is not None else default


def _cca(req, result_code: int):
    """Build a CCA with the mandatory AVPs the CCA ABNF requires (RFC 8506 §3.2):
    CC-Request-Type, CC-Request-Number and Auth-Application-Id echoed from the
    request. `req.answer()` only seeds Session-Id/Result-Code/Origin."""
    answer = req.answer(result_code)
    answer.set_avp("Auth-Application-Id", RO_APPLICATION_ID)
    ct = req.get_avp("CC-Request-Type")
    if ct is not None:
        answer.set_avp("CC-Request-Type", ct)
    cn = req.get_avp("CC-Request-Number")
    if cn is not None:
        answer.set_avp("CC-Request-Number", cn)
    return answer


def _grant_cca(req, granted_seconds: int):
    """A 2001 CCA carrying MSCC -> Granted-Service-Unit -> CC-Time."""
    answer = _cca(req, SUCCESS)
    answer.set_avp(
        "Multiple-Services-Credit-Control",
        [("Granted-Service-Unit", [("CC-Time", int(granted_seconds))])],
    )
    return answer


@diameter.on_request
async def on_diameter(req):
    if req.command_name != "CCR":
        # This bridge only serves Credit-Control; anything else is undeliverable.
        return req.reject(UNABLE_TO_DELIVER, "bridge serves Ro CCR only")

    cc_type = req.get_avp("CC-Request-Type")
    account = _account(req)
    session = req.get_avp("Session-Id")
    if account is None:
        return req.reject(UNABLE_TO_DELIVER, "no Subscription-Id")

    try:
        if cc_type in (INITIAL, UPDATE):
            # Reserve the next quota from the HTTP backend.
            want = _unit_seconds(req, REQUESTED_SERVICE_UNIT, DEFAULT_GRANT_S)
            resp = await _http().post(
                "/reserve",
                json={"account": account, "session": str(session), "seconds": want},
            )
            resp.raise_for_status()
            granted = int(resp.json().get("granted_seconds", 0))
            if granted <= 0:
                log.info(f"[ocs-bridge] {account}: no balance -> 4012")
                return _cca(req, CREDIT_LIMIT_REACHED)
            return _grant_cca(req, granted)

        if cc_type == TERMINATION:
            # Report FINAL usage (Used-Service-Unit CC-Time, not Requested).
            # Fire-and-forget: acknowledge the CCR-T now and push usage on the loop.
            used = _unit_seconds(req, USED_SERVICE_UNIT, 0) or 0
            asyncio.create_task(_report(account, str(session), used))
            return _cca(req, SUCCESS)

        if cc_type == EVENT:
            # One-shot debit (SMS/RCS DIRECT_DEBITING).
            resp = await _http().post(
                "/debit", json={"account": account, "units": 1, "kind": "event"}
            )
            resp.raise_for_status()
            if not resp.json().get("ok", False):
                return _cca(req, CREDIT_LIMIT_REACHED)
            return _cca(req, SUCCESS)

        return req.reject(UNABLE_TO_DELIVER, f"unknown CC-Request-Type {cc_type}")

    except (httpx.HTTPError, asyncio.TimeoutError) as exc:
        # Backend unreachable -> Credit-Control-Failure-Handling.
        if FAIL_OPEN:
            log.warn(f"[ocs-bridge] backend down, failing OPEN: {exc}")
            return _grant_cca(req, DEFAULT_GRANT_S)
        log.error(f"[ocs-bridge] backend down, failing CLOSED: {exc}")
        return req.reject(UNABLE_TO_DELIVER, "billing backend unavailable")


async def _report(account: str, session: str, seconds: int) -> None:
    """Push final usage to the backend; best-effort, off the answer path."""
    try:
        await _http().post(
            "/report", json={"account": account, "session": session, "seconds": seconds}
        )
    except (httpx.HTTPError, asyncio.TimeoutError) as exc:
        log.warn(f"[ocs-bridge] usage report failed for {account}: {exc}")
