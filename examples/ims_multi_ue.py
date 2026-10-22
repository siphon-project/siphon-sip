"""Many IMS UEs in one process: each UE registers into an IMS core (IMS-AKA
over IPsec sec-agree, 3GPP TS 33.203) from an address of its own, and a
plain-SIP "tester" calls through any of them both ways.

    MO:  tester  ->  siphon (as UE n)  ->  P-CSCF / IMS
    MT:  IMS     ->  siphon (as UE n)  ->  tester

The UE list is constant data: the inline UES tuple below, or a CSV file named
by $MULTI_UE_CSV with the header

    impu,impi,k,op,opc,imei,address

(supply op OR opc per row; an empty address means "no address right now").
Addresses are expected to change while siphon runs, so the source is re-read
every 10 s and every UE is told its current address. Restating an unchanged
address is a no-op, so this is safe to run on a timer. A UE whose address
changed gets a fresh registration from the new one; a UE whose address is
empty waits as `awaiting_address`.

Cross-request state lives in `registration` itself (the entries, their
state, their address). Nothing is kept in module globals, so a hot reload
changes nothing: `registration.add` only runs for an AoR that has no entry.

Config: examples/ims_multi_ue.yaml. Cookbook: docs/cookbook/ims-multi-ue.md.
"""
import csv
import json
import os
import time

from siphon import b2bua, registration, timer, log

HOME = os.environ.get("IMS_HOME", "ims.mnc01.mcc001.3gppnetwork.org")
PCSCF = os.environ.get("PCSCF", f"sip:pcscf.{HOME}:5060")
TESTER = os.environ.get("TESTER", "sip:tester@192.0.2.100:5060")
UE_CSV = os.environ.get("MULTI_UE_CSV")             # unset: the inline UES
STATUS_FILE = os.environ.get("MULTI_UE_STATUS")     # optional JSON per tick
INTERVAL = int(os.environ["MULTI_UE_INTERVAL"]) if os.environ.get("MULTI_UE_INTERVAL") else None

# Protected ports repeat across UEs, as they do across real handsets: the SAs
# are told apart by address.
UE_PORT_C = 6100
UE_PORT_S = 6101
IMS_FEATURES = ["mmtel", "smsip"]

# 3GPP test range (MCC 001 / MNC 01) with TS 35.208 Test Set 1 secrets.
# Replace with your own subscribers, or point $MULTI_UE_CSV at a file.
UES = (
    {
        "impu": f"sip:001010000000001@{HOME}",
        "impi": f"001010000000001@{HOME}",
        "k": "465b5ce8b199b49faa5f0a2ee238a6bc",
        "op": "",
        "opc": "cd63cb71954a9f4e48a5994e37a02baf",
        "imei": "01234567-000001-0",
        "address": "203.0.113.11",
    },
    {
        "impu": f"sip:001010000000002@{HOME}",
        "impi": f"001010000000002@{HOME}",
        "k": "465b5ce8b199b49faa5f0a2ee238a6bc",
        "op": "",
        "opc": "cd63cb71954a9f4e48a5994e37a02baf",
        "imei": "01234567-000002-0",
        "address": "203.0.113.12",
    },
)


def _load_ues():
    """The UE rows, or None when the CSV cannot be read (change nothing)."""
    if not UE_CSV:
        return list(UES)
    try:
        with open(UE_CSV, newline="") as handle:
            return [row for row in csv.DictReader(handle) if row.get("impu")]
    except OSError as error:
        log.error(f"multi-ue: cannot read {UE_CSV}: {error}")
        return None


def _sync():
    """Add the UEs siphon does not know yet, and give every UE its address."""
    rows = _load_ues()
    if rows is None:
        return
    for row in rows:
        impu = row["impu"]
        address = (row.get("address") or "").strip() or None
        try:
            if registration.status(impu) is None:
                registration.add(
                    impu,
                    PCSCF,
                    user=row["impi"],
                    interval=INTERVAL,
                    auth="aka",
                    k=row["k"],
                    op=row.get("op") or None,
                    opc=row.get("opc") or None,
                    ipsec=True,
                    ue_port_c=UE_PORT_C,
                    ue_port_s=UE_PORT_S,
                    imei=row.get("imei") or None,
                    ims_features=IMS_FEATURES,
                    local_addr=address,
                    # Never fall back to the process's own address.
                    require_local_addr=True,
                )
                log.info(f"multi-ue: added {impu} at {address}")
            else:
                registration.set_local_addr(impu, address)
        except ValueError as error:
            # A duplicate address, a malformed key: this UE only.
            log.error(f"multi-ue: {impu}: {error}")
    # A UE dropped from the source is left registered on purpose: removing an
    # IPsec entry does not tear its SAs down (they lapse at their hard
    # lifetime), so a script that wants that should de-register explicitly.


def _write_status():
    """Dump the per-state counts and the entries for an outside observer."""
    if not STATUS_FILE:
        return
    snapshot = {
        "time": time.time(),
        "counts": dict(registration.counts()),
        "entries": [dict(entry) for entry in registration.list()],
    }
    temporary = STATUS_FILE + ".tmp"
    try:
        with open(temporary, "w") as handle:
            json.dump(snapshot, handle)
        os.replace(temporary, STATUS_FILE)
    except OSError as error:
        log.error(f"multi-ue: cannot write {STATUS_FILE}: {error}")


# The registration namespace is live before this module runs, so the UEs start
# registering at once rather than on the first tick.
_sync()


@timer.every(seconds=10, name="multi_ue_sync")
def sync_addresses():
    _sync()
    _write_status()


@registration.on_change
def on_registration_change(aor, event_type, state):
    # One line per change with a wall-clock stamp, so refresh spread can be
    # read straight off the log.
    log.info(
        f"multi-ue event={event_type} aor={aor} t={time.time():.3f} "
        f"expires_in={state.get('expires_in')} status={state.get('status_code')}"
    )


def _userpart(uri):
    text = str(uri)
    for scheme in ("sips:", "sip:", "tel:"):
        if text.startswith(scheme):
            text = text[len(scheme):]
            break
    return text.split("@", 1)[0].split(";", 1)[0]


def _impu_for_user(user):
    """The IMPU whose userpart is `user` (linear, once per call)."""
    for entry in registration.list():
        if _userpart(entry["aor"]) == user:
            return entry["aor"]
    return None


@b2bua.on_invite
def on_invite(call):
    # MT: the INVITE arrived on one of the per-UE sockets, so the address it
    # arrived on names the UE that was called.
    flow = call.flow
    called = registration.find_by_local(flow.local_addr) if flow is not None else None
    if called is not None:
        log.info(f"[{call.id}] MT for {called} -> {TESTER}")
        call.dial(TESTER, timeout=30)
        return

    # MO: from the tester on the process's own listener. The From userpart
    # picks which UE places the call.
    from_uri = call.from_uri
    impu = _impu_for_user(from_uri.user) if from_uri is not None and from_uri.user else None
    if impu is None:
        call.reject(403, "Unknown UE")
        return
    if registration.status(impu) != "registered":
        call.reject(503, "IMS Registration Not Ready")
        return
    # The UE->P-CSCF flow over its SA, sourced from <its address>:ue_port_c.
    flow = registration.flow(impu)
    if flow is None:
        call.reject(503, "IMS Registration Not Ready")
        return

    ruri = call.ruri
    dialled = ruri.user if ruri is not None else None
    if not dialled:
        call.reject(484, "Address Incomplete")
        return
    target = f"sip:{dialled}@{HOME}"
    route = registration.service_route(impu)
    log.info(f"[{call.id}] MO {impu} -> {target} (service-route entries: {len(route)})")
    call.set_header("P-Preferred-Identity", f"<{impu}>")
    call.dial(
        target,
        flow=flow,
        route=route,
        header_policy="ims-intra-trust-domain@2026",
        copy=["P-Preferred-Identity"],
        timeout=30,
    )


@b2bua.on_failure
def on_failure(call, code, reason):
    log.info(f"[{call.id}] failed: {code} {reason}")
    call.reject(code, reason)


@b2bua.on_bye
def on_bye(call, initiator):
    call.terminate()
