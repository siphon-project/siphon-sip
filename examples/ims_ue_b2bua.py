"""IMS UE B2BUA — bridge a plain-SIP "tester" to an IMS core both ways, on top
of an IMS-AKA + IPsec sec-agree registration (3GPP TS 33.203).

    MO:  tester  ->  siphon  ->  IMS     (originating)
    MT:  IMS     ->  siphon  ->  tester   (terminating)

The registration itself is declared in ims_ue_b2bua.yaml (`registrant.entries`)
— NOT here. The Rust `registration` binding is installed after this script's
top-level code runs, so a module-level `registration.add(...)` would hit the
unconfigured stub and raise. Declaring it in YAML registers it at the right
time; this script only does the call bridging, reading the registration's SA
flow and Service-Route at call time (when the binding is live).

Configure via the env vars below (defaults match ims_ue_b2bua.yaml — the 3GPP
test range MCC 001 / MNC 01). Keep IMPU / UE_IP / PCSCF_IP in sync with the yaml.
"""
import os

from siphon import b2bua, registration, log

# Must match ims_ue_b2bua.yaml.
UE_IP = os.environ.get("UE_IP", "10.0.0.20")          # this host's IP on the SA
PCSCF_IP = os.environ.get("PCSCF_IP", "10.0.0.10")    # used to detect MT calls
HOME = os.environ.get("IMS_HOME", "ims.mnc01.mcc001.3gppnetwork.org")
IMPU = os.environ.get("IMPU", "sip:001010000000001@" + HOME)  # == registrant aor

# Where incoming (MT) calls are bridged to — the plain-SIP tester.
TESTER = os.environ.get("TESTER", "sip:5555@10.0.0.100:5060")

log.info(f"IMS UE B2BUA loaded; bridging tester <-> IMS for {IMPU}")


def _from_ims(call) -> bool:
    """True when the A-leg INVITE came from the P-CSCF — i.e. a terminating
    (MT) call delivered to our registered Contact over the SA."""
    return call.source_ip == PCSCF_IP


@b2bua.on_invite
def on_invite(call):
    if _from_ims(call):
        # MT: IMS -> tester. The A-leg arrived on the protected server port;
        # responses egress back over the same SA automatically. Bridge to the
        # plain-SIP tester on the B-leg.
        log.info(f"[{call.id}] MT call from IMS -> {TESTER}")
        call.dial(TESTER, timeout=30)
        return

    # MO: tester -> IMS. The B-leg must ride the established SA: sent to the
    # P-CSCF protected server port, sourced from the UE protected client port.
    # registration.flow() returns exactly that flow once the handshake is up.
    flow = registration.flow(IMPU, UE_IP)
    if flow is None:
        log.warn(f"[{call.id}] MO call but IMS registration not ready yet")
        call.reject(503, "IMS Registration Not Ready")
        return

    # Carry the S-CSCF Service-Route we captured at registration so the request
    # traverses the originating S-CSCF (RFC 3608), and assert our IMPU via
    # P-Preferred-Identity (the IMS derives P-Asserted-Identity from the SA the
    # request arrived on, but PPI tells it which IMPU to assert).
    route = registration.service_route(IMPU)
    ruri = call.ruri
    dialled = ruri.user if ruri is not None else None
    target = f"sip:{dialled}@{HOME}" if dialled else IMPU

    log.info(f"[{call.id}] MO call -> IMS {target} (service-route entries: {len(route)})")
    call.set_header("P-Preferred-Identity", f"<{IMPU}>")
    call.dial(
        target,
        flow=flow,
        route=route,
        # Intra-trust preset preserves P-* (incl. P-Preferred-Identity).
        header_policy="ims-intra-trust-domain@2026",
        copy=["P-Preferred-Identity"],
        timeout=30,
    )


@b2bua.on_answer
def on_answer(call, reply):
    log.info(f"[{call.id}] answered ({reply.status_code})")


@b2bua.on_failure
def on_failure(call, code, reason):
    log.info(f"[{call.id}] failed: {code} {reason}")
    call.reject(code, reason)


@b2bua.on_bye
def on_bye(call, initiator):
    log.info(f"[{call.id}] BYE ({initiator}) — tearing down both legs")
    call.terminate()
