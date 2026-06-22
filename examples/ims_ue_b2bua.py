"""IMS UE B2BUA — register INTO an IMS core as a handset (IMS-AKA over IPsec,
3GPP TS 33.203) and bridge a plain-SIP "tester" both ways.

    MO:  tester  ->  siphon  ->  IMS     (originating)
    MT:  IMS     ->  siphon  ->  tester   (terminating)

Configure via the env vars below (see ims_ue_b2bua.yaml). Defaults use the
3GPP test range (MCC 001 / MNC 01) and TS 35.208 Test Set 1 secrets — replace
USIM_K / USIM_OPC with your real subscriber keys.

The registration handshake (Security-Client/Server, AKA, the four kernel SAs)
is driven entirely by the Rust side once registration.add(ipsec=True, ...) is
called; this script only originates the registration and bridges calls.
"""
import os

from siphon import b2bua, registration, log

# --- Identity & topology (replace with your deployment's values) ----------
UE_IP = os.environ.get("UE_IP", "10.0.0.20")          # this host's IP on the SA
PCSCF = os.environ.get("PCSCF", "sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org:5060")
PCSCF_IP = os.environ.get("PCSCF_IP", "10.0.0.10")    # used to detect MT calls
HOME = os.environ.get("IMS_HOME", "ims.mnc01.mcc001.3gppnetwork.org")
IMPI = os.environ.get("IMPI", "001010000000001@" + HOME)
IMPU = os.environ.get("IMPU", "sip:001010000000001@" + HOME)
USIM_K = os.environ.get("USIM_K", "465b5ce8b199b49faa5f0a2ee238a6bc")
USIM_OPC = os.environ.get("USIM_OPC", "cd63cb71954a9f4e48a5994e37a02baf")

# Where incoming (MT) calls are bridged to — the plain-SIP tester.
TESTER = os.environ.get("TESTER", "sip:5555@10.0.0.100:5060")

# UE protected ports — MUST match the listen.udp entries in the yaml.
UE_PORT_C = int(os.environ.get("UE_PORT_C", "6100"))
UE_PORT_S = int(os.environ.get("UE_PORT_S", "6101"))

# --- Register into the IMS (runs on script load / hot-reload) --------------
# Idempotent: re-adding the same AoR replaces the entry. The background loop
# performs the initial REGISTER -> 401 -> SA install -> protected REGISTER.
registration.add(
    IMPU,
    PCSCF,
    user=IMPI,
    auth="aka",
    k=USIM_K,
    opc=USIM_OPC,
    ipsec=True,
    ue_port_c=UE_PORT_C,
    ue_port_s=UE_PORT_S,
)
log.info(f"IMS UE: registering {IMPU} via {PCSCF} (protected ports {UE_PORT_C}/{UE_PORT_S})")


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
