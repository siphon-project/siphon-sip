"""
SIPhon IMS I-CSCF script — interrogating entry point to IMS core.

The I-CSCF sits between the P-CSCF and S-CSCF. It queries the HSS via
Diameter Cx to discover which S-CSCF should handle each request:

  REGISTER flow:
    UE -> P-CSCF -> I-CSCF --(Cx UAR)--> HSS
                           <--(Cx UAA)-- HSS (returns S-CSCF URI)
                    I-CSCF -> S-CSCF

  INVITE flow:
    P-CSCF -> I-CSCF --(Cx LIR)--> HSS
                      <--(Cx LIA)-- HSS (returns serving S-CSCF)
              I-CSCF -> S-CSCF

S-CSCF failover: when a REGISTER to the assigned S-CSCF fails with
408/5xx, the @proxy.on_failure handler re-queries the HSS with
user_auth_type=2 (REGISTRATION_AND_CAPABILITIES) to get a capabilities
list and tries the next S-CSCF.

The I-CSCF does NOT authenticate — that's the S-CSCF's job.

Equivalent to: opensips_ims_icscf/opensips.cfg from docker_open5gs

Config: examples/ims_icscf.yaml

Note: In a lab without a real HSS, you can hardcode the S-CSCF address
      and skip the Diameter lookups (see SCSCF_FALLBACK below).
"""
from siphon import proxy, diameter, log

REALM = "ims.example.com"

# Fallback S-CSCF for lab deployments without HSS Diameter.
# Set to None to require Diameter Cx for S-CSCF discovery.
SCSCF_FALLBACK = "sip:scscf.ims.example.com:6060"

# 3GPP TS 29.229 User-Authorization-Type values
UAT_REGISTRATION = 0
UAT_DE_REGISTRATION = 1
UAT_REGISTRATION_AND_CAPABILITIES = 2


def find_scscf_for_register(request, user_auth_type=None):
    """Discover the S-CSCF for a REGISTER via Diameter Cx UAR.

    Sends a User-Authorization-Request to the HSS, which returns the
    assigned S-CSCF in the Server-Name AVP.

    Args:
        request: The inbound REGISTER request.
        user_auth_type: Optional User-Authorization-Type AVP value.
            Use UAT_REGISTRATION_AND_CAPABILITIES (2) for failover
            to request a capabilities list instead of the assigned S-CSCF.

    Falls back to SCSCF_FALLBACK when no Diameter peer is connected.
    """
    if diameter.peer_count() > 0:
        visited = request.get_header("P-Visited-Network-ID") or REALM
        result = diameter.cx_uar(str(request.from_uri), visited,
                                 user_auth_type=user_auth_type)
        if result and result.get("server_name"):
            log.info(f"UAR -> S-CSCF: {result['server_name']}")
            return result["server_name"]
        if result:
            log.warn(f"UAR returned no server_name (result_code={result.get('result_code')})")

    if SCSCF_FALLBACK:
        return SCSCF_FALLBACK

    return None


def find_scscf_for_request(request):
    """Discover the serving S-CSCF via Diameter Cx LIR.

    Sends a Location-Info-Request to the HSS for the target user.
    The HSS returns the S-CSCF currently serving that user.

    Falls back to SCSCF_FALLBACK when no Diameter peer is connected.
    """
    if diameter.peer_count() > 0:
        result = diameter.cx_lir(str(request.ruri))
        if result and result.get("server_name"):
            log.info(f"LIR -> S-CSCF: {result['server_name']}")
            return result["server_name"]
        if result:
            log.warn(f"LIR returned no server_name (result_code={result.get('result_code')})")

    if SCSCF_FALLBACK:
        return SCSCF_FALLBACK

    return None


@proxy.on_request("REGISTER")
def handle_register(request):
    log.info(f"I-CSCF REGISTER from {request.from_uri}")

    scscf = find_scscf_for_register(request)
    if not scscf:
        log.error(f"no S-CSCF found for {request.from_uri}")
        request.reply(500, "No S-CSCF Available")
        return

    log.info(f"routing REGISTER to S-CSCF {scscf}")
    request.set_header("X-I-CSCF-First-SCSCF", scscf)
    request.relay(scscf)


@proxy.on_failure
def register_failure(request, reply):
    """S-CSCF failover: re-query HSS with REGISTRATION_AND_CAPABILITIES."""
    if request.method != "REGISTER":
        reply.relay()
        return

    if reply.status_code != 408 and reply.status_code < 500:
        reply.relay()
        return

    first_scscf = request.get_header("X-I-CSCF-First-SCSCF")
    log.warn(f"S-CSCF {first_scscf} failed ({reply.status_code}), trying capabilities query")

    next_scscf = find_scscf_for_register(
        request, user_auth_type=UAT_REGISTRATION_AND_CAPABILITIES)

    if next_scscf and next_scscf != first_scscf:
        log.info(f"failover REGISTER to S-CSCF {next_scscf}")
        request.remove_header("X-I-CSCF-First-SCSCF")
        request.relay(next_scscf)
        return

    log.error(f"no alternate S-CSCF available for {request.from_uri}")
    reply.relay()


@proxy.on_request("OPTIONS")
def handle_options(request):
    if request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return
    request.relay()


@proxy.on_request
def handle_request(request):
    if request.method in ("REGISTER", "OPTIONS"):
        return  # handled above

    # In-dialog requests follow the route set.
    if request.in_dialog:
        # loose_route() consumes only Route entries that identify us
        # (RFC 3261 §16.4).  A False return means the top Route belongs to
        # another proxy, and relay() follows it (§16.6) — so forward either
        # way.  Rejecting here would 404 a perfectly routable in-dialog
        # request whose route set simply points somewhere else next.
        request.loose_route()
        request.relay()
        return

    # Initial request — find the serving S-CSCF via Cx LIR.
    scscf = find_scscf_for_request(request)
    if not scscf:
        log.error(f"no S-CSCF found for {request.ruri}")
        request.reply(404, "User Not Found")
        return

    log.info(f"routing {request.method} to S-CSCF {scscf}")
    request.relay(scscf)
