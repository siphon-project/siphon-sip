"""
SIPhon IMS S-CSCF lab script — combined P-CSCF + S-CSCF for testing.

Uses standard SIP digest auth (not AKA) so regular SIPp can authenticate.
For AKA/IPsec testing, use ims_pcscf.py + ims_scscf.py with sipp_ipsec.

Full IMS call flow (MOC → MTC):

  Registration:
    UE-A (alice) → S-CSCF: REGISTER → 401 challenge → REGISTER + auth → 200 OK
    UE-B (bob)   → S-CSCF: REGISTER → 401 challenge → REGISTER + auth → 200 OK

  Mobile Originated Call (MOC):
    UE-A → S-CSCF: INVITE sip:bob@ims.test
      S-CSCF detects originating (Route: orig) → adds P-Asserted-Identity
      S-CSCF evaluates originating iFCs (AS routing)
      S-CSCF looks up bob → Contact sip:bob@ue_b:port
      S-CSCF relays INVITE to bob

  Mobile Terminated Call (MTC):
    S-CSCF → UE-B: INVITE (from location lookup)
    UE-B → S-CSCF → UE-A: 200 OK
    UE-A → S-CSCF → UE-B: ACK

  Call teardown:
    UE-A → S-CSCF → UE-B: BYE
    UE-B → S-CSCF → UE-A: 200 OK

Config: sipp/ims/scscf-lab.yaml
"""
from siphon import proxy, registrar, auth, log

REALM = "ims.test"
SCSCF_URI = f"sip:scscf.{REALM}:6060"


@proxy.on_request("REGISTER")
def handle_register(request):
    log.info(f"S-CSCF REGISTER from {request.from_uri}")

    # Standard SIP digest auth (lab mode — no AKA, no HSS).
    if not auth.require_www_digest(request, realm=REALM):
        log.info(f"sent 401 challenge to {request.from_uri}")
        return

    # De-registration check.
    is_dereg = request.get_header("Expires") == "0"
    registrar.save(request)

    if is_dereg:
        log.info(f"deregistered {request.from_uri}")
        return

    # Build P-Associated-URI from the authenticated identity.
    public_id = f"sip:{request.auth_user}"
    if "@" not in public_id:
        public_id = f"{public_id}@{REALM}"
    request.add_reply_header("P-Associated-URI", f"<{public_id}>")

    # Service-Route: subsequent requests from this UE route through S-CSCF.
    # The "orig" parameter marks originating-session routing (3GPP TS 24.229).
    request.add_reply_header("Service-Route", f"<sip:orig@{REALM}:6060;lr>")

    log.info(f"registered {request.from_uri} at S-CSCF")


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

    # In-dialog requests (re-INVITE, BYE, UPDATE, PRACK, etc.)
    if request.in_dialog:
        if request.loose_route():
            request.record_route()
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    # --- Originating / Terminating call processing ---
    is_originating = request.route_user == "orig"

    if is_originating:
        log.info(f"originating {request.method} from {request.from_uri} to {request.ruri}")

        # Add P-Asserted-Identity for the originating user.
        request.set_header("P-Asserted-Identity", f"<{request.from_uri}>")

        # Add P-Charging-Vector ICID for charging correlation.
        if not request.has_header("P-Charging-Vector"):
            icid = request.generate_icid()
            request.set_header("P-Charging-Vector", f'icid-value="{icid}"')

    else:
        log.info(f"terminating {request.method} to {request.ruri}")

    # Location lookup for the target user.
    contacts = registrar.lookup(str(request.ruri))
    if not contacts:
        request.reply(404, "User Not Found")
        return

    request.record_route()
    if len(contacts) == 1:
        request.relay(contacts[0].uri)
    else:
        request.fork([c.uri for c in contacts])
