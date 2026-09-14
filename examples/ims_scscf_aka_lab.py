"""
SIPhon IMS S-CSCF AKA lab script — standalone local Milenage AKA, no HSS.

The AKA counterpart of ims_scscf_lab.py (which uses plain SIP digest). It
challenges REGISTER with IMS AKA computed locally from `auth.aka_credentials`
(3GPP TS 35.206 Milenage) via `auth.require_aka_digest`, so a P-CSCF running
ims_pcscf.py can complete a full VoLTE IPsec sec-agree registration without a
Diameter Cx interface or an HSS. The 401 it emits carries `ck=`/`ik=` in the
WWW-Authenticate header, which the P-CSCF's `reply.take_av()` strips and uses
to set up the IPsec SAs.

Once the UE is registered, a re-REGISTER or de-REGISTER that the P-CSCF
received over the SA arrives with `integrity-protected="yes"` in its
Authorization header (TS 24.229). `auth.verify_integrity_protected` accepts it
without a new challenge, but only when its IMPI is the one that registered the
IMPU. AKA nonces are single-use, so anything else is challenged again.

In a real deployment the S-CSCF fetches authentication vectors from the HSS over
Cx (MAR) — see ims_scscf.py. This lab variant generates them locally so the
IPsec/AKA path can be exercised standalone (e.g. the sipp-ipsec CI test).

Config: sipp/ipsec/siphon-scscf.yaml
"""
from siphon import proxy, registrar, auth, log

REALM = "ims.test"


@proxy.on_request("REGISTER")
def handle_register(request):
    log.info(f"S-CSCF REGISTER from {request.from_uri}")

    if auth.verify_integrity_protected(request):
        # Protected re-/de-REGISTER from the IMPI that registered this IMPU:
        # verify_integrity_protected set request.auth_user, no challenge owed.
        log.info(
            f"accepted integrity-protected REGISTER from {request.auth_user} "
            f"without a challenge"
        )
    # Local IMS AKA challenge — Milenage from auth.aka_credentials. On an
    # unauthenticated REGISTER this sends 401 with the RAND||AUTN nonce plus
    # ck=/ik= for the P-CSCF; on the authenticated re-REGISTER it verifies the
    # AKA response and returns True.
    elif not auth.require_aka_digest(request, realm=REALM):
        log.info(f"sent 401 AKA challenge to {request.from_uri}")
        return

    # Authenticated — save the binding and answer 200 OK.
    registrar.save(request)
    log.info(f"registered {request.from_uri} at S-CSCF")


@proxy.on_request("OPTIONS")
def handle_options(request):
    # Health-check / keepalive.
    if request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return
    request.relay()
