"""
SIPhon IMS S-CSCF AKA lab script — standalone local Milenage AKA, no HSS.

The AKA counterpart of ims_scscf_lab.py (which uses plain SIP digest). It
challenges REGISTER with IMS AKA computed locally from `auth.aka_credentials`
(3GPP TS 35.206 Milenage) via `auth.require_aka_digest`, so a P-CSCF running
ims_pcscf.py can complete a full VoLTE IPsec sec-agree registration without a
Diameter Cx interface or an HSS. The 401 it emits carries `ck=`/`ik=` in the
WWW-Authenticate header, which the P-CSCF's `reply.take_av()` consumes to derive
the IPsec SA keys.

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

    # Local IMS AKA challenge — Milenage from auth.aka_credentials. On an
    # unauthenticated REGISTER this sends 401 with the RAND||AUTN nonce plus
    # ck=/ik= for the P-CSCF; on the authenticated re-REGISTER it verifies the
    # AKA response and returns True.
    if not auth.require_aka_digest(request, realm=REALM):
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
