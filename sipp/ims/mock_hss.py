"""A Cx HSS for the I-CSCF end-to-end test — siphon in server mode.

Answers User-Authorization-Request and Location-Info-Request (3GPP TS 29.228)
with a Server-Name naming the S-CSCF the I-CSCF should route to. Everything Cx
means lives here in the script; siphon only transports the messages, which is
the same division of labour `examples/hss_s6a.py` shows for S6a.

It exists so a test can prove the I-CSCF **used the answer**: it names an
S-CSCF address that is deliberately not the script's `SCSCF_FALLBACK`, so a
lookup that silently returned nothing routes somewhere else and the test fails
rather than passing on the fallback path.
"""

from siphon import diameter, log

# Server-Name (TS 29.229 §6.3.6) — 3GPP vendor-specific.
VENDOR_3GPP = 10415
AVP_SERVER_NAME = 602

DIAMETER_SUCCESS = 2001

# Deliberately NOT the I-CSCF script's SCSCF_FALLBACK: the test asserts the
# REGISTER arrives here, which it only can if the Cx answer was awaited and
# read. Matches the `sipp-ims-scscf` container's address.
ASSIGNED_SCSCF = "sip:172.20.0.76:6060"


@diameter.on_request("cx:UAR")
async def on_uar(request):
    """Answer a REGISTER's S-CSCF discovery with the assigned server."""
    log.info(f"HSS: UAR for {request.get_avp('Public-Identity')} -> {ASSIGNED_SCSCF}")
    answer = request.answer(DIAMETER_SUCCESS)
    answer.set_avp(AVP_SERVER_NAME, ASSIGNED_SCSCF, VENDOR_3GPP)
    return answer


@diameter.on_request("cx:LIR")
async def on_lir(request):
    """Answer a non-REGISTER's serving-S-CSCF lookup with the same server."""
    log.info(f"HSS: LIR for {request.get_avp('Public-Identity')} -> {ASSIGNED_SCSCF}")
    answer = request.answer(DIAMETER_SUCCESS)
    answer.set_avp(AVP_SERVER_NAME, ASSIGNED_SCSCF, VENDOR_3GPP)
    return answer
