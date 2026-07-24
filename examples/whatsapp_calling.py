"""
SIPhon gateway for the WhatsApp Business Calling API (voice).

Bridges WhatsApp voice calls (SIP over TLS to Meta's `wa.meta.vc`) to an
internal SIP network (PBX / on-net trunk) as a B2BUA, both directions:

    WhatsApp  <-- SIP/TLS + SRTP -->  SIPhon  <-- SIP + RTP -->  internal

Direction is detected with ``call.from_gateway("whatsapp")`` — the A-leg source
IP, which on the inbound TLS connection is handshake-verified and therefore a
trustworthy signal. The ``X-FB-External-Domain: wa.meta.vc`` header Meta stamps
is only a corroborating hint: Meta does not do mutual TLS, so any peer that
reaches the TLS port could forge that header, whereas it cannot forge its source
IP on an established TLS connection. Meta sources calls from a wide published set
of ranges, so the ``whatsapp`` gateway group lists them under ``source_networks``
(see whatsapp_calling.yaml) — that makes ``from_gateway`` membership stable
regardless of what ``wa.meta.vc`` currently resolves to.

Outbound (internal -> WhatsApp) calls authenticate to Meta with SIP digest:
Meta answers the first INVITE with 407 and SIPhon resends with
``Proxy-Authorization`` automatically once ``call.set_credentials()`` is set.
The digest username is the normalised business phone number (also placed on the
From header); the password is Meta's per-number SIP password (GET the phone
number settings with ``include_sip_credentials=true``).

Environment:
    WHATSAPP_BUSINESS_NUMBER   E.164 of your WhatsApp business number (From user
                               + digest username on outbound calls), e.g. +15551234567
    WHATSAPP_SIP_PASSWORD      Meta-generated per-number SIP digest password
    WHATSAPP_MEDIA_MODE        "sdes" (default) or "dtls" — SRTP keying to match
                               how the number is provisioned on Meta's side

WhatsApp also has a messaging API (text / media / templates over HTTP). For that
see the siphon-http "WhatsApp Cloud API" cookbook — it is a separate, HTTP-only
integration.

Run: ``siphon -c examples/whatsapp_calling.yaml``
"""
import os

from siphon import b2bua, proxy, gateway, rtpengine, log

BUSINESS_NUMBER = os.environ.get("WHATSAPP_BUSINESS_NUMBER", "")
SIP_PASSWORD = os.environ.get("WHATSAPP_SIP_PASSWORD", "")

# SDES keying (the default) is a plain SRTP trunk, so the built-in srtp_to_rtp /
# rtp_to_srtp profiles apply. DTLS-SRTP (Meta's default keying) uses the custom
# whatsapp_dtls_* profiles in whatsapp_calling.yaml — validate those against your
# own number first.
if os.environ.get("WHATSAPP_MEDIA_MODE", "sdes").lower() == "dtls":
    PROFILE_FROM_WHATSAPP = "whatsapp_dtls_in"    # Meta is the offering A-leg
    PROFILE_TO_WHATSAPP = "whatsapp_dtls_out"     # internal is the offering A-leg
else:
    PROFILE_FROM_WHATSAPP = "srtp_to_rtp"
    PROFILE_TO_WHATSAPP = "rtp_to_srtp"


@proxy.on_request("OPTIONS")
def health(request):
    # Answer OPTIONS keepalives from the internal side (Meta does not send them).
    request.reply(200, "OK")


@b2bua.on_invite
async def route(call):
    # Source-IP membership (handshake-verified on TLS) is the trust signal for
    # "this came from WhatsApp"; see the module docstring on why not the header.
    if call.from_gateway("whatsapp"):
        await _from_whatsapp(call)
    else:
        await _to_whatsapp(call)


async def _from_whatsapp(call):
    """WhatsApp -> internal: a WhatsApp user is calling the business number."""
    wacid = call.get_header("x-wa-meta-wacid")
    destination = gateway.select("internal")
    if not destination:
        log.error(f"[{call.id}] no healthy internal gateway (wacid={wacid})")
        call.reject(503, "Service Unavailable")
        return
    log.info(f"[{call.id}] WhatsApp -> internal: {destination.uri} (wacid={wacid})")
    # Meta offers SRTP (SDES) or DTLS-SRTP + OPUS; anchor and present RTP inward.
    await rtpengine.offer(call, profile=PROFILE_FROM_WHATSAPP)
    call.dial(destination.uri)


async def _to_whatsapp(call):
    """internal -> WhatsApp: dial a WhatsApp user (E.164) over the TLS trunk."""
    ruri = call.ruri
    e164 = ruri.user if ruri else None
    if not e164:
        log.error(f"[{call.id}] no destination number in R-URI")
        call.reject(404, "Not Found")
        return
    if not BUSINESS_NUMBER or not SIP_PASSWORD:
        log.error(f"[{call.id}] WHATSAPP_BUSINESS_NUMBER / WHATSAPP_SIP_PASSWORD unset")
        call.reject(503, "Service Unavailable")
        return
    log.info(f"[{call.id}] internal -> WhatsApp: {e164}")
    # Business-initiated call: From is the business number, and the same value is
    # the digest username. SIPhon answers Meta's 407 with Proxy-Authorization.
    call.set_from_user(BUSINESS_NUMBER)
    call.set_credentials(BUSINESS_NUMBER, SIP_PASSWORD)
    await rtpengine.offer(call, profile=PROFILE_TO_WHATSAPP)
    # transport=tls routes over TLS; Contact/Via carry advertised_address (the
    # FQDN Meta knows). No re-INVITE is ever sent toward Meta (no session timer).
    call.dial(f"sip:{e164}@wa.meta.vc:5061;transport=tls")


@b2bua.on_answer
async def answered(call, reply):
    # Reuse the offer profile (keyed by A-leg Call-ID) so SRTP/DTLS direction and
    # crypto stay consistent on the 200 OK.
    await rtpengine.answer(reply, call=call)
    log.info(f"[{call.id}] answered ({reply.status_code})")


@b2bua.on_failure
async def failed(call, code, reason):
    log.warn(f"[{call.id}] B-leg failed: {code} {reason}")
    await rtpengine.delete(call)
    call.reject(code, reason)


@b2bua.on_bye
async def ended(call, initiator):
    log.info(f"[{call.id}] BYE (initiator: {initiator.side})")
    await rtpengine.delete(call)


@b2bua.on_cancel
async def cancelled(call):
    # Caller abandoned an unanswered call — release the anchored media.
    log.info(f"[{call.id}] CANCEL (unanswered)")
    await rtpengine.delete(call)
