"""
SIPhon SBC for Microsoft Teams Direct Routing.

Bridges a Microsoft Teams tenant (mutual TLS + SRTP) to a PSTN carrier trunk
(UDP/TCP + RTP) as a B2BUA:

    Teams  <-- mutual TLS / SRTP -->  SIPhon SBC  <-- RTP -->  carrier trunk

Provisioned on the Teams side (in the tenant, not here):
  * The SBC FQDN (``advertised_address`` in teams_sbc.yaml) is paired with the
    tenant via ``New-CsOnlinePSTNGateway``.
  * The TLS certificate is issued by a CA on Microsoft's supported Direct
    Routing list (Let's Encrypt is NOT supported) and its SAN matches the
    paired FQDN. The same identity is used as the server cert (Teams -> SBC)
    and the outbound client cert (SBC -> Teams, mutual TLS).

Direct Routing requires the SBC to present a client certificate when it dials
Teams; without one Teams aborts the TLS handshake with ``CertificateUnknown``.
That client identity is configured with ``tls.client_certificate`` /
``tls.client_private_key`` (see teams_sbc.yaml).

Run: ``siphon -c examples/teams_sbc.yaml``
"""
from siphon import b2bua, proxy, gateway, rtpengine, log


@proxy.on_request("OPTIONS")
def health(request):
    # Teams polls the SBC with OPTIONS to keep the trunk "Active" — answer it.
    request.reply(200, "OK")


@b2bua.on_invite
async def route(call):
    # Detect direction by gateway membership (source IP in the "teams" group's
    # resolved addresses) instead of a hardcoded CIDR — the trunk list lives in
    # gateway.groups, and this tracks Teams' sip/sip2/sip3 endpoints as they
    # resolve. Trustworthy here because the leg arrives over (mutual) TLS.
    if call.from_gateway("teams"):
        # Teams -> PSTN: hand the call to the carrier trunk, transcode the
        # SRTP Teams offers down to RTP for the carrier.
        destination = gateway.select("carrier")
        if not destination:
            log.error(f"[{call.id}] no healthy carrier gateway")
            call.reject(503, "Service Unavailable")
            return
        log.info(f"[{call.id}] Teams -> carrier: {destination.uri}")
        await rtpengine.offer(call, profile="srtp_to_rtp")
        call.dial(destination.uri)
    else:
        # PSTN -> Teams: dial the Teams trunk over mutual TLS, transcode the
        # carrier's RTP up to SRTP for Teams. The ``transport=tls`` on the
        # gateway URI routes over TLS; the SBC presents tls.client_certificate
        # and sends the Teams hostname as SNI. Contact/Via carry the paired SBC
        # FQDN (advertised_address), which Teams matches against the gateway.
        destination = gateway.select("teams")
        if not destination:
            log.error(f"[{call.id}] no healthy Teams gateway")
            call.reject(503, "Service Unavailable")
            return
        log.info(f"[{call.id}] carrier -> Teams: {destination.uri}")
        # Teams rejects non-E.164 request URIs. If your carrier delivers bare
        # digits, normalise before dial(), e.g.:
        #     call.set_ruri_user("+<E.164 number>")
        await rtpengine.offer(call, profile="rtp_to_srtp")
        call.dial(destination.uri)


@b2bua.on_answer
async def answered(call, reply):
    # Reuse the offer profile (keyed by A-leg Call-ID) so the SRTP/RTP
    # direction and crypto stay consistent on the 200 OK.
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
    # Caller abandoned an unanswered call — on_bye/on_failure won't fire, but
    # the offer already anchored media, so release it here.
    log.info(f"[{call.id}] CANCEL (unanswered)")
    await rtpengine.delete(call)
