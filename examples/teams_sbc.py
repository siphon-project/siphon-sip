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


# The profile for the pair that remains after a transfer, keyed on
# (survivor is Teams, target is Teams). The survivor offers, the target answers,
# so each entry reads "survivor's media -> target's media".
TRANSFER_PROFILES = {
    (False, False): "rtp_passthrough",  # carrier -> carrier: plain RTP both ends
    (False, True): "rtp_to_srtp",       # carrier -> Teams
    (True, False): "srtp_to_rtp",       # Teams   -> carrier
    (True, True): "srtp_to_srtp",       # Teams   -> Teams: SRTP both ends
}


def uri_host(uri):
    """Host of a SIP URI string, lowercased — ``sip:user@host:port;params`` -> ``host``."""
    rest = uri.split(":", 1)[-1].split("?", 1)[0]
    rest = rest.rsplit("@", 1)[-1].split(";", 1)[0]
    if rest.startswith("["):
        return rest.split("]", 1)[0].lstrip("[").lower()
    return rest.split(":", 1)[0].lower()


def targets_teams(uri):
    """True when a transfer target is on the Teams side of the SBC.

    Here that means the Refer-To names one of the ``teams`` gateway group's own
    hosts. If your deployment names Teams users another way (a number range the
    carrier refers to, say), this is the function to replace.
    """
    host = uri_host(uri)
    return any(uri_host(destination.uri) == host for destination in gateway.list("teams"))


@b2bua.on_refer
async def on_refer(call):
    """A party transfers the call away — route and anchor the pair that REMAINS.

    A siphon-terminated transfer dials the target directly: ``@b2bua.on_invite``
    does not run again, so this handler makes both decisions that one made for
    the original call, and neither can be inherited from it.

    **Where the new leg goes.** ``next_hop=`` picks the trunk. The target can be
    on either side: a transfer to a PSTN number leaves via the carrier, a
    transfer to a Teams user goes back to Teams.

    **Which media profile it gets.** Every call here is anchored with a
    DIRECTION-BOUND profile: ``srtp_to_rtp`` means "the offerer speaks SRTP, the
    answerer speaks plain RTP". A transfer takes one of those two parties out of
    the call, so the profile that suited the original pairing is usually wrong
    for the new one — and the failure is silent, a connected call with no audio
    in either direction.

    The rule: **the survivor is the peer of the referrer**, and the profile
    describes survivor -> target. With two sides that is four pairings:

      survivor   target    next_hop   profile
      carrier    carrier   carrier    ``rtp_passthrough``
      carrier    Teams     teams      ``rtp_to_srtp``
      Teams      carrier   carrier    ``srtp_to_rtp``
      Teams      Teams     teams      ``srtp_to_srtp``

    ``call.refer_side`` ("a"/"b") says which leg referred. In practice Teams is
    almost always the transferor, so the first two rows are the ones that carry
    traffic, but the SBC should not fall over on the others.
    """
    if not call.refer_to:
        call.reject_refer(400, "Bad Request")
        return

    # from_gateway() answers for the A-leg; refer_side says which leg referred.
    # They agree exactly when the Teams party is the one transferring — and the
    # survivor is whoever did not.
    a_leg_is_teams = call.from_gateway("teams")
    referrer_is_teams = a_leg_is_teams == (call.refer_side == "a")
    survivor_is_teams = not referrer_is_teams
    target_is_teams = targets_teams(call.refer_to)

    group = "teams" if target_is_teams else "carrier"
    destination = gateway.select(group)
    if not destination:
        log.error(f"[{call.id}] no healthy {group} gateway for transfer")
        call.reject_refer(503, "Service Unavailable")
        return

    profile = TRANSFER_PROFILES[(survivor_is_teams, target_is_teams)]
    log.info(
        f"[{call.id}] transfer -> {call.refer_to} via {destination.uri} "
        f"(survivor={'teams' if survivor_is_teams else 'carrier'}, "
        f"target={group}, profile={profile})"
    )
    call.accept_refer(
        # Verbatim: whatever URI parameters a Refer-To aimed at Teams carries
        # are Teams' own, so do not rebuild it. Reshape the number only on the
        # carrier rows (number_policy= / format=), never on a Teams target.
        target=call.refer_to,
        # The Teams gateway URI carries transport=tls, which the Refer-To itself
        # need not, so the new leg is routed by this and not by the target.
        next_hop=destination.uri,
        mode="terminate",
        # The pair that REMAINS after the referrer leaves — never simply the
        # profile the call started with. See docs/cookbook/call-transfer.md.
        profile=profile,
    )


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
