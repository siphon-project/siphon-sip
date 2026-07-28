"""
STIR/SHAKEN edge proxy — sign on egress, verify on ingress.

A simple two-direction example for a SIP interconnect / SBC edge:

  * Calls leaving toward the PSTN/peer get a SHAKEN ``Identity`` header
    (Authentication Service).  The attestation level is decided by the script
    from whatever business logic applies — here, a trivial "is the calling
    number one of ours?" check.
  * Calls arriving from a peer get their ``Identity`` header verified
    (Verification Service).  A hard validation failure is rejected with
    438 (RFC 8224 §6.2.2); otherwise the result is stamped onto the asserted
    identity with ``verstat`` and the call is relayed.

Requires a ``stir:`` block in siphon.yaml with both ``signing`` and
``verification`` configured (see siphon.yaml for the reference).
"""
from siphon import proxy, stir, log

# Numbers we are authoritative for — full attestation (A). Everything else we
# originate gets gateway attestation (C). Real deployments derive this from the
# registrar / subscriber DB.
OUR_PREFIXES = ("1202555",)


def _attestation_for(orig_tn: str) -> str:
    digits = "".join(character for character in orig_tn if character.isdigit())
    return "A" if digits.startswith(OUR_PREFIXES) else "C"


@proxy.on_request("INVITE")
def on_invite(request):
    if request.in_dialog:
        # loose_route() consumes only Route entries that identify us
        # (RFC 3261 §16.4).  A False return means the top Route belongs to
        # another proxy, and relay() follows it (§16.6) — so forward either
        # way.  Rejecting here would 404 a perfectly routable in-dialog
        # request whose route set simply points somewhere else next.
        request.loose_route()
        request.relay()
        return

    inbound_from_peer = request.source_ip_in(["203.0.113.0/24"])

    if inbound_from_peer:
        # --- Verification Service (inbound) ---
        result = stir.verify(request)
        log.info(f"STIR verstat={result.verstat} reason={result.reason}")
        if result.verstat == "TN-Validation-Failed":
            # RFC 8224 §6.2.2 — invalid Identity header.
            request.reply(438, "Invalid Identity Header")
            return
        # Convey the outcome downstream (ATIS-1000074 §5.3.1).
        stir.apply_verstat(request, result)
    else:
        # --- Authentication Service (outbound) ---
        orig = request.from_uri.user if request.from_uri else None
        if orig:
            attestation = _attestation_for(orig)
            origid = stir.sign(request, attestation=attestation)
            log.info(f"STIR signed attest={attestation} origid={origid}")

    request.record_route()
    request.relay()
