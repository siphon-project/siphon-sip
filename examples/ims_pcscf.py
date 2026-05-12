"""
SIPhon IMS P-CSCF script — first contact point for UEs.

Handles VoLTE/IMS registration with IPsec sec-agree and media anchoring.

Flow (3GPP TS 33.203 / TS 24.229):
  1. UE sends initial REGISTER with Security-Client header (unprotected, port 5060)
  2. P-CSCF relays REGISTER to S-CSCF; S-CSCF returns 401 with WWW-Authenticate
     containing ck=/ik=
  3. P-CSCF strips ck=/ik= from the relayed 401, allocates IPsec SAs, injects
     Security-Server, forwards 401 to UE
  4. UE establishes IPsec SAs, re-sends REGISTER over protected ports
  5. P-CSCF activates the SAs on the 200 OK from S-CSCF
  6. Subsequent requests flow over IPsec-protected ports

  + Path-token MT routing (RFC 3327 §5 / TS 24.229 §5.2.7.2):
      a. On REGISTER, P-CSCF mints an opaque token and inserts a Path
         entry of the form ``<sip:TOKEN@${ipsec.path_host};lr>``.
      b. After upstream 200 OK, the binding is cached locally with the
         token via ``registrar.save_proxy(request, reply, flow_token=)``,
         capturing the inbound flow (source_addr, listener local_addr,
         accepted-connection id).
      c. On a mobile-terminating request from the S-CSCF, the topmost
         Route is the Path URI we advertised; ``loose_route()`` consumes
         it, ``request.consumed_route_user`` exposes the token,
         ``registrar.lookup_by_token(token)`` resolves to the binding,
         and ``request.relay(flow=binding.flow)`` sends the request back
         over the captured flow without DNS-resolving the Contact URI
         (which is unreachable for IMS-AKA UEs behind NAT/IPSec).

Equivalent to: opensips_ims_pcscf/opensips.cfg from docker_open5gs

Config: examples/ims_pcscf.yaml
"""
import secrets

from siphon import proxy, registrar, ipsec, diameter, log, Transform

REALM = "ims.example.com"
PCSCF_URI = f"sip:{REALM};lr"

# Track Rx sessions per dialog (call_id -> rx_session_id).
# Used to release QoS resources on BYE.
rx_sessions = {}

# Pending Path-tokens by Call-ID — minted on the initial REGISTER and
# attached to the binding when the upstream 200 OK arrives.  Cleared on
# 200 (consumed) or on REGISTER failure (timeout/4xx — we don't want to
# leak the slot indefinitely; in production wire a TTL).
pending_path_tokens: dict[str, str] = {}

# Operator transform policy — first one acceptable to the UE wins.
PREFERRED_TRANSFORMS = [
    Transform.HmacSha1_96Null,
    Transform.HmacMd5_96Null,
]


def _select_transform(offers):
    """Pick the first PREFERRED_TRANSFORM that any UE offer accepts."""
    for transform in PREFERRED_TRANSFORMS:
        for offer in offers:
            if transform.compatible_with(offer):
                return transform, offer
    return None, None


def on_invite_reply(request, reply):
    """Called when an INVITE response arrives (on_reply callback).

    On 200 OK with SDP, request dedicated bearer via Rx AAR to PCRF.
    The PCRF provisions a dedicated EPS bearer through the PGW (Gx).
    """
    if reply.status_code != 200:
        return

    if diameter.peer_count() == 0:
        return

    call_id = request.call_id
    source_ip = request.source_ip

    result = diameter.rx_aar(
        media_type="audio",
        framed_ip=source_ip,
        flow_description=f"permit in 17 from {source_ip} to any",
    )
    if result:
        rx_sessions[call_id] = result["session_id"]
        log.info(f"Rx AAR success: session={result['session_id']} "
                 f"result_code={result['result_code']}")
    else:
        log.warn(f"Rx AAR failed for call {call_id}")


@proxy.on_request("REGISTER")
def handle_register(request):
    log.info(f"REGISTER from {request.from_uri} via {request.transport}")

    # Force UE to use security agreement (IPsec): reject REGISTER without
    # Security-Client (3GPP TS 33.203 §6.1, RFC 3329).
    offers = request.parse_security_client()
    if not offers and not request.has_header("Security-Verify"):
        request.set_reply_header("Require", "sec-agree")
        request.reply(421, "Extension Required")
        log.info(f"rejected {request.from_uri}: no Security-Client (IPsec required)")
        return

    # Add Path so subsequent requests route through us (RFC 3327).
    # Mint an opaque token and use the framework helper that builds
    # ``<sip:TOKEN@${ipsec.path_host};lr>`` — siphon owns the host part
    # so MT requests reach *this* P-CSCF instance in a multi-replica
    # deployment.
    token = secrets.token_urlsafe(16)
    pending_path_tokens[request.call_id] = token
    request.add_pcscf_path(token)
    request.set_header("P-Visited-Network-ID", REALM)

    # Relay to S-CSCF.  The 401 flow-back is handled by handle_register_reply.
    request.record_route()
    request.relay()


@proxy.on_reply
async def handle_reply(request, reply):
    """P-CSCF reply path — handles AKA challenge stripping + SA setup.

    Async because ``ipsec.allocate()`` does kernel ``ip xfrm`` work and
    returns a coroutine.  The Rust dispatcher detects async handlers via
    ``asyncio.iscoroutinefunction`` and awaits them.
    """

    # We only care about REGISTER replies on the IPsec path.
    if request.method != "REGISTER":
        reply.relay()
        return

    if reply.status_code == 401:
        await _handle_401_register(request, reply)
        reply.relay()
        return

    if reply.status_code == 200:
        _handle_200_register(request, reply)
        reply.relay()
        return

    reply.relay()


async def _handle_401_register(request, reply):
    """Extract CK/IK from S-CSCF challenge, install SAs, inject Security-Server."""
    offers = request.parse_security_client()
    if not offers:
        log.warn(f"401 REGISTER for {request.call_id}: no Security-Client to negotiate against")
        return

    transform, chosen = _select_transform(offers)
    if transform is None:
        log.warn(f"401 REGISTER for {request.call_id}: no acceptable UE transform offered")
        return

    # take_av() strips ck=/ik= from the 401's auth headers in place — this
    # is what protects the access side from leaking key material.
    av = reply.take_av()
    if av is None:
        log.debug(f"401 REGISTER for {request.call_id}: no ck/ik params in WWW-Authenticate")
        return

    # Tie SA lifetime to the registration's Expires (3GPP TS 33.203 §7.4) —
    # the kernel will expire the SAs even if the script forgets to clean
    # up.  +60 s grace allows a re-REGISTER round-trip before expiry.
    expires_secs = (request.contact_expires or 600) + 60

    # No `protocol=` kwarg → multi-protocol XFRM selectors (TS 33.203
    # §7.2: "the SAs shall be used to protect *all* SIP signalling …
    # including over UDP and TCP").  One SPI pair covers both transports
    # under a single AuthVectorHandle consumption.  Required for iOS
    # handsets that REGISTER over TCP but emit MO MESSAGE over UDP —
    # the old single-transport pin would silently drop the MESSAGE on
    # `XfrmInStateMismatch`.
    try:
        pending = await ipsec.allocate(
            av, chosen, transform, expires_secs=expires_secs,
        )
    except (ValueError, RuntimeError) as exc:
        log.error(f"ipsec.allocate failed for {request.call_id}: {exc}")
        return

    params = pending.security_server_params()
    # RFC 3329 §2.2: only emit `protocol=` when the UE didn't use the
    # default UDP — keeps the wire format every existing UE expects.
    proto_param = f"; protocol={params.protocol}" if params.protocol != "udp" else ""
    reply.set_header(
        "Security-Server",
        f"{params.mechanism}; alg={params.alg}; ealg={params.ealg}; "
        f"spi-c={params.spi_c}; spi-s={params.spi_s}; "
        f"port-c={params.port_c}; port-s={params.port_s}{proto_param}",
    )

    ipsec.stash(request.call_id, pending)
    log.info(
        f"401 REGISTER for {request.call_id}: SAs allocated, "
        f"Security-Server injected (alg={params.alg})"
    )


def _handle_200_register(request, reply):
    """Activate stashed SAs, cache binding with Path-token, store P-AU."""
    pending = ipsec.unstash(request.call_id)
    if pending is not None:
        try:
            pending.activate()
            log.info(f"200 REGISTER for {request.call_id}: SAs activated")
        except ValueError as exc:
            log.warn(f"PendingSA.activate failed: {exc}")

    # Cache the binding locally with the Path-token so MT requests
    # carrying the token in the topmost Route can relay back over the
    # captured inbound flow without consulting the Contact URI.
    token = pending_path_tokens.pop(request.call_id, None)
    if token is not None:
        try:
            registrar.save_proxy(request, reply, flow_token=token)
            log.info(f"200 REGISTER for {request.call_id}: binding cached with flow_token")
        except ValueError as exc:
            log.warn(f"save_proxy failed for {request.call_id}: {exc}")

    pau = reply.get_header("P-Associated-URI")
    if pau:
        aor = str(request.from_uri)
        registrar.set_associated_uris(aor, [pau])
        log.info(f"cached P-Associated-URI for {aor}: {pau}")


@proxy.on_request("SUBSCRIBE|PUBLISH")
def handle_presence(request):
    """Forward presence requests (reg event, presence) toward the S-CSCF."""
    if request.in_dialog:
        if request.loose_route():
            request.record_route()
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    request.record_route()
    request.relay()


@proxy.on_request("OPTIONS")
def handle_options(request):
    if request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return
    request.relay()


@proxy.on_request
def handle_request(request):
    if request.method in ("REGISTER", "OPTIONS", "SUBSCRIBE", "PUBLISH"):
        return  # handled above

    # In-dialog requests (re-INVITE, BYE, UPDATE, PRACK, etc.)
    if request.in_dialog:
        if not request.loose_route():
            request.reply(404, "Not Here")
            return

        request.record_route()

        # Strip security headers from mid-dialog requests (topology hiding).
        request.remove_header("Security-Verify")

        # BYE — release Rx QoS resources (dedicated bearer teardown).
        if request.method == "BYE":
            rx_session = rx_sessions.pop(request.call_id, None)
            if rx_session and diameter.peer_count() > 0:
                result = diameter.rx_str(rx_session)
                log.info(f"Rx STR for call {request.call_id}: "
                         f"result_code={result}")

        request.relay()
        return

    # Initial INVITE — add P-Visited-Network-ID and route.
    if request.method == "INVITE":
        request.ensure_header("P-Visited-Network-ID", REALM)

    # Path-token MT routing (TS 24.229 §5.2.7.2): if the topmost Route
    # we just consumed in loose_route() carries one of our flow tokens,
    # send the request back over the captured inbound flow.  This
    # bypasses DNS resolution of the Contact URI — required for IMS-AKA
    # UEs whose Contact URI carries the private NATed address.
    consumed_token = request.consumed_route_user
    if consumed_token:
        binding = registrar.lookup_by_token(consumed_token)
        if binding and binding.flow:
            request.record_route()
            on_reply = on_invite_reply if request.method == "INVITE" else None
            request.relay(flow=binding.flow, on_reply=on_reply)
            return

    # Look up registered contacts for terminating calls.
    contacts = registrar.lookup(str(request.ruri))
    if not contacts:
        # Not registered locally — relay toward S-CSCF / I-CSCF.
        request.record_route()
        # Use on_reply to trigger Rx AAR on 200 OK (QoS reservation).
        if request.method == "INVITE":
            request.relay(on_reply=on_invite_reply)
        else:
            request.relay()
        return

    request.record_route()
    if len(contacts) == 1:
        if request.method == "INVITE":
            request.relay(contacts[0].uri, on_reply=on_invite_reply)
        else:
            request.relay(contacts[0].uri)
    else:
        request.fork([c.uri for c in contacts])
