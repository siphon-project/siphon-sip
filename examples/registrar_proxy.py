"""
{{ sip_uac_name }} Registrar — SIPhon proxy script.

Replaces the OpenSIPS routing logic for the registrar role:
- REGISTER with digest auth (HA1 via REST API)
- INVITE from TLS subscribers → relay to AS (TCP)
- INVITE from TCP (AS) → lookup registered subscriber → relay (TLS)
- In-dialog routing via loose-route (double Record-Route transport bridging)
- Contact insert/delete notifications to REST API
- P-Asserted-Identity injection (subscriber → AS)
- Header stripping on replies (AS → subscriber)
- SUBSCRIBE/PUBLISH blocking
"""
import httpx
from siphon import proxy, registrar, auth, log

# Ansible-templated values (replace with your own)
SERVER_DOMAIN = "{{ server_domain }}"         # e.g. "sip.example.com"
LOCAL_IP = "{{ local_ip }}"                   # e.g. "10.0.0.1"
AS_DOMAIN = "{{ as_domain }}"                 # e.g. "app.example.com"

# REST API for external contact notifications (co-located on localhost)
REST_API = "http://127.0.0.1:8000"

# Reusable HTTP client (sync — avoids event loop issues in registrar callbacks)
_http_client = httpx.Client(timeout=5.0)


# ---------------------------------------------------------------------------
# Registration state change → notify external API
# ---------------------------------------------------------------------------
@registrar.on_change
def on_reg_change(aor, event_type, contacts):
    """Notify external API when a contact is inserted or deleted."""
    aor = aor.removeprefix("sip:").removeprefix("sips:")
    sip_uri = f"{LOCAL_IP}:5060;transport=tcp"
    contact_uris = [c.uri for c in contacts] if contacts else []

    if event_type in ("registered", "refreshed"):
        received = (contacts[0].received or contacts[0].uri) if contacts else ""
        expires = contacts[0].expires if contacts else None
        log.info(
            f"Contact {event_type} for AOR {aor}: "
            f"received={received}, contacts={contact_uris}, expires={expires}"
        )
        params = {"sip_uri": sip_uri, "received": received}
        if expires is not None:
            params["expires"] = expires
        try:
            resp = _http_client.get(
                f"{REST_API}/contact/insert/{aor}",
                params=params,
            )
            log.info(f"API contact insert for {aor}: status={resp.status_code}")
        except Exception as e:
            log.error(f"API contact insert failed for {aor}: {e}")

    elif event_type in ("deregistered", "expired"):
        log.info(f"Contact {event_type} for AOR {aor}: contacts={contact_uris}")
        try:
            resp = _http_client.get(
                f"{REST_API}/contact/delete/{aor}",
                params={"sip_uri": sip_uri},
            )
            log.info(f"API contact delete for {aor}: status={resp.status_code}")
        except Exception as e:
            log.error(f"API contact delete failed for {aor}: {e}")


# ---------------------------------------------------------------------------
# Main request routing
# ---------------------------------------------------------------------------
@proxy.on_request
def route(request):
    # OPTIONS keepalive — reply 200 immediately (no auth)
    if request.method == "OPTIONS" and not request.ruri.user:
        request.reply(200, "OK")
        return

    # Block SUBSCRIBE/PUBLISH
    if request.method == "SUBSCRIBE":
        request.reply(405, "Method Not Allowed")
        return
    if request.method == "PUBLISH":
        request.reply(503, "Service Unavailable")
        return

    # Log REGISTER and INVITE
    if request.method in ("REGISTER", "INVITE"):
        user = request.from_uri.user or "?" if request.from_uri else "?"
        log.info(
            f"[{request.call_id}] {request.method} {user}@{request.ruri} "
            f"from {request.source_ip}"
        )

    # -------------------------------------------------------------------
    # In-dialog (sequential) requests
    # -------------------------------------------------------------------
    if request.in_dialog:
        # loose_route() consumes only Route entries that identify us
        # (RFC 3261 §16.4).  A False return means the top Route belongs to
        # another proxy, and relay() follows it (§16.6) — so route either way.
        # Rejecting here would 404 a perfectly routable in-dialog request
        # whose route set simply points somewhere else next.
        request.loose_route()

        # Any double Record-Route entries pointing to us are now consumed.
        # If the R-URI still resolves to a local domain (e.g. an AS put our
        # address in Contact), do a registrar lookup rather than blindly
        # relaying into a loop.
        if request.ruri.is_local:
            contacts = registrar.lookup(request.ruri)
            if not contacts:
                request.reply(404, "Not Found")
                return
            request.fork([c.received or c.uri for c in contacts])
        else:
            request.relay()
        return

    # CANCEL — matched to transaction by core
    if request.method == "CANCEL":
        request.relay()
        return

    # -------------------------------------------------------------------
    # REGISTER — digest auth, then save location
    # -------------------------------------------------------------------
    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=SERVER_DOMAIN):
            return  # 401 challenge sent

        user = request.from_uri.user or "?" if request.from_uri else "?"
        is_unregister = request.contact_expires == 0
        if is_unregister:
            log.info(f"Unregistering {user} from {request.source_ip}")
        else:
            log.info(
                f"Registering {user} from {request.source_ip} "
                f"expires={request.contact_expires}"
            )

        request.fix_nated_register()
        registrar.save(request, force=True)
        return

    # -------------------------------------------------------------------
    # Non-REGISTER: authenticate & route
    # -------------------------------------------------------------------

    if request.transport == "tls" and request.ruri.is_local:
        # --- Subscriber side (TLS) → authenticate then relay to AS ---

        if not auth.require_digest(request, realm=SERVER_DOMAIN):
            return  # 407 challenge sent

        # Anti-spoofing: From user must match authenticated user
        if request.auth_user and request.from_uri:
            if request.auth_user != request.from_uri.user:
                log.info(
                    f"Call not authorized from {request.from_uri} "
                    f"(auth: {request.auth_user}) to {request.to_uri}"
                )
                request.reply(403, "Forbidden auth ID")
                return

        if request.method == "INVITE":
            log.info(f"Call authorized from {request.from_uri} to {request.to_uri}")

        # Record-route for mid-dialog requests (not REGISTER/MESSAGE)
        if request.method not in ("REGISTER", "MESSAGE"):
            request.record_route()

        # Fix NATed contact before relaying
        request.fix_nated_contact()

        # P-Asserted-Identity — we've verified the caller
        if request.from_uri:
            request.set_header(
                "P-Asserted-Identity",
                f"<sip:{request.from_uri.user}@{SERVER_DOMAIN}>",
            )

        # Relay to Application Server via TCP
        request.relay(next_hop=f"sip:{AS_DOMAIN}:5060;transport=tcp")
        return

    if request.transport == "tcp":
        # --- AS side (TCP) → route to registered subscriber ---

        if not request.ruri.is_local:
            log.error(
                f"Request from {request.from_uri} to {request.ruri} "
                f"not allowed — not our domain"
            )
            request.reply(403, "Relay Forbidden")
            return

        if request.method == "INVITE":
            # Fix RURI domain so registrar lookup matches
            request.set_ruri_host(SERVER_DOMAIN)

            contacts = registrar.lookup(request.ruri)
            if not contacts:
                log.error(f"No location found for {request.ruri}")
                request.reply(404, "Not Found")
                return

            # AS provides the correct destination number in To header
            if request.to_uri:
                request.set_ruri_user(request.to_uri.user)

            request.record_route()

            log.info("Relaying to subscriber")
            request.fork([c.received or c.uri for c in contacts])
            return

    # -------------------------------------------------------------------
    # Preloaded Route check (anti-abuse)
    # -------------------------------------------------------------------
    if request.has_header("Route"):
        log.error(
            f"Attempt to route with preloaded Route "
            f"[{request.from_uri}/{request.to_uri}/{request.ruri}/{request.call_id}]"
        )
        if request.method != "ACK":
            request.reply(403, "Preload Route denied")
        return

    # Record-route (not for REGISTER/MESSAGE)
    if request.method not in ("REGISTER", "MESSAGE"):
        request.record_route()

    # No user in RURI
    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return

    # Default: lookup location and relay
    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return

    request.fork([c.received or c.uri for c in contacts])


# ---------------------------------------------------------------------------
# Reply processing — strip internal headers before sending to subscriber
#
# request.transport is the transport of the ORIGINAL request:
#   "tls" → subscriber initiated → reply comes from AS → strip internal hdrs
#   "tcp" → AS initiated → reply comes from subscriber
# ---------------------------------------------------------------------------
@proxy.on_reply
def reply_route(request, reply):
    if request.transport == "tls":
        # Reply from AS back to subscriber — strip internal headers
        reply.remove_header("P-Asserted-Identity")
        for hdr in ("X-Core-Id", "X-Tenant-Id", "X-Call-Type"):
            reply.remove_header(hdr)

    reply.relay()
