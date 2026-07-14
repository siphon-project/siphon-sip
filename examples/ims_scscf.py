"""
SIPhon IMS S-CSCF script — serving call session control function.

The S-CSCF is the central registrar and call controller in IMS:

  REGISTER flow:
    1. I-CSCF forwards REGISTER to S-CSCF
    2. S-CSCF sends Cx MAR to HSS -> gets AKA auth vectors
    3. S-CSCF challenges UE with 401 (AKAv1-MD5)
    4. UE re-sends REGISTER with credentials
    5. S-CSCF verifies, sends Cx SAR to HSS (server assignment)
    6. HSS returns user profile with iFCs and public identities
    7. S-CSCF stores registration, returns 200 with Service-Route + P-Associated-URI

  INVITE flow:
    1. S-CSCF receives INVITE (originating or terminating)
    2. Evaluates Initial Filter Criteria (iFC) from user profile
    3. Routes to application servers per iFC priority
    4. Performs location lookup for terminating leg
    5. Forks to registered contacts

Equivalent to: opensips_ims_scscf/opensips.cfg from docker_open5gs

Config: examples/ims_scscf.yaml

Note: In a lab without a real HSS, local AKA credentials (aka_credentials
      in the YAML config) substitute for Diameter Cx MAR/SAR.
"""
from siphon import proxy, registrar, auth, diameter, presence, isc, log

REALM = "ims.example.com"
SCSCF_URI = f"sip:scscf.{REALM}:6060"
# Notifier (S-CSCF) To-tag for reg-event dialogs. One stable tag is enough: a
# reg-event dialog is keyed on (Call-ID, subscriber From-tag), both unique per
# UE, so the notifier tag need not vary. Keeping it stable lets the initial 2xx,
# every in-dialog NOTIFY, and the on_change broadcast all address the same dialog.
SCSCF_NOTIFIER_TAG = "scscf-notif"

# Server-Assignment-Type values (3GPP TS 29.228 §6.3.15)
SAT_NO_ASSIGNMENT = 0
SAT_REGISTRATION = 1
SAT_RE_REGISTRATION = 2
SAT_UNREGISTERED_USER = 3
SAT_TIMEOUT_DEREGISTRATION = 4
SAT_USER_DEREGISTRATION = 5


@proxy.on_request("REGISTER")
def handle_register(request):
    log.info(f"S-CSCF REGISTER from {request.from_uri}")

    # Authenticate with AKA digest.
    # In production IMS this triggers Cx MAR to the HSS for auth vectors.
    # In lab mode, uses local Milenage credentials from aka_credentials config.
    if not auth.require_aka_digest(request, realm=REALM):
        log.info(f"sent 401 AKA challenge to {request.from_uri}")
        return

    # Determine if this is a de-registration (Expires: 0).
    is_dereg = request.get_header("Expires") == "0"

    # Send Cx SAR to HSS to confirm server assignment (if HSS connected).
    user_data_xml = None
    if diameter.peer_count() > 0:
        public_id = f"sip:{request.auth_user}"
        if "@" not in public_id:
            public_id = f"{public_id}@{REALM}"
        sat = SAT_USER_DEREGISTRATION if is_dereg else SAT_REGISTRATION
        result = diameter.cx_sar(public_id, SCSCF_URI, sat)
        if result:
            log.info(f"SAR result_code={result.get('result_code')}")
            user_data_xml = result.get("user_data")
            if user_data_xml:
                count = isc.store_profile(public_id, user_data_xml)
                log.info(f"stored {count} iFC rules for {public_id}")
        else:
            log.warn("SAR failed — proceeding with local data")

    # Build the implicit registration set (3GPP TS 23.228) — the public
    # identities that share this UE's bindings.  In production with HSS,
    # this list comes from the SAA user profile XML; here we derive it
    # from the authenticated identity.
    public_id = f"sip:{request.auth_user}"
    if "@" not in public_id:
        public_id = f"{public_id}@{REALM}"
    tel_id = None
    if request.auth_user and request.auth_user.isdigit():
        tel_id = f"tel:+{request.auth_user}"

    implicit_set = [public_id]
    if tel_id:
        implicit_set.append(tel_id)

    if is_dereg:
        registrar.save(request)
        if diameter.peer_count() > 0:
            isc.remove_profile(public_id)
        log.info(f"deregistered {request.from_uri}")
        return

    # Save the registration AND declare the implicit set.  Lookups for
    # any IMPU in the set (e.g. terminating INVITE to the tel-URI) will
    # resolve to this binding.
    registrar.save(request, aliases=implicit_set)

    # P-Associated-URI on the 200 OK lists the same set for the UE.
    associated_uris = ", ".join(f"<{u}>" for u in implicit_set)
    request.add_reply_header("P-Associated-URI", associated_uris)

    # Service-Route: subsequent requests from this UE route through S-CSCF.
    # The "orig" parameter marks originating-session routing (3GPP TS 24.229).
    request.add_reply_header("Service-Route", f"<sip:orig@{REALM}:6060;lr>")

    # Store service routes for this user (used by registrar.service_route()).
    registrar.set_service_routes(str(request.from_uri), [f"sip:orig@{REALM}:6060;lr"])

    log.info(f"registered {request.from_uri} at S-CSCF")


@proxy.on_request("SUBSCRIBE")
async def handle_subscribe(request):
    """Handle SUBSCRIBE for the reg event package (RFC 3680) and others.

    The S-CSCF is the notifier for reg-event, so it terminates the SUBSCRIBE
    dialog locally rather than relaying it. To make refresh and un-SUBSCRIBE
    work, the initial 2xx establishes a real dialog (our To-tag, RFC 6665
    §4.1.3) and the subscription is stored with its dialog identifiers. A later
    in-dialog SUBSCRIBE is then matched back by dialog (Call-ID + From-tag) and
    either refreshes the timer or, on Expires:0, tears the subscription down
    with a terminal NOTIFY.
    """
    expires = int(request.get_header("Expires") or "3600")

    # --- In-dialog SUBSCRIBE: refresh or un-SUBSCRIBE (RFC 6665 §4.4.1) ---
    if request.in_dialog:
        sub_id = presence.find_by_dialog(request.call_id, request.from_tag)
        if sub_id is None:
            # Not one of our local reg-event dialogs — it's a subscription we
            # proxy for someone else; loose-route it onward. If it isn't
            # routable either, the dialog is unknown (RFC 6665 §4.4.1).
            if request.loose_route():
                request.relay()
            else:
                request.reply(481, "Subscription Does Not Exist")
            return

        # reg-event is a self-subscription: the watched AoR is the subscriber,
        # and From-URI is stable across the dialog, so it is the resource.
        aor = str(request.from_uri)
        if expires == 0:
            presence.unsubscribe(sub_id)
            sub_state = "terminated;reason=timeout"
        else:
            presence.refresh(sub_id, expires)
            sub_state = f"active;expires={expires}"

        # 200 echoes the dialog To-tag from the request; the in-dialog NOTIFY
        # reflects the new state, From-tag = our dialog tag (the To-tag the
        # subscriber addressed this request to).
        request.reply(200, "OK")
        body = registrar.reginfo_xml(aor, state="full")
        await proxy.send_request("NOTIFY", str(request.from_uri), headers={
            "Event": "reg",
            "Subscription-State": sub_state,
            "Content-Type": "application/reginfo+xml",
            "To": str(request.from_uri),
            "From": f"<{SCSCF_URI}>;tag={request.to_tag}",
        }, body=body)
        log.info(f"reg {'un-' if expires == 0 else 're-'}SUBSCRIBE from "
                 f"{request.from_uri}: {sub_state}")
        return

    # --- Initial reg SUBSCRIBE (RFC 3680): respond locally, establish dialog ---
    if request.event == "reg":
        aor = str(request.ruri)

        # Assign our To-tag on the 2xx (RFC 6665 §4.1.3) so the subscriber's
        # later in-dialog refresh / un-SUBSCRIBE lands back here and
        # find_by_dialog() can resolve it. Store the subscription WITH its
        # dialog identifiers (Call-ID + tags) so the lookup has something to
        # match — subscribe() (no dialog state) would not be findable.
        request.set_reply_to_tag(SCSCF_NOTIFIER_TAG)
        presence.subscribe_dialog(
            str(request.from_uri), aor, "reg", expires,
            request.call_id, request.from_tag, SCSCF_NOTIFIER_TAG,
        )

        request.set_header("Subscription-State", f"active;expires={expires}")
        request.reply(200, "OK")

        # Initial NOTIFY with full reginfo (RFC 3680 §3.2), in-dialog: From-tag
        # is the To-tag we just assigned.
        body = registrar.reginfo_xml(aor, state="full", version=0)
        await proxy.send_request("NOTIFY", str(request.from_uri), headers={
            "Event": "reg",
            "Subscription-State": f"active;expires={expires}",
            "Content-Type": "application/reginfo+xml",
            "To": str(request.from_uri),
            "From": f"<{SCSCF_URI}>;tag={SCSCF_NOTIFIER_TAG}",
        }, body=body)
        log.info(f"reg SUBSCRIBE from {request.from_uri} for {aor}: "
                 f"sent 200 + initial NOTIFY")
        return

    # Other subscriptions — relay if we know the target.
    contacts = registrar.lookup(str(request.ruri))
    if contacts:
        request.record_route()
        request.relay(contacts[0].uri)
    else:
        request.reply(404, "Not Found")


@registrar.on_change
async def on_registration_change(aor, event_type, contacts):
    """Send NOTIFY to all reg event subscribers when registration state changes.

    Triggered by the registrar broadcast channel on save/remove/expire.
    """
    for watcher in presence.subscribers(aor):
        if watcher.get("event") != "reg":
            continue
        body = registrar.reginfo_xml(aor, state="partial")
        await proxy.send_request("NOTIFY", watcher["subscriber"], headers={
            "Event": "reg",
            "Subscription-State": "active",
            "Content-Type": "application/reginfo+xml",
            "To": watcher["subscriber"],
            "From": f"<{SCSCF_URI}>;tag={SCSCF_NOTIFIER_TAG}",
        }, body=body)
    log.info(f"reg change: {event_type} for {aor}, "
             f"notified {len(list(presence.subscribers(aor)))} watchers")


@proxy.on_request("OPTIONS")
def handle_options(request):
    if request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return
    request.relay()


@proxy.on_request
def handle_request(request):
    if request.method in ("REGISTER", "SUBSCRIBE", "OPTIONS"):
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
    #
    # Detect originating vs terminating by checking the Route header.
    # "orig" parameter in Route = originating session (3GPP TS 24.229 §5.4.3.2).
    is_originating = request.route_user == "orig"

    if is_originating:
        log.info(f"originating {request.method} from {request.from_uri} to {request.ruri}")

        # Add P-Asserted-Identity for the originating user.
        asserted = registrar.asserted_identity(str(request.from_uri))
        if asserted:
            request.set_header("P-Asserted-Identity", asserted)
        else:
            request.set_header("P-Asserted-Identity", f"<{request.from_uri}>")

        # Add P-Charging-Vector ICID for charging correlation.
        if not request.has_header("P-Charging-Vector"):
            icid = request.generate_icid()
            request.set_header("P-Charging-Vector", f'icid-value="{icid}"')

        # Evaluate originating iFCs — route through matching Application Servers.
        aor = str(request.from_uri)
        headers = [("P-Asserted-Identity", request.get_header("P-Asserted-Identity") or "")]
        matches = isc.evaluate(aor, request.method, str(request.ruri),
                               headers, "originating")
        if matches:
            # Route to the first matching AS. The AS processes the request
            # and returns it to the S-CSCF (via Route header) for the next
            # iFC or final routing. Full ISC chaining is handled by the
            # AS sending back through the S-CSCF's Route.
            target_as = matches[0]["server_name"]
            log.info(f"iFC: routing to AS {target_as} "
                     f"(priority={matches[0]['priority']}, "
                     f"default_handling={matches[0]['default_handling']})")
            request.record_route()
            # Prepend Route so the request returns to S-CSCF after AS processing.
            request.prepend_route(f"sip:orig@{REALM}:6060")
            request.relay(target_as)
            return

    else:
        log.info(f"terminating {request.method} to {request.ruri}")

        # Evaluate terminating iFCs for the called user.
        aor = str(request.ruri)
        headers = []
        matches = isc.evaluate(aor, request.method, str(request.ruri),
                               headers, "terminating")
        if matches:
            target_as = matches[0]["server_name"]
            log.info(f"iFC: routing to AS {target_as} "
                     f"(priority={matches[0]['priority']})")
            request.record_route()
            request.relay(target_as)
            return

    # After iFC evaluation (or no iFCs matched), perform location lookup.
    contacts = registrar.lookup(str(request.ruri))
    if not contacts:
        request.reply(404, "User Not Found")
        return

    request.record_route()
    if len(contacts) == 1:
        request.relay(contacts[0].uri)
    else:
        request.fork([c.uri for c in contacts])
