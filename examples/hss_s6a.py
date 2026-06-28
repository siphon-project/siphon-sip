"""SIPhon as an S6a HSS endpoint (3GPP TS 29.272) — illustrative.

This shows the division of labour: **siphon transports** inbound Diameter
requests to Python and ships the answer the script returns; the **script owns
all S6a semantics** — subscriber data, SQN management, and authentication-vector
crypto. siphon does not implement Milenage or any S6a logic.

The inbound serving path is the same `@diameter.on_request` hook the DRA uses
(enabled by `diameter.listen` + a tenant whose `clients` are the MMEs). Instead
of forwarding, the handler builds an answer with `req.answer(...)` and populates
it — including the nested Authentication-Info → E-UTRAN-Vector grouping — using
the generic grouped-AVP value shape (`list` of `(code, value[, vendor])`).

Two deployment shapes, same handler:
  - **MME/DRA dials in**: set `diameter.listen` + a tenant whose `clients` are
    the peers allowed to connect (source-IP ACL).
  - **HSS dials the DRA**: omit `diameter.listen`; put the DRA under the
    tenant's `connect_to` list. siphon initiates the connection and still
    serves the AIR/ULR relayed back over it (RFC 6733 §2.1 — transport
    direction is independent of request direction).

Run: siphon --config examples/hss_s6a.yaml  (model a config on examples/dra.yaml).
"""

from siphon import diameter, log

VENDOR_3GPP = 10415

# 3GPP Result-Codes / Experimental-Result-Codes the script chooses.
DIAMETER_SUCCESS = 2001
DIAMETER_ERROR_USER_UNKNOWN = 5001
DIAMETER_UNABLE_TO_COMPLY = 5012

# AVP codes the script reads/writes (siphon's dictionary also resolves these
# names, so strings work too — using ints here to be explicit).
AVP_USER_NAME = 1            # IMSI
AVP_VISITED_PLMN_ID = 1407


# Per-command filters scope each handler (mirrors @proxy.on_request("INVITE")).
# The app-qualified "<app>:<cmd>" form keeps these from matching the same
# command code on another application; the most specific filter wins. App and
# command names are case-insensitive — lowercase app names ("s6a", "cx", "sh",
# …) match the config's `application:` convention. Names are validated at
# decoration time, so a typo raises instead of silently never firing.
# "purge-ue" (not "PUR") targets S6a Purge-UE (321) — "PUR" is Sh's
# Profile-Update (307).
@diameter.on_request("s6a:AIR")
async def on_air(req):
    return _handle_air(req)


@diameter.on_request("s6a:ULR")
async def on_ulr(req):
    return _handle_ulr(req)


@diameter.on_request("s6a:purge-ue")
async def on_purge_ue(req):
    return req.answer(DIAMETER_SUCCESS)  # Purge-UE: nothing to return


def _handle_air(req):
    imsi = req.get_avp(AVP_USER_NAME)
    subscriber = _lookup_subscriber(imsi)
    if subscriber is None:
        return req.reject(DIAMETER_ERROR_USER_UNKNOWN, f"unknown IMSI {imsi}")

    plmn = req.get_avp(AVP_VISITED_PLMN_ID)  # bytes (3 octets)
    # The SCRIPT computes the vectors — its own crypto / external UDM. siphon
    # only transports the result. (Placeholder bytes here; a real HSS would
    # run Milenage + the TS 33.401 KASME KDF and manage SQN.)
    vectors = _compute_eps_vectors(subscriber, plmn, count=1)

    answer = req.answer(DIAMETER_SUCCESS)
    # Build Authentication-Info → one or more E-UTRAN-Vector groups, each
    # carrying RAND / XRES / AUTN / KASME. Grouped AVPs are a `list` of
    # `(code, value)` child tuples; values may themselves be lists (nesting).
    answer.set_avp(
        "Authentication-Info",
        [
            (
                "E-UTRAN-Vector",
                [
                    ("RAND", v["rand"]),
                    ("XRES", v["xres"]),
                    ("AUTN", v["autn"]),
                    ("KASME", v["kasme"]),
                ],
            )
            for v in vectors
        ],
        vendor=VENDOR_3GPP,
    )
    log.info(f"AIA: {len(vectors)} vector(s) for {imsi}")
    return answer


def _handle_ulr(req):
    imsi = req.get_avp(AVP_USER_NAME)
    subscriber = _lookup_subscriber(imsi)
    if subscriber is None:
        return req.reject(DIAMETER_ERROR_USER_UNKNOWN)

    answer = req.answer(DIAMETER_SUCCESS)
    answer.set_avp("ULA-Flags", 1, vendor=VENDOR_3GPP)
    # Subscription-Data is a (large) grouped AVP; the script assembles whatever
    # APN profile it manages. Shown minimal here.
    answer.set_avp("Subscription-Data", [], vendor=VENDOR_3GPP)
    log.info(f"ULA for {imsi}")
    return answer


# --- Script-owned subscriber DB + crypto (NOT siphon's responsibility) ------

def _lookup_subscriber(imsi):
    # Replace with your real subscriber store (DB, Redis, external UDM).
    return {"imsi": imsi} if imsi else None


def _compute_eps_vectors(subscriber, plmn, count):
    # Placeholder. A real HSS runs Milenage (f1..f5) + the TS 33.401 Annex A.2
    # KASME KDF here, and increments the subscriber's SQN.
    return [
        {
            "rand": b"\x00" * 16,
            "xres": b"\x00" * 8,
            "autn": b"\x00" * 16,
            "kasme": b"\x00" * 32,
        }
        for _ in range(count)
    ]
