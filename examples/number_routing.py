"""Number routing patterns: LNP correction and a redirect (3xx) server.

SIPhon does the SIP. The lookups here are the business-logic parts, stubbed as
plain functions you replace with your real data source (an SQL query, an HTTP
API, ``cache.fetch``, ``proxy.enum_lookup`` ...):

  * ``lnp_dip``     -> your ported-number database / SOA dip
  * ``routes_for``  -> your redirect routing table

Two roles are shown. The active handler does LNP and relays. To run this as a
redirect server instead, register ``as_redirect_server`` and drop the relay
handler (see the note at the bottom).

For carrier least-cost routing (cost-ordered failover across gateway pools),
use the built-in LCR feature (``lcr.route`` + ``call.route``) rather than a
hand-rolled redirect. See docs/cookbook/least-cost-routing.md.
"""

from siphon import proxy, log

CARRIER_HOST = "carrier.example.net"


# --- your business logic (replace these two stubs) --------------------------

def lnp_dip(number: str) -> str | None:
    """Return the LRN for a ported number, or None if not ported / unknown.

    Replace with your real dip: an SS7/SOA query, an HTTP API, or a local copy
    of the ported-number database.
    """
    ported = {"+15551234567": "+15559990000"}   # demo data
    return ported.get(number)


def routes_for(number: str) -> list[str]:
    """Return redirect target(s) for a number, most-preferred first.

    Replace with your routing table.
    """
    return [
        f"sip:{number}@gw1.example.net",
        f"sip:{number}@gw2.example.net",
    ]


# --- Role 1: LNP correction, then relay -------------------------------------

@proxy.on_request("INVITE")
def route(request):
    called = request.ruri.user or ""

    lrn = lnp_dip(called)
    if lrn is not None:
        # RFC 4694: flag the dip as done (npdi) and carry the routing number
        # (rn). set_ruri takes a full URI, so the params land on the wire as-is.
        request.set_ruri(f"sip:{called};npdi;rn={lrn}@{CARRIER_HOST};user=phone")
        log.info(f"LNP {called} ported -> rn={lrn}")

    request.relay()


# --- Role 2: redirect server (3xx) ------------------------------------------
# Not registered above. To run SIPhon as a redirect server, decorate this with
# @proxy.on_request("INVITE") instead of `route`.

def as_redirect_server(request):
    called = request.ruri.user or ""
    routes = routes_for(called)
    if not routes:
        request.reply(404, "Not Found")
        return

    # One Contact per target; the caller retries them in order. Use 302 for a
    # single move, 300 for a choice of several.
    for uri in routes:
        request.add_reply_header("Contact", f"<{uri}>")
    request.reply(300 if len(routes) > 1 else 302, "Multiple Choices")
