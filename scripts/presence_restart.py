"""Reg-event notifier for scripts/presence_restart_test.sh.

A registrar that is also the reg event notifier (RFC 3680), as an S-CSCF is:
REGISTER is saved, a reg SUBSCRIBE gets a dialog of its own and an initial
NOTIFY, and every registration or de-registration of an AoR is NOTIFYed to
its watchers in their dialogs, each document carrying the subscription's next
version.  Nothing here persists anything: the presence store does that when
the registrar is on Redis, and the test restarts this notifier in between.
"""
from siphon import proxy, registrar, presence, log

NOTIFIER_TAG = "notifier"


def _reginfo(aor, state, version, contact_state):
    return (
        '<?xml version="1.0"?>\n'
        f'<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="{version}" '
        f'state="{state}">\n'
        f'  <registration aor="{aor}" id="r0" state="{contact_state}"/>\n'
        "</reginfo>\n"
    )


@proxy.on_request("REGISTER")
def handle_register(request):
    registrar.save(request)


@proxy.on_request("SUBSCRIBE")
async def handle_subscribe(request):
    if request.get_header("Event") != "reg":
        request.reply(489, "Bad Event")
        return
    aor = str(request.from_uri)
    expires = int(request.get_header("Expires") or "600")
    contact = (request.get_header("Contact") or "").strip().strip("<>")
    request.set_reply_to_tag(NOTIFIER_TAG)
    sub_id = presence.subscribe_dialog(
        contact, aor, "reg", expires,
        request.call_id, request.from_tag, NOTIFIER_TAG,
        local_uri=str(request.to_uri), remote_uri=aor,
    )
    request.set_header("Subscription-State", f"active;expires={expires}")
    request.reply(200, "OK")
    body = _reginfo(aor, "full", presence.next_version(sub_id), "active")
    await presence.notify(sub_id, body=body, content_type="application/reginfo+xml",
                          subscription_state=f"active;expires={expires}")


@registrar.on_change
async def on_registration_change(aor, event_type, contacts):
    if event_type not in ("registered", "deregistered", "expired"):
        return
    state = "active" if event_type == "registered" else "terminated"
    for watcher in presence.subscribers(aor):
        body = _reginfo(aor, "partial", presence.next_version(watcher["id"]), state)
        await presence.notify(watcher["id"], body=body,
                              content_type="application/reginfo+xml",
                              subscription_state="active")
    log.info(f"reg change {event_type} for {aor}")
