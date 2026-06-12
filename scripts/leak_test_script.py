"""
Leak-test proxy script.

Same routing as `proxy_default.py`, plus the Python dispatch paths a minimal
proxy script never exercises — `@registrar.on_change` (the original prod leak
surface) and `@timer.every`. `scripts/mem_leak_test.sh` runs siphon with this
script so the memory-leak regression covers those handler paths in addition to
the call/registrar paths.
"""
from siphon import proxy, registrar, auth, log, timer

DOMAIN = "example.com"


@proxy.on_request
def route(request):
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        return

    if request.method == "SUBSCRIBE":
        # Create a short-expiry subscribe_state dialog and accept it. The leak
        # test abandons these (no un-SUBSCRIBE), so the L1 sweep must reap them
        # once they expire — exercising SubscribeStore::sweep_stale end to end.
        try:
            proxy.subscribe_state.create(request, expires=10)
        except Exception as error:
            log.warn(f"subscribe_state.create failed: {error}")
        request.reply(200, "OK")
        return

    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return

    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return

    request.record_route()
    request.fork([c.uri for c in contacts])


@registrar.on_change
def on_reg_change(aor, event_type, contacts):
    """Fires on every registration state change — this is the dispatch path
    (registration.on_change) that leaked in production. Touch the args so the
    handler actually allocates Python objects each call."""
    summary = f"{event_type}:{aor}:{len(contacts)}"
    log.debug(f"reg change {summary}")


@timer.every(seconds=2)
def periodic():
    """Exercises the @timer.every dispatch path on a steady cadence."""
    log.debug("leak-test timer tick")
