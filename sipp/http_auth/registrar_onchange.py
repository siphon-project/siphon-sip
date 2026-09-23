"""On-change blocking-notify regression script.

Isolates the registrar-side analogue of the blocking-while-attached hazard:
every location save fires `@registrar.on_change`, which here performs a
*blocking* HTTP notify (stdlib `urllib`, so no extra image dependency) — the
same shape as a production script's `httpx` contact-insert callback to a
registrar-api.

Auth is STATIC (no HTTP HA1 fetch), so the on_change notify is the ONLY blocking
call in the REGISTER path — this test exercises the Python-level blocking case
specifically. Unlike siphon's own Rust blocking calls, siphon cannot `detach`
around a script's blocking call; the question this answers is whether a
Python-level blocking call in a handler stalls the free-threaded GC the way a
Rust one does (Python's socket ops release the GIL around the syscall, so it
should not). The engine must keep completing registrations under load.
"""
import urllib.request

from siphon import proxy, registrar, auth, log

REALM = "example.com"
# Reuses the mock HTTP backend (it 200s any GET after AUTH_DELAY_MS); the body
# is ignored. The delay widens the blocking window, as a slow registrar-api would.
NOTIFY_BASE = "http://172.20.0.61:8080/contact/insert/"


@registrar.on_change
def on_reg_change(aor, event_type, contacts):
    aor = aor.removeprefix("sip:").removeprefix("sips:")
    try:
        urllib.request.urlopen(NOTIFY_BASE + aor, timeout=5).read()
    except Exception as error:
        log.error(f"contact notify failed for {aor}: {error}")


@proxy.on_request
async def route(request):
    if request.method == "OPTIONS" and not request.ruri.user:
        request.reply(200, "OK")
        return
    if request.method == "REGISTER":
        if not await auth.require_digest(request, realm=REALM):
            return  # 401 challenge already sent
        registrar.save(request, force=True)  # fires on_change → blocking notify
        return
    request.reply(404, "Not Found")
