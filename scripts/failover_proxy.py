"""Test fixture proxy for terminating failover across an AoR's bindings.

Two acceptance scenarios share this script.

1. **Per-binding Path routing** (`sip:bob@…`).  Two bindings for one AoR, each
   registered through a different edge proxy (the REGISTERs carry different RFC
   3327 Path headers).  The script does nothing but `request.fork(contacts,
   strategy="sequential")` — it never touches Route.  Each branch must go out
   through *its own* binding's Path, so when the first edge answers 404 the
   second branch reaches a different edge and the call completes.

2. **Failure re-targeting** (`sip:carol@…`).  A single-destination
   `request.relay()` to a primary backend that rejects the call, with
   `@proxy.on_failure` sending it to a backup.  The handler has to fire at all
   (there is no fork here, so nothing aggregates) and its `request.relay()` has
   to actually re-send, or the caller never gets an answer.

Run by scripts/failover_test.sh via sipp/docker-compose.yaml
(`--profile failover`), config sipp/configs/siphon.failover-test.yaml.
"""
from siphon import proxy, registrar, log

# Scenario 2's two backends: the primary rejects, the backup answers.
CAROL_PRIMARY = "sip:carol@172.20.0.95:5060"
CAROL_BACKUP = "sip:carol@172.20.0.97:5060"


@proxy.on_request("REGISTER")
def handle_register(request):
    # No auth: the fixture is about routing, and each UE registers exactly once.
    # registrar.save() stores the REGISTER's Path vector with the binding, which
    # is the whole input to scenario 1.
    registrar.save(request)


@proxy.on_request("INVITE")
def handle_invite(request):
    if request.in_dialog:
        request.loose_route()
        request.relay()
        return

    # Stay in the path so the caller's in-dialog ACK/BYE come back through us.
    request.record_route()

    user = request.ruri.user

    if user == "carol":
        # Scenario 2: one destination, no fork, no aggregator.
        request.relay(CAROL_PRIMARY)
        return

    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return

    for contact in contacts:
        log.info(f"[failover] binding {contact.uri} path={contact.path} q={contact.q}")

    # Scenario 1: the script deliberately sets no Route.  Each branch's route
    # set has to come from its own binding's Path.
    request.fork(contacts, strategy="sequential")


@proxy.on_request
def handle_other(request):
    # An unfiltered handler runs for EVERY method, including the ones handled
    # above — so it has to bow out for those or its action would overwrite
    # theirs (the fork/relay decision is the last one written before dispatch).
    if request.method in ("REGISTER", "INVITE"):
        return
    if request.in_dialog:
        request.loose_route()
        request.relay()
        return
    request.reply(200, "OK")


@proxy.on_failure
def failure_route(request, reply):
    # Scenario 2: re-target to the backup instead of answering the failure
    # upstream.  Bounded by the framework (MAX_FAILURE_RETARGETS) — and since
    # the backup answers, the chain ends after one retarget anyway.
    if request.method == "INVITE" and request.ruri.user == "carol":
        log.info(f"[failover] on_failure {reply.status_code} — retrying {CAROL_BACKUP}")
        request.relay(CAROL_BACKUP)
        return

    reply.relay()
