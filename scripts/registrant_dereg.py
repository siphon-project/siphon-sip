"""Remove an outbound registration once it is live, to prove it de-registers.

Paired with sipp/registrant_upstream_registrar.xml, which answers the initial
REGISTER and then waits for the `Expires: 0` that removing the trunk must put on
the wire (RFC 3261 §10.2.2).

The trigger is `registration.status()` rather than a module-level flag, so the
timer stays stateless: once the entry is gone, `status()` returns None and the
later ticks do nothing.
"""

from siphon import log, registration, timer

TRUNK = "sip:trunk1@registrar.test"


@timer.every(seconds=2, name="drop_the_trunk")
def drop_the_trunk():
    state = registration.status(TRUNK)
    if state != "registered":
        # Not up yet (or already removed) — nothing to clear.
        return

    log.info(f"trunk {TRUNK} is registered; removing it to force a de-REGISTER")
    registration.remove(TRUNK)
