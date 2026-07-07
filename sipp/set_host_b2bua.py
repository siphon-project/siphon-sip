"""Test fixture B2BUA script for the call.set_from_host() / set_to_host() acceptance scenario.

On every out-of-dialog INVITE the B2BUA pins the B-leg From host to a tenant
domain and the To host to a trunk domain, then dials a fixed downstream UAS.
This is the multitenant-SBC shape: the downstream selects the tenant from the
From domain, so the B-leg From host must carry the tenant domain instead of the
B2BUA advertised address (topology-hiding default).

The UAS (sipp/b2bua_set_host_uas.xml) asserts on the wire that the received
INVITE's From host == TENANT_DOMAIN and To host == TRUNK_DOMAIN. Without the
overrides the From host would be the advertised address (127.0.0.1) and the
assertion would fail.

Native run: see sipp/b2bua_set_host_uas.xml header.
"""
from siphon import b2bua, log

TENANT_DOMAIN = "tenant.example.test"
TRUNK_DOMAIN = "trunk.example.test"
UAS_NEXT_HOP = "sip:127.0.0.2:5061"


@b2bua.on_invite
def on_invite(call):
    log.info(f"[set-host-test] on_invite ruri={call.ruri} from={call.from_uri}")
    call.set_from_host(TENANT_DOMAIN)
    call.set_to_host(TRUNK_DOMAIN)
    call.dial(str(call.ruri), next_hop=UAS_NEXT_HOP)


@b2bua.on_answer
def on_answer(call, reply):
    log.info(f"[set-host-test] answered {reply.status_code}")


@b2bua.on_bye
def on_bye(call, initiator):
    log.info(f"[set-host-test] bye by {initiator.side}")


@b2bua.on_failure
def on_failure(call, code, reason):
    log.warn(f"[set-host-test] failure {code} {reason}")
    call.reject(code, reason)
