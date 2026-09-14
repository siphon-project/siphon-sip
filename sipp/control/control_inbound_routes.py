"""Health-only script for the script-free control-plane harness.

The point of this file is what is NOT in it. There is no `@b2bua.on_invite`
here, and no routing decision of any kind — `control.inbound` in
siphon-control-inbound.yaml is what hands every out-of-dialog INVITE to the
application, which is the deployment shape where all the policy lives in the
controller and siphon ships no call logic at all.

The one handler answers the container healthcheck's OPTIONS, so compose can tell
a started siphon from a listening one. It is deliberately not an INVITE handler:
if it were, the config path under test would never fire.
"""

from siphon import proxy


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")
