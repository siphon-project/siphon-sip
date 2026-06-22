from siphon import proxy, auth


@proxy.on_request("REGISTER")
def on_register(request):
    # Always challenge: a client that never supplies valid credentials (the
    # toll-fraud scanner pattern) accrues failed_auth_ban failures until banned.
    if auth.require_www_digest(request, "siphon"):
        request.reply(200, "OK")
    # else: 401 challenge already sent by require_www_digest (counts as a failure)
