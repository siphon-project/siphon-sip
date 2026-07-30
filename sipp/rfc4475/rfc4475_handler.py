from siphon import proxy


@proxy.on_request
def on_request(request):
    # Answer 200 for anything that reaches the script. A message the parser
    # could not represent never gets here and the client sees silence; a message
    # the RFC 3261 validation layer refused gets the status that layer named
    # (400 or 505) instead of this 200. Those three outcomes are exactly what
    # the client distinguishes.
    request.reply(200, "OK")
