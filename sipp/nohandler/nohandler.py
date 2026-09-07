"""Method-filtered handlers only — nothing claims OPTIONS.

This is the script shape that answered every qualify probe with
`500 Server Internal Error`: it routes what it was written to route and never
thinks about OPTIONS, because nothing prompts it to. A registrar qualifies its
bindings forever (Asterisk's `qualify_frequency` and its equivalents), so a
siphon registered to a provider answered one of these every few seconds — and
it looked healthy from both ends, because a qualifying registrar takes any
final response as proof of life.

Deliberately does NOT register a catch-all `@proxy.on_request`: a catch-all
matches every method, so the framework fallback under test would never run.
"""
from siphon import proxy


@proxy.on_request("REGISTER")
def on_register(request):
    request.reply(200, "OK")
