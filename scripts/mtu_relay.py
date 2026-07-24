"""Minimal relay for the RFC 3261 §18.1.1 over-MTU UDP->TCP docker test.

siphon relays every MESSAGE to a fixed next hop selected by the R-URI userpart,
so one siphon instance serves both test cases against transport-restricted
SIPp receivers:

  * MESSAGE to `tcprecv@` -> relayed to the TCP-only receiver.  It only arrives
    if siphon (correctly) switched an over-MTU request to TCP.
  * MESSAGE to `udprecv@` -> relayed to the UDP-only receiver.  It only arrives
    if siphon (correctly) kept an under-MTU request on UDP.

Receiver addresses come from the environment so the same script serves the
IPv4 and IPv6 compose stacks.  OPTIONS is answered locally for the healthcheck.
"""
import os

from siphon import proxy

TCP_RECV = os.environ["MTU_RECV_TCP"]  # e.g. "sip:172.30.0.20:5060"
UDP_RECV = os.environ["MTU_RECV_UDP"]  # e.g. "sip:172.30.0.21:5060"


@proxy.on_request("MESSAGE")
def on_message(request):
    if (request.ruri.user or "") == "tcprecv":
        request.relay(TCP_RECV)
    else:
        request.relay(UDP_RECV)


@proxy.on_request("OPTIONS")
def on_options(request):
    # Container healthcheck probe.
    request.reply(200, "OK")
