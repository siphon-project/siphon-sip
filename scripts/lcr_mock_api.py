#!/usr/bin/env python3
"""Minimal mock LCR API for the SIPp failover test (scripts/lcr_sipp_test.sh).

Returns two carriers for every query, by next-hop: carrier-a (which the first
UAS rejects with 503) then carrier-b (which answers 200). No dependencies — just
the stdlib, so the test needs no FastAPI/uvicorn. The real reference API is
examples/lcr_api_server.py.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

CARRIER_A = os.environ.get("LCR_CARRIER_A", "sip:127.0.0.1:5071")
CARRIER_B = os.environ.get("LCR_CARRIER_B", "sip:127.0.0.1:5072")
# Per-carrier ring timeout — short for carrier A so the timeout-reroute test
# fails over quickly when carrier A is silent.
CARRIER_A_TIMEOUT = int(os.environ.get("LCR_CARRIER_A_TIMEOUT", "5"))
LISTEN = ("127.0.0.1", int(os.environ.get("LCR_MOCK_PORT", "8088")))


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps({
            "routes": [
                {"carrier_id": "carrier-a", "next_hop": CARRIER_A,
                 "rate": 0.0042, "timeout_secs": CARRIER_A_TIMEOUT},
                {"carrier_id": "carrier-b", "next_hop": CARRIER_B,
                 "rate": 0.0051, "timeout_secs": 5},
            ],
            "cache_ttl_secs": 0,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(LISTEN, Handler).serve_forever()
