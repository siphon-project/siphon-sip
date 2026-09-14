#!/usr/bin/env python3
"""Mock LCR API for the sipp-b2bua-lcr job.

Answers every route query with the route set in routes.json (or the file named
by LCR_ROUTES), unchanged: a case that needs different carriers, policies or
timeouts changes that file, not this server. A GET is a health probe.

Standard library only, so it runs on the python3 already in the siphon test
image. Each query is printed to stdout, so the job's logs show what siphon
asked.
"""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROUTES = os.environ.get(
    "LCR_ROUTES",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "routes.json"),
)
LISTEN = (
    os.environ.get("LCR_MOCK_HOST", "0.0.0.0"),
    int(os.environ.get("LCR_MOCK_PORT", "8088")),
)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        query = self.rfile.read(length).decode("utf-8", errors="replace")
        print(f"LCR query {self.path} {query}", flush=True)
        with open(ROUTES, "rb") as routes:
            self.reply(routes.read())

    def do_GET(self):
        self.reply(b'{"status": "ok"}')

    def reply(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"LCR mock listening on {LISTEN[0]}:{LISTEN[1]}, routes from {ROUTES}", flush=True)
    ThreadingHTTPServer(LISTEN, Handler).serve_forever()
