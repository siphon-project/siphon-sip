#!/usr/bin/env python3
"""Mock LCR API for the sipp-b2bua-lcr job.

Answers every route query with a route set read from a file, unchanged: a case
that needs different carriers, policies or timeouts changes a file, not this
server. A GET is a health probe.

The file is picked by the number the query dials, so one siphon and one mock
serve every case: routes.<number>.json next to this file when it exists (the
dialled number without its leading +), else routes.json (or the file named by
LCR_ROUTES). Files are re-read on every query.

Standard library only, so it runs on the python3 already in the siphon test
image. Each query is printed to stdout with the file that answered it, so the
job's logs show what siphon asked and what it was given.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROUTES = os.environ.get("LCR_ROUTES", os.path.join(HERE, "routes.json"))
LISTEN = (
    os.environ.get("LCR_MOCK_HOST", "0.0.0.0"),
    int(os.environ.get("LCR_MOCK_PORT", "8088")),
)


def routes_for(query):
    """The routes file for a query: its dialled number's own, else the default."""
    try:
        dialled = json.loads(query).get("dialed_number")
    except (ValueError, AttributeError):
        return ROUTES
    if not isinstance(dialled, str):
        return ROUTES
    number = dialled[1:] if dialled.startswith("+") else dialled
    # ASCII digits only, so a dialled number can never name a path elsewhere.
    if number.isascii() and number.isdigit():
        candidate = os.path.join(HERE, f"routes.{number}.json")
        if os.path.isfile(candidate):
            return candidate
    return ROUTES


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        query = self.rfile.read(length).decode("utf-8", errors="replace")
        routes_file = routes_for(query)
        print(f"LCR query {self.path} {query} -> {os.path.basename(routes_file)}", flush=True)
        with open(routes_file, "rb") as routes:
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
    print(f"LCR mock listening on {LISTEN[0]}:{LISTEN[1]}, default routes from {ROUTES}", flush=True)
    ThreadingHTTPServer(LISTEN, Handler).serve_forever()
