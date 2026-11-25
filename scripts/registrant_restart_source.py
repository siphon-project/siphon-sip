#!/usr/bin/env python3
"""The trunk source scripts/registrant_restart_test.sh points siphon at.

    registrant_restart_source.py PORT STATE_FILE TOKEN

Serves the two halves of the registrant HTTP source contract
(docs/reference/registrant-api.md):

    GET /trunks          the list: one trunk while STATE_FILE reads "listed",
                         none once it reads "unlisted"
    GET /lookup?aor=...  the one trunk by AoR, listed or not, 404 for any other

Both need `Authorization: Bearer TOKEN`. Every request is appended to
STATE_FILE.requests (path and whether the Authorization matched) so the test can
tell the lookup was asked.
"""

import json
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

AOR = "sip:trunk1@registrar.test"
TRUNK = {
    "aor": AOR,
    "registrar": "sip:127.0.0.1:25070",
    "username": "line-user-7",
    "password": "secret123",
    "contact": "sip:edge@127.0.0.1:25060",
    "interval": 600,
}


def main() -> None:
    port, state_file, token = int(sys.argv[1]), sys.argv[2], sys.argv[3]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _answer(self, status: int, body) -> None:
            payload = json.dumps(body).encode() if body is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            authorised = self.headers.get("Authorization") == f"Bearer {token}"
            with open(state_file + ".requests", "a", encoding="utf-8") as log:
                log.write(f"{self.path} authorised={authorised}\n")
            if not authorised:
                return self._answer(401, None)
            url = urllib.parse.urlparse(self.path)
            if url.path == "/trunks":
                with open(state_file, encoding="utf-8") as handle:
                    listed = handle.read().strip() == "listed"
                return self._answer(200, {"registrants": [TRUNK] if listed else []})
            if url.path == "/lookup":
                aor = urllib.parse.parse_qs(url.query).get("aor", [""])[0]
                if aor == AOR:
                    return self._answer(200, TRUNK)
                return self._answer(404, None)
            return self._answer(404, None)

    HTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
