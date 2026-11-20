"""Fixture target for tools/api_fuzz_lab.py — a DELIBERATELY fragile API
on 127.0.0.1 (ephemeral port). Test-only; never deploy. The OpenAPI
document is fuzz_openapi.json next to this file.

Vulnerable routes (the fuzzer must report each):
  GET  /items/{item_id}  int() without validation -> 500 + Python traceback
  GET  /search?q=        a quote breaks the "SQL" -> 500 + sqlite error text
  GET  /greet?name=      evaluates {{a*b}} arithmetic (SSTI simulation)
  GET  /slow?pattern=    long input -> slow response (ReDoS simulation)
  GET  /crash?n=         n == "-1" -> connection closed without a response
FP-control routes (must NOT be reported):
  GET  /safe/{item_id}   validates, answers 400 JSON for bad input
  GET  /echo?msg=        echoes input literally (marker NOT evaluated)
  GET  /docs-page?topic= static page that always contains a traceback
  GET  /flaky?x=         alternates 200/500 -> unstable baseline, skipped
  POST /orders           state-changing; not fuzzed unless --methods post
`hits` counts requests (gate tests prove 0 were sent).
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SLOW_S = 0.6
TRACE = ('Traceback (most recent call last):\n  File "/app/api.py", line '
         '42, in get_item\n    item_id = int(raw)\nValueError: invalid '
         'literal for int() with base 10')


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.server.hits += 1
        self.server.posts += 1
        self._send(201, json.dumps({"created": True}))

    def do_GET(self):
        self.server.hits += 1
        parts = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        path = parts.path
        if path.startswith("/items/"):
            raw = urllib.parse.unquote(path[len("/items/"):])
            try:
                return self._send(200, json.dumps({"id": int(raw)}))
            except ValueError:
                return self._send(500, TRACE, "text/plain")
        if path.startswith("/safe/"):
            raw = urllib.parse.unquote(path[len("/safe/"):])
            if not raw.isdigit() or len(raw) > 9:
                return self._send(400, json.dumps({"error": "bad id"}))
            return self._send(200, json.dumps({"id": int(raw)}))
        if path == "/search":
            if "'" in q.get("q", ""):
                return self._send(500, 'sqlite3.OperationalError: near "'
                                  + "'" + '": syntax error', "text/plain")
            return self._send(200, json.dumps({"results": []}))
        if path == "/greet":
            name = q.get("name", "")
            out = re.sub(r"\{\{(\d+)\*(\d+)\}\}",
                         lambda m: str(int(m.group(1)) * int(m.group(2))),
                         name)
            return self._send(200, f"<p>Hello {out}</p>", "text/html")
        if path == "/echo":
            return self._send(200, json.dumps({"echo": q.get("msg", "")}))
        if path == "/slow":
            if len(q.get("pattern", "")) > 1000:
                time.sleep(SLOW_S)
            return self._send(200, json.dumps({"ok": True}))
        if path == "/crash":
            if q.get("n") == "-1":
                self.close_connection = True
                return None  # no response at all
            return self._send(200, json.dumps({"n": q.get("n")}))
        if path == "/docs-page":
            return self._send(200, "<h1>Reading errors</h1><pre>" + TRACE +
                              "</pre>", "text/html")
        if path == "/flaky":
            self.server.flaky += 1
            if self.server.flaky % 2 == 0:
                return self._send(500, "oops", "text/plain")
            return self._send(200, json.dumps({"ok": True}))
        return self._send(404, json.dumps({"error": "no route"}))


def start():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    srv.hits = srv.posts = srv.flaky = 0
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def stop(srv) -> None:
    srv.shutdown()
    srv.server_close()
