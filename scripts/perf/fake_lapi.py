#!/usr/bin/env python3
"""Minimal CrowdSec LAPI for the attack lab.

Runs on the defender's loopback (bfw allows plain HTTP to a loopback LAPI —
the bouncer key never leaves the host). Implements just the endpoints the lab
needs:

  GET  /v1/decisions/stream?startup=...  -> {"new": [...], "deleted": [...]}
  POST /__push {"value": "1.2.3.4", "duration": "2m"}   -> add a ban decision
  POST /__unban {"value": "1.2.3.4"}                     -> mark it deleted

Startup=true returns the full active set in `new`; delta polls return only
decisions pushed since the previous poll, and unbans in `deleted`. State is
in-memory; the lab orchestrates pushes via `docker exec` curl.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"next_id": 1, "active": {}, "new": [], "deleted": []}
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.path.startswith("/v1/decisions/stream"):
            return self._json(404, {"error": "not found"})
        startup = "startup=true" in self.path
        with LOCK:
            if startup:
                new = [d for d in STATE["active"].values()]
            else:
                new, STATE["new"] = STATE["new"], []
            deleted, STATE["deleted"] = STATE["deleted"], []
        self._json(200, {"new": new or None, "deleted": deleted or None})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/__push":
            with LOCK:
                did = STATE["next_id"]
                STATE["next_id"] += 1
                d = {
                    "id": did,
                    "origin": "attack-lab",
                    "scope": "Ip",
                    "value": body["value"],
                    "type": "ban",
                    "duration": body.get("duration", "10m"),
                    "scenario": "attack-lab push",
                    "until": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 600)),
                }
                STATE["active"][body["value"]] = d
                STATE["new"].append(d)
            return self._json(200, {"id": did})
        if self.path == "/__unban":
            with LOCK:
                d = STATE["active"].pop(body["value"], None)
                if d:
                    STATE["deleted"].append(d)
            return self._json(200, {"ok": bool(d)})
        self._json(404, {"error": "not found"})


ThreadingHTTPServer(("127.0.0.1", 8085), Handler).serve_forever()
