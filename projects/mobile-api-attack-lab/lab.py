"""Loopback-only, fully synthetic authorization and business-logic training lab."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from threading import Lock

SYNTHETIC_RECORDS = {
    "100": {"owner": "alice", "value": "SYNTHETIC_ALICE_RECORD"},
    "200": {"owner": "bob", "value": "SYNTHETIC_BOB_RECORD"},
}
SYNTHETIC_WALLETS = {"alice": 100, "bob": 100}
LOCK = Lock()


class LocalLabHandler(BaseHTTPRequestHandler):
    """Nothing here authenticates real users. Never expose it to a network."""

    def log_message(self, format, *args):
        pass

    def _reply(self, status: int, data: dict):
        body = json.dumps(data, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _actor(self) -> str | None:
        actor = self.headers.get("X-Lab-Actor")
        return actor if actor in SYNTHETIC_WALLETS else None

    def do_GET(self):
        match = re.fullmatch(r"/(unsafe|fixed)/records/(100|200)", self.path)
        if not match:
            return self._reply(404, {"error": "unknown synthetic route"})
        mode, record_id = match.groups()
        actor = self._actor()
        if actor is None:
            return self._reply(401, {"error": "synthetic actor missing"})
        record = SYNTHETIC_RECORDS[record_id]
        if mode == "fixed" and record["owner"] != actor:
            return self._reply(403, {"error": "not your record"})
        # Deliberately vulnerable: unsafe mode omits owner check.
        return self._reply(200, {"id": record_id, "owner": record["owner"],
                                 "value": record["value"], "synthetic": True})

    def do_POST(self):
        match = re.fullmatch(r"/(unsafe|fixed)/transfers", self.path)
        if not match:
            return self._reply(404, {"error": "unknown synthetic route"})
        actor = self._actor()
        if actor is None:
            return self._reply(401, {"error": "synthetic actor missing"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1024:
                raise ValueError("invalid length")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or set(payload) != {"from", "to", "amount"}:
                raise ValueError("invalid payload")
            source, target, amount = payload["from"], payload["to"], payload["amount"]
            if source not in SYNTHETIC_WALLETS or target not in SYNTHETIC_WALLETS:
                raise ValueError("invalid synthetic wallet")
            if type(amount) is not int or not 1 <= amount <= 50 or source == target:
                raise ValueError("invalid synthetic amount")
        except (ValueError, json.JSONDecodeError, TypeError):
            return self._reply(400, {"error": "invalid synthetic request"})
        mode = match.group(1)
        # Deliberately vulnerable: unsafe transfers trust a caller-selected source.
        if mode == "fixed" and source != actor:
            return self._reply(403, {"error": "source is not yours"})
        with LOCK:
            if SYNTHETIC_WALLETS[source] < amount:
                return self._reply(409, {"error": "insufficient synthetic balance"})
            SYNTHETIC_WALLETS[source] -= amount
            SYNTHETIC_WALLETS[target] += amount
            balances = dict(SYNTHETIC_WALLETS)
        return self._reply(200, {"synthetic": True, "balances": balances})


def make_server(port: int = 0) -> ThreadingHTTPServer:
    if not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("port must be 0–65535")
    server = ThreadingHTTPServer(("127.0.0.1", port), LocalLabHandler)
    return server


def main():
    parser = argparse.ArgumentParser(description="Deliberately vulnerable 127.0.0.1-only lab")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with make_server(args.port) as server:
        print("SYNTHETIC OWNED LAB ONLY:", server.server_address, flush=True)
        print("Unsafe endpoints intentionally omit authorization. Do not expose externally.",
              flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
