"""Positive/negative authorization controls against the local-only synthetic API."""
import json
from pathlib import Path
import sys
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab import make_server, SYNTHETIC_WALLETS


class LocalLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(0)
        cls.base = "http://127.0.0.1:" + str(cls.server.server_address[1])
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def request(self, route, actor="bob", payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = Request(self.base + route, data=data, headers={
            "X-Lab-Actor": actor, "Content-Type": "application/json"
        })
        try:
            with urlopen(req, timeout=3) as resp:
                return resp.status, json.load(resp)
        except HTTPError as exc:
            return exc.code, json.load(exc)

    def test_vulnerable_bola_is_observable_in_owned_lab(self):
        code, data = self.request("/unsafe/records/100", actor="bob")
        self.assertEqual(code, 200)
        self.assertEqual(data["owner"], "alice")

    def test_fixed_bola_denies_cross_owner(self):
        code, _ = self.request("/fixed/records/100", actor="bob")
        self.assertEqual(code, 403)

    def test_fixed_owner_allowed(self):
        code, data = self.request("/fixed/records/200", actor="bob")
        self.assertEqual(code, 200)
        self.assertEqual(data["owner"], "bob")

    def test_unknown_actor_denied(self):
        code, _ = self.request("/unsafe/records/100", actor="unknown")
        self.assertEqual(code, 401)

    def test_fixed_transfer_rejects_unauthorized_source(self):
        code, _ = self.request("/fixed/transfers", actor="bob", payload={
            "from": "alice", "to": "bob", "amount": 1
        })
        self.assertEqual(code, 403)

    def test_unsafe_transfer_demonstrates_business_logic_gap(self):
        with self.subTest("synthetic transfer"):
            code, result = self.request("/unsafe/transfers", actor="bob", payload={
                "from": "alice", "to": "bob", "amount": 1
            })
            self.assertEqual(code, 200)
            self.assertIn("balances", result)
        # Keep shared fixture state deterministic across tests.
        with __import__("lab").LOCK:
            SYNTHETIC_WALLETS.update({"alice": 100, "bob": 100})

    def test_same_url_denies_after_synthetic_remediation(self):
        self.server.remediation_enabled = False
        try:
            pre_status, pre = self.request("/unsafe/records/100", actor="bob")
            self.assertEqual(pre_status, 200)
            self.assertEqual(pre["owner"], "alice")
            self.server.remediation_enabled = True
            post_status, _ = self.request("/unsafe/records/100", actor="bob")
            self.assertEqual(post_status, 403)
        finally:
            self.server.remediation_enabled = False

    def test_invalid_amount_rejected(self):
        code, _ = self.request("/unsafe/transfers", payload={
            "from": "alice", "to": "bob", "amount": -1
        })
        self.assertEqual(code, 400)

    def test_listener_is_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
