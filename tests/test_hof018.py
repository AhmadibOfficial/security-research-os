"""HOF-018 synthetic evidence gates: no status-code-only false discoveries."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hof018_runner", ROOT / "scripts" / "hof018_run.py")
hof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hof)


def normal_rows():
    return [
        {"id": "unsafe-cross-owner", "response": {"status": 200,
         "body": {"owner": "alice", "value": "SYNTHETIC_ALICE_RECORD", "synthetic": True}}},
        {"id": "fixed-cross-owner", "response": {"status": 403,
         "body": {"error": "not your record"}}},
        {"id": "fixed-own-owner", "response": {"status": 200,
         "body": {"owner": "bob", "value": "SYNTHETIC_BOB_RECORD", "synthetic": True}}},
        {"id": "anonymous-denied", "response": {"status": 401,
         "body": {"error": "synthetic actor missing"}}},
        {"id": "same-route-after-remediation", "response": {"status": 403,
         "body": {"error": "not your record"}}},
    ]


class HOF018EvidenceTests(unittest.TestCase):
    def test_expected_one_positive_four_negative_controls(self):
        matrix, observations, metrics = hof._evidence(normal_rows())
        self.assertEqual(metrics["synthetic_true_positives"], 1)
        self.assertEqual(metrics["synthetic_true_negatives"], 4)
        self.assertEqual(metrics["synthetic_false_positives"], 0)
        self.assertEqual(metrics["synthetic_false_negatives"], 0)
        self.assertEqual(sum(x["impact_verified"] for x in matrix["cases"]), 1)
        self.assertEqual(len(observations), 5)

    def test_http_200_alone_is_not_accepted_as_a_verified_gap(self):
        rows = normal_rows()
        rows[0]["response"]["body"]["value"] = "unknown_record"
        with self.assertRaises(ValueError):
            hof._evidence(rows)

    def test_forged_owner_rejected(self):
        rows = normal_rows()
        rows[0]["response"]["body"]["owner"] = "bob"
        with self.assertRaises(ValueError):
            hof._evidence(rows)

    def test_failed_remediation_is_release_hold(self):
        rows = normal_rows()
        rows[4]["response"]["status"] = 200
        with self.assertRaises(ValueError):
            hof._evidence(rows)

    def test_missing_negative_control_is_hold(self):
        with self.assertRaises(ValueError):
            hof._evidence(normal_rows()[:-1])

    def test_denied_response_must_not_leak_protected_record(self):
        rows = normal_rows()
        rows[1]["response"]["body"]["value"] = "SYNTHETIC_ALICE_RECORD"
        with self.assertRaisesRegex(ValueError, "exposed protected"):
            hof._evidence(rows)

    def test_authorized_owner_control_must_return_correct_record(self):
        rows = normal_rows()
        rows[2]["response"]["body"]["value"] = "SYNTHETIC_ALICE_RECORD"
        with self.assertRaisesRegex(ValueError, "incorrect synthetic"):
            hof._evidence(rows)

    def test_invalid_response_body_fails_closed(self):
        rows = normal_rows()
        rows[0]["response"]["body"] = "unstructured"
        with self.assertRaisesRegex(ValueError, "Malformed"):
            hof._evidence(rows)

    def test_unknown_tool_module_is_not_imported(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "fake.py"
            file.write_text("raise RuntimeError('must never execute')")
            with self.assertRaisesRegex(ValueError, "Unknown staged"):
                hof._module("fake_tool", file)

    def test_tampered_staged_module_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "lab.py"
            file.write_text("raise RuntimeError('must never execute')")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                hof._module("hof018_lab", file)

    def test_trusted_module_digest_is_pinned_per_component(self):
        self.assertEqual(set(hof.TRUSTED_MODULE_SHA256),
                         {"hof018_lab", "hof018_auditor", "hof018_reporter"})
        for digest in hof.TRUSTED_MODULE_SHA256.values():
            self.assertEqual(len(digest), 64)
            self.assertTrue(all(ch in "0123456789abcdef" for ch in digest))

    def test_private_json_output_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "private" / "artifact.json"
            hof._private_write(path, {"case": "SYNTHETIC_ONLY"})
            self.assertEqual(json.loads(path.read_text())["case"], "SYNTHETIC_ONLY")
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            with self.assertRaises(ValueError):
                hof._private_write(path, {"case": "unsafe overwrite"})

    def test_source_tree_disallowed_as_private_output(self):
        with self.assertRaises(ValueError):
            hof._assert_private_location(ROOT / "DO_NOT_WRITE.json")

    def test_report_output_never_claims_external_recognition(self):
        matrix, _, metrics = hof._evidence(normal_rows())
        self.assertEqual(metrics["total_synthetic_scenarios"], 5)
        self.assertEqual(matrix["scope"]["mode"], "synthetic_offline")


if __name__ == "__main__":
    unittest.main()
