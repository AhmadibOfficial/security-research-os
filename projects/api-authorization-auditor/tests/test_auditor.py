"""Synthetic-only authorization contract tests."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("offline_api_auditor", ROOT / "auditor.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / "fixtures/owned-lab-matrix.json").read_text())

    def test_fixture_is_valid(self):
        report = mod.assess(self.document)
        self.assertEqual(report["total_cases"], 4)
        self.assertEqual(report["candidate_count"], 1)

    def test_authorized_own_object_no_alert(self):
        observed = mod.assess(self.document)["observations"][0]
        self.assertEqual(observed["category"], "expected_policy_behavior")

    def test_denied_cross_owner_no_alert(self):
        observed = mod.assess(self.document)["observations"][1]
        self.assertEqual(observed["category"], "expected_policy_behavior")

    def test_verified_denial_bypass_is_still_candidate(self):
        observed = mod.assess(self.document)["observations"][2]
        self.assertEqual(observed["category"], "authorization_gap_candidate")
        self.assertEqual(observed["validation_status"], "requires_manual_validation")

    def test_unknown_outcome_is_not_positive(self):
        observed = mod.assess(self.document)["observations"][3]
        self.assertEqual(observed["category"], "insufficient_evidence")

    def test_unverified_granted_only_review(self):
        self.document["cases"][2]["impact_verified"] = False
        out = mod.assess(self.document)
        self.assertEqual(out["candidate_count"], 0)
        self.assertEqual(out["observations"][2]["category"], "unverified_access_mismatch")

    def test_strict_scope(self):
        self.document["scope"]["mode"] = "external_live"
        with self.assertRaises(ValueError):
            mod.assess(self.document)

    def test_reject_raw_evidence_or_urls(self):
        self.document["cases"][2]["request_url"] = "https://example.com/token"
        with self.assertRaises(ValueError):
            mod.assess(self.document)

    def test_reject_inconsistent_impact_confirmation(self):
        self.document["cases"][1]["impact_verified"] = True
        with self.assertRaises(ValueError):
            mod.assess(self.document)

    def test_malformed_unhashable_values_fail_closed(self):
        self.document["cases"][0]["dimension"] = {"bad": "mapping"}
        with self.assertRaises(ValueError):
            mod.assess(self.document)

    def test_reject_duplicate_scenarios(self):
        self.document["cases"][1]["id"] = self.document["cases"][0]["id"]
        with self.assertRaises(ValueError):
            mod.assess(self.document)

    def test_output_redacts_principal_and_owner(self):
        out = json.dumps(mod.assess(self.document))
        self.assertNotIn('"alice"', out)
        self.assertNotIn('"bob"', out)

    def test_refuse_symlink_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fixture.json"
            target.write_text(json.dumps(self.document))
            link = Path(tmp) / "link.json"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                mod.assess_file(link)


if __name__ == "__main__":
    unittest.main()
