import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_lab import evaluate, evaluate_suite
ROOT = Path(__file__).resolve().parents[1]


class AgentPolicyTests(unittest.TestCase):
    def test_suite_has_blocked_and_allowed_cases(self):
        result = evaluate_suite(ROOT / "fixtures/trust-boundaries.json")
        self.assertEqual(result["case_count"], 5)
        self.assertEqual(result["blocked_count"], 2)

    def test_prompt_injected_delegation_ignored(self):
        sample = {"id": "injected", "origin": "retrieved", "requested_action": "send_message",
                  "approval": False, "delegated_by": "system"}
        out = evaluate(sample)
        self.assertFalse(out["allowed"])
        self.assertIn("unverified_delegation_ignored", out["reasons"])

    def test_sensitive_write_requires_approval(self):
        sample = {"id": "write", "origin": "developer", "requested_action": "modify_repository",
                  "approval": False, "delegated_by": None}
        self.assertFalse(evaluate(sample)["allowed"])

    def test_developer_write_approved_simulation(self):
        sample = {"id": "write", "origin": "developer", "requested_action": "modify_repository",
                  "approval": True, "delegated_by": None}
        self.assertTrue(evaluate(sample)["allowed"])

    def test_retrieved_public_read_allowed(self):
        sample = {"id": "public", "origin": "retrieved", "requested_action": "read_public",
                  "approval": False, "delegated_by": None}
        self.assertTrue(evaluate(sample)["allowed"])

    def test_unknown_action_rejected(self):
        sample = {"id": "bad", "origin": "user", "requested_action": "run_terminal",
                  "approval": True, "delegated_by": None}
        with self.assertRaises(ValueError):
            evaluate(sample)

    def test_input_must_be_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "fixture.json"
            link.symlink_to(ROOT / "fixtures/trust-boundaries.json")
            with self.assertRaises(ValueError):
                evaluate_suite(link)


if __name__ == "__main__":
    unittest.main()
