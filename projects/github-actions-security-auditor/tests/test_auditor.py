"""Source-only GitHub Actions security rules with negative fixture controls."""
import importlib.util
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("actions_auditor", ROOT / "auditor.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class WorkflowTests(unittest.TestCase):
    def test_malicious_fixture_finds_four_categories(self):
        report = mod.audit_file(ROOT / "fixtures/insecure-synthetic.yml")
        rules = {x["rule_id"] for x in report["findings"]}
        self.assertEqual(rules, {"AST-GHA-001", "AST-GHA-002", "AST-GHA-004", "AST-GHA-005"})
        self.assertEqual(report["finding_count"], 4)

    def test_safe_fixture_does_not_trigger(self):
        report = mod.audit_file(ROOT / "fixtures/safer-synthetic.yml")
        self.assertEqual(report["finding_count"], 0)

    def test_workflow_on_key_is_not_boolean(self):
        document = mod.yaml.load("on: pull_request\njobs:\n  build:\n    steps: []\n",
                                 Loader=mod.StrictLoader)
        self.assertEqual(document["on"], "pull_request")
        self.assertEqual(mod.audit(document)["finding_count"], 0)

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            mod.yaml.load("on: push\non: pull_request\njobs: {}\n", Loader=mod.StrictLoader)

    def test_privileged_trigger_without_untrusted_checkout_is_not_high_risk(self):
        data = {"on": "pull_request_target", "permissions": {"contents": "read"},
                "jobs": {"safe": {"steps": [{"uses":
                    "actions/checkout@0123456789abcdef0123456789abcdef01234567"}]}}}
        self.assertEqual(mod.audit(data)["finding_count"], 0)

    def test_detect_explicit_write_scope(self):
        data = {"on": "push", "permissions": {"contents": "write"},
                "jobs": {"ship": {"steps": []}}}
        self.assertEqual(mod.audit(data)["findings"][0]["rule_id"], "AST-GHA-003")

    def test_untrusted_shell_expression_detected(self):
        data = {"on": "issues", "jobs": {"label": {"steps": [
            {"run": "echo ${{ github.event.issue.title }}"}]}}}
        rules = [f["rule_id"] for f in mod.audit(data)["findings"]]
        self.assertEqual(rules, ["AST-GHA-005"])

    def test_env_substitution_does_not_equal_script_injection(self):
        data = {"on": "issues", "jobs": {"label": {"steps": [
            {"env": {"TITLE": "${{ github.event.issue.title }}"},
             "run": "printf '%s' \"$TITLE\""}]}}}
        self.assertEqual(mod.audit(data)["finding_count"], 0)

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "workflow.yml"
            target.write_text("on: push\njobs:\n  job:\n    steps: []\n")
            link = Path(temp) / "link.yml"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                mod.audit_file(link)

    def test_output_never_copies_shell_commands(self):
        import json
        report = mod.audit_file(ROOT / "fixtures/insecure-synthetic.yml")
        self.assertNotIn("echo", json.dumps(report))
        self.assertNotIn("github.event.pull_request.title", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
