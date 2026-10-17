"""Fast, offline checks of query-pack structure and acceptance gates."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_lab.py"

spec = importlib.util.spec_from_file_location("lab_runner", RUNNER)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


def synthetic_report(lines):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": [
            {"locations": [{"physicalLocation": {"region": {"startLine": n}}}]}
            for n in sorted(lines)
        ]}],
    }


class QueryPackTests(unittest.TestCase):
    def test_fixture_compiles_and_markers_match_open_sinks(self):
        lab.check_source()

    def test_two_vulnerable_and_two_negative_controls(self):
        vulnerable, fixed = lab.markers()
        self.assertEqual(len(vulnerable), 2)
        self.assertEqual(len(fixed), 2)
        self.assertFalse(vulnerable & fixed)

    def test_acceptance_passes_when_actual_codeql_locations_are_right(self):
        vulnerable, _ = lab.markers()
        lab.audit_sarif(synthetic_report(vulnerable))

    def test_acceptance_rejects_missed_vulnerability(self):
        vulnerable, _ = lab.markers()
        with self.assertRaisesRegex(ValueError, "missing positive lines"):
            lab.audit_sarif(synthetic_report(set(list(vulnerable)[:1])))

    def test_acceptance_rejects_false_positive(self):
        vulnerable, fixed = lab.markers()
        with self.assertRaisesRegex(ValueError, "alerts on negative lines"):
            lab.audit_sarif(synthetic_report(vulnerable | fixed))

    def test_reject_fake_tool_results(self):
        vulnerable, _ = lab.markers()
        result = synthetic_report(vulnerable)
        result["runs"][0]["tool"]["driver"]["name"] = "Not CodeQL"
        with self.assertRaisesRegex(ValueError, "not produced by CodeQL"):
            lab.audit_sarif(result)

    def test_sarif_cannot_be_exported_to_repository(self):
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "test.sarif"
            sample.write_text(json.dumps(synthetic_report(lab.markers()[0])))
            with self.assertRaises(ValueError):
                lab._save_private(sample, ROOT / "results.sarif")

    def test_saved_synthetic_sarif_is_private_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "test.sarif"
            sample.write_text(json.dumps(synthetic_report(lab.markers()[0])))
            out = Path(temp) / "nested" / "evidence.sarif"
            lab._save_private(sample, out)
            self.assertEqual(out.stat().st_mode & 0o077, 0)
            with self.assertRaises(FileExistsError):
                lab._save_private(sample, out)

    def test_static_only_cli_passes_without_codeql(self):
        result = subprocess.run([sys.executable, str(RUNNER), "--static-only"],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not a CodeQL execution result", result.stdout)


if __name__ == "__main__":
    unittest.main()
