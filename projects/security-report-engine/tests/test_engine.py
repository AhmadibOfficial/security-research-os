import json
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from report_engine import canonical, read_source, to_sarif, to_html, write_private
ROOT = Path(__file__).resolve().parents[1]


class ReportsTests(unittest.TestCase):
    def setUp(self):
        self.summary = read_source(ROOT / "fixtures/workflow-observations.json")

    def test_supported_input(self):
        self.assertEqual(self.summary["observation_count"], 2)

    def test_raw_evidence_redacted_in_all_formats(self):
        for output in (json.dumps(self.summary), json.dumps(to_sarif(self.summary)),
                       to_html(self.summary)):
            self.assertNotIn("PRIVATE_TEXT_TO_DISCARD", output)
            self.assertNotIn("SYNTHETIC_SECRET_NEVER_ECHO", output)

    def test_sarif_has_rule_definitions(self):
        sarif = to_sarif(self.summary)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 2)

    def test_html_structure(self):
        document = to_html(self.summary)
        self.assertIn("<!doctype html>", document)
        self.assertIn("unverified", document)

    def test_bad_rule_id_rejected(self):
        source = {"schema_version": "0.1", "assessment_type": "offline_workflow_static",
                  "findings": [{"rule_id": "<script>"}]}
        with self.assertRaises(ValueError):
            canonical(source)

    def test_unknown_report_format_rejected(self):
        with self.assertRaises(ValueError):
            canonical({"schema_version": "0.1", "assessment_type": "unknown", "findings": []})

    def test_output_owner_only_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            write_private(path, json.dumps(self.summary))
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            with self.assertRaises(ValueError):
                write_private(path, "something else")

    def test_symlink_input_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "link.json"
            link.symlink_to(ROOT / "fixtures/workflow-observations.json")
            with self.assertRaises(ValueError):
                read_source(link)


if __name__ == "__main__":
    unittest.main()
