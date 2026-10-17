import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import audit_source
ROOT = Path(__file__).resolve().parents[1]


class WebViewTests(unittest.TestCase):
    def test_unsafe_fixture_rule_coverage(self):
        x = audit_source(ROOT / "fixtures/SyntheticUnsafeActivity.java")
        self.assertEqual({f["rule_id"] for f in x["findings"]},
                         {"WV-001", "WV-002", "WV-003", "WV-004"})

    def test_safer_fixture_zero_signals(self):
        x = audit_source(ROOT / "fixtures/SyntheticSaferActivity.java")
        self.assertEqual(x["finding_count"], 0)

    def test_no_source_snippets_in_report(self):
        r = audit_source(ROOT / "fixtures/SyntheticUnsafeActivity.java")
        self.assertNotIn("LabBridge", json.dumps(r))
        self.assertNotIn("package org", json.dumps(r))

    def test_kotlin_synthetic_setting(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Lab.kt"
            path.write_text("webView.settings.javaScriptEnabled = true\n")
            self.assertEqual(audit_source(path)["findings"][0]["rule_id"], "WV-002")

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "link.java"
            link.symlink_to(ROOT / "fixtures/SyntheticUnsafeActivity.java")
            with self.assertRaises(ValueError):
                audit_source(link)

    def test_reject_wrong_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fake.txt"
            path.write_text("view.addJavascriptInterface(x, y)")
            with self.assertRaises(ValueError):
                audit_source(path)


if __name__ == "__main__":
    unittest.main()
