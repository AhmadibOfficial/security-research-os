"""Synthetic CodeQL SARIF fixtures; no external scanning or real findings."""
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from research_os.cli import main
from research_os.codeql import import_codeql_sarif, list_codeql_candidates, triage_codeql_candidate
from research_os.core import add_case, add_scope


def example(rule="py/path-injection", message="SYNTHETIC PRIVATE PATH /secrets/example.txt"):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}},
            "results": [{"ruleId": rule, "level": "warning", "message": {"text": message},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/private.py"},
                            "region": {"startLine": 123}}}]}]}]}


class CodeQLQueueTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.scope = add_scope("Test source", "owned synthetic repository", "Own lab",
            (date.today() + timedelta(days=30)).isoformat(), self.root)
        self.report = self.root / "synthetic.sarif"
        self.report.write_text(json.dumps(example()), encoding="utf-8")

    def test_import_has_private_permissions_and_no_raw_data(self):
        result = import_codeql_sarif(self.report, self.scope["id"], self.root)
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["new_candidates"], 1)
        ledger = self.root / "codeql_queue.json"
        self.assertEqual(ledger.stat().st_mode & 0o077, 0)
        stored = ledger.read_text()
        self.assertNotIn("SYNTHETIC PRIVATE", stored)
        self.assertNotIn("src/private.py", stored)
        self.assertNotIn("/secrets/", stored)
        self.assertEqual(list_codeql_candidates(self.root)[0]["status"], "queued")

    def test_duplicate_sarif_does_not_duplicate_candidates(self):
        a = import_codeql_sarif(self.report, self.scope["id"], self.root)
        b = import_codeql_sarif(self.report, self.scope["id"], self.root)
        self.assertEqual(a, b)
        self.assertEqual(len(list_codeql_candidates(self.root)), 1)

    def test_same_finding_requires_separate_scope(self):
        scope_b = add_scope("Another lab", "another owned repo", "Own lab",
            (date.today() + timedelta(days=30)).isoformat(), self.root)
        import_codeql_sarif(self.report, self.scope["id"], self.root)
        import_codeql_sarif(self.report, scope_b["id"], self.root)
        self.assertEqual(len({x["id"] for x in list_codeql_candidates(self.root)}), 2)

    def test_unregistered_or_expired_scope_rejected(self):
        with self.assertRaises(ValueError):
            import_codeql_sarif(self.report, "SCOPE-invalid", self.root)
        scopes = self.root / "scopes.json"
        old = json.loads(scopes.read_text())
        old[0]["expires"] = "2000-01-01"
        scopes.write_text(json.dumps(old))
        with self.assertRaises(ValueError):
            import_codeql_sarif(self.report, self.scope["id"], self.root)

    def test_malformed_format_and_wrong_tool_rejected(self):
        for doc in ({}, {"version": "2.0.0", "runs": []},
                    {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Other"}}}]}):
            self.report.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                import_codeql_sarif(self.report, self.scope["id"], self.root)

    def test_reject_symlinks_and_oversized_files(self):
        link = self.root / "link.sarif"
        link.symlink_to(self.report)
        with self.assertRaises(ValueError):
            import_codeql_sarif(link, self.scope["id"], self.root)
        with self.report.open("wb") as f:
            f.truncate(16 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            import_codeql_sarif(self.report, self.scope["id"], self.root)

    def test_result_limit_fail_closed(self):
        x = example()
        x["runs"][0]["results"] *= 3001
        self.report.write_text(json.dumps(x))
        with self.assertRaises(ValueError):
            import_codeql_sarif(self.report, self.scope["id"], self.root)
        self.assertFalse((self.root / "codeql_queue.json").exists())

    def test_manual_triage_is_not_vulnerability_validation(self):
        import_codeql_sarif(self.report, self.scope["id"], self.root)
        id_ = list_codeql_candidates(self.root)[0]["id"]
        self.assertEqual(triage_codeql_candidate(id_, "reviewing", self.root)["status"], "reviewing")
        with self.assertRaises(ValueError):
            triage_codeql_candidate(id_, "case_linked", self.root)
        self.assertEqual(triage_codeql_candidate(id_, "dismissed", self.root)["status"], "dismissed")
        with self.assertRaises(ValueError):
            triage_codeql_candidate(id_, "reviewing", self.root)

    def test_link_requires_evidenced_case_in_same_scope(self):
        import_codeql_sarif(self.report, self.scope["id"], self.root)
        id_ = list_codeql_candidates(self.root)[0]["id"]
        triage_codeql_candidate(id_, "reviewing", self.root)
        other = add_scope("Other", "other synthetic project", "Own lab",
            (date.today() + timedelta(days=30)).isoformat(), self.root)
        case = add_case("codeql-security-research", other["id"], "Synthetic case", self.report, self.root)
        with self.assertRaises(ValueError):
            triage_codeql_candidate(id_, "case_linked", self.root, case["id"])
        not_evidenced = add_case("codeql-security-research", self.scope["id"], "No evidence",
                                 directory=self.root)
        with self.assertRaises(ValueError):
            triage_codeql_candidate(id_, "case_linked", self.root, not_evidenced["id"])
        valid = add_case("codeql-security-research", self.scope["id"], "Private synthetic hypothesis",
                          self.report, self.root)
        self.assertEqual(triage_codeql_candidate(id_, "case_linked", self.root, valid["id"])["case_id"],
                         valid["id"])

    def test_cli_import_queue_and_triage(self):
        from io import StringIO
        import contextlib
        out = StringIO()
        argv = ["--data-dir", str(self.root), "codeql-import", "--scope-id", self.scope["id"],
                "--sarif", str(self.report)]
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(argv), 0)
        self.assertIn("1 unverified findings", out.getvalue())
        out = StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["--data-dir", str(self.root), "codeql-queue"]), 0)
        queue = json.loads(out.getvalue())
        self.assertEqual(queue[0]["status"], "queued")
        self.assertNotIn("SYNTHETIC PRIVATE", out.getvalue())


if __name__ == "__main__":
    unittest.main()
