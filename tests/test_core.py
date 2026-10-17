"""Test the research lifecycle using synthetic examples only."""

import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from research_os.core import (
    add_case, add_recognition, add_scope, fingerprint_file, ingest_android_report, next_project,
    registry, scorecard, update_case, validate_registry,
)


class ResearchOSTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.doc = registry()
        self.expires = (date.today() + timedelta(days=30)).isoformat()

    def scope(self):
        return add_scope("Owned laboratory", "http://localhost:8080", "Own synthetic lab",
                         self.expires, self.home)

    def test_12_projects_and_priority(self):
        validate_registry(self.doc)
        self.assertEqual(len(self.doc["projects"]), 12)
        self.assertEqual(next_project(self.doc)["repo"], "security-research-os")

    def test_duplicate_project_rejected(self):
        self.doc["projects"][1]["repo"] = self.doc["projects"][0]["repo"]
        with self.assertRaises(ValueError):
            validate_registry(self.doc)

    def test_expired_scope_rejected(self):
        with self.assertRaises(ValueError):
            add_scope("expired", "localhost", "test lab", "2000-01-01", self.home)

    def test_scope_and_case_written_private(self):
        scope = self.scope()
        c = add_case("security-research-os", scope["id"], "Synthetic weak test", directory=self.home)
        self.assertEqual(c["status"], "hypothesis")
        self.assertEqual((self.home / "cases.json").stat().st_mode & 0o077, 0)
        self.assertEqual((self.home / "scopes.json").stat().st_mode & 0o077, 0)

    def test_unregistered_project_denied(self):
        scope = self.scope()
        with self.assertRaises(ValueError):
            add_case("other-project", scope["id"], "Hypothesis", directory=self.home)

    def test_fingerprint_is_sha256_only(self):
        data = self.home / "synthetic.txt"
        data.write_text("harmless synthetic evidence", encoding="utf-8")
        self.assertEqual(len(fingerprint_file(data)), 64)

    def test_cannot_validate_without_evidence(self):
        scope = self.scope()
        record = add_case("security-research-os", scope["id"], "Hypothesis", directory=self.home)
        with self.assertRaises(ValueError):
            update_case(record["id"], "reproduced", directory=self.home)

    def test_valid_state_machine(self):
        scope = self.scope()
        evidence = self.home / "sample.txt"
        evidence.write_text("synthetic data")
        record = add_case("security-research-os", scope["id"], "Hypothesis",
                          evidence_path=evidence, directory=self.home)
        for new_status in ("reproduced", "triaged", "disclosed", "resolved", "acknowledged"):
            new = update_case(record["id"], new_status,
                              disclosure_reference="Private report HOF-TEST" if new_status == "disclosed" else None,
                              directory=self.home)
            self.assertEqual(new["status"], new_status)
        with self.assertRaises(ValueError):
            update_case(record["id"], "rejected", directory=self.home)

    def test_recognition_requires_acknowledgment(self):
        scope = self.scope()
        record = add_case("security-research-os", scope["id"], "Hypothesis", directory=self.home)
        with self.assertRaises(ValueError):
            add_recognition(record["id"], "github-security-lab", "https://example.org/award", self.home)

    def test_recognition_claim_never_counts_as_verified(self):
        scope = self.scope()
        evidence = self.home / "synthetic.txt"
        evidence.write_text("synthetic")
        record = add_case("security-research-os", scope["id"], "Hypothesis", evidence,
                          self.home)
        for status in ("reproduced", "triaged", "disclosed", "acknowledged"):
            update_case(record["id"], status,
                        disclosure_reference="private case" if status == "disclosed" else None,
                        directory=self.home)
        claim = add_recognition(record["id"], "github-security-lab",
                                "https://example.org/acknowledgment", directory=self.home)
        self.assertEqual(claim["verification_status"], "unverified")
        stats = scorecard(self.doc, self.home)
        self.assertEqual(stats["verified_recognition_count"], 0)
        self.assertEqual(stats["unverified_recognition_claim_count"], 1)
        self.assertNotIn("Hypothesis", json.dumps(stats))

    def test_android_toolkit_report_import_deduplicates_without_raw_findings(self):
        scope = self.scope()
        report = self.home / "synthetic-report.json"
        report.write_text(json.dumps({"schema_version": "1.0", "assessment_type": "offline_static",
                                      "summary": {"total_observations": 1},
                                      "findings": [{"title": "FAKE PRIVATE FINDING", "evidence": {"observation": "test"}}]}))
        item1 = ingest_android_report(report, scope["id"], self.home)
        item2 = ingest_android_report(report, scope["id"], self.home)
        self.assertEqual(item1, item2)
        stored = (self.home / "scans.json").read_text()
        self.assertNotIn("FAKE PRIVATE FINDING", stored)
        self.assertEqual(item1["observation_count"], 1)

    def test_scan_import_requires_valid_schema(self):
        scope = self.scope()
        report = self.home / "bad.json"
        report.write_text("{}")
        with self.assertRaises(ValueError):
            ingest_android_report(report, scope["id"], self.home)

    def test_reject_file_symlink(self):
        target = self.home / "real.txt"
        target.write_text("synthetic")
        link = self.home / "symlink.txt"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            fingerprint_file(link)


if __name__ == "__main__":
    unittest.main()
