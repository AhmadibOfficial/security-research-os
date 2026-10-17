import json
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from portfolio import prepare, render_html, generate
ROOT = Path(__file__).resolve().parents[1]
PROGRAM = "AHMAD-IB Hall of Fame Automation Program"


def record():
    return {"id": "synthetic-case", "program": "owasp-mobile",
            "contribution": "Approved synthetic test contribution",
            "public_url": "https://example.org/evidence",
            "verification_status": "externally_verified",
            "publication_approved": True,
            "authorization_to_publish": True}


class PublicationTests(unittest.TestCase):
    def test_pending_claim_is_hidden(self):
        doc = json.loads((ROOT / "fixtures/synthetic-unverified.json").read_text())
        self.assertEqual(prepare(doc)["public_contribution_count"], 0)

    def test_verified_and_approved_example_is_rendered(self):
        out = prepare({"program": PROGRAM, "records": [record()]})
        self.assertEqual(out["public_contribution_count"], 1)
        self.assertIn("Approved synthetic", render_html(out))

    def test_unapproved_record_is_not_public(self):
        r = record()
        r["publication_approved"] = False
        self.assertEqual(prepare({"program": PROGRAM, "records": [r]})["contributions"], [])

    def test_no_publish_without_permission(self):
        r = record()
        r["authorization_to_publish"] = False
        self.assertEqual(prepare({"program": PROGRAM, "records": [r]})["contributions"], [])

    def test_http_link_not_eligible(self):
        r = record()
        r["public_url"] = "http://example.org/award"
        with self.assertRaises(ValueError):
            prepare({"program": PROGRAM, "records": [r]})

    def test_unrecognized_program_rejected(self):
        r = record()
        r["program"] = "unverified-awards"
        with self.assertRaises(ValueError):
            prepare({"program": PROGRAM, "records": [r]})

    def test_private_finding_fields_cannot_be_exported(self):
        r = record()
        r["private_disclosure_text"] = "private researcher material"
        with self.assertRaises(ValueError):
            prepare({"program": PROGRAM, "records": [r]})

    def test_never_overwrites_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "portfolio.html"
            source = ROOT / "fixtures/synthetic-unverified.json"
            self.assertEqual(generate(source, destination), 0)
            self.assertEqual(destination.stat().st_mode & 0o077, 0)
            with self.assertRaises(ValueError):
                generate(source, destination)


if __name__ == "__main__":
    unittest.main()
