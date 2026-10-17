import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import scan_manifest

ROOT = Path(__file__).resolve().parents[1]


class DeepLinkTests(unittest.TestCase):
    def test_fixture_has_two_browsable_links(self):
        r = scan_manifest(ROOT / "fixtures/synthetic-manifest.xml")
        self.assertEqual(r["deeplink_count"], 2)

    def test_plaintext_broad_gateway_flagged(self):
        r = scan_manifest(ROOT / "fixtures/synthetic-manifest.xml")
        self.assertIn("plaintext_link_scheme", r["deeplinks"][0]["observations"])
        self.assertIn("broad_web_uri_matching_candidate", r["deeplinks"][0]["observations"])

    def test_verified_https_example_not_flagged(self):
        r = scan_manifest(ROOT / "fixtures/synthetic-manifest.xml")
        self.assertEqual(r["deeplinks"][1]["observations"], [])

    def test_internal_not_mistaken_for_browsable(self):
        data = scan_manifest(ROOT / "fixtures/synthetic-manifest.xml")
        self.assertNotIn(".InternalOnly", [x["component"] for x in data["deeplinks"]])

    def test_reject_non_manifest_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.xml"
            p.write_text("<not-manifest/>")
            with self.assertRaises(ValueError):
                scan_manifest(p)

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "link.xml"
            link.symlink_to(ROOT / "fixtures/synthetic-manifest.xml")
            with self.assertRaises(ValueError):
                scan_manifest(link)


if __name__ == "__main__":
    unittest.main()
