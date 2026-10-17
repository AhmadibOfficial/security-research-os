import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from auditor import aws_policy, azure_role, audit_file
ROOT = Path(__file__).resolve().parents[1]


class CloudIAMTests(unittest.TestCase):
    def test_aws_overprivileged_fixture(self):
        r = audit_file(ROOT / "fixtures/aws-overprivileged.json")
        self.assertEqual({x["rule"] for x in r["observations"]},
                         {"IAM-AWS-001", "IAM-AWS-002"})

    def test_aws_least_privilege_negative(self):
        r = audit_file(ROOT / "fixtures/aws-least-privilege.json")
        self.assertEqual(r["finding_count"], 0)

    def test_azure_wildcard_fixture(self):
        r = audit_file(ROOT / "fixtures/azure-overprivileged.json")
        self.assertEqual(r["observations"][0]["rule"], "IAM-AZ-001")

    def test_aws_deny_not_flagged(self):
        self.assertEqual(aws_policy({"Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*"}]}), [])

    def test_exception_style_needs_review(self):
        r = aws_policy({"Statement": [
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]})
        self.assertEqual(r[0]["rule"], "IAM-AWS-003")

    def test_missing_aws_statement_rejected(self):
        with self.assertRaises(ValueError):
            aws_policy({"foo": "bar"})

    def test_invalid_azure_permissions_rejected(self):
        with self.assertRaises(ValueError):
            azure_role({"permissions": "anything"})

    def test_output_does_not_dump_arn(self):
        r = audit_file(ROOT / "fixtures/aws-least-privilege.json")
        self.assertNotIn("arn:aws:", json.dumps(r))

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            lnk = Path(tmp) / "link.json"
            lnk.symlink_to(ROOT / "fixtures/aws-overprivileged.json")
            with self.assertRaises(ValueError):
                audit_file(lnk)


if __name__ == "__main__":
    unittest.main()
