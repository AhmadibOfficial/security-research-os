"""Offline AWS/Azure access-policy snapshot auditor; no cloud credentials or API calls."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

MAX_BYTES = 1024 * 1024


def _setof(value):
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return set(value)
    raise ValueError("Expected a string or array of strings")


def aws_policy(doc: dict) -> list[dict]:
    if not isinstance(doc, dict) or not isinstance(doc.get("Statement"), (list, dict)):
        raise ValueError("Invalid AWS IAM policy Statement")
    statements = doc["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    findings = []
    for i, statement in enumerate(statements):
        if not isinstance(statement, dict):
            raise ValueError("Invalid AWS statement")
        if statement.get("Effect") not in {"Allow", "Deny"}:
            raise ValueError("Invalid AWS effect")
        if "NotAction" in statement or "NotResource" in statement:
            findings.append({"rule": "IAM-AWS-003", "position": i,
                             "finding": "Exception-based policy needs context review"})
            continue
        actions = _setof(statement.get("Action", []))
        resources = _setof(statement.get("Resource", []))
        if statement["Effect"] != "Allow":
            continue
        if "*" in actions and "*" in resources:
            findings.append({"rule": "IAM-AWS-001", "position": i,
                             "finding": "Allow all actions on all resources"})
        elif "*" in resources and any(x in actions for x in ("iam:PassRole", "sts:AssumeRole")):
            findings.append({"rule": "IAM-AWS-002", "position": i,
                             "finding": "Role delegation with wildcard resource"})
    return findings


def azure_role(doc: dict) -> list[dict]:
    if not isinstance(doc, dict):
        raise ValueError("Invalid Azure custom role")
    perms = doc.get("permissions")
    if not isinstance(perms, list):
        raise ValueError("Azure role permissions must be an array")
    findings = []
    for i, item in enumerate(perms):
        if not isinstance(item, dict):
            raise ValueError("Invalid Azure permission entry")
        actions = _setof(item.get("actions", []))
        data_actions = _setof(item.get("dataActions", []))
        if "*" in actions or "*" in data_actions:
            findings.append({"rule": "IAM-AZ-001", "position": i,
                             "finding": "Wildcard Azure management/data permissions"})
    return findings


def audit_file(path: Path) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Expected regular local JSON policy <= 1 MiB")
    raw = path.read_bytes()
    doc = json.loads(raw)
    if not isinstance(doc, dict) or set(doc) != {"provider", "policy"}:
        raise ValueError("Expected provider and policy fields only")
    if doc["provider"] == "aws":
        findings = aws_policy(doc["policy"])
    elif doc["provider"] == "azure":
        findings = azure_role(doc["policy"])
    else:
        raise ValueError("Unsupported cloud provider")
    return {"assessment_type": "offline_iam_snapshot", "schema_version": "0.1",
            "provider": doc["provider"],
            "sha256": hashlib.sha256(raw).hexdigest(),
            "finding_count": len(findings),
            "observations": [dict(item, status="requires_manual_validation") for item in findings],
            "limitations": [
                "Role assignments, resource policies, SCPs, deny logic and effective permissions are not computed.",
                "Wildcard patterns alone are not proof of reachable privilege escalation.",
                "Never import live credentials or disclose unreviewed policy details.",
            ]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("snapshot", type=Path)
    args = p.parse_args()
    try:
        print(json.dumps(audit_file(args.snapshot), indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
