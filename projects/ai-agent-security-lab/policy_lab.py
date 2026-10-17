"""Synthetic AI-agent tool authorization lab; never executes real tools."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

TRUST = {"system": 3, "developer": 2, "user": 1, "retrieved": 0}
ACTIONS = {
    "read_public": {"min_trust": 0, "approval": False},
    "read_private": {"min_trust": 1, "approval": False},
    "send_message": {"min_trust": 1, "approval": True},
    "modify_repository": {"min_trust": 2, "approval": True},
    "transfer_funds": {"min_trust": 3, "approval": True},
}
MAX_BYTES = 512_000
ID = re.compile(r"[a-z][a-z0-9_-]{0,60}\Z")


def evaluate(case: dict) -> dict:
    required = {"id", "origin", "requested_action", "approval", "delegated_by"}
    if not isinstance(case, dict) or set(case) != required:
        raise ValueError("Expected strict synthetic agent case schema")
    if not isinstance(case["id"], str) or not ID.fullmatch(case["id"]):
        raise ValueError("Invalid synthetic case ID")
    origin, action = case["origin"], case["requested_action"]
    if origin not in TRUST or action not in ACTIONS:
        raise ValueError("Invalid trust origin or tool action")
    if type(case["approval"]) is not bool:
        raise ValueError("Approval must be a boolean")
    delegate = case["delegated_by"]
    if delegate is not None and delegate not in TRUST:
        raise ValueError("Unknown delegation source")
    spec = ACTIONS[action]
    # This lab intentionally refuses to inherit higher authority from
    # retrieved text. Real applications need signed, granular delegation.
    effective = TRUST[origin]
    reasons = []
    if delegate is not None and TRUST[delegate] > effective:
        reasons.append("unverified_delegation_ignored")
    if effective < spec["min_trust"]:
        reasons.append("trust_boundary")
    if spec["approval"] and not case["approval"]:
        reasons.append("human_approval_required")
    return {"id": case["id"], "requested_action": action, "allowed": not reasons,
            "reasons": reasons, "execution": "simulated_only"}


def evaluate_suite(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Expected local regular synthetic JSON fixture <= 500 KiB")
    raw = path.read_bytes()
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {"mode", "cases"} or data["mode"] != "synthetic_only":
        raise ValueError("Only synthetic agent traces allowed")
    if not isinstance(data["cases"], list) or not 1 <= len(data["cases"]) <= 1000:
        raise ValueError("Expected 1–1000 synthetic cases")
    ids, results = set(), []
    for item in data["cases"]:
        result = evaluate(item)
        if result["id"] in ids:
            raise ValueError("Duplicate scenario identifier")
        ids.add(result["id"])
        results.append(result)
    return {"schema_version": "0.1", "suite_sha256": hashlib.sha256(raw).hexdigest(),
            "case_count": len(results), "blocked_count": sum(not x["allowed"] for x in results),
            "results": results,
            "limitations": ["This is a policy simulator, not an LLM penetration test.",
                            "Simulated approval is test data, not actual approval.",
                            "No external tools or systems are invoked."]}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("fixture", type=Path)
    args = p.parse_args()
    try:
        print(json.dumps(evaluate_suite(args.fixture), indent=2))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
