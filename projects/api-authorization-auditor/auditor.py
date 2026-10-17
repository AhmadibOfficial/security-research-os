"""Offline authorization evidence-matrix analyzer. It makes no HTTP requests."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

MAX_INPUT_BYTES = 1024 * 1024
MAX_CASES = 2000
NAME = re.compile(r"[a-z][a-z0-9_-]{0,79}\Z")
DIMENSIONS = {"object", "function", "tenant"}
OPERATIONS = {"read", "write", "execute"}
DECISIONS = {"allow", "deny"}
OBSERVATIONS = {"granted", "blocked", "unknown"}


def _token(value: object, name: str) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError(f"Invalid {name}: use a short lowercase synthetic label")
    return value


def assess(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != {"scope", "cases"}:
        raise ValueError("Expected only 'scope' and 'cases' at document root")
    scope = document["scope"]
    if not isinstance(scope, dict) or scope != {
        "mode": "synthetic_offline",
        "authorization_basis": "owned_lab",
    }:
        raise ValueError("Only declared, owned synthetic-offline fixtures are accepted")
    cases = document["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError(f"Expected 1–{MAX_CASES} synthetic cases")
    allowed = {"id", "dimension", "operation", "principal", "resource_owner",
               "expected", "observed", "impact_verified"}
    ids = set()
    observations = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != allowed:
            raise ValueError("Case must use only the documented fields")
        case_id = _token(case["id"], "case id")
        _token(case["principal"], "principal")
        _token(case["resource_owner"], "resource owner")
        if case_id in ids:
            raise ValueError("Duplicate scenario id")
        ids.add(case_id)
        for field, accepted in (
            ("dimension", DIMENSIONS), ("operation", OPERATIONS),
            ("expected", DECISIONS), ("observed", OBSERVATIONS),
        ):
            value = case[field]
            if not isinstance(value, str) or value not in accepted:
                raise ValueError(f"Invalid {field} in synthetic authorization case")
        if type(case["impact_verified"]) is not bool:
            raise ValueError("impact_verified must be a boolean")
        if case["observed"] != "granted" and case["impact_verified"]:
            raise ValueError("Impact cannot be marked verified for blocked/unknown outcome")
        if case["expected"] == "deny" and case["observed"] == "granted":
            category = ("authorization_gap_candidate" if case["impact_verified"]
                        else "unverified_access_mismatch")
            priority = "high" if case["impact_verified"] else "review"
        elif case["expected"] == "allow" and case["observed"] == "blocked":
            category, priority = "unexpected_denial", "low"
        elif case["observed"] == "unknown":
            category, priority = "insufficient_evidence", "review"
        else:
            category, priority = "expected_policy_behavior", "none"
        observations.append({
            "scenario_id": case_id, "dimension": case["dimension"],
            "operation": case["operation"], "category": category,
            "priority": priority, "validation_status": "requires_manual_validation"
            if category in {"authorization_gap_candidate", "unverified_access_mismatch"}
            else "configuration_observation",
        })
    return {
        "schema_version": "0.1", "assessment_type": "synthetic_offline_matrix",
        "total_cases": len(cases),
        "candidate_count": sum(x["category"] == "authorization_gap_candidate"
                               for x in observations),
        "observations": observations,
        "limitations": [
            "This offline tool does not send requests or independently verify impact.",
            "The input claims are not proof of system behavior or target authorization.",
            "Potential authorization gaps require separate authorized manual review.",
        ],
    }


def assess_file(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("Input must be a regular, local file <= 1 MiB")
    raw = path.read_bytes()
    document = json.loads(raw)
    result = assess(document)
    result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic API authorization matrix")
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(assess_file(args.fixture), sort_keys=True, indent=2))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"HOLD: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
