"""Private, fail-closed intake and triage of local CodeQL SARIF 2.1.0 findings.

No CodeQL query is run; no external target is contacted. Raw messages, URLs,
source snippets, or absolute paths are never copied into the private index.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path

from research_os.core import _read_private, _write_private, fingerprint_file

LEDGER = "codeql_queue.json"
MAX_SARIF_BYTES = 16 * 1024 * 1024
MAX_RUNS = 12
MAX_RESULTS = 3000
RULE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,119}\Z")


def _valid_scope(scope_id: str, directory: Path | None) -> None:
    if not isinstance(scope_id, str) or not scope_id.startswith("SCOPE-"):
        raise ValueError("Recorded scope ID is required")
    scopes = _read_private("scopes.json", directory)
    scope = next((s for s in scopes if s.get("id") == scope_id), None)
    if scope is None or date.fromisoformat(scope["expires"]) < date.today():
        raise ValueError("Current recorded authorization scope is required")


def _safe_rule_id(value: object) -> str:
    if isinstance(value, str) and RULE_PATTERN.fullmatch(value):
        return value
    return "unclassified"


def _finding_identity(run_number: int, finding: dict) -> str:
    # Hash all path/message/region fields without retaining them. Imported
    # metadata does not certify reachability, impact, or exploitability.
    raw = {
        "run": run_number,
        "rule": finding.get("ruleId"),
        "locations": finding.get("locations", []),
        "fingerprints": finding.get("partialFingerprints", {}),
        "message": finding.get("message", {}),
    }
    canonical = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def import_codeql_sarif(path: Path, scope_id: str, directory: Path | None = None) -> dict:
    """Index CodeQL SARIF locally without ever saving the underlying results.

    Each candidate is a low-trust observation requiring independent triage.
    """
    _valid_scope(scope_id, directory)
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SARIF_BYTES:
        raise ValueError("SARIF must be a regular, local file <= 16 MiB")
    digest = fingerprint_file(path)
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("version") != "2.1.0":
        raise ValueError("Expected SARIF version 2.1.0")
    runs = report.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= MAX_RUNS:
        raise ValueError("SARIF must contain 1–12 valid runs")

    candidates = {}
    total = 0
    for run_number, run in enumerate(runs):
        if not isinstance(run, dict) or not isinstance(run.get("tool"), dict):
            raise ValueError("SARIF run lacks a tool declaration")
        driver = run["tool"].get("driver")
        if not isinstance(driver, dict) or driver.get("name") != "CodeQL":
            raise ValueError("Only CodeQL SARIF output is accepted")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("SARIF results must be an array")
        total += len(results)
        if total > MAX_RESULTS:
            raise ValueError("SARIF result limit exceeded")
        for finding in results:
            if not isinstance(finding, dict):
                raise ValueError("Invalid SARIF finding")
            fingerprint = _finding_identity(run_number, finding)
            # Scope is part of the identity: a finding cannot implicitly
            # transfer authorization between different research assets.
            candidate_id = "CQL-" + hashlib.sha256(
                (scope_id + ":" + fingerprint).encode("utf-8")
            ).hexdigest()[:24]
            level = finding.get("level", "warning")
            level = level if level in {"error", "warning", "note", "none"} else "unknown"
            candidates.setdefault(candidate_id, {
                "type": "candidate",
                "id": candidate_id,
                "scope_id": scope_id,
                "rule_id": _safe_rule_id(finding.get("ruleId")),
                "level": level,
                "fingerprint_sha256": fingerprint,
                "status": "queued",
                "case_id": None,
            })
    entries = _read_private(LEDGER, directory)
    found = next((item for item in entries if item.get("type") == "import"
                  and item.get("scope_id") == scope_id and item.get("file_sha256") == digest), None)
    if found:
        return found.copy()
    known_ids = {item["id"] for item in entries if item.get("type") == "candidate"}
    fresh = [item for key, item in sorted(candidates.items()) if key not in known_ids]
    record = {
        "type": "import",
        "id": "CQLRUN-" + hashlib.sha256((scope_id + digest).encode()).hexdigest()[:24],
        "scope_id": scope_id,
        "file_sha256": digest,
        "finding_count": total,
        "new_candidates": len(fresh),
        "status": "requires_manual_validation",
    }
    _write_private(LEDGER, [*entries, *fresh, record], directory)
    return record.copy()


def list_codeql_candidates(directory: Path | None = None) -> list[dict]:
    """Private local queue listing; no source paths, messages or raw SARIF."""
    return [
        {key: item[key] for key in ("id", "rule_id", "level", "status", "scope_id", "case_id")}
        for item in _read_private(LEDGER, directory) if item.get("type") == "candidate"
    ]


def triage_codeql_candidate(candidate_id: str, status: str, directory: Path | None = None,
                            case_id: str | None = None) -> dict:
    """Advance manual review, never automatically validate or disclose an issue."""
    transitions = {"queued": {"reviewing", "dismissed"},
                   "reviewing": {"dismissed", "case_linked"},
                   "dismissed": set(), "case_linked": set()}
    entries = _read_private(LEDGER, directory)
    item = next((x for x in entries if x.get("type") == "candidate"
                 and x.get("id") == candidate_id), None)
    if item is None:
        raise ValueError("Research candidate not found")
    _valid_scope(item["scope_id"], directory)
    if status not in transitions[item["status"]]:
        raise ValueError("Invalid research candidate status transition")
    if status == "case_linked":
        case = next((x for x in _read_private("cases.json", directory)
                     if x.get("id") == case_id), None)
        if case is None or case.get("scope_id") != item["scope_id"]:
            raise ValueError("A research case with the same scope is required")
        if not case.get("evidence_sha256"):
            raise ValueError("Linked research case must have evidence")
        item["case_id"] = case_id
    elif case_id is not None:
        raise ValueError("Case ID is only allowed when linking a case")
    item["status"] = status
    _write_private(LEDGER, entries, directory)
    return {key: item[key] for key in ("id", "status", "case_id")}
