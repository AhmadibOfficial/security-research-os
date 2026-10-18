#!/usr/bin/env python3
"""HOF-018: evidence-led research→remediation proof in a synthetic loopback lab.

Only imports locally staged project sources. No third-party targets, scans,
payments, vendor disclosure, Git writes, or network beyond 127.0.0.1.
"""
from __future__ import annotations

import argparse
from datetime import date, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from research_os.core import add_case, add_scope, update_case, scorecard, registry


def _module(name: str, file: Path):
    if file.is_symlink() or not file.is_file() or file.suffix != ".py":
        raise ValueError("Expected trusted, regular local Python module")
    spec = importlib.util.spec_from_file_location(name, file)
    if spec is None or spec.loader is None:
        raise ValueError("Unable to load staged source module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _private_write(path: Path, payload: object) -> None:
    """Exclusive file creation; never overwrite or follow output symlinks."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ValueError("Refusing to overwrite existing or linked evidence")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _probe(port: int, route: str, actor: str | None) -> dict:
    if route not in {"/unsafe/records/100", "/fixed/records/100",
                     "/fixed/records/200"}:
        raise ValueError("Only three predeclared synthetic routes are allowed")
    headers = {"X-Lab-Actor": actor} if actor else {}
    req = Request(f"http://127.0.0.1:{port}{route}", headers=headers)
    try:
        with urlopen(req, timeout=3) as response:
            status = response.status
            body = response.read(4096)
    except HTTPError as exc:
        status = exc.code
        body = exc.read(4096)
    if status not in {200, 401, 403}:
        raise ValueError("Unexpected lab response code")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise ValueError("Expected structured synthetic JSON response")
    return {"status": status, "body": parsed}


def _evidence(rows: list[dict]) -> dict:
    """Derive outcomes from actual loopback responses, never claimed booleans."""
    if len(rows) != 5 or len({x["id"] for x in rows}) != 5:
        raise ValueError("The complete five-scenario control matrix is required")
    expected = {
        "unsafe-cross-owner": (True, 200, "alice"),
        "fixed-cross-owner": (False, 403, None),
        "fixed-own-owner": (False, 200, "bob"),
        "anonymous-denied": (False, 401, None),
        "same-route-after-remediation": (False, 403, None),
    }
    cases, observation = [], []
    tp = tn = fp = fn = 0
    for item in rows:
        ident = item["id"]
        if ident not in expected:
            raise ValueError("Unexpected scenario identifier")
        ground_truth_positive, expected_status, expected_owner = expected[ident]
        response = item["response"]
        status, body = response["status"], response["body"]
        authenticated = body.get("synthetic") is True
        owner = body.get("owner")
        is_gap = ident == "unsafe-cross-owner" and status == 200 and authenticated and owner == "alice" and body.get("value") == "SYNTHETIC_ALICE_RECORD"
        if status != expected_status or (expected_owner is not None and owner != expected_owner):
            raise ValueError(f"Observed response contradicts expected synthetic fixture: {ident}")
        if ground_truth_positive and not is_gap:
            raise ValueError("Synthetic unauthorized-read proof is missing")
        classified_positive = is_gap
        if ground_truth_positive:
            tp += int(classified_positive)
            fn += int(not classified_positive)
        else:
            fp += int(classified_positive)
            tn += int(not classified_positive)
        decision = "granted" if status == 200 else "blocked"
        cases.append({
            "id": ident, "dimension": "object", "operation": "read",
            "principal": "bob" if ident != "anonymous-denied" else "anonymous",
            "resource_owner": "bob" if ident == "fixed-own-owner" else "alice",
            "expected": "allow" if ident == "fixed-own-owner" else "deny",
            "observed": decision,
            # This flag is DERIVED from the HTTP evidence, not accepted from input.
            "impact_verified": bool(is_gap),
        })
        observation.append({
            "scenario": ident, "expected_status": expected_status,
            "observed_status": status,
            "detected_synthetic_gap": classified_positive,
        })
    metrics = {
        "synthetic_true_positives": tp, "synthetic_true_negatives": tn,
        "synthetic_false_positives": fp, "synthetic_false_negatives": fn,
        "total_synthetic_scenarios": len(rows),
    }
    if metrics != {
        "synthetic_true_positives": 1, "synthetic_true_negatives": 4,
        "synthetic_false_positives": 0, "synthetic_false_negatives": 0,
        "total_synthetic_scenarios": 5,
    }:
        raise ValueError("Synthetic detection or negative control gate failed")
    return {"scope": {"mode": "synthetic_offline", "authorization_basis": "owned_lab"},
            "cases": cases}, observation, metrics


def _assert_private_location(path: Path) -> None:
    resolved = path.expanduser().resolve(strict=False)
    if resolved.is_relative_to(ROOT):
        raise ValueError("Private outputs cannot be placed inside the Git repository")


def run(lab_file: Path, auditor_file: Path, report_file: Path,
        private_directory: Path, output: Path) -> dict:
    for path in (private_directory, output):
        _assert_private_location(path)
    if output.exists() or output.is_symlink():
        raise ValueError("Report already exists or is a symlink")
    lab = _module("hof018_lab", lab_file)
    auditor = _module("hof018_auditor", auditor_file)
    reporter = _module("hof018_reporter", report_file)

    with lab.make_server(0) as server:
        host, port = server.server_address
        if host != "127.0.0.1" or getattr(server, "remediation_enabled", None) is not False:
            raise ValueError("Owned synthetic lab must be loopback-only, unremediated initially")
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            rows = []
            for ident, route, actor in (
                ("unsafe-cross-owner", "/unsafe/records/100", "bob"),
                ("fixed-cross-owner", "/fixed/records/100", "bob"),
                ("fixed-own-owner", "/fixed/records/200", "bob"),
                ("anonymous-denied", "/unsafe/records/100", None),
            ):
                rows.append({"id": ident, "response": _probe(port, route, actor)})
            # Same route, same actor and record: enable the correction in
            # the owned synthetic lab and verify the gap no longer reproduces.
            server.remediation_enabled = True
            rows.append({"id": "same-route-after-remediation",
                         "response": _probe(port, "/unsafe/records/100", "bob")})
        finally:
            server.shutdown()
            thread.join(timeout=4)

    matrix, observations, metrics = _evidence(rows)
    audit = auditor.assess(matrix)
    if audit.get("candidate_count") != 1:
        raise ValueError("Auditor failed to identify exactly one synthetic gap")
    interesting = [x for x in audit["observations"] if x["category"] == "authorization_gap_candidate"]
    if len(interesting) != 1 or interesting[0]["scenario_id"] != "unsafe-cross-owner":
        raise ValueError("Auditor classification or provenance mismatch")
    safe = [x for x in audit["observations"] if x["category"] == "expected_policy_behavior"]
    if len(safe) != 4:
        raise ValueError("Safe controls were incorrectly escalated")
    canonical = reporter.canonical(audit)
    if canonical["observation_count"] != 1:
        raise ValueError("Reporter must exclude all four expected-safe controls")
    if canonical["observations"][0]["rule_id"] != "authorization_gap_candidate":
        raise ValueError("Reporter lost synthetic finding classification")
    if "SYNTHETIC_ALICE_RECORD" in json.dumps(canonical):
        raise ValueError("The report contained raw lab evidence")

    # Raw controlled lab observations live only in a private ephemeral file.
    # The persistent ledger retains a digest, scope, and case state, not responses.
    with tempfile.TemporaryDirectory(prefix="ahmadib-hof018-") as temp:
        proof = Path(temp) / "synthetic-proof.json"
        _private_write(proof, {"mode": "owned_synthetic_lab",
                               "observations": observations, "metrics": metrics})
        digest = hashlib.sha256(proof.read_bytes()).hexdigest()
        scope = add_scope("HOF018 owned synthetic lab",
                          "127.0.0.1 ephemeral synthetic authorization fixtures",
                          "Code created and controlled by project owner",
                          (date.today() + timedelta(days=30)).isoformat(),
                          private_directory)
        case = add_case("api-authorization-auditor", scope["id"],
                        "Synthetic object access bypass and controlled same-route remediation",
                        proof, private_directory)
        case = update_case(case["id"], "reproduced",
                           directory=private_directory)
        if case["evidence_sha256"] != digest:
            raise ValueError("Research OS failed to preserve evidence fingerprint")
    if scorecard(registry(), private_directory)["verified_recognition_count"] != 0:
        raise ValueError("Synthetic cases may never create verified recognition credits")

    artifact = {
        "schema_version": "0.1",
        "milestone": "HOF-018",
        "scope": "owned_loopback_synthetic_only",
        "case_id": case["id"], "case_status": case["status"],
        "evidence_sha256": digest, "metrics": metrics,
        "report": canonical, "quality_gate": "synthetic_passed",
        "disclosure": "not_authorized_or_applicable",
        "recognition": "none",
        "limits": [
            "No third-party vulnerability, patch, disclosure, or bounty was demonstrated.",
            "Synthetic remediation switch demonstrates same-route denial after correction.",
            "GitHub-hosted CI and real CodeQL gates remain separately blocked.",
        ],
    }
    _private_write(output, artifact)
    return artifact


def main() -> int:
    ap = argparse.ArgumentParser(description="HOF-018: owned synthetic research-to-fix proof")
    ap.add_argument("--lab-file", type=Path, required=True)
    ap.add_argument("--auditor-file", type=Path, required=True)
    ap.add_argument("--report-file", type=Path, required=True)
    ap.add_argument("--private-dir", type=Path,
                    default=Path.home() / ".local/share/ahmad-ib-research-os/hof018")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    try:
        result = run(args.lab_file, args.auditor_file, args.report_file,
                     args.private_dir, args.out)
        print(json.dumps({"milestone": result["milestone"],
                          "status": result["quality_gate"],
                          "metrics": result["metrics"],
                          "case_status": result["case_status"],
                          "release": "HOLD"}, indent=2))
        return 0
    except (OSError, ValueError, ImportError, URLError, json.JSONDecodeError) as exc:
        print(f"HOLD: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
