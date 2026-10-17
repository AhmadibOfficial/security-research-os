"""Small offline CLI for the Hall of Fame program registry and private ledger."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from research_os.codeql import import_codeql_sarif, list_codeql_candidates, triage_codeql_candidate
from research_os.core import (
    DEFAULT_PRIVATE, add_case, add_recognition, add_scope, ingest_android_report, next_project,
    registry, scorecard, update_case, validate_registry,
)


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="research-os", description="Evidence-led, authorized research coordination")
    p.add_argument("--data-dir", type=Path, default=DEFAULT_PRIVATE,
                   help="Private local ledger directory (never commit it)")
    commands = p.add_subparsers(dest="command", required=True)
    commands.add_parser("verify", help="Verify the 12-project public registry")
    commands.add_parser("status", help="Show non-sensitive project status")
    commands.add_parser("next", help="Choose the next development milestone")
    commands.add_parser("scorecard", help="Show aggregate counts without private evidence")
    commands.add_parser("issue-template", help="Generate a public-safe GitHub build issue")
    scope = commands.add_parser("scope-add", help="Record an explicitly authorized research scope privately")
    for name, help_text in (("name", "Short scope name"), ("asset", "Exact asset or lab scope"),
                            ("basis", "Basis of written authorization"), ("expires", "YYYY-MM-DD")):
        scope.add_argument("--" + name, required=True, help=help_text)
    imported = commands.add_parser("scan-import", help="Privately ingest an Android Toolkit JSON evidence summary")
    imported.add_argument("--scope-id", required=True)
    imported.add_argument("--report", type=Path, required=True)
    case = commands.add_parser("case-add", help="Record a hypothesis in the private ledger")
    for field in ("project", "scope-id", "title"):
        case.add_argument("--" + field, required=True)
    case.add_argument("--evidence", type=Path, help="Optional local evidence file (hashed, never copied)")
    transition = commands.add_parser("case-status", help="Advance a case through gated evidence states")
    transition.add_argument("--case-id", required=True)
    transition.add_argument("--status", required=True)
    transition.add_argument("--evidence", type=Path)
    transition.add_argument("--disclosure-reference")
    recognition = commands.add_parser("recognition-add", help="Log an unverified public recognition claim")
    for field in ("case-id", "program", "url"):
        recognition.add_argument("--" + field, required=True)
    codeql = commands.add_parser("codeql-import", help="Index local CodeQL SARIF privately without storing raw findings")
    codeql.add_argument("--scope-id", required=True)
    codeql.add_argument("--sarif", type=Path, required=True)
    commands.add_parser("codeql-queue", help="Show locally indexed, unverified CodeQL candidates")
    triage = commands.add_parser("codeql-triage", help="Record manual CodeQL candidate triage")
    triage.add_argument("--candidate-id", required=True)
    triage.add_argument("--status", choices=("reviewing", "dismissed", "case_linked"), required=True)
    triage.add_argument("--case-id")
    return p.parse_args(argv)


def main(argv=None) -> int:
    options = parse_args(argv)
    try:
        portfolio = registry()
        validate_registry(portfolio)
        if options.command == "verify":
            print("PASS: 12 project definitions, dependencies, recognition targets")
        elif options.command == "status":
            print(portfolio["program"])
            for p in portfolio["projects"]:
                print(f"{p['id']:02d} {p['repo']:<35} {p['state']:<16} {p['priority']}")
        elif options.command == "next":
            p = next_project(portfolio)
            print(json.dumps({k: p[k] for k in ("id", "repo", "state", "next_gate")}, indent=2))
        elif options.command == "scorecard":
            print(json.dumps(scorecard(portfolio, options.data_dir), indent=2))
        elif options.command == "issue-template":
            p = next_project(portfolio)
            print(f"[HOF] {p['id']:02d} — {p['repo']}: {p['next_gate']}")
            print(f"\nProject: {p['repo']}\nGoal: {p['goal']}\nNext gate: {p['next_gate']}")
            print("\nAcceptance: synthetic tests, CI green, authorized scope, redacted evidence, reproducible documentation.")
            print("No live scanning, vulnerability disclosure, or credit claim is implied by this task.")
        elif options.command == "scope-add":
            record = add_scope(options.name, options.asset, options.basis, options.expires, options.data_dir)
            print(f"Recorded private scope {record['id']} (claim of authorization, not independent verification)")
        elif options.command == "scan-import":
            result = ingest_android_report(options.report, options.scope_id, options.data_dir)
            print(f"Private Android evidence {result['id']} indexed: {result['observation_count']} unverified observations")
        elif options.command == "codeql-import":
            item = import_codeql_sarif(options.sarif, options.scope_id, options.data_dir)
            print(f"CodeQL report {item['id']} indexed privately: {item['finding_count']} unverified findings, {item['new_candidates']} new candidates")
        elif options.command == "codeql-queue":
            print(json.dumps(list_codeql_candidates(options.data_dir), indent=2))
        elif options.command == "codeql-triage":
            item = triage_codeql_candidate(options.candidate_id, options.status, options.data_dir, options.case_id)
            print(f"CodeQL candidate {item['id']}: {item['status']} (no validation implied)")
        elif options.command == "case-add":
            record = add_case(options.project, options.scope_id, options.title, options.evidence,
                              options.data_dir, portfolio)
            print(f"Private research case created: {record['id']} (hypothesis, not confirmed)")
        elif options.command == "case-status":
            record = update_case(options.case_id, options.status, options.evidence,
                                 options.disclosure_reference, options.data_dir)
            print(f"Case {record['id']} moved to {record['status']}")
        elif options.command == "recognition-add":
            record = add_recognition(options.case_id, options.program, options.url,
                                     options.data_dir, portfolio)
            print(f"Recognition claim {record['id']} recorded as UNVERIFIED")
        return 0
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
