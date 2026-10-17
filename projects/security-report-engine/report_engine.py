"""Privacy-first JSON / SARIF / HTML rendering from known synthetic tool summaries."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
from html import escape
import json
import os
from pathlib import Path
import re
import sys

KNOWN_TYPES = {
    "offline_workflow_static": "github-actions-security-auditor",
    "offline_iam_snapshot": "cloud-iam-auditor",
    "synthetic_offline_matrix": "api-authorization-auditor",
}
RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,120}\Z")


def canonical(report: dict) -> dict:
    if not isinstance(report, dict) or report.get("schema_version") != "0.1":
        raise ValueError("Expected approved project summary schema 0.1")
    assessment = report.get("assessment_type")
    if assessment not in KNOWN_TYPES:
        raise ValueError("Unsupported report type")
    findings = report.get("findings", report.get("observations"))
    if not isinstance(findings, list) or len(findings) > 3000:
        raise ValueError("Expected a bounded findings/observations array")
    items = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Invalid report entry")
        rule = finding.get("rule_id") or finding.get("rule") or finding.get("category")
        if not isinstance(rule, str) or not RULE.fullmatch(rule):
            raise ValueError("Invalid report rule identifier")
        severity = finding.get("severity", "review")
        if severity not in {"critical", "high", "medium", "low", "review", "warning", "info"}:
            severity = "review"
        items.append({"rule_id": rule, "severity": severity, "status": "unverified"})
    return {
        "schema_version": "0.1",
        "generator": "AHMAD-IB security-report-engine",
        "origin_tool": KNOWN_TYPES[assessment],
        "assessment_type": assessment,
        "observation_count": len(items),
        "observations": items,
        "limitations": "Static or synthetic observations are not validated vulnerabilities.",
    }


def to_sarif(summary: dict) -> dict:
    ids = sorted({x["rule_id"] for x in summary["observations"]})
    rules = [{"id": rule, "shortDescription": {"text": rule}} for rule in ids]
    levels = {"critical": "error", "high": "error", "medium": "warning",
              "warning": "warning", "low": "note", "info": "note", "review": "note"}
    results = [{
        "ruleId": item["rule_id"],
        "level": levels.get(item["severity"], "note"),
        "message": {"text": "Offline observation; independently validate before disclosure."}
    } for item in summary["observations"]]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": summary["origin_tool"], "rules": rules
        }}, "results": results}],
    }


def to_html(summary: dict) -> str:
    lines = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
             "<title>AHMAD-IB security observations</title>",
             "<style>body{font:16px system-ui;max-width:860px;margin:3rem auto;line-height:1.55}"
             "th,td{border-bottom:1px solid #ddd;padding:.7rem;text-align:left}"
             "table{border-collapse:collapse;width:100%}</style></head><body>",
             "<h1>Security observations — unverified</h1>",
             "<p>Tool: " + escape(summary["origin_tool"]) + "</p>",
             "<table><thead><tr><th>Rule</th><th>Severity</th><th>Status</th></tr></thead><tbody>"]
    for item in summary["observations"]:
        lines.append("<tr>" + "".join(
            "<td>" + escape(str(item[k])) + "</td>" for k in ("rule_id", "severity", "status")
        ) + "</tr>")
    lines += ["</tbody></table><p>Offline evidence alone is not proof of exploitation.</p>",
              "</body></html>"]
    return "\n".join(lines) + "\n"


def read_source(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Expected a regular input JSON file <= 2 MiB")
    return canonical(json.loads(path.read_text(encoding="utf-8")))


def write_private(path: Path, data: str) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise ValueError("Refusing to overwrite report output or symlink")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(data)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("input", type=Path)
    p.add_argument("--format", choices=["json", "html", "sarif"], required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        summary = read_source(args.input)
        if args.format == "json":
            document = json.dumps(summary, indent=2) + "\n"
        elif args.format == "sarif":
            document = json.dumps(to_sarif(summary), indent=2) + "\n"
        else:
            document = to_html(summary)
        write_private(args.output, document)
        print("Wrote private, unverified " + args.format.upper() + " observations")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
