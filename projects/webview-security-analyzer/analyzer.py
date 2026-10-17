"""Conservative, source-only Java/Kotlin WebView configuration review.

No project build, code execution, bytecode analysis, or network operations.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

RULES = [
    ("WV-001", "javascript_interface", re.compile(r"\.\s*addJavascriptInterface\s*\("),
     "JavaScript bridge registered; evaluate trust boundaries and Android version"),
    ("WV-002", "javascript_enabled", re.compile(r"\.\s*(?:setJavaScriptEnabled)\s*\(\s*true\s*\)|\.javaScriptEnabled\s*=\s*true"),
     "JavaScript enabled; not inherently unsafe"),
    ("WV-003", "allow_file_access", re.compile(r"\.\s*setAllowFileAccess\s*\(\s*true\s*\)|\.allowFileAccess\s*=\s*true"),
     "File access explicitly allowed; inspect URL and origin handling"),
    ("WV-004", "insecure_ssl_bypass", re.compile(r"\.\s*proceed\s*\(\s*\)"),
     "SSL error proceed() candidate; verify receiver and call path"),
    ("WV-005", "mixed_content_always_allow", re.compile(r"(?:MIXED_CONTENT_ALWAYS_ALLOW|setMixedContentMode\s*\(\s*0\s*\))"),
     "Potential always-allow mixed content setting"),
]
SUFFIXES = {".java", ".kt"}


def audit_source(path: Path) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.suffix not in SUFFIXES:
        raise ValueError("Expected a local regular .java/.kt source file")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Source file exceeds 1 MiB")
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    findings = []
    for code, category, pattern, assessment in RULES:
        for match in pattern.finditer(text):
            lineno = text.count("\n", 0, match.start()) + 1
            findings.append({"rule_id": code, "category": category, "line": lineno,
                             "assessment": assessment, "status": "requires_code_review"})
    findings.sort(key=lambda x: (x["line"], x["rule_id"]))
    return {"assessment_type": "offline_source_heuristics", "schema_version": "0.1",
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "finding_count": len(findings), "findings": findings,
            "limitations": [
                "Regex review cannot establish dataflow, origin verification, or exploitability.",
                "Results can include comments/strings and miss aliases, wrappers or reflection.",
                "A bridge or JavaScript flag alone is not a security vulnerability.",
            ]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("source", type=Path)
    args = p.parse_args()
    try:
        print(json.dumps(audit_source(args.source), indent=2))
        return 0
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
