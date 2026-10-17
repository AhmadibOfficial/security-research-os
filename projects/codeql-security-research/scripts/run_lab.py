#!/usr/bin/env python3
"""Offline synthetic CodeQL gate: compile query, analyze fixtures and check results.

Does not scan the internet, install or execute Flask, or publish SARIF.
CodeQL dependencies may be downloaded during 'codeql pack install'.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
QUERY = ROOT / "queries" / "UntrustedPathReview.ql"
SOURCE = ROOT / "fixtures" / "python" / "flask_path_cases.py"
CONFIG = ROOT / "qlpack.yml"


def markers() -> tuple[set[int], set[int]]:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    positives = {i for i, text in enumerate(lines, 1) if "# EXPECT_ALERT" in text}
    negatives = {i for i, text in enumerate(lines, 1) if "# EXPECT_NO_ALERT" in text}
    return positives, negatives


def check_source() -> None:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
    positives, negatives = markers()
    opens = {
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "open"
    }
    if len(positives) < 2 or len(negatives) < 2:
        raise ValueError("Both positive and negative security fixtures are required")
    if not positives.issubset(opens) or not negatives.issubset(opens):
        raise ValueError("Each expected result marker must be beside a real open() sink")
    content = QUERY.read_text(encoding="utf-8")
    required = ("@kind path-problem", "PathInjectionFlow::flowPath",
                "import semmle.python.security.dataflow.PathInjectionQuery",
                "@id ahmadib/untrusted-python-file-path")
    if not all(value in content for value in required):
        raise ValueError("CodeQL query is missing required baseline declarations")
    if "codeql/python-all" not in CONFIG.read_text(encoding="utf-8"):
        raise ValueError("CodeQL pack dependency is missing")
    print(f"PASS: Python fixture syntax, {len(positives)} positives and "
          f"{len(negatives)} negative controls; query metadata checks")
    print("NOTE: This is not a CodeQL execution result.")


def execute(args: list[str], cwd: Path) -> None:
    display = " ".join(str(x) for x in args)
    print(f"$ {display}", flush=True)
    subprocess.run(args, cwd=cwd, check=True, timeout=900)


def result_locations(document: dict) -> set[int]:
    rows = set()
    for run in document.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                physical = location.get("physicalLocation", {})
                region = physical.get("region", {})
                line = region.get("startLine")
                if isinstance(line, int):
                    rows.add(line)
    return rows


def audit_sarif(document: dict) -> None:
    if document.get("version") != "2.1.0":
        raise ValueError("Expected SARIF 2.1.0")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("CodeQL output contains no runs")
    if not any(r.get("tool", {}).get("driver", {}).get("name") == "CodeQL" for r in runs):
        raise ValueError("Analysis was not produced by CodeQL")
    # The query's sink.getNode() is expected to locate open() path arguments.
    locations = result_locations(document)
    wanted, safe = markers()
    missing = wanted - locations
    false_positives = safe & locations
    if missing or false_positives:
        raise ValueError(
            f"CodeQL acceptance failed: missing positive lines={sorted(missing)}, "
            f"alerts on negative lines={sorted(false_positives)}, "
            f"observed lines={sorted(locations)}"
        )
    print(f"PASS: CodeQL executed and detected {len(wanted)} synthetic positive "
          f"locations without flagging {len(safe)} fixed controls.")


def _save_private(source: Path, target: Path) -> None:
    target = target.expanduser().resolve(strict=False)
    if target.is_relative_to(ROOT):
        raise ValueError("SARIF evidence must remain OUTSIDE the source repository")
    if target.exists() or target.is_symlink():
        raise FileExistsError("Refusing to overwrite a SARIF file")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        mode |= os.O_NOFOLLOW
    fd = os.open(target, mode, 0o600)
    with os.fdopen(fd, "wb") as output, source.open("rb") as report:
        shutil.copyfileobj(report, output)
    print(f"Private synthetic SARIF saved: {target}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Synthetic CodeQL research gate")
    ap.add_argument("--static-only", action="store_true",
                    help="Check Python source/fixtures without claiming CodeQL ran")
    ap.add_argument("--sarif-out", type=Path,
                    help="Keep raw synthetic CodeQL SARIF outside the Git repository")
    ns = ap.parse_args()
    try:
        check_source()
        if ns.static_only:
            return 0
        binary = shutil.which("codeql")
        if not binary:
            print("HOLD: CodeQL CLI is not on PATH; query compilation and "
                  "detection have NOT been validated.", file=sys.stderr)
            return 3
        execute([binary, "version"], ROOT)
        execute([binary, "pack", "install"], ROOT)
        execute([binary, "query", "compile", str(QUERY)], ROOT)
        with tempfile.TemporaryDirectory(prefix="ahmadib-codeql-") as temp:
            scratch = Path(temp)
            database = scratch / "db"
            sarif = scratch / "results.sarif"
            execute([binary, "database", "create", str(database),
                     "--language=python", f"--source-root={SOURCE.parent}"], ROOT)
            execute([binary, "database", "analyze", str(database), str(QUERY),
                     "--format=sarif-latest", f"--output={sarif}", "--rerun"], ROOT)
            report = json.loads(sarif.read_text(encoding="utf-8"))
            audit_sarif(report)
            if ns.sarif_out:
                _save_private(sarif, ns.sarif_out)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"HOLD: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
