#!/usr/bin/env python3
"""Offline consolidated verification for all 12 AHMAD-IB Hall of Fame tools.

Reads immutable, locally fetched Git branch tips into temporary workspaces.
Never merges, pushes, exploits targets, deploys, publishes, or relaxes CI gates.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile

# Each source revision is explicitly pinned: silently updated branches are blocked.
SOURCES = {
    2: ("research-os", "feature/hof-003-codeql-query-pack", "5f0301d104751d87c020a02a56bd0b948b7e2b41"),
    3: ("codeql-security-research", "feature/hof-003-codeql-query-pack", "5f0301d104751d87c020a02a56bd0b948b7e2b41"),
    4: ("api-authorization-auditor", "feature/hof-004-offline-api-authorization-auditor", "88409b610d2edc6ea0c731f2fe1bbc447351a8d1"),
    5: ("github-actions-security-auditor", "feature/hof-005-offline-actions-security-auditor", "80743c54d698ff03d4d5efadbf4c6ae041b4afac"),
    6: ("mobile-api-attack-lab", "feature/hof-06-mobile-api-attack-lab", "93145f1cb81cec143b1fe65dcd94f76878da909a"),
    7: ("android-deeplink-analyzer", "feature/hof-07-android-deeplink-analyzer", "fb8f08358d67d0fc1944a615362335d9b42a6b51"),
    8: ("webview-security-analyzer", "feature/hof-08-webview-security-analyzer", "6b9c426f80acc681d03596ab660e9dc357b59add"),
    9: ("ai-agent-security-lab", "feature/hof-09-ai-agent-security-lab", "886e135fd61280508da0a35973bacad059c3fe02"),
    10: ("cloud-iam-auditor", "feature/hof-10-cloud-iam-auditor", "3360a7231db894816b7dfde3605db793402b78d5"),
    11: ("security-report-engine", "feature/hof-11-security-report-engine", "e755b559797adc73eac246543636eea3191aa7e0"),
    12: ("security-research-portfolio", "feature/hof-12-security-research-portfolio", "16f0cb8a7918b1f214c02138ff4720ab9a4ff812"),
}


def execute(args: list[str], cwd: Path, *, timeout=120, env=None) -> dict:
    try:
        r = subprocess.run(args, cwd=cwd, env=env, timeout=timeout,
                           text=True, capture_output=True, check=False)
        return {"status": "passed" if r.returncode == 0 else "failed",
                "exit_code": r.returncode, "stdout": r.stdout[-600:],
                "stderr": r.stderr[-600:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "blocked", "reason": str(exc)[:250]}


def require_executed_tests(check: dict) -> dict:
    """Do not count a successful no-tests-discovered unittest as a pass."""
    if check.get("status") != "passed":
        return check
    stream = check.get("stdout", "") + "\n" + check.get("stderr", "")
    matches = re.findall(r"Ran (\d+) tests? in", stream)
    if not matches or int(matches[-1]) < 1:
        return {**check, "status": "failed",
                "reason": "Test discovery returned success without executing tests"}
    return {**check, "executed_tests": int(matches[-1])}


def from_ref(repo: Path, ref: str, expected: str, source: str, destination: Path):
    check = execute(["git", "rev-parse", "--verify", ref + "^{commit}"], repo)
    if check["status"] != "passed" or check["stdout"].strip() != expected:
        raise ValueError("Pinned source missing or changed: " + ref)
    raw = subprocess.run(["git", "archive", "--format=tar", ref, source], cwd=repo,
                         check=True, capture_output=True, timeout=60).stdout
    allowed = PurePosixPath(source)
    parents = {str(p) for p in allowed.parents if str(p) != "."}
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        members = archive.getmembers()
        if not members or len(members) > 450:
            raise ValueError("Source archive empty or unexpectedly large")
        for member in members:
            path = PurePosixPath(member.name)
            in_scope = (member.name.rstrip("/") == str(allowed) or
                        member.name.startswith(str(allowed) + "/") or
                        (member.isdir() and member.name.rstrip("/") in parents))
            if (path.is_absolute() or ".." in path.parts or not in_scope or
                    not (member.isdir() or member.isfile()) or member.size > 3_000_000):
                raise ValueError("Unsafe or unexpected Git archive member")
            out = destination.joinpath(*path.parts)
            if not out.resolve(strict=False).is_relative_to(destination.resolve()):
                raise ValueError("Path traversal blocked")
        for member in members:
            out = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                out.mkdir(parents=True, exist_ok=True)
            else:
                out.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source_stream, out.open("xb") as target:
                    if source_stream is None:
                        raise ValueError("Missing archived source")
                    target.write(source_stream.read())


def main() -> int:
    parser = argparse.ArgumentParser(description="12-project consolidated synthetic verification")
    parser.add_argument("--research-os", type=Path, default=Path.home() / "security-research-os")
    parser.add_argument("--android-root", type=Path, default=Path.home() / "android-security-toolkit-public")
    parser.add_argument("--fetch", action="store_true",
                        help="Fetch latest Git refs; changed heads remain blocked until pin update")
    parser.add_argument("--codeql-runtime", action="store_true",
                        help="Execute the actual licensed CodeQL engine; may download query packs")
    parser.add_argument("--out", type=Path, help="Private JSON status record, outside source repository")
    args = parser.parse_args()
    repo = args.research_os.expanduser().resolve()
    if not (repo / ".git").exists():
        parser.error("Expected local Research OS Git clone")
    if args.fetch:
        fetched = execute(["git", "fetch", "--no-tags", "origin"], repo)
        if fetched["status"] != "passed":
            print("HOLD: cannot fetch source branches", fetched, file=sys.stderr)
            return 2
    with tempfile.TemporaryDirectory(prefix="ahmadib-hof-") as workspace:
        work = Path(workspace)
        os.chmod(work, 0o700)
        results = []
        dirs = {}
        android = args.android_root.expanduser().resolve()
        if not (android / ".git").exists():
            # Current historical Kali checkouts commonly use this directory.
            alternate = Path.home() / "android-security-toolkit"
            if (alternate / ".git").exists():
                android = alternate.resolve()
        if (android / ".git").exists():
            first = execute([sys.executable, "-m", "pytest", "-q"], android, timeout=180)
        else:
            first = {"status": "blocked", "reason": "Android Security Toolkit checkout missing"}
        results.append({"id": 1, "project": "android-security-toolkit", "checks": [first]})
        for number, (name, branch, sha) in SOURCES.items():
            target = work / str(number)
            target.mkdir()
            ref = "origin/" + branch
            checks = []
            try:
                requested = ("src", "tests", "portfolio.json") if number == 2 else ("projects/" + name,)
                for source in requested:
                    from_ref(repo, ref, sha, source, target)
                cwd = target if number == 2 else target / "projects" / name
                dirs[number] = cwd
                env = dict(os.environ, PYTHONPATH=str(cwd / "src")) if number == 2 else None
                # Project 05 needs a locally installed YAML parser. Record a
                # missing optional dependency as BLOCKED, not an application
                # test failure, and never auto-purchase or install packages.
                optional = (execute([sys.executable, "-c", "import yaml"], cwd)
                            if number == 5 else {"status": "passed"})
                if optional["status"] != "passed":
                    checks.append({"status": "blocked",
                                   "reason": "Missing local PyYAML; source tests not executed"})
                else:
                    checks.append(require_executed_tests(execute(
                        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                        cwd, env=env, timeout=180)))
                if number == 2:
                    checks.append(execute([sys.executable, "-m", "research_os", "verify"],
                                          cwd, env=env))
                if number == 3:
                    checks.append(execute([sys.executable, "scripts/run_lab.py", "--static-only"], cwd))
                    if args.codeql_runtime:
                        checks.append(execute([sys.executable, "scripts/run_lab.py"],
                                              cwd, timeout=900))
                    else:
                        checks.append({"status": "blocked",
                                       "reason": "CodeQL runtime not demonstrated; requires licensed CLI"})
            except (ValueError, OSError, subprocess.CalledProcessError,
                    subprocess.TimeoutExpired, tarfile.TarError) as exc:
                checks.append({"status": "blocked", "reason": str(exc)[:300]})
            results.append({"id": number, "project": name, "source_ref": ref,
                            "expected_sha": sha, "checks": checks})
        integrations = []
        # Contract-only cross-project fixtures; no live app, CodeQL scan or exploit.
        if 2 in dirs:
            osroot = dirs[2]
            private = work / "research-private"
            env = dict(os.environ, PYTHONPATH=str(osroot / "src"))
            def os_cli(*args):
                return execute([sys.executable, "-m", "research_os", "--data-dir",
                                str(private), *args], osroot, env=env)
            registered = os_cli("scope-add", "--name", "Synthetic contract lab",
                                "--asset", "owned synthetic examples",
                                "--basis", "Self-created source fixtures",
                                "--expires", "2099-12-31")
            if registered["status"] == "passed":
                import re
                found = re.search(r"SCOPE-[0-9a-f]+", registered["stdout"])
                if found is None:
                    integrations.append({"name": "01/03->02 scope setup", "status": "failed"})
                else:
                    scope_id = found.group(0)
                    ast = work / "synthetic-android.json"
                    ast.write_text(json.dumps({
                        "schema_version": "1.0", "assessment_type": "offline_static",
                        "summary": {"total_observations": 1},
                        "findings": [{"id": "SYNTHETIC-ONLY"}]
                    }))
                    os.chmod(ast, 0o600)
                    integrations.append({"name": "01->02 synthetic JSON contract",
                                         **os_cli("scan-import", "--scope-id", scope_id,
                                                  "--report", str(ast))})
                    sarif = work / "synthetic-codeql.sarif"
                    sarif.write_text(json.dumps({
                        "version": "2.1.0", "runs": [{
                            "tool": {"driver": {"name": "CodeQL"}},
                            "results": [{
                                "ruleId": "synthetic/local-example",
                                "message": {"text": "PRIVATE_SYNTHETIC_MARKER"},
                                "locations": [{
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "synthetic.py"},
                                        "region": {"startLine": 3}
                                    }
                                }]
                            }]
                        }]
                    }))
                    os.chmod(sarif, 0o600)
                    integrations.append({"name": "03->02 synthetic SARIF contract",
                                         **os_cli("codeql-import", "--scope-id", scope_id,
                                                  "--sarif", str(sarif))})
                    queue = os_cli("codeql-queue")
                    if "PRIVATE_SYNTHETIC_MARKER" in queue.get("stdout", ""):
                        queue["status"] = "failed"
                        queue["reason"] = "Sensitive SARIF marker escaped private ledger"
                    integrations.append({"name": "02 private CodeQL queue", **queue})
            else:
                integrations.append({"name": "01/03->02 scope setup", **registered})
        if 11 in dirs:
            report_engine = dirs[11] / "report_engine.py"
            for number, fixture, entry in ((4, "fixtures/owned-lab-matrix.json", "auditor.py"),
                                    (5, "fixtures/insecure-synthetic.yml", "auditor.py"),
                                    (7, "fixtures/synthetic-manifest.xml", "analyzer.py"),
                                    (8, "fixtures/SyntheticUnsafeActivity.java", "analyzer.py"),
                                    (9, "fixtures/trust-boundaries.json", "policy_lab.py"),
                                    (10, "fixtures/aws-overprivileged.json", "auditor.py")):
                if number not in dirs:
                    integrations.append({"name": str(number) + "->11", "status": "blocked"})
                    continue
                source = dirs[number]
                try:
                    raw = subprocess.run([sys.executable, entry, fixture], cwd=source,
                                         capture_output=True, text=True, timeout=90)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    integrations.append({"name": str(number) + "->11", "status": "blocked",
                                         "reason": type(exc).__name__})
                    continue
                if raw.returncode:
                    integrations.append({"name": str(number) + "->11", "status": "failed",
                                         "reason": raw.stderr[-300:]})
                    continue
                try:
                    # Do not parse execute()'s deliberately truncated log output;
                    # the original full JSON stream is required for schema checks.
                    document = json.loads(raw.stdout)
                    source_file = work / ("input-" + str(number) + ".json")
                    source_file.write_text(json.dumps(document))
                    os.chmod(source_file, 0o600)
                    dest = work / ("output-" + str(number) + ".json")
                    converted = execute([sys.executable, str(report_engine), str(source_file),
                                         "--format", "json", "--output", str(dest)], work)
                    if converted["status"] == "passed":
                        converted_doc = json.loads(dest.read_text())
                        if converted_doc.get("observation_count") is None or dest.stat().st_mode & 0o077:
                            converted["status"] = "failed"
                            converted["reason"] = "Invalid or nonprivate adapter output"
                    integrations.append({"name": str(number) + "->11", **converted})
                except (ValueError, OSError, json.JSONDecodeError) as exc:
                    integrations.append({"name": str(number) + "->11",
                                         "status": "failed", "reason": str(exc)[:300]})
        if 12 in dirs:
            portfolio_output = work / "portfolio.html"
            check = execute([sys.executable, "portfolio.py",
                             "fixtures/synthetic-unverified.json", "--out", str(portfolio_output)],
                            dirs[12])
            if check["status"] == "passed" and "NOT-AN-AWARD" in portfolio_output.read_text():
                check["status"] = "failed"
                check["reason"] = "An unverified award escaped publication filter"
            integrations.append({"name": "12-unverified-claim-exclusion", **check})
        # HOF-018: actual synthetic HTTP evidence must flow through Project 06,
        # Project 04, the Research OS private ledger and Project 11. Source
        # packages come from pinned branch heads, never an unstaged local build.
        if all(project in dirs for project in (4, 6, 11)):
            demo_out = work / "hof018-reviewed.json"
            end_to_end = execute([
                sys.executable, str(Path(__file__).with_name("hof018_run.py")),
                "--lab-file", str(dirs[6] / "lab.py"),
                "--auditor-file", str(dirs[4] / "auditor.py"),
                "--report-file", str(dirs[11] / "report_engine.py"),
                "--private-dir", str(work / "hof018-ledger"),
                "--out", str(demo_out),
            ], repo, timeout=90)
            if end_to_end["status"] == "passed":
                try:
                    proof = json.loads(demo_out.read_text(encoding="utf-8"))
                    if (proof.get("quality_gate") != "synthetic_passed"
                            or proof.get("metrics", {}).get("synthetic_true_positives") != 1
                            or proof.get("metrics", {}).get("synthetic_false_positives") != 0
                            or proof.get("metrics", {}).get("synthetic_false_negatives") != 0
                            or proof.get("report", {}).get("observation_count") != 1
                            or proof.get("case_status") != "reproduced"):
                        end_to_end["status"] = "failed"
                        end_to_end["reason"] = "Insufficient end-to-end research evidence"
                except (ValueError, OSError, json.JSONDecodeError) as exc:
                    end_to_end["status"] = "failed"
                    end_to_end["reason"] = "Missing verified synthetic output: " + str(exc)[:200]
            integrations.append({"name": "HOF-018: 06->04->02->11 same-route remediation",
                                 **end_to_end})
        else:
            integrations.append({"name": "HOF-018: 06->04->02->11 same-route remediation",
                                 "status": "blocked", "reason": "Required source package missing"})
        statuses = []
        for item in results:
            values = [check["status"] for check in item["checks"]]
            item["status"] = "failed" if "failed" in values else "blocked" if "blocked" in values else "passed"
            statuses.append(item["status"])
        summary = {word: statuses.count(word) for word in ("passed", "failed", "blocked")}
        integration_statuses = [step["status"] for step in integrations]
        if "failed" in integration_statuses:
            summary["integration_failure_count"] = integration_statuses.count("failed")
        report = {"program": "AHMAD-IB Hall of Fame Automation Program", "projects": results,
                  "integrations": integrations, "summary": summary, "release": "HOLD",
                  "notes": ["GitHub-hosted CI remains billing-blocked.",
                            "Synthetic results do not validate external vulnerabilities.",
                            "No sources merged; no repository visibility changed."]}
    if args.out:
        dest = args.out.expanduser().resolve(strict=False)
        if dest.is_relative_to(repo):
            parser.error("Private test report output must remain outside repository")
        dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
            file.write("\n")
    print(json.dumps({"summary": summary,
                      "integrations": [{"name": x["name"], "status": x["status"]}
                                       for x in integrations], "release": "HOLD"}, indent=2))
    return (1 if summary["failed"] or summary.get("integration_failure_count", 0)
            else 2 if summary["blocked"] or any(item["status"] == "blocked" for item in integrations)
            else 0)


if __name__ == "__main__":
    raise SystemExit(main())
