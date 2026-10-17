"""Offline GitHub Actions workflow heuristics; no commands or workflows are run."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    import yaml
except ImportError as exc:
    raise SystemExit("HOLD: install PyYAML in an isolated environment (pip install -r requirements.txt)") from exc

MAX_BYTES = 512 * 1024
SHA = re.compile(r"^[0-9a-fA-F]{40}$")
ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
UNTRUSTED = (
    "github.event.pull_request.title", "github.event.pull_request.body",
    "github.event.issue.title", "github.event.issue.body",
    "github.event.comment.body", "github.event.issue_comment.body",
    "github.head_ref", "github.event.review.body",
)


class StrictLoader(yaml.BaseLoader):
    """Keep YAML 'on' as a string; reject duplicate keys instead of overwriting."""

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise ValueError("YAML mapping expected")
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("Non-string or duplicate YAML mapping key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _expressions(text: str) -> bool:
    for value in EXPRESSION.findall(text):
        compact = "".join(value.lower().split())
        if any(term in compact for term in UNTRUSTED):
            return True
    return False


def _events(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return set(value)
    if isinstance(value, dict):
        return set(value)
    raise ValueError("Unsupported GitHub Actions on: event declaration")


def _permissions(value: object, position: str, emit) -> None:
    if value is None:
        return
    if isinstance(value, str):
        if value == "write-all":
            emit("AST-GHA-002", "high", position, "Overly broad GITHUB_TOKEN permissions")
        elif value not in {"read-all", "{}"}:
            raise ValueError("Unsupported token permissions declaration")
        return
    if not isinstance(value, dict):
        raise ValueError("Permissions must be a mapping or write-all/read-all")
    for key, state in value.items():
        if not isinstance(key, str) or state not in {"read", "write", "none"}:
            raise ValueError("Unsupported permission name/value")
        if state == "write":
            emit("AST-GHA-003", "review", position, "Write-capable GITHUB_TOKEN scope needs review")


def audit(document: object) -> dict:
    if not isinstance(document, dict) or "on" not in document or "jobs" not in document:
        raise ValueError("Expected a GitHub Actions document with 'on' and 'jobs'")
    events = _events(document["on"])
    jobs = document["jobs"]
    if not isinstance(jobs, dict) or not jobs or len(jobs) > 120:
        raise ValueError("Workflow must declare 1–120 jobs")
    found = []
    dedupe = set()

    def emit(rule_id, severity, position, assessment):
        key = (rule_id, position)
        if key not in dedupe:
            dedupe.add(key)
            found.append({
                "rule_id": rule_id, "severity": severity, "position": position,
                "assessment": assessment, "status": "requires_manual_validation",
            })

    _permissions(document.get("permissions"), "workflow", emit)
    for job_name, job in jobs.items():
        if not isinstance(job_name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", job_name):
            raise ValueError("Invalid job name")
        if not isinstance(job, dict):
            raise ValueError("Job must be an object")
        job_position = "job:" + job_name
        _permissions(job.get("permissions"), job_position, emit)
        steps = job.get("steps", [])
        if not isinstance(steps, list) or len(steps) > 400:
            raise ValueError("Job steps must be a list of at most 400")
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ValueError("Workflow step must be a mapping")
            location = f"{job_position}:step:{i + 1}"
            action = step.get("uses")
            if action is not None:
                if not isinstance(action, str):
                    raise ValueError("Action use must be a string")
                if not action.startswith("./") and not action.startswith("docker://"):
                    name, sep, ref = action.rpartition("@")
                    if not sep or not ACTION.fullmatch(name) or not SHA.fullmatch(ref):
                        emit("AST-GHA-001", "review", location,
                             "Remote action is not pinned to an immutable full commit SHA")
                if "pull_request_target" in events and action.startswith("actions/checkout@"):
                    settings = step.get("with", {})
                    if not isinstance(settings, dict):
                        raise ValueError("Action inputs must be a mapping")
                    source = str(settings.get("ref", "")) + " " + str(settings.get("repository", ""))
                    compact = "".join(source.lower().split())
                    if "github.event.pull_request.head" in compact or "refs/pull/" in compact:
                        emit("AST-GHA-004", "high", location,
                             "Privileged pull_request_target may check out untrusted PR code; inspect execution paths")
            run = step.get("run")
            if run is not None:
                if not isinstance(run, str):
                    raise ValueError("Run step must be a string")
                if _expressions(run):
                    emit("AST-GHA-005", "high", location,
                         "Untrusted event expression interpolated directly into shell script")
    return {
        "schema_version": "0.1", "assessment_type": "offline_workflow_static",
        "finding_count": len(found), "findings": found,
        "limitations": [
            "These are offline patterns, not evidence of a successful attack.",
            "Permission risk depends on repository settings and execution trust boundaries.",
            "Review workflow_run, reusable workflows, environment protections and hidden execution paths manually.",
        ],
    }


def audit_file(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Expected an existing, non-symlink YAML workflow <= 512 KiB")
    raw = path.read_bytes()
    parsed = yaml.load(raw.decode("utf-8"), Loader=StrictLoader)
    results = audit(parsed)
    results["input_sha256"] = hashlib.sha256(raw).hexdigest()
    return results


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Read-only, offline GitHub Actions security audit")
    p.add_argument("workflow", type=Path)
    args = p.parse_args(argv)
    try:
        print(json.dumps(audit_file(args.workflow), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeDecodeError, yaml.YAMLError) as exc:
        print(f"HOLD: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
