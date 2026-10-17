"""Research coordination without network requests or sensitive evidence upload."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4


PROGRAM_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIVATE = Path.home() / ".local" / "share" / "ahmad-ib-research-os"
PROJECT_STATES = {"planned", "building", "foundation_live", "complete"}
CASE_STATUSES = ("hypothesis", "reproduced", "triaged", "disclosed", "resolved", "acknowledged", "rejected")
TRANSITIONS = {
    "hypothesis": {"reproduced", "rejected"},
    "reproduced": {"triaged", "rejected"},
    "triaged": {"disclosed", "rejected"},
    "disclosed": {"resolved", "acknowledged", "rejected"},
    "resolved": {"acknowledged"},
    "acknowledged": set(),
    "rejected": set(),
}


def registry(path: Path | None = None) -> dict:
    return json.loads((path or PROGRAM_ROOT / "portfolio.json").read_text(encoding="utf-8"))


def validate_registry(document: dict) -> None:
    projects = document.get("projects")
    if not isinstance(projects, list) or len(projects) != 12:
        raise ValueError("Program must define exactly 12 projects")
    ids, repos = set(), set()
    for project in projects:
        for key in ("id", "repo", "priority", "state", "goal", "depends_on", "next_gate"):
            if key not in project:
                raise ValueError(f"Missing {key} in project definition")
        if project["id"] in ids or project["repo"] in repos:
            raise ValueError("Duplicate project ID or repository")
        if project["state"] not in PROJECT_STATES:
            raise ValueError("Unknown project state")
        if not re.fullmatch(r"[a-z][a-z0-9-]+", project["repo"]):
            raise ValueError("Invalid repository slug")
        if project["priority"] not in {"high", "medium"}:
            raise ValueError("Unexpected priority")
        ids.add(project["id"])
        repos.add(project["repo"])
    for project in projects:
        if not isinstance(project["depends_on"], list):
            raise ValueError("Dependencies must be a list")
        if project["id"] in project["depends_on"] or not set(project["depends_on"]).issubset(ids):
            raise ValueError("Invalid project dependency")
    if len({p["id"] for p in document.get("recognition_targets", [])}) != len(document.get("recognition_targets", [])):
        raise ValueError("Duplicate recognition target ID")


def next_project(doc: dict) -> dict:
    """Choose an active build, then an actionable priority, deterministically."""
    projects = doc["projects"]
    active = [p for p in projects if p["state"] == "building"]
    if active:
        return sorted(active, key=lambda p: p["id"])[0]
    ready = [p for p in projects if p["state"] == "planned" and all(
        next(d["state"] for d in projects if d["id"] == dep) in {"foundation_live", "complete"}
        for dep in p["depends_on"]
    )]
    if not ready:
        raise ValueError("No actionable project; update dependencies or states")
    return sorted(ready, key=lambda p: (p["priority"] != "high", p["id"]))[0]


def _store_dir(directory: Path | None = None) -> Path:
    root = directory or DEFAULT_PRIVATE
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink():
        raise ValueError("Private storage directory may not be a symlink")
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _read_private(name: str, directory: Path | None = None) -> list:
    location = _store_dir(directory) / name
    if location.is_symlink():
        raise ValueError("Private store must not be a symlink")
    if not location.exists():
        return []
    data = json.loads(location.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Private data must contain a list")
    return data


def _write_private(name: str, entries: list, directory: Path | None = None) -> None:
    root = _store_dir(directory)
    destination = root / name
    if destination.is_symlink():
        raise ValueError("Private store must not be a symlink")
    temp = root / ("." + name + "." + uuid4().hex + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(entries, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, destination)
    finally:
        if temp.exists():
            temp.unlink()


def add_scope(name: str, asset: str, authorization_basis: str, expires: str, directory: Path | None = None) -> dict:
    """Log a claimed authorization boundary. This is not independent proof of consent."""
    expiration = date.fromisoformat(expires)
    if expiration < date.today():
        raise ValueError("Authorization expiration is in the past")
    if not all((name.strip(), asset.strip(), authorization_basis.strip())):
        raise ValueError("Scope name, asset and basis must be nonempty")
    scopes = _read_private("scopes.json", directory)
    entry = {
        "id": "SCOPE-" + uuid4().hex[:12], "name": name.strip(),
        "asset": asset.strip(), "authorization_basis": authorization_basis.strip(),
        "expires": expiration.isoformat(), "recorded_at": date.today().isoformat(),
    }
    scopes.append(entry)
    _write_private("scopes.json", scopes, directory)
    return entry


def fingerprint_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Evidence must be an existing regular file")
    if path.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("Evidence file exceeds the 100 MB local hashing limit")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def add_case(project: str, scope_id: str, title: str, evidence_path: Path | None = None,
             directory: Path | None = None, portfolio: dict | None = None) -> dict:
    portfolio = portfolio or registry()
    if project not in {p["repo"] for p in portfolio["projects"]}:
        raise ValueError("Project is not registered")
    scopes = _read_private("scopes.json", directory)
    scope = next((s for s in scopes if s["id"] == scope_id), None)
    if scope is None or date.fromisoformat(scope["expires"]) < date.today():
        raise ValueError("A current recorded authorization scope is required")
    if not title.strip() or len(title) > 160:
        raise ValueError("Title must contain 1–160 characters")
    cases = _read_private("cases.json", directory)
    record = {
        "id": "CASE-" + uuid4().hex[:12], "project": project, "scope_id": scope_id,
        "title": title.strip(), "status": "hypothesis", "created_at": date.today().isoformat(),
        "evidence_sha256": fingerprint_file(evidence_path) if evidence_path else None,
        "disclosure_reference": None,
    }
    cases.append(record)
    _write_private("cases.json", cases, directory)
    return record


def update_case(case_id: str, status: str, evidence_path: Path | None = None,
                disclosure_reference: str | None = None, directory: Path | None = None) -> dict:
    cases = _read_private("cases.json", directory)
    current = next((c for c in cases if c["id"] == case_id), None)
    if current is None:
        raise ValueError("Research case not found")
    if status not in TRANSITIONS[current["status"]]:
        raise ValueError("Invalid or unverified research state transition")
    scope = next((s for s in _read_private("scopes.json", directory) if s["id"] == current["scope_id"]), None)
    if scope is None or date.fromisoformat(scope["expires"]) < date.today():
        raise ValueError("Scope expired or missing; cannot advance research case")
    if evidence_path is not None:
        current["evidence_sha256"] = fingerprint_file(evidence_path)
    if status in {"reproduced", "triaged", "disclosed", "resolved", "acknowledged"} and not current["evidence_sha256"]:
        raise ValueError("Evidence SHA-256 required before advancing a research case")
    if status == "disclosed" and not disclosure_reference:
        raise ValueError("Private disclosure tracking reference is required")
    if disclosure_reference:
        current["disclosure_reference"] = disclosure_reference.strip()
    current["status"] = status
    _write_private("cases.json", cases, directory)
    return current


def add_recognition(case_id: str, program: str, public_url: str, directory: Path | None = None,
                    portfolio: dict | None = None) -> dict:
    portfolio = portfolio or registry()
    if program not in {x["id"] for x in portfolio["recognition_targets"]}:
        raise ValueError("Recognition program unknown")
    case = next((c for c in _read_private("cases.json", directory) if c["id"] == case_id), None)
    if case is None or case["status"] != "acknowledged":
        raise ValueError("Recognition claims require an acknowledged case")
    url = urlparse(public_url)
    if url.scheme != "https" or not url.hostname:
        raise ValueError("Recognition evidence must have a public HTTPS URL")
    claims = _read_private("recognition.json", directory)
    item = {"id": "REC-" + uuid4().hex[:12], "case_id": case_id,
            "program": program, "public_url": public_url,
            "verification_status": "unverified", "recorded_at": date.today().isoformat()}
    claims.append(item)
    _write_private("recognition.json", claims, directory)
    return item


def scorecard(doc: dict, directory: Path | None = None) -> dict:
    """Public-safe counts only; no titles, findings or authorization data."""
    cases = _read_private("cases.json", directory)
    recognitions = _read_private("recognition.json", directory)
    states = {key: sum(p["state"] == key for p in doc["projects"]) for key in sorted(PROJECT_STATES)}
    return {
        "program": doc["program"], "project_count": len(doc["projects"]),
        "project_states": states, "research_case_count": len(cases),
        "acknowledged_case_count": sum(c["status"] == "acknowledged" for c in cases),
        "verified_recognition_count": sum(x["verification_status"] == "verified" for x in recognitions),
        "unverified_recognition_claim_count": sum(x["verification_status"] != "verified" for x in recognitions),
    }


def ingest_android_report(report_path: Path, scope_id: str, directory: Path | None = None) -> dict:
    """Import a project-01 evidence summary locally, never the raw findings.

    This does not validate a vulnerability or grant permission to scan a target.
    """
    digest = fingerprint_file(report_path)
    data = json.loads(report_path.read_text(encoding="utf-8"))
    if data.get("schema_version") != "1.0" or data.get("assessment_type") != "offline_static":
        raise ValueError("Not a recognized Android Security Toolkit evidence report")
    summary = data.get("summary", {})
    count = summary.get("total_observations")
    if not isinstance(count, int) or count < 0 or not isinstance(data.get("findings"), list):
        raise ValueError("Malformed Android Security Toolkit evidence report")
    if count != len(data["findings"]):
        raise ValueError("Evidence report observation count is inconsistent")
    scopes = _read_private("scopes.json", directory)
    scope = next((s for s in scopes if s["id"] == scope_id), None)
    if scope is None or date.fromisoformat(scope["expires"]) < date.today():
        raise ValueError("A current recorded authorization scope is required")
    entries = _read_private("scans.json", directory)
    found = next((x for x in entries if x["sha256"] == digest and x["scope_id"] == scope_id), None)
    if found:
        return found
    entry = {
        "id": "SCAN-" + uuid4().hex[:12],
        "scope_id": scope_id,
        "source_project": "android-security-toolkit",
        "sha256": digest,
        "observation_count": count,
        "status": "requires_manual_validation",
        "recorded_at": date.today().isoformat(),
    }
    entries.append(entry)
    _write_private("scans.json", entries, directory)
    return entry
