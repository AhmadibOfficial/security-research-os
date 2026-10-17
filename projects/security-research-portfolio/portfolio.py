"""Offline, approval-gated, disclosure-safe cybersecurity research portfolio."""
from __future__ import annotations
import argparse
from html import escape
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

MAX_BYTES = 1024 * 1024
SAFE_FIELD = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._/-]{0,120}\Z")
PUBLIC_PROGRAMS = {
    "github-security-lab", "google-bughunters", "msrc",
    "hackerone", "owasp-mobile",
}


def _public_https(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Expected a public HTTPS link")
    url = urlparse(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        raise ValueError("Recognition evidence must use HTTPS without embedded credentials")
    if url.hostname in {"localhost", "127.0.0.1"} or url.hostname.endswith(".local"):
        raise ValueError("Private/local URL is not eligible for the public portfolio")
    return value


def prepare(document: dict) -> dict:
    if not isinstance(document, dict) or set(document) != {"program", "records"}:
        raise ValueError("Invalid public portfolio document")
    if document["program"] != "AHMAD-IB Hall of Fame Automation Program":
        raise ValueError("Unrecognized portfolio program")
    records = document["records"]
    if not isinstance(records, list) or len(records) > 1000:
        raise ValueError("Expected at most 1000 portfolio records")
    accepted = []
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Invalid portfolio record")
        required = {"id", "program", "contribution", "public_url", "verification_status",
                    "publication_approved", "authorization_to_publish"}
        if set(record) != required:
            raise ValueError("Only allowlisted public fields accepted")
        rid = record["id"]
        if not isinstance(rid, str) or not SAFE_FIELD.fullmatch(rid) or rid in seen:
            raise ValueError("Invalid or duplicate public portfolio ID")
        seen.add(rid)
        if record["program"] not in PUBLIC_PROGRAMS:
            raise ValueError("Unrecognized external recognition program")
        if record["verification_status"] not in {"pending", "externally_verified"}:
            raise ValueError("Invalid verification state")
        if type(record["publication_approved"]) is not bool or type(record["authorization_to_publish"]) is not bool:
            raise ValueError("Publication flags must be explicit booleans")
        # The URL and status remain human-provided assertions; they cannot be
        # independently verified by this offline renderer.
        if record["verification_status"] != "externally_verified":
            continue
        if not (record["publication_approved"] and record["authorization_to_publish"]):
            continue
        contribution = record["contribution"]
        if not isinstance(contribution, str) or not SAFE_FIELD.fullmatch(contribution):
            raise ValueError("Only concise, public-safe contribution descriptions accepted")
        link = _public_https(record["public_url"])
        accepted.append({"id": rid, "program": record["program"],
                         "contribution": contribution, "public_url": link})
    return {"schema_version": "0.1", "publication_policy": "explicit_human_approval",
            "public_contribution_count": len(accepted), "contributions": accepted,
            "disclaimer": "Evidence and third-party eligibility must be checked independently before publication."}


def render_html(document: dict) -> str:
    items = ["<!doctype html>", "<html lang=\"en\"><head><meta charset=\"utf-8\">",
             "<title>AHMAD-IB — Research Contributions</title></head><body>",
             "<h1>Security research contributions</h1>",
             "<p>Published only after evidence review and disclosure permission.</p>"]
    for record in document["contributions"]:
        items.append("<article><h2>" + escape(record["contribution"]) +
                     "</h2><p>" + escape(record["program"]) +
                     "</p><a rel=\"noopener noreferrer\" href=\"" +
                     escape(record["public_url"], quote=True) + "\">Public evidence</a></article>")
    items.append("</body></html>")
    return "\n".join(items) + "\n"


def generate(source: Path, destination: Path) -> int:
    if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_BYTES:
        raise ValueError("Use a regular local JSON manifest <= 1 MiB")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Refusing to overwrite a portfolio output")
    report = prepare(json.loads(source.read_text(encoding="utf-8")))
    destination.parent.mkdir(parents=True, exist_ok=True)
    mode = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        mode |= os.O_NOFOLLOW
    fd = os.open(destination, mode, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(render_html(report))
    return report["public_contribution_count"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("source", type=Path)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    try:
        count = generate(args.source, args.out)
        print(f"Generated private HTML with {count} eligible, reviewed contribution records.")
        print("HOLD: This tool does not independently verify third-party acknowledgments.")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
