#!/usr/bin/env python3
"""Build a separate, source-only PRIVATE project-03 repository from staging.

Never publishes a public repo and never copies raw SARIF or old Git history.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEST = Path.home() / "codeql-security-research"
GITHUB_NAME = "AhmadibOfficial/codeql-security-research"
SOURCE_FILES = (
    "README.md", "LICENSE", "qlpack.yml", ".gitignore",
    ".github/workflows/ci.yml",
    "queries/UntrustedPathReview.ql",
    "fixtures/python/flask_path_cases.py",
    "scripts/run_lab.py", "scripts/promote_private.py",
    "tests/test_pack.py",
)
FORBIDDEN = (".apk", ".aab", ".apks", ".pfx", ".jks", ".pem", ".key",
             ".sarif", ".bqrs", ".sqlite", ".db")


def execute(argv: list[str], cwd: Path, **kwargs) -> subprocess.CompletedProcess:
    print("$", " ".join(argv), flush=True)
    return subprocess.run(argv, cwd=cwd, check=True, timeout=600, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-only", action="store_true",
                        help="Prepare and verify a clean repo without contacting GitHub")
    args = parser.parse_args()

    if DEST.exists() or DEST.is_symlink():
        print(f"HOLD: {DEST} already exists; refusing to overwrite.", file=sys.stderr)
        return 2
    if not args.local_only and shutil.which("gh") is None:
        print("HOLD: gh CLI is required for private GitHub publication.", file=sys.stderr)
        return 2

    try:
        execute([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], ROOT)
        execute([sys.executable, "scripts/run_lab.py", "--static-only"], ROOT)

        if not args.local_only:
            probe = subprocess.run(["gh", "repo", "view", GITHUB_NAME, "--json", "name"],
                                   text=True, capture_output=True, check=False, timeout=20)
            if probe.returncode == 0:
                print(f"HOLD: GitHub repository {GITHUB_NAME} exists. No duplicate created.",
                      file=sys.stderr)
                return 2

        DEST.mkdir(mode=0o700, parents=False, exist_ok=False)
        for relative in SOURCE_FILES:
            src = ROOT / relative
            if src.is_symlink() or not src.is_file() or any(relative.endswith(x) for x in FORBIDDEN):
                raise ValueError("Missing/unsafe source file: " + relative)
            target = DEST / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)

        lock = ROOT / "codeql-pack.lock.yml"
        if lock.is_file() and not lock.is_symlink():
            shutil.copy2(lock, DEST / lock.name)

        execute(["git", "init", "-b", "main"], DEST)
        execute(["git", "add", "--", *SOURCE_FILES], DEST)
        if (DEST / "codeql-pack.lock.yml").exists():
            execute(["git", "add", "--", "codeql-pack.lock.yml"], DEST)
        stage = execute(["git", "ls-files", "--cached"], DEST, capture_output=True, text=True)
        tracked = stage.stdout.splitlines()
        if set(tracked) - set(SOURCE_FILES) - {"codeql-pack.lock.yml"}:
            raise ValueError("Unexpected files staged")
        if any(path.endswith(FORBIDDEN) or "__pycache__" in path for path in tracked):
            raise ValueError("Unsafe staged file")
        execute(["git", "commit", "-m", "feat: initialize synthetic CodeQL security research pack"], DEST)
        if args.local_only:
            print("PASS: Clean standalone local repo created. No GitHub changes made.")
            return 0

        execute(["gh", "repo", "create", GITHUB_NAME, "--private", "--source", str(DEST),
                 "--remote", "origin", "--push",
                 "--description", "Synthetic CodeQL research and evidence quality lab"], DEST)
        print(f"PRIVATE SOURCE PUSH COMPLETE: https://github.com/{GITHUB_NAME}")
        print("HOLD: CodeQL runtime test and GitHub CI must both be demonstrated "
              "before any public-release consideration.")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print(f"HOLD: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
