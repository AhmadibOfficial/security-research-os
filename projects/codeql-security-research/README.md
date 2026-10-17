# AHMAD-IB Hall of Fame — Project 03: CodeQL Security Research

> Not every vulnerability matters. Fix the ones that do.

**Status: source-built baseline; actual CodeQL CLI execution NOT YET verified.**

This pack is a separate, private-by-default engineering component of the 12-project [AHMAD-IB Hall of Fame Automation Program](https://github.com/AhmadibOfficial/android-security-toolkit/issues/7). The immediate research purpose is to build an accurate and reproducible CodeQL query/testing workflow before analyzing any authorized real-world repository.

## First baseline query

`queries/UntrustedPathReview.ql` is a **derivative research baseline** that reuses the existing `codeql/python-all` `PathInjectionFlow` library (related to GitHub's built-in `py/path-injection` query). It does **not** constitute an original CodeQL discovery, custom sanitizer model, CVE, Hall-of-Fame entry, or confirmed vulnerability.

The deliberately synthetic `flask_path_cases.py` fixture has two untrusted `open()` path flows and two controls (constant path and allowlisted path). The Flask sample must not be deployed or executed as a network service.

## Install the official CodeQL CLI bundle on Kali

**Prerequisite:** Use CodeQL only where GitHub's licensing terms permit. The bundle is distributed subject to GitHub's [CodeQL terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md). In particular, routine proprietary-code CI is **not** covered by the research/open-source grant.

From this pack directory, after the normal source tests:

```bash
bash scripts/install_codeql_kali.sh
# The first run prints the terms and stops.
# Only after reviewing and accepting them:
bash scripts/install_codeql_kali.sh --accept-reviewed-terms
export PATH="$HOME/.local/opt/codeql-bundle/codeql:$PATH"
codeql version
codeql resolve packs
```

The installer needs `gh`, `tar` and `sha256sum`; it finds the latest official non-prerelease `codeql-bundle-v*` release, downloads a platform-specific Linux `.tar.gz` bundle, checks its published GitHub SHA-256, and extracts to `~/.local/opt/codeql-bundle`. It refuses to overwrite an existing installation, requires no `sudo`, does not change shell configuration, and does not upload any project data. Bundle download requires internet access and sufficient disk space.

For manual installation, follow the [official GitHub setup instructions](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli).

## First run on Kali

```bash
# Python 3.11+; no Python third-party packages are required for the offline checks.
python3 -m unittest discover -s tests -v
python3 scripts/run_lab.py --static-only
```

The preceding commands test the local gate code and fixture syntax, **not CodeQL**.

When the official CodeQL CLI is legitimately available on PATH, and its terms allow this use case, run:

```bash
codeql version
python3 scripts/run_lab.py \
  --sarif-out "$HOME/.cache/ahmadib-codeql-lab/path-fixtures.sarif"
```

That command installs query-pack dependencies, compiles the `.ql` file, creates an offline CodeQL database from the synthetic fixture, runs the query, reads actual SARIF, and **fails closed** unless both vulnerable locations are reported and neither fixed location is reported. It never launches Flask or connects to a target. SARIF stays in your local cache with owner-only file permissions.

Official guidance: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/test-custom-queries

## Connect to Project 02 Research OS

After obtaining a **genuine CodeQL-generated SARIF** result, record the synthetic owned-lab scope privately in Research OS, then import the SARIF candidate digest:

```bash
# Run these from your Research OS checkout, not from this directory.
PYTHONPATH=src python3 -m research_os scope-add \
  --name "Owned CodeQL lab" --asset "local synthetic fixture only" \
  --basis "Created and controlled synthetic test corpus" \
  --expires 2027-01-01

# Substitute the actual generated SCOPE identifier:
PYTHONPATH=src python3 -m research_os codeql-import \
  --scope-id SCOPE-REPLACE_WITH_REAL_ID \
  --sarif "$HOME/.cache/ahmadib-codeql-lab/path-fixtures.sarif"

PYTHONPATH=src python3 -m research_os codeql-queue
```

The Research OS private queue deduplicates and marks candidates `queued`; it does **not** promote them to validated findings.

## Private standalone publication

The source can be promoted into an isolated, **PRIVATE** `AhmadibOfficial/codeql-security-research` repository using `python3 scripts/promote_private.py` from this staged pack. That creates a clean Git history and never changes the repo to public. Do not promote it to public until an authorized release gate has demonstrated both the CodeQL runtime and repo hygiene.

## Safety and next research work

- Only analyze local synthetic fixtures or explicitly authorized source repositories.
- Treat alerts as hypotheses until triage, reproducibility and impact are established.
- No third-party APKs, source code, credentials or private SARIF evidence in Git.
- Investigate missed security-relevant data flows and unnecessary alerts with negative fixtures **before** proposing custom CodeQL models and upstream contributions.
- GitHub Actions account billing restrictions currently prevent hosted CI; local CodeQL verification is a separate gate, not permission to bypass the account restriction.
