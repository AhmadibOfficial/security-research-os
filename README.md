# AHMAD-IB Hall of Fame Automation Program — Research OS

> Not every vulnerability matters. Fix the ones that do.

An open-source, evidence-led foundation for **12 coordinated security research projects**. Its goal is substantive research, responsible fixes, qualified disclosures, and verified recognition—not report volume or fabricated CVE/Hall-of-Fame claims.

This repository is **project 02, `security-research-os`**. The published `android-security-toolkit` is project 01 and supplies the first technical research/evidence interface.

## Public project registry

The `portfolio.json` file lists all 12 projects, their priorities, dependencies, current development state, next gates, and five recognition programs. Changing a project state is a code-reviewed, tested registry update; no milestone or award is represented as completed without proof.

## Quick start (Python 3.11+)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
research-os verify
research-os status
research-os next
research-os scorecard
```

There is **no login, paid service, or external API** required for offline project coordination.

## Scope and private research ledger

The default research ledger lives outside Git, under `~/.local/share/ahmad-ib-research-os/`. The tool hashes optional evidence locally and stores only SHA-256 fingerprints, not the file bytes.

```bash
research-os scope-add --name 'My test lab' --asset 'localhost synthetic API' \
  --basis 'I own and operate this laboratory' --expires 2027-01-01
research-os case-add --project security-research-os --scope-id SCOPE-REPLACE_WITH_REAL_ID \
  --title 'Synthetic authorization hypothesis'
```

Scope declaration records a *claim*, not independent proof of authorization. `case-status` enforces the research lifecycle and evidence prerequisites; `recognition-add` records claims as **unverified** until independently validated. Public scorecards reveal counts only, not case titles, evidence, private scopes or identities.

## Automation — and its honest boundary

GitHub Actions verifies both Python versions and creates **one deduplicated public-safe build milestone issue weekly**. It never automatically scans external targets, uploads private evidence, writes speculative vulnerability reports, or credits awards. Actual AI-driven engineering requires an authorized connected coding agent: GitHub Actions alone does not autonomously generate secure research code.

Development agents can take the next issue, implement changes on a feature branch, add synthetic tests and open PRs. Low-risk verified changes may be merged using established CI gates; sensitive disclosure decisions remain human-reviewed.

## Recognition targets

GitHub Security Lab CodeQL Wall of Fame; Google Bug Hunters; Microsoft Security Response Center; HackerOne; OWASP Mobile Application Security. These are **targets, not achievements**.

## Research safety

Only analyze owned or explicitly authorized assets. Confirm a finding's exploitability and meaningful impact before disclosure. Follow target-specific vulnerability disclosure rules. Do not push real third-party APKs, keys, private case files or unreviewed evidence.

See `docs/PROGRAM_ROADMAP.md`, `docs/RESEARCH_PROTOCOL.md` and `.github/workflows/`.

## Connect Project 01 → Project 02

Import an **existing local** `android-security-toolkit` JSON evidence report only after recording the relevant authorized scope:

```bash
research-os scan-import --scope-id SCOPE-REPLACE_WITH_REAL_ID \
  --report "$HOME/.cache/ahmad-sec/reports/evidence-EXAMPLE.json"
```

This stores only a SHA-256 digest, observation count, and scope reference in private local storage. It **does not** upload or duplicate raw evidence and never promotes warnings to validated vulnerabilities. The actual Android finding review remains a separate, authorized research task.
