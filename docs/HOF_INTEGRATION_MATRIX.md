# AHMAD-IB Hall of Fame — Cross-project integration contract

> Not every vulnerability matters. Fix the ones that do.

## Status

**Source-only integration, private, no release authorization.** All twelve tools have initial source implementations; this does **not** mean that all tools have passed their suites or that original vulnerabilities have been found. Full hosted CI is currently prevented from launching by the GitHub account billing/spending restriction.

A single consolidated offline verifier is staged in `scripts/verify_hof_portfolio.py`. It uses the existing Git branches as source; it does **not** merge or publish them. It refuses to silently accept revised branch heads by checking a full 40-character source SHA per tool.

## Source-of-truth interface map

| Producer | Consumer | Accepted payload | Required boundary |
| --- | --- | --- | --- |
| 01 Android Security Toolkit | 02 Research OS | Structured offline APK JSON, SHA-256 and observation count | Recorded authorized scope, no raw APKs in Git, observations unverified |
| 03 CodeQL Security Research | 02 Research OS | Genuine CodeQL SARIF 2.1.0; synthetic contract test uses mock SARIF | Real QL execution must be separately established; hash-only private intake |
| 04 API Authorization Auditor | 11 Security Report Engine | Offline `synthetic_offline_matrix` observations | Scenarios and policy mismatch are not live exploit proof |
| 05 GitHub Actions Security Auditor | 11 Security Report Engine | Offline `offline_workflow_static` findings | No workflow execution or third-party attack |
| 10 Cloud IAM Auditor | 11 Security Report Engine | Offline `offline_iam_snapshot` observations | Not a calculation of effective IAM access |
| 06 Mobile/API Lab | 04 API Authorization Auditor | Expected vs observed own-lab authorization behavior | Bind 127.0.0.1, synthetic actors, no real money or customers |
| 07 Android Deep-Link Analyzer | 11 Security Report Engine | Redacted `offline_manifest_xml` flags → `DL-*` rule IDs | Drop activity/host details, static observations only |
| 08 WebView Security Analyzer | 11 Security Report Engine | Redacted `offline_source_heuristics` rule IDs | Drop source snippets and locations, regex matches unverified |
| 09 AI Agent Security Lab | 11 Security Report Engine | Redacted `synthetic_agent_permissions` denial reasons | Simulated permissions do not grant actual tool permissions |
| 02 Research OS | 12 Security Research Portfolio | Only independently verified and publication-authorized acknowledgments | No private cases, unresolved disclosures, fabricated awards |
| 11 Report Engine | GitHub Code Scanning | SARIF validation required before any upload | No automatic Code Scanning upload or external disclosure |

## Single Kali verification gate

Use the existing clone after verifying it contains the integration runner:

```bash
cd ~/security-research-os
git fetch origin
git switch -c review/hof-integration origin/feature/hof-consolidated-integration
python3 scripts/verify_hof_portfolio.py --fetch \
  --out "$HOME/.cache/ahmad-sec/hof-consolidated-review.json"
```

The runner checks project 01's local Android toolkit and projects 02–12 from their individually **pinned** Git branches. Each project is archived to a private temporary directory, never checked out over the user's worktree. Only regular files are extracted; symlinks, traversal and unplanned ref changes fail closed.

The runner starts the Project 06 synthetic HTTP lab **only on loopback** as part of its tests. It does not run CodeQL CLI unless `--codeql-runtime` is explicitly supplied in an eligible licensed environment.

It records test failures rather than papering over them. A nonzero exit is expected while CodeQL and hosted CI remain unresolved. An output file is private, owner-only, and refuses an existing destination.

## Consolidated exit criteria

1. Compile and regression-test each project's positive and negative synthetic examples, not only its happy path.
2. Execute all documented cross-project schemas with private fake fixtures; inspect redaction and non-overwrite behavior.
3. Validate the real CodeQL query with the official licensed CodeQL CLI and actual positive/negative source cases.
4. Check Android targets only with explicit authorization, and never treat an exported component or manifest setting as a verified weakness without code/behavior evidence.
5. Validate generated SARIF against the standard and a compatible local parser before any Code Scanning upload.
6. Remove or correct false positives and protect legitimate workflow/SDK configurations with negative regression cases.
7. Make the source-only repository split into eleven independent repositories through staged, reviewable history only after quality gates pass.
8. Resolve the GitHub Actions billing gate, repeat hosted CI on precise reviewed commits, and inspect branch protection and source hygiene.
9. Permit responsible disclosure and research publication only with independent authorization and external recognition evidence.
10. Record a separate release decision for each component; **no bulk unreviewed public release**.

**Current release decision: HOLD.** This integration branch does not change `main`, repository visibility, billing, targets, or issue disclosure policies.
