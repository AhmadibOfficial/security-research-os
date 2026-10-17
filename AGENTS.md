# AHMAD-IB Hall of Fame program — instructions for coding agents

## Objective

Build a coordinated 12-project research ecosystem that produces **meaningful, verifiable fixes**, not inflated report counts. Follow `portfolio.json` and `docs/PROGRAM_ROADMAP.md` as the source of truth.

## Default execution authority

Routine, reversible source changes are authorized without repeated approval **only when** the coding agent has valid write access to the target repository and can verify the requested issue and CI results. Work on one narrowly scoped milestone per PR. Do not bypass branch protection or merge failing, unreviewed or unsafe changes.

## Required development sequence

1. Read the target project's current code, issues and known limitations.
2. Identify the highest-priority unblocked work in the public `portfolio.json` registry.
3. Create or use an issue specifying threat model, synthetic fixtures, expected observations and negative cases.
4. Implement on a feature branch, write synthetic tests, preserve stable schemas and report uncertainty.
5. Run compilation, static checks, tests, package build and privacy audit.
6. Open a PR with evidence, compatibility notes and limitations.
7. Merge only after verified CI and change inspection; if blocked, document the failure and stop.
8. Update roadmap status only with demonstrated results and links.

## Prohibited automated actions

- Scanning or interacting with external systems without explicit authorization and scope.
- Sending research findings to third parties, publishing private evidence or claiming a vulnerability is proven solely by static analysis.
- Crediting CVEs, bounty awards, Hall-of-Fame placements or vendor acknowledgments without externally verifiable proof.
- Moving actual customer APKs, credentials, access tokens, authentication cookies or private investigation data into public repos.
- Force pushes/history rewrites, paid provisioning, visibility changes, disabling security checks or suppressing test failures.

## Research quality gates

- Exact affected asset and conditions; reliable evidence with hashes.
- Distinguish configuration observations, hypotheses, validated technical issues, and confirmed impact.
- Check Android platform/version semantics and protection layers; control false positives.
- Validate against fixed-case negative tests, not only positive detection.
- Disclosure and public write-ups require authorization and affected-party coordination.

GitHub Actions schedules builds and milestone issues, **not arbitrary AI code generation**. An authorized coding agent must separately be connected to execute these instructions.
