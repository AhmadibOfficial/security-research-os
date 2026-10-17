# AHMAD-IB Hall of Fame — Project 05: GitHub Actions Security Auditor

**Status:** private development, read-only, offline workflow analysis. This tool does not call GitHub APIs, run workflow scripts, or prove exploitation.

## Detection rules

| Rule | Check | Classification |
| --- | --- | --- |
| AST-GHA-001 | Remote action reference is not pinned to a full 40-character commit SHA | Review |
| AST-GHA-002 | Broad `permissions: write-all` token privilege | High-priority review |
| AST-GHA-003 | Explicit job/workflow token scope with `write` | Review |
| AST-GHA-004 | `pull_request_target` and checkout of pull-request-controlled code | High-priority review |
| AST-GHA-005 | Direct interpolation of known untrusted GitHub event fields in a `run:` script | High-priority review |

These are **potentially dangerous configurations, not confirmed vulnerabilities**. Some have valid uses or contextual mitigations. Conversely, absence of findings does not mean a workflow is secure.

GitHub advises against executing untrusted PR code in privileged `pull_request_target` workflows, advocates least-privilege tokens, and recommends pinning actions to commit SHAs. See https://docs.github.com/en/actions/reference/security/secure-use and https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target

## Run on Kali

```bash
cd projects/github-actions-security-auditor
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python auditor.py fixtures/insecure-synthetic.yml
python auditor.py fixtures/safer-synthetic.yml
```

PyYAML's `BaseLoader` is intentionally used to preserve YAML's `on:` key as text; duplicate mapping keys are rejected. This file reader neither evaluates expressions nor runs commands. No cloud account or billing method is needed for local analysis.

## Research quality and boundaries

- Synthetic examples only in Git. Treat third-party workflow files as sensitive where required.
- Flags show candidate review priorities and not successful attacks or CVEs.
- Rule coverage is intentionally limited; it cannot reason about conditional branches, code execution after checkout, inherited repository settings, reusable workflows, self-hosted runner exposure or custom action behavior.
- Output consists of rule IDs, positions and observations without printing the contents of shell commands, secrets or GitHub event fields.
- Proposed next gate: semantically validate `pull_request_target` checkout followed by execution, detect privilege escalation through `workflow_run` artifacts, and create vulnerable/fixed fixtures before moving to real authorized repositories.
- Keep this work private while GitHub Actions hosted CI is blocked by the account payment/spending restriction.
