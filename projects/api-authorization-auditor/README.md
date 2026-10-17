# AHMAD-IB Hall of Fame — Project 04: API Authorization Auditor

**Status:** source-only, offline synthetic verification. No external requests.

The first engine compares explicitly documented *expected* authorization decisions against **reported observations** from a controlled test fixture. It does not issue HTTP requests, capture credentials, infer success from HTTP status codes, or automatically declare vulnerabilities.

## Threat models

- Broken object-level authorization (BOLA): users accessing other users' protected resources
- Broken function-level authorization (BFLA): roles invoking restricted operations
- Tenant isolation failures: resources crossing tenant boundaries

## Run locally

```bash
python3 -m unittest discover -s tests -v
python3 auditor.py fixtures/owned-lab-matrix.json
```

This built-in fixture records four synthetic situations: allowed self-access, denied cross-owner access, a simulated tenant authorization gap, and an inconclusive operation. The simulated gap is a **research candidate**, not an independently confirmed weakness.

## Input contract

The input must contain `scope: {mode: synthetic_offline, authorization_basis: owned_lab}` plus 1–2000 cases. Each case requires a synthetic ID, authorization dimension (`object`, `function`, `tenant`), operation (`read`, `write`, `execute`), short synthetic principal and owner labels, expected policy (`allow`/`deny`), recorded decision (`granted`/`blocked`/`unknown`), and an explicit Boolean `impact_verified`.

Unexpected fields, URLs and raw request bodies are rejected. No access tokens, personal data, headers, responses or private endpoints should be stored in this repository. Reports include only sanitized scenario IDs, categories and SHA-256 of source input (not the raw input). A true simulated impact produces `authorization_gap_candidate`, always with `requires_manual_validation`.

## Next gate

Expand into a **local Docker-only** API lab with matrix fixtures covering horizontal/vertical authorization, IDOR, multi-tenancy and state-changing business logic. Keep actual testing within owned or explicitly authorized scopes; no blind target probing. Bridge validated evidence to the private Research OS case ledger, then build a standalone repository.

GitHub Actions CI and any public release remain blocked by the Research OS account's verified billing restriction.
