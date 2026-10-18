# HOF-018 — Unified security research-to-remediation engine

**Program:** AHMAD-IB Hall of Fame Automation Program  
**Principle:** Not every vulnerability matters. Fix the ones that do.  
**Status:** Source implementation staged; runtime verification and public release HOLD.

## Demonstration design

1. Project 06 serves only 127.0.0.1 with synthetic Alice and Bob records.
2. Observe Bob reading Alice's record on the deliberately unsafe /unsafe/records/100 route; the 200 response must contain an exact owned-lab synthetic record marker and Alice ownership. HTTP 200 alone is insufficient.
3. Negative controls: cross-owner access on the fixed route must be denied; own-object access must succeed; anonymous access must be blocked.
4. Enable the **lab-only, per-server remediation flag** and request the SAME unsafe path as Bob; access must now be 403.
5. Project 04 derives five authorization cases from these actual observations instead of accepting an externally supplied impact_verified boolean.
6. Project 02 creates an owned, synthetic scope and evidence-backed research case; case status remains reproduced, not disclosed or externally confirmed.
7. Project 11 generates **one unverified candidate**. Correctly authorized/denied behavior is excluded from vulnerability findings.
8. Require metrics: one synthetic true positive, four true negatives, zero false positives and zero false negatives in THIS fixture only. This does not estimate real-world accuracy.
9. Never generate third-party vulnerability disclosures, CVE claims, bounty claims, awards or hall-of-fame credits from the synthetic result.

## One-command consolidated verification (Kali)

Run from the existing Research OS Git checkout:

```bash
cd ~/security-research-os
git fetch origin
git switch -c review/hof-018 origin/feature/hof-018-end-to-end-research-engine
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/verify_hof_portfolio.py --fetch \
  --out "$HOME/.cache/ahmad-sec/hof-018-portfolio-review.json"
```

Use a **new filename** for subsequent results. Output files are exclusive and owner-only. The consolidated verifier checks source pins and runs the five HTTP probes through local pinned project modules; it does not send probes outside loopback.

## Evidence and privacy

- The lab uses fake actor headers, not real authentication. Never expose the unsafe server on real networks or use third-party records.
- Private file evidence/<sha256>.json stores **only synthetic status observations and test metrics** under the private Research OS data directory. Its digest is saved in the local case ledger.
- Status reproduced means proven only in this owned lab. It is not a verified finding against an external asset.
- The remediation is an explicit simulation switch for the same owned endpoint. It is not a production patch.
- The report engine strips raw response data, excludes correct/denied controls from alerts, and marks the sole candidate unverified.
- CodeQL runtime validation remains separate and pending. GitHub-hosted CI is independently blocked by account billing restrictions.
- The user approved source development and a unified verification phase; no automatic public release or external disclosure is authorized.

## Release gate

The **exact GitHub branch source** needs to pass the end-to-end localhost probes, module regression suites, contract checks, privacy verification and consolidated project checks. Investigate and correct failures before promotion. Keep all pending PRs DRAFT and the repository PRIVATE. The full release decision remains HOLD.
