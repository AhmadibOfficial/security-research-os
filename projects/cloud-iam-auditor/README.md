# Project 10 — Cloud IAM Auditor

Offline, read-only initial analyzer for **synthetic AWS IAM policy and Azure custom-role JSON snapshots**. It does not connect to AWS, Azure or any customer tenant; it collects no credentials.

Flags wildcard allow-all AWS policies, wildcard role delegation and broad Azure roles as **manual review candidates**. Effective access depends on all applicable policies, assignment scopes, conditional constraints, boundaries and explicit denies, which this first stage does not model.

Use `python3 auditor.py fixtures/aws-overprivileged.json` and `python3 -m unittest discover -s tests -v` during consolidated verification.

**Verification status:** Tests authored, not run. Azure and AWS effective-permission analysis remains a later milestone.
