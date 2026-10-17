# Project 03 — CodeQL research intake (HOF-002)

## Purpose

Keep static-analysis candidates organized without allowing pattern matches to become unverified vulnerability claims. This integration is a **local intake and triage interface** between CodeQL SARIF output and the AHMAD-IB Hall of Fame Research OS. Actual query packs, vulnerable/fixed fixtures, and CodeQL query execution belong in the future `codeql-security-research` repository.

## Input and safeguards

- Accept only local **SARIF 2.1.0** with a `CodeQL` tool declaration.
- Require a current locally recorded authorization scope before importing.
- At most 12 runs and 3,000 findings, maximum 16 MiB per input.
- Reject symlinks, malformed results and unsupported tool names/versions.
- Use SHA-256 for input and candidate identities, including the authorization scope in candidate identity.
- Store the ledger locally outside Git in `~/.local/share/ahmad-ib-research-os/` with private mode `0700` directory and atomically written `0600` files.
- Deduplicate identical reports and candidates.
- Never store raw SARIF messages, URLs, source snippets, or source paths. Even fingerprints and rule IDs should be treated as potentially sensitive metadata; do not commit the local ledger.
- Only source-only synthetic tests are used; no external testing or disclosures are performed.

## Manual lifecycle

`queued → reviewing → dismissed`, or `queued → reviewing → case_linked`.

Linking requires an existing evidence-backed research case associated with the exact same recorded authorization scope. This operation is **not vulnerability verification** or permission to contact a vendor.

## Commands

```bash
research-os codeql-import --scope-id SCOPE-... --sarif /path/to/owned-project.sarif
research-os codeql-queue
research-os codeql-triage --candidate-id CQL-... --status reviewing
research-os codeql-triage --candidate-id CQL-... --status case_linked --case-id CASE-...
```

## Acceptance checks

`PYTHONPATH=src python3 -m unittest discover -s tests -v` verifies parsing, privacy, de-duplication, scope isolation, malformed inputs, limits and state changes with synthetic data only. This does not prove CodeQL runtime execution or vulnerability impact.

**Public-release boundary:** The Research OS GitHub Actions account billing restriction remains unresolved. Local green tests do not authorize making the repository public.
