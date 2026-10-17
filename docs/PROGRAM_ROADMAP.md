# Program roadmap — 12 repositories

## Phase 1: Foundation and research operations (days 1–30)

**Project 01 `android-security-toolkit`:** baseline released, CI and structured evidence shipped. Ongoing accuracy and authorized-fixture validation remains essential.

**Project 02 `security-research-os`:** shared backlog, scope registry, controlled evidence ledger, lifecycle gates, non-sensitive scorecard, public recognition registry.

Exit: working test suite, public repository, CI, local-only sensitive data and one reproducible synthetic end-to-end case.

## Phase 2: Genuine discovery capability (days 31–60)

**Project 03 `codeql-security-research`:** testable CodeQL query packs and vulnerable/fixed source-code fixtures.

**Project 06 `mobile-api-attack-lab`:** local-only safe Android/API demo applications with authorization faults and fixed variants.

**Project 04 `api-authorization-auditor`:** authorization matrix tested against lab identities, privileges and resource ownership.

**Project 05 `github-actions-security-auditor`:** CI trust-boundary rules, synthetic workflow fixtures and clear risk descriptions.

Exit: at least one meaningful proof-of-detection and fixed-version negative test per major rule; no active testing outside approved scope.

## Phase 3: Depth, reuse, and recognition (days 61–90 and beyond)

**Project 07 `android-deeplink-analyzer`:** deep-link inventory and unsafe-input triage.

**Project 08 `webview-security-analyzer`:** JavaScript bridge and WebView trust-boundary inventory.

**Project 09 `ai-agent-security-lab`:** isolated AI agent authority and input-trust experiments.

**Project 10 `cloud-iam-auditor`:** offline AWS/Azure identity policy review.

**Project 11 `security-report-engine`:** interoperable JSON, SARIF and human-readable reports.

**Project 12 `security-research-portfolio`:** independently verified, disclosure-approved contributions and acknowledgments.

Exit: accepted remediations or qualifying research contributions *where earned*, truthful verification records and responsible public write-ups when permitted.

## Common engineering gates

- Source provenance and license compatibility
- Concrete threat model with non-speculative impact
- Synthetic regression tests and explicit false-positive controls
- Offline build, CI and privacy audit
- Authorization and target-scope evidence for live research
- Responsible private disclosure and permission to publish
- Credit only after verifiable external acknowledgment

## HOF-003 — CodeQL query engineering (development staging, 17 October 2026)

- **Built in draft source:** `projects/codeql-security-research/` contains an isolated Python CodeQL query pack, synthetic vulnerable and fixed Flask filesystem-path examples, offline fixture/acceptance tests, and a script to split the pack into its own *private* repository.
- **Source baseline:** `UntrustedPathReview.ql` reuses GitHub CodeQL's established Python path-injection taint-tracking library. This is a baseline and is not a new query discovery, proven vulnerability or recognition claim.
- **Next evidence gate:** a legitimately installed CodeQL CLI must compile the query and produce genuine SARIF for the deliberately vulnerable/fixed corpus; scripts refuse to claim CodeQL success based on Python fixture tests.
- **Project 02 intake:** import the actual synthetic CodeQL SARIF into the locally scoped `codeql-import` queue to establish candidate provenance and de-duplication, not exploit confirmation.
- **Publication:** standalone repository remains PRIVATE; GitHub Actions is currently blocked by account billing restrictions. Do not bypass the hosted CI/approval policy by making it public.
