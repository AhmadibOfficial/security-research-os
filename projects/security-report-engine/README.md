# Project 11 — Security Report Engine

Convert allowlisted, source-only security **observations** into sanitized JSON, HTML, and SARIF 2.1.0. Each report remains explicitly unverified; user-controlled raw messages and source snippets are not reproduced.

Use `python3 report_engine.py fixtures/workflow-observations.json --format sarif --output "$HOME/.cache/ahmadib-report.sarif"` during later consolidated testing. The export refuses existing files, uses mode 0600 and does not automatically upload to GitHub Code Scanning or publish a report.

Current adapters support **Projects 04, 05 and 10** summary schemas. Project 01 Android Toolkit SARIF adapter, Project 07/08/09 adapters, source locations and validated severity models remain future work. The resulting SARIF structure requires formal schema and Code Scanning compatibility verification.

**Verification status:** Code and tests authored, execution deferred.
