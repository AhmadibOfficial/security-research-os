# Project 08 — WebView Security Analyzer

An offline Java/Kotlin source inventory of security-relevant WebView settings, bridges, and SSL-error handling. Positive and negative synthetic fixtures are provided. Rule matches are **code review candidates**, not established data flows or exploitable vulnerabilities.

Use `python3 analyzer.py fixtures/SyntheticUnsafeActivity.java` and `python3 -m unittest discover -s tests -v` in the later consolidated verification phase.

Next: build an AST/data-flow analyzer that resolves WebView origins, user-controlled URLs, JavaScript interface exposure, and API-level protections. Current string patterns intentionally have limited precision.

**Verification status:** Tests authored, not yet run.
