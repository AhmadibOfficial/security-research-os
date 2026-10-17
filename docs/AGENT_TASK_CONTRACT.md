# Agent task contract

Use this format for every bounded research-tool engineering issue:

- **Project ID / repository:** one of the twelve registered projects.
- **Scope:** `synthetic-offline` by default; separate written authorization is required for external assets.
- **Problem / security property:** exact failure mode, not a generic feature idea.
- **Threat model:** necessary privileges, reachable component, attacker-controlled input and expected consequence.
- **Reproduction:** synthetic fixture including affected and fixed examples, with no third-party APK.
- **Definition of done:** tests, deterministic outputs, privacy controls, false-positive regression and documentation.
- **Release gates:** GitHub CI green; change review; no binary or private history artifacts.
- **Prohibited operations:** active scanning, disclosure, publication of secrets, branch protection bypass and unauthorized cloud provisioning.

A score, an exported Android component, or a token-looking string alone is not a confirmed vulnerability.
