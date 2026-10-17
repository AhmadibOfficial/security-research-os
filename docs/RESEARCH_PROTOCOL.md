# Research protocol: evidence before recognition

1. **Authorization**: record exact asset, owner/authorization basis and expiration locally. Never treat an in-scope-looking public URL as permission.
2. **Hypothesis**: state the security property, necessary attacker capability and expected impact, without claiming a vulnerability.
3. **Reproduce**: build a synthetic test or obtain authorized evidence, identify affected/versioned asset, fingerprint locally.
4. **Triage**: confirm technical behavior, false positives, permissions, user context and harm. Not every exported Android component is exploitable.
5. **Coordinate**: privately submit a minimal report through the vendor's designated channel. Do not share secrets or customer data.
6. **Repair and retest**: document remediation evidence and regression tests where permitted.
7. **Recognize**: record accepted CVE, Hall-of-Fame listing, maintainer acknowledgment or substantive OWASP contribution only with verifiable public proof. A mere submission remains an unverified claim.

Research OS records lifecycle state but **does not independently adjudicate truth**. Human review of actual authorization and impact is mandatory before external interaction or disclosure.
