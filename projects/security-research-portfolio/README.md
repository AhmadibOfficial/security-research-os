# Project 12 — Security Research Portfolio

Build a publication-safe portfolio from **explicitly reviewed, externally acknowledged contributions**. The default sample has only a pending claim and therefore renders **zero recognized contributions**.

Publishability requires external acknowledgment status, explicit publication approval, valid public HTTPS evidence, and disclosure permission. These fields are **human assertions**, not independently verified by this offline tool; a reviewer must check the actual third-party evidence before any page goes live. The renderer cannot make a vulnerability, CVE or Hall-of-Fame placement appear legitimate merely because a field says `externally_verified`.

Use `python3 portfolio.py fixtures/synthetic-unverified.json --out "$HOME/.cache/ahmadib-portfolio-review.html"` during consolidated verification. It creates a private, owner-only file and never deploys a website.

**Verification status:** Tests authored, not run. Public publishing and external award claims remain explicitly controlled.
