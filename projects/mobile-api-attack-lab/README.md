# Project 06 — Mobile/API Attack Lab

An **intentionally vulnerable, synthetic training environment** for AHMAD-IB research.

Source-only development. The lab binds to `127.0.0.1` and contains no production data, third-party endpoints or external test targets. It demonstrates a vulnerable and a fixed route for object ownership checks and wallet-source authorization. The actor header is a **fake lab identity** and provides no real authentication.

Run `python3 -m unittest discover -s tests -v` to exercise both vulnerable and fixed behavior locally. To launch the lab deliberately: `python3 lab.py --port 8765`. Never expose the unsafe API beyond loopback, add real money, or deploy the vulnerable mode. Future Android client integration should be local-emulator-only and isolated.

**Verification status:** Tests authored but held for the program-wide verification phase.
