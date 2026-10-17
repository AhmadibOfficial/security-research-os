"""SYNTHETIC CodeQL lab fixture. Never deploy this demonstration service.

VULNERABLE functions demonstrate a source-to-filesystem-sink path.
FIXED controls are intentionally separate so missing findings can be assessed.
"""
from pathlib import Path
from flask import Flask, abort, request

app = Flask(__name__)
ROOT = Path("/synthetic/fixtures")  # no real files are required


@app.get("/unsafe")
def vulnerable_file_read():
    filename = request.args.get("name")
    with open(filename, "rb") as handle:  # EXPECT_ALERT: source to open()
        return handle.read()


@app.get("/unsafe-copy")
def vulnerable_file_copy():
    filename = request.args.get("name")
    output = ROOT / filename
    with open(output, "rb") as handle:  # EXPECT_ALERT: base-path concat alone is not safety
        return handle.read()


@app.get("/constant")
def fixed_constant_file():
    with open(ROOT / "documentation.txt", "rb") as handle:  # EXPECT_NO_ALERT
        return handle.read()


@app.get("/allowlist")
def fixed_allowlist_file():
    untrusted = request.args.get("name", "")
    allowlist = {"guide": "guide.txt", "help": "help.txt"}
    if untrusted not in allowlist:
        abort(404)
    with open(ROOT / allowlist[untrusted], "rb") as handle:  # EXPECT_NO_ALERT
        return handle.read()
