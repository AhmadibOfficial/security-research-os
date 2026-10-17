"""Offline analysis of Android deep-link exposure from local manifest XML."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"
MAX_BYTES = 512_000


def scan_manifest(path: Path) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Provide a regular local XML manifest <= 500 KiB")
    root = ET.fromstring(path.read_bytes())
    if root.tag != "manifest":
        raise ValueError("Expected Android manifest XML, not arbitrary XML")
    application = root.find("application")
    if application is None:
        raise ValueError("Missing Android application element")
    items = []
    for component in list(application):
        if component.tag not in {"activity", "activity-alias"}:
            continue
        component_name = component.get(ANDROID + "name", "")
        for f in component.findall("intent-filter"):
            actions = {x.get(ANDROID + "name") for x in f.findall("action")}
            categories = {x.get(ANDROID + "name") for x in f.findall("category")}
            if "android.intent.action.VIEW" not in actions or "android.intent.category.BROWSABLE" not in categories:
                continue
            schemes = sorted({x.get(ANDROID + "scheme") for x in f.findall("data")
                              if x.get(ANDROID + "scheme")})
            hosts = sorted({x.get(ANDROID + "host") for x in f.findall("data")
                            if x.get(ANDROID + "host")})
            exported = component.get(ANDROID + "exported")
            auto_verify = f.get(ANDROID + "autoVerify") == "true"
            flags = []
            if not hosts and any(x in {"http", "https"} for x in schemes):
                flags.append("broad_web_uri_matching_candidate")
            if "http" in schemes:
                flags.append("plaintext_link_scheme")
            if "https" in schemes and not auto_verify:
                flags.append("app_link_verification_not_requested")
            if exported == "false":
                flags.append("browsable_filter_on_explicitly_unexported_component")
            items.append({
                "component": component_name, "exported": exported,
                "schemes": schemes, "hosts": hosts,
                "auto_verify_requested": auto_verify,
                "observations": flags, "validation_status": "static_observation",
            })
    return {"schema_version": "0.1", "assessment_type": "offline_manifest_xml",
            "deeplink_count": len(items), "deeplinks": items,
            "limitations": [
                "Only a local decoded manifest is analyzed; effective merged manifests may differ.",
                "Android platform, version, intent data combinations, Digital Asset Links and runtime checks need manual validation.",
                "Broad matching is not itself a confirmed access-control vulnerability.",
            ]}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("manifest", type=Path)
    args = p.parse_args()
    try:
        print(json.dumps(scan_manifest(args.manifest), indent=2))
        return 0
    except (ValueError, OSError, ET.ParseError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
