#!/usr/bin/env python3
"""Guest scan protocol with a real ClamAV adapter."""
import json
import sys

try:
    from .clamav_scanner import make_clamav_scanner
except ImportError:
    from clamav_scanner import make_clamav_scanner


def run_scan(request, scanner):
    """Return a versioned result; scanner errors always fail closed."""
    device_id = request.get("device_id") if isinstance(request, dict) else None
    scan_id = request.get("scan_id") if isinstance(request, dict) else None

    result = {
        "schema_version": 1,
        "device_id": device_id if isinstance(device_id, str) else "",
        "scan_id": scan_id if isinstance(scan_id, str) else "",
        "completed": False,
        "clean": False,
        "findings": 0,
    }

    if not result["device_id"].strip() or not result["scan_id"].strip():
        return result

    try:
        outcome = scanner(request)
        if not isinstance(outcome, dict):
            return result

        findings = outcome.get("findings")
        clean = outcome.get("clean")
        if type(findings) is not int or findings < 0 or type(clean) is not bool:
            return result

        result["findings"] = findings
        result["completed"] = True
        result["clean"] = clean and findings == 0
        return result
    except Exception:
        return result


def main():
    try:
        request = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        print(json.dumps({"error": "Invalid JSON request"}), file=sys.stderr)
        return 2

    if not isinstance(request, dict):
        print(json.dumps({"error": "Request must be a JSON object"}), file=sys.stderr)
        return 2

    if not isinstance(request.get("device_id"), str) or not request["device_id"].strip():
        print(json.dumps({"error": "Missing device_id"}), file=sys.stderr)
        return 2
    if not isinstance(request.get("scan_id"), str) or not request["scan_id"].strip():
        print(json.dumps({"error": "Missing scan_id"}), file=sys.stderr)
        return 2

    scanner = make_clamav_scanner()
    result = run_scan(request, scanner)
    print(json.dumps(result, sort_keys=True))

    if not result["completed"]:
        return 2
    if not result["clean"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
