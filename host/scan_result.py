import json
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanResult:
    device_id: str
    scan_id: str
    completed: bool
    clean: bool
    findings: int
    schema_version: int = 1


_REQUIRED_FIELDS = {
    "schema_version",
    "device_id",
    "scan_id",
    "completed",
    "clean",
    "findings",
}


def parse_scan_result(payload):
    """Parse a JSON string or dictionary; return None for invalid input."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            return None

    if not isinstance(payload, dict):
        return None

    if set(payload) != _REQUIRED_FIELDS:
        return None

    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        return None
    if not isinstance(payload["device_id"], str) or not payload["device_id"].strip():
        return None
    if not isinstance(payload["scan_id"], str) or not payload["scan_id"].strip():
        return None
    if type(payload["completed"]) is not bool:
        return None
    if type(payload["clean"]) is not bool:
        return None
    if type(payload["findings"]) is not int or payload["findings"] < 0:
        return None

    return ScanResult(
        device_id=payload["device_id"],
        scan_id=payload["scan_id"],
        completed=payload["completed"],
        clean=payload["clean"],
        findings=payload["findings"],
        schema_version=payload["schema_version"],
    )


def validate_scan_result(result, expected_device_id):
    """Accept only a parsed result bound to this device and a clean scan."""
    if isinstance(result, (str, dict)):
        result = parse_scan_result(result)

    if not isinstance(result, ScanResult):
        return False
    if result.schema_version != 1:
        return False
    if not isinstance(expected_device_id, str) or not expected_device_id:
        return False
    if result.device_id != expected_device_id:
        return False
    if not result.scan_id:
        return False
    if result.completed is not True or result.clean is not True:
        return False
    if type(result.findings) is not int or result.findings != 0:
        return False

    return True
