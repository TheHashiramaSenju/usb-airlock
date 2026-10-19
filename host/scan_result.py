from dataclasses import dataclass


@dataclass(frozen=True)
class ScanResult:
    device_id: str
    scan_id: str
    completed: bool
    clean: bool
    findings: int


def validate_scan_result(result, expected_device_id):
    if not isinstance(result, ScanResult):
        return False

    if not result.device_id or result.device_id != expected_device_id:
        return False

    if not result.scan_id:
        return False

    if result.completed is not True:
        return False

    if result.clean is not True:
        return False

    if type(result.findings) is not int or result.findings != 0:
        return False

    return True
