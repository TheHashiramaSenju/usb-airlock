from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import os
import stat
import subprocess

from host.linux_quarantine import inspect_block_device


class QuarantineStatus(Enum):
    QUARANTINED = "quarantined"
    FAILED = "failed"


@dataclass(frozen=True)
class QuarantineResult:
    device_id: str
    status: QuarantineStatus
    reason: str


class QuarantineController:
    def quarantine(self, device_id: str, device_node: str) -> QuarantineResult:
        raise NotImplementedError

    def is_quarantined(self, device_id: str) -> bool:
        raise NotImplementedError


class TestQuarantineController(QuarantineController):
    """Policy simulation only; applies no operating-system protection."""

    def __init__(self):
        self._quarantined = set()

    def quarantine(self, device_id: str, device_node: str = "") -> QuarantineResult:
        if not isinstance(device_id, str) or not device_id.strip():
            return QuarantineResult(
                str(device_id), QuarantineStatus.FAILED, "Invalid device identifier"
            )
        self._quarantined.add(device_id)
        return QuarantineResult(
            device_id, QuarantineStatus.QUARANTINED,
            "TEST ONLY: no operating-system protection applied",
        )

    def is_quarantined(self, device_id: str) -> bool:
        return device_id in self._quarantined


class LinuxQuarantineController(QuarantineController):
    """Read-only verification; does not claim or apply full host isolation."""

    def __init__(self, rules_path="config/99-usb-airlock.rules"):
        self.rules_path = Path(rules_path)

    def quarantine(self, device_id: str, device_node: str) -> QuarantineResult:
        def failed(reason):
            return QuarantineResult(device_id, QuarantineStatus.FAILED, reason)

        if not isinstance(device_id, str) or not device_id.strip():
            return failed("Invalid device identifier")

        inspection = inspect_block_device(device_node)
        if not inspection.safe_to_consider:
            return failed(inspection.reason)

        if not self.rules_path.is_file():
            return failed("Candidate udev rule is missing")

        try:
            result = subprocess.run(
                ["udevadm", "info", "--query=property", "--name", device_node],
                capture_output=True, text=True, timeout=5, check=True,
            )
            properties = dict(
                line.split("=", 1)
                for line in result.stdout.splitlines()
                if "=" in line
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return failed(f"Cannot verify active udev properties: {exc}")

        if properties.get("UDISKS_IGNORE") != "1":
            return failed("Active udev rule is not confirmed for this device")

        try:
            info = os.stat(device_node)
        except OSError as exc:
            return failed(f"Cannot inspect device-node permissions: {exc}")

        if not stat.S_ISBLK(info.st_mode):
            return failed("Target is not a block-device node")

        if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0:
            return failed("Device-node permissions do not match quarantine policy")

        return failed(
            "Basic permissions verified, but full host isolation is not proven; "
            "refusing to report QUARANTINED"
        )

    def is_quarantined(self, device_id: str) -> bool:
        return False
