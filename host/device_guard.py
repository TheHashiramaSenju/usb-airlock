import json
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceCheck:
    allowed: bool
    device: str
    reason: str


PROTECTED_DISKS = {"/dev/sda", "/dev/nvme0n1"}


def check_usb_disk(device):
    if not isinstance(device, str) or not device.startswith("/dev/"):
        return DeviceCheck(False, str(device), "Invalid device path")

    if device in PROTECTED_DISKS:
        return DeviceCheck(False, device, "Protected disk")

    try:
        result = subprocess.run(
            ["lsblk", "--json", "--paths",
             "--output", "NAME,TYPE,TRAN,MOUNTPOINTS", device],
            check=True, capture_output=True, text=True, timeout=5,
        )
        data = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return DeviceCheck(False, device, f"Inspection failed: {exc}")

    devices = data.get("blockdevices", [])
    if len(devices) != 1:
        return DeviceCheck(False, device, "Device not uniquely identified")

    root = devices[0]
    if root.get("name") != device:
        return DeviceCheck(False, device, "Device path mismatch")
    if root.get("type") != "disk":
        return DeviceCheck(False, device, "Whole disk required")
    if root.get("tran") != "usb":
        return DeviceCheck(False, device, "USB transport not confirmed")

    def walk(node):
        yield node
        for child in node.get("children") or []:
            yield from walk(child)

    for node in walk(root):
        if any(node.get("mountpoints") or []):
            return DeviceCheck(False, device, "A filesystem is mounted")

    return DeviceCheck(
        True, device, "Preflight passed; quarantine has not been applied"
    )
