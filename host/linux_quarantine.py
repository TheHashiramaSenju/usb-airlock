import json
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceInspection:
    device: str
    safe_to_consider: bool
    reason: str


def inspect_block_device(device_node):
    """Read-only preflight; does not enforce quarantine."""
    if not isinstance(device_node, str) or not device_node.startswith("/dev/"):
        return DeviceInspection(str(device_node), False, "Invalid device path")

    try:
        result = subprocess.run(
            [
                "lsblk", "--json", "--paths",
                "--output", "NAME,TYPE,TRAN,MOUNTPOINTS,PKNAME",
                device_node,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        data = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return DeviceInspection(
            device_node, False, f"Device inspection failed: {exc}"
        )

    devices = data.get("blockdevices", [])
    if len(devices) != 1:
        return DeviceInspection(
            device_node, False, "Device not uniquely identified"
        )

    root = devices[0]
    if root.get("type") != "disk":
        return DeviceInspection(
            device_node, False, "Target must be a whole disk, not a partition"
        )

    if root.get("tran") != "usb":
        return DeviceInspection(
            device_node, False, "Target is not identified as USB storage"
        )

    def walk(node):
        yield node
        for child in node.get("children") or []:
            yield from walk(child)

    for node in walk(root):
        for mountpoint in node.get("mountpoints") or []:
            if mountpoint:
                return DeviceInspection(
                    device_node,
                    False,
                    f"Device tree contains a mounted filesystem: {mountpoint}",
                )

    return DeviceInspection(
        device_node,
        True,
        "Read-only preflight passed; quarantine is not applied",
    )
