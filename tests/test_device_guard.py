import json
import unittest
from unittest.mock import patch, Mock

from host.device_guard import check_usb_disk


class DeviceGuardTests(unittest.TestCase):
    def test_invalid_path_rejected(self):
        self.assertFalse(check_usb_disk("sda").allowed)

    def test_protected_disk_rejected_without_inspection(self):
        with patch("host.device_guard.subprocess.run") as run:
            result = check_usb_disk("/dev/sda")
        self.assertFalse(result.allowed)
        run.assert_not_called()

    def test_partition_rejected(self):
        output = {"blockdevices": [{
            "name": "/dev/sdz1", "type": "part",
            "tran": "usb", "mountpoints": [None]
        }]}
        with patch("host.device_guard.subprocess.run") as run:
            run.return_value = Mock(stdout=json.dumps(output))
            result = check_usb_disk("/dev/sdz1")
        self.assertFalse(result.allowed)

    def test_mounted_usb_disk_rejected(self):
        output = {"blockdevices": [{
            "name": "/dev/sdz", "type": "disk",
            "tran": "usb", "mountpoints": [None],
            "children": [{
                "name": "/dev/sdz1", "type": "part",
                "tran": "usb", "mountpoints": ["/media/test"]
            }]
        }]}
        with patch("host.device_guard.subprocess.run") as run:
            run.return_value = Mock(stdout=json.dumps(output))
            result = check_usb_disk("/dev/sdz")
        self.assertFalse(result.allowed)

    def test_unmounted_usb_disk_passes_preflight_only(self):
        output = {"blockdevices": [{
            "name": "/dev/sdz", "type": "disk",
            "tran": "usb", "mountpoints": [None]
        }]}
        with patch("host.device_guard.subprocess.run") as run:
            run.return_value = Mock(stdout=json.dumps(output))
            result = check_usb_disk("/dev/sdz")
        self.assertTrue(result.allowed)
        self.assertIn("not been applied", result.reason)


if __name__ == "__main__":
    unittest.main()
