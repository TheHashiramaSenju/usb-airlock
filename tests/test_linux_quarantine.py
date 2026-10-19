import json
import subprocess
import unittest
from unittest.mock import patch

from host.linux_quarantine import inspect_block_device


class LinuxPreflightTests(unittest.TestCase):
    @patch("host.linux_quarantine.subprocess.run")
    def test_non_usb_disk_is_rejected(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({
                "blockdevices": [{
                    "name": "/dev/sdb",
                    "type": "disk",
                    "tran": "sata",
                    "mountpoints": [None],
                    "children": [],
                }]
            }),
            stderr="",
        )

        result = inspect_block_device("/dev/sdb")
        self.assertFalse(result.safe_to_consider)
        self.assertIn("not identified as USB", result.reason)

    @patch("host.linux_quarantine.subprocess.run")
    def test_mounted_usb_disk_is_rejected(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({
                "blockdevices": [{
                    "name": "/dev/sdb",
                    "type": "disk",
                    "tran": "usb",
                    "mountpoints": [None],
                    "children": [{
                        "name": "/dev/sdb1",
                        "type": "part",
                        "mountpoints": ["/media/test"],
                    }],
                }]
            }),
            stderr="",
        )

        result = inspect_block_device("/dev/sdb")
        self.assertFalse(result.safe_to_consider)
        self.assertIn("mounted filesystem", result.reason)

    @patch("host.linux_quarantine.subprocess.run", side_effect=OSError("test"))
    def test_inspection_failure_is_rejected(self, run):
        result = inspect_block_device("/dev/sdb")
        self.assertFalse(result.safe_to_consider)
        self.assertIn("inspection failed", result.reason)


if __name__ == "__main__":
    unittest.main()
