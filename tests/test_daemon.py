import unittest
from unittest.mock import Mock, patch

from host import daemon
from host.quarantine import QuarantineResult, QuarantineStatus


class DeviceInventoryTests(unittest.TestCase):
    def setUp(self):
        daemon.devices.clear()
        self.controller_patch = patch.object(daemon, "quarantine_controller")
        self.controller = self.controller_patch.start()
        self.addCleanup(self.controller_patch.stop)

    def make_device(self, action="add", sys_path="/sys/devices/usb1/1-2"):
        device = Mock()
        device.action = action
        device.sys_path = sys_path
        device.properties = {
            "DEVTYPE": "disk",
            "DEVNAME": "/dev/sdz",
        }

        usb_parent = Mock()
        usb_parent.properties = {
            "ID_VENDOR_ID": "abcd",
            "ID_MODEL_ID": "1234",
        }
        device.find_parent.side_effect = (
            lambda subsystem, devtype:
            usb_parent if (subsystem, devtype) == ("usb", "usb_device")
            else None
        )
        return device

    def test_usb_device_is_tracked_and_quarantine_attempted(self):
        device = self.make_device()
        self.controller.quarantine.return_value = QuarantineResult(
            "device-A", QuarantineStatus.FAILED, "Test failure"
        )

        with patch.object(daemon, "get_device_identity", return_value="device-A"):
            daemon.handle_device(device)

        self.assertIn(device.sys_path, daemon.devices)
        self.assertEqual(
            daemon.devices[device.sys_path]["device_id"], "device-A"
        )
        self.controller.quarantine.assert_called_once_with(
            "device-A", "/dev/sdz"
        )

    def test_failed_quarantine_is_not_reported_as_success(self):
        device = self.make_device()
        self.controller.quarantine.return_value = QuarantineResult(
            "device-A", QuarantineStatus.FAILED, "Enforcement unavailable"
        )

        with patch.object(daemon, "get_device_identity", return_value="device-A"):
            with self.assertLogs("usb-airlock", level="WARNING") as captured:
                daemon.handle_device(device)

        self.assertTrue(
            any("QUARANTINE_FAILED_CLOSED" in line for line in captured.output)
        )
        self.assertEqual(self.controller.quarantine.call_count, 1)

    def test_removal_clears_tracked_device_without_quarantine(self):
        device = self.make_device(action="remove")
        daemon.devices[device.sys_path] = {"device_id": "device-A"}

        daemon.handle_device(device)

        self.assertNotIn(device.sys_path, daemon.devices)
        self.controller.quarantine.assert_not_called()

    def test_partition_event_does_not_start_separate_quarantine(self):
        device = self.make_device()
        device.properties["DEVTYPE"] = "partition"

        with patch.object(daemon, "get_device_identity", return_value="device-A"):
            daemon.handle_device(device)

        self.controller.quarantine.assert_not_called()


if __name__ == "__main__":
    unittest.main()
