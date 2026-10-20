import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vm.guest.clamav_scanner import make_clamav_scanner


class ClamAVScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "input"
        self.root.mkdir()
        self.scanner = make_clamav_scanner(
            scan_root=str(self.root),
            timeout_seconds=5,
        )

    def tearDown(self):
        self.temp.cleanup()

    @patch("vm.guest.clamav_scanner.subprocess.run")
    def test_clean_scan(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        self.assertEqual(
            self.scanner({"device_id": "device-1"}),
            {"clean": True, "findings": 0},
        )
        args = run.call_args.args[0]
        self.assertIn("--cross-fs=no", args)
        self.assertIn(str(self.root.resolve()), args)

    @patch("vm.guest.clamav_scanner.subprocess.run")
    def test_detection_is_not_clean(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1,
            stdout="/scan/input/sample.exe: Test.Signature FOUND\n",
            stderr="",
        )
        self.assertEqual(
            self.scanner({}),
            {"clean": False, "findings": 1},
        )

    @patch("vm.guest.clamav_scanner.subprocess.run")
    def test_error_exit_fails_closed(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=2, stdout="", stderr="database error"
        )
        with self.assertRaises(RuntimeError):
            self.scanner({})

    @patch("vm.guest.clamav_scanner.subprocess.run")
    def test_timeout_fails_closed(self, run):
        run.side_effect = subprocess.TimeoutExpired("clamscan", 5)
        with self.assertRaises(RuntimeError):
            self.scanner({})

    @patch("vm.guest.clamav_scanner.subprocess.run")
    def test_detection_exit_without_finding_fails_closed(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=""
        )
        with self.assertRaises(RuntimeError):
            self.scanner({})

    @patch("vm.guest.clamav_scanner.subprocess.run")
    def test_missing_scan_root_fails_closed(self, run):
        scanner = make_clamav_scanner(
            scan_root=str(self.root / "missing")
        )
        with self.assertRaises(RuntimeError):
            scanner({})
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
