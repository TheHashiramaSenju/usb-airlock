import unittest

from vm.guest.agent import run_scan


class GuestAgentTests(unittest.TestCase):
    def setUp(self):
        self.request = {"device_id": "device-A", "scan_id": "scan-001"}

    def test_clean_scan_result(self):
        result = run_scan(
            self.request,
            lambda request: {"clean": True, "findings": 0},
        )
        self.assertTrue(result["completed"])
        self.assertTrue(result["clean"])
        self.assertEqual(result["findings"], 0)

    def test_findings_prevent_clean_result(self):
        result = run_scan(
            self.request,
            lambda request: {"clean": True, "findings": 2},
        )
        self.assertTrue(result["completed"])
        self.assertFalse(result["clean"])

    def test_scanner_exception_fails_closed(self):
        def broken(request):
            raise RuntimeError("scanner failed")

        result = run_scan(self.request, broken)
        self.assertFalse(result["completed"])
        self.assertFalse(result["clean"])

    def test_malformed_scanner_output_fails_closed(self):
        result = run_scan(self.request, lambda request: {"clean": True})
        self.assertFalse(result["completed"])
        self.assertFalse(result["clean"])

    def test_missing_identity_fails_closed(self):
        result = run_scan({}, lambda request: {"clean": True, "findings": 0})
        self.assertFalse(result["completed"])
        self.assertFalse(result["clean"])


if __name__ == "__main__":
    unittest.main()
