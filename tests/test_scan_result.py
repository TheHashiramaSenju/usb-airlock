import unittest

from host.scan_result import parse_scan_result, validate_scan_result


def clean_payload():
    return {
        "schema_version": 1,
        "device_id": "device-A",
        "scan_id": "scan-001",
        "completed": True,
        "clean": True,
        "findings": 0,
    }


class ScanResultTests(unittest.TestCase):
    def test_valid_json_result_accepted(self):
        self.assertTrue(validate_scan_result(clean_payload(), "device-A"))

    def test_valid_json_string_accepted(self):
        import json
        self.assertTrue(
            validate_scan_result(json.dumps(clean_payload()), "device-A")
        )

    def test_wrong_device_rejected(self):
        self.assertFalse(validate_scan_result(clean_payload(), "device-B"))

    def test_incomplete_scan_rejected(self):
        payload = clean_payload()
        payload["completed"] = False
        self.assertFalse(validate_scan_result(payload, "device-A"))

    def test_findings_rejected(self):
        payload = clean_payload()
        payload["findings"] = 1
        self.assertFalse(validate_scan_result(payload, "device-A"))

    def test_extra_field_rejected(self):
        payload = clean_payload()
        payload["extra"] = "unexpected"
        self.assertIsNone(parse_scan_result(payload))

    def test_boolean_findings_rejected(self):
        payload = clean_payload()
        payload["findings"] = True
        self.assertIsNone(parse_scan_result(payload))

    def test_invalid_json_rejected(self):
        self.assertIsNone(parse_scan_result("{broken"))


if __name__ == "__main__":
    unittest.main()
