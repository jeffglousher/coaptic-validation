import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from esp32 import read_capture, record_captures
from source_identity import LOCKS


class DeviceEvidenceTests(unittest.TestCase):
    def fixture(self):
        case = {"chip": "esp32c3", "run_id": "fresh-image", "oscore": True}
        result = {"schema": "coaptic-device/1", "chip": "esp32c3", "run_id": "fresh-image",
                  "oscore": True, "passed": True, "stack_high_water_bytes": 32000, "stack_capacity_bytes": 200000}
        return case, result

    def test_capture_must_match_image_and_nonempty_stack_measurement(self):
        case, result = self.fixture()
        raw = "boot log\nCOAPTIC_DEVICE " + json.dumps(result)
        self.assertEqual(read_capture(raw, case), result)
        for text in ["", raw + "\n" + raw, raw + "\nCOAPTIC_DEVICE_FAIL panic"]:
            with self.assertRaises(ValueError):
                read_capture(text, case)
        for key, value in [("run_id", "stale"), ("chip", "esp32"), ("oscore", False),
                           ("passed", False), ("stack_high_water_bytes", 0),
                           ("stack_high_water_bytes", 200000), ("stack_capacity_bytes", True)]:
            invalid = dict(result, **{key: value})
            with self.assertRaises(ValueError):
                read_capture("COAPTIC_DEVICE " + json.dumps(invalid), case)

    def test_c6_capture_cannot_qualify_a_c3_image(self):
        case, result = self.fixture()
        case["chip"] = result["chip"] = "esp32c6"
        raw = "COAPTIC_DEVICE " + json.dumps(result)
        self.assertEqual(read_capture(raw, case), result)
        with self.assertRaises(ValueError):
            read_capture(raw, dict(case, chip="esp32c3"))

    def test_esphome_capture_retains_runtime_identity_through_console_colors(self):
        case, result = self.fixture()
        case["runtime_kind"] = result["runtime"] = "esphome"
        raw = "\x1b[32m[coaptic_probe] COAPTIC_DEVICE " + json.dumps(result) + "\x1b[0m"
        self.assertEqual(read_capture(raw, case), result)
        result["runtime"] = "standalone"
        with self.assertRaises(ValueError):
            read_capture("COAPTIC_DEVICE " + json.dumps(result), case)

    def test_capture_hash_preserves_serial_console_line_endings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "image.elf"
            firmware.write_bytes(b"firmware")
            cases = []
            captures = []
            for secured in [False, True]:
                case, result = self.fixture()
                case["oscore"] = result["oscore"] = secured
                case.update(build_passed=True, firmware=firmware.name,
                            firmware_sha256=hashlib.sha256(b"firmware").hexdigest())
                capture = root / f"capture-{secured}.log"
                raw = ("boot\r\nCOAPTIC_DEVICE " + json.dumps(result) + "\r\n").encode()
                capture.write_bytes(raw)
                cases.append(case)
                captures.append(capture)
            report = {"build_passed": True, "cases": cases, "source": "1" * 40, "suite_source": "2" * 40,
                      "dirty": False, "suite_dirty": False, "suite_locks": {name: "3" * 64 for name in LOCKS}}
            record_captures(report, root / "build.json", captures,
                            expected_library_revision="1" * 40, expected_suite_revision="2" * 40)
            self.assertTrue(report["runtime_passed"])
            for case, capture in zip(cases, captures, strict=True):
                self.assertEqual(case["capture_sha256"], hashlib.sha256(capture.read_bytes()).hexdigest())
            # A valid serial result and unchanged image cannot qualify a different candidate.
            with self.assertRaisesRegex(ValueError, "different library revision"):
                record_captures(report, root / "build.json", captures,
                                expected_library_revision="4" * 40, expected_suite_revision="2" * 40)


if __name__ == "__main__":
    unittest.main()
