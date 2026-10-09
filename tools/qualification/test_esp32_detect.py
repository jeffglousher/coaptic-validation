import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from esp32_detect import chip_name, identify, select_images


class ChipSelectionTests(unittest.TestCase):
    def test_unprepared_riscv_chips_do_not_select_c3(self):
        self.assertEqual(chip_name("ESP32-C3"), "esp32c3")
        self.assertEqual(chip_name("ESP32-C6"), "esp32c6")
        self.assertEqual(chip_name("ESP32-S3"), "esp32s3")
        for name in ["ESP32", "ESP32-H2", "ESP32-C5", "RISC-V"]:
            with self.assertRaises(ValueError):
                chip_name(name)

    def test_identification_resets_and_closes_the_selected_port(self):
        events = []
        class Device:
            CHIP_NAME = "ESP32-C6"
            def __enter__(self):
                return self
            def __exit__(self, *args):
                events.append("closed")
            def get_chip_description(self):
                return "ESP32-C6 revision"
        def connect(**kwargs):
            self.assertEqual(kwargs, {"port": "COM7", "chip": "auto", "connect_attempts": 3})
            return Device()
        def reset(device, mode):
            events.append(mode)
        self.assertEqual(identify("COM7", connect, reset)["chip"], "esp32c6")
        self.assertEqual(events, ["hard-reset", "closed"])
        Device.CHIP_NAME = "ESP32-S3"
        self.assertEqual(identify("COM7", connect, reset)["chip"], "esp32s3")
        self.assertEqual(events[-2:], ["hard-reset", "closed"])

    def test_moved_artifacts_retain_chip_and_image_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = []
            for secured in [False, True]:
                name = f"image-{secured}.elf"
                (root / name).write_bytes(bytes([secured]))
                cases.append({"chip": "esp32c6", "oscore": secured, "build_passed": True,
                              "firmware": name, "firmware_sha256": hashlib.sha256(bytes([secured])).hexdigest(),
                              "run_id": name})
            path = root / "build.json"
            path.write_text(json.dumps({"schema": "coaptic-esp32-qualification/1", "chip": "esp32c6",
                                        "build_passed": True, "cases": cases}))
            self.assertEqual(len(select_images(path, "esp32c6")), 2)
            with self.assertRaises(ValueError):
                select_images(path, "esp32s3")
            with self.assertRaises(ValueError):
                select_images(path, "esp32c3")
            (root / cases[0]["firmware"]).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                select_images(path, "esp32c6")

    def test_esphome_factory_image_is_bound_to_the_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = []
            for secured in [False, True]:
                firmware = f"image-{secured}.elf"
                factory = f"image-{secured}.factory.bin"
                (root / firmware).write_bytes(b"elf")
                (root / factory).write_bytes(b"factory")
                cases.append({"chip": "esp32c6", "oscore": secured, "build_passed": True,
                              "firmware": firmware, "firmware_sha256": hashlib.sha256(b"elf").hexdigest(),
                              "flash_image": factory, "flash_image_sha256": hashlib.sha256(b"factory").hexdigest(),
                              "run_id": firmware})
            path = root / "build.json"
            path.write_text(json.dumps({"schema": "coaptic-esphome-qualification/1", "chip": "esp32c6",
                                        "build_passed": True, "cases": cases}))
            self.assertEqual(select_images(path, "esp32c6")[0]["flash_image"], str((root / cases[0]["flash_image"]).resolve()))
            (root / cases[0]["flash_image"]).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                select_images(path, "esp32c6")


if __name__ == "__main__":
    unittest.main()
