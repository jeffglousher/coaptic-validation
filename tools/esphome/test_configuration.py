import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qualification"))
from esphome_probe import configuration
from source_identity import LOCKS

LIBRARY = "1" * 40
SUITE = "2" * 40


def network_configuration(root, runtime="bundled", chip="esp32s3"):
    config = configuration(chip, False, "a" * 32, root / "build")
    config["external_components"][0]["components"] = ["coaptic_network"]
    del config["coaptic_probe"]
    config["coaptic_network"] = {"run_id": "a" * 32, "qualification_only": True,
                                  "rust_runtime": runtime}
    config["wifi"] = {"ssid": "qualification-test", "reboot_timeout": "0s"}
    return config


def archive_fixture(root, config):
    """Opaque test bytes validate generation/refusal, never firmware linking."""
    source = Path(__file__).resolve().parent / "components/coaptic_network"
    component = root / "components/coaptic_network"
    shutil.copytree(source, component, ignore=shutil.ignore_patterns("lib", "__pycache__"))
    config["external_components"][0]["source"]["path"] = str(root / "components")
    config["coaptic_network"].update(expected_library_revision=LIBRARY, expected_suite_revision=SUITE)
    directory = component / "lib"
    directory.mkdir()
    archive = directory / "libcoaptic_esphome_probe.a"
    archive.write_bytes(b"configuration-only opaque fixture; not a linkable archive")
    report = {"schema": "coaptic-esphome-archive/2", "target": "xtensa-esp32s3-none-elf",
              "features": ["network", "standalone"], "source": LIBRARY, "suite_source": SUITE,
              "dirty": False, "suite_dirty": False, "suite_locks": {name: "3" * 64 for name in LOCKS},
              "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    return archive, directory / "build.json", report


class ConfigurationRefusalTests(unittest.TestCase):
    def test_bundled_network_refuses_wrong_chip_and_corrupt_archive(self):
        for change, message in [
            ("chip", "prepared only for ESP32-S3"),
            ("corrupt", "archive checksum mismatch"),
            ("source", "source provenance mismatch"),
            ("suite_source", "source provenance mismatch"),
            ("dirty", "source provenance mismatch"),
            ("suite_dirty", "source provenance mismatch"),
            ("schema", "source provenance mismatch"),
            ("suite_locks", "lockfile provenance mismatch"),
            ("expected_library_revision", "requires both expected source revisions"),
            ("target", "target or features mismatch"),
        ]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = network_configuration(root, chip="esp32c3" if change == "chip" else "esp32s3")
                archive, marker, report = archive_fixture(root, config)
                if change == "corrupt":
                    archive.write_bytes(b"corruption")
                elif change == "expected_library_revision":
                    del config["coaptic_network"][change]
                elif change in report:
                    report[change] = True if change.endswith("dirty") else "stale"
                marker.write_text(json.dumps(report), encoding="utf-8")
                path = root / "network.yaml"
                path.write_text(json.dumps(config), encoding="utf-8")
                result = subprocess.run([sys.executable, "-m", "esphome", "config", str(path)],
                                        capture_output=True, text=True, timeout=60)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stdout + result.stderr)

    def test_bundled_and_external_network_runtimes_generate_without_replacing_component_dirs(self):
        for runtime in ["source", "bundled", "external"]:
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = network_configuration(root, runtime)
                if runtime == "bundled":
                    _, marker, report = archive_fixture(root, config)
                    marker.write_text(json.dumps(report), encoding="utf-8")
                path = root / "network.yaml"
                path.write_text(json.dumps(config), encoding="utf-8")
                result = subprocess.run([sys.executable, "-m", "esphome", "compile", str(path),
                                         "--only-generate"], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                cmake = (root / "build/CMakeLists.txt").read_text()
                self.assertEqual(re.findall(r"set\(EXTRA_COMPONENT_DIRS ([^)]*)\)", cmake),
                                 ["${CMAKE_SOURCE_DIR}/src"])
                manifest = (root / "build/src/idf_component.yml").read_text()
                if runtime == "bundled":
                    self.assertIn("coaptic_rust_network", manifest)
                    self.assertIn((root / "components/coaptic_network/coaptic_rust_network").as_posix(), manifest.replace("\\", "/"))
                elif runtime == "source":
                    self.assertIn("coaptic_rust_probe", manifest)
                    self.assertIn("COAPTIC_RUST_MANIFEST", cmake)
                else:
                    self.assertNotIn("coaptic_rust_network", manifest)
                    self.assertNotIn("COAPTIC_RUST_MANIFEST", cmake)

    def test_unprepared_variants_invalid_identity_and_other_toolchains_refuse(self):
        for field, value, message in [
            ("variant", "esp32h2", "only available on ESP32C3, ESP32C6, ESP32S3"),
            ("framework", {"type": "arduino"}, "only available with framework(s) esp-idf"),
            ("toolchain", "platformio", "requires the native esp-idf toolchain"),
            ("run_id", "stale", "32 lowercase hexadecimal characters"),
        ]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = configuration("esp32c3", False, "a" * 32, root / "build")
                owner = config["coaptic_probe"] if field == "run_id" else config["esp32"]
                owner[field] = value
                path = root / "probe.yaml"
                path.write_text(json.dumps(config), encoding="utf-8")
                result = subprocess.run([sys.executable, "-m", "esphome", "config", str(path)],
                                        capture_output=True, text=True, timeout=60)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
