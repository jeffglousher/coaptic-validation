"""Real ESPHome schema/codegen checks; never compile or access a device."""
import copy
import base64
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml


COMPONENTS = Path(__file__).resolve().parent / "components"


def configuration(root):
    return {
        "esphome": {"name": "libcoap-codegen", "build_path": str(root / "build")},
        "esp32": {"variant": "esp32s3", "framework": {"type": "esp-idf", "version": "5.5.5"},
                  "toolchain": "esp-idf"},
        "logger": {"hardware_uart": "USB_SERIAL_JTAG"},
        "wifi": {"ssid": "qualification-test", "reboot_timeout": "0s", "power_save_mode": "NONE"},
        "api": {"encryption": {"key": base64.b64encode(bytes([1]) * 32).decode()}},
        "ota": [{"platform": "esphome", "password": "configuration-only-placeholder"}],
        "external_components": [{"source": {"type": "local", "path": str(COMPONENTS)},
                                 "components": ["libcoap_benchmark"]}],
        "libcoap_benchmark": {"qualification_only": True, "allow_unprotected": True,
                              "run_id": "a" * 32, "server_run_id": "b" * 32,
                              "peer_address": "192.168.1.134", "peer_port": 5684,
                              "start_delay_ms": 45000},
    }


def invoke(root, config, generate=False):
    source = root / "configuration.yaml"
    source.write_text(json.dumps(config), encoding="utf-8")
    command = [sys.executable, "-B", "-m", "esphome", "compile" if generate else "config", str(source)]
    if generate:
        command.append("--only-generate")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(command, capture_output=True, text=True, timeout=90, env=env)


class LibcoapBenchmarkConfigurationTests(unittest.TestCase):
    def test_native_codegen_consumes_pinned_idf_component_and_preserves_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = configuration(root)
            result = invoke(root, config, generate=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            build = root / "build"
            generated = (build / "src/main.cpp").read_text()
            for expected in ["set_run_id(\"" + "a" * 32, "set_server_run_id(\"" + "b" * 32,
                             "set_peer_port(5684)", "set_start_delay_ms(45000)"]:
                self.assertIn(expected, generated)
            self.assertRegex(generated, f"set_peer_address\\({int(ipaddress.IPv4Address('192.168.1.134'))}(?:UL)?\\)")
            defines = (build / "src/esphome/core/defines.h").read_text()
            self.assertIn("USE_API", defines)
            self.assertIn("USE_API_NOISE", defines)
            self.assertIn("#define USE_OTA\n", defines)
            self.assertIn("#define USE_OTA_ENCRYPTION\n", defines)
            self.assertIn("USE_WIFI", defines)
            self.assertNotIn("coaptic_network", generated)
            self.assertTrue((build / "src/esphome/components/libcoap_benchmark/libcoap_benchmark.cpp").is_file())
            sdkconfig = (build / "sdkconfig.libcoap-codegen").read_text()
            self.assertIn("CONFIG_COAP_CLIENT_SUPPORT=y", sdkconfig)
            for option in ["COAP_SERVER_SUPPORT", "COAP_MBEDTLS_PSK", "COAP_MBEDTLS_PKI",
                           "COAP_OSCORE_SUPPORT", "COAP_TCP_SUPPORT", "COAP_WEBSOCKETS", "COAP_DEBUGGING"]:
                self.assertIn(f"CONFIG_{option}=n", sdkconfig)
            # Check the generated project consumes the component path, not just
            # a manifest that happens to exist beside unreferenced source.
            cmake = (build / "CMakeLists.txt").read_text()
            self.assertIn("coaptic_libcoap_benchmark", cmake)
            generated_manifest = yaml.safe_load((build / "src/idf_component.yml").read_text())
            local_dependency = generated_manifest["dependencies"]["coaptic_libcoap_benchmark"]
            self.assertEqual(Path(local_dependency["path"]).resolve(),
                             (COMPONENTS / "libcoap_benchmark/idf_component").resolve())
            manifest = (COMPONENTS / "libcoap_benchmark/idf_component/idf_component.yml").read_text()
            self.assertIn('idf: "==5.5.5"', manifest)
            self.assertIn("espressif/coap:", manifest)
            self.assertIn('version: "==4.3.5~8"', manifest)
            self.assertIn("REQUIRES espressif__coap", (COMPONENTS / "libcoap_benchmark/idf_component/CMakeLists.txt").read_text())

    def test_explicit_unprotected_qualification_and_identity_are_required(self):
        changes = [("qualification_only", None), ("qualification_only", False),
                   ("allow_unprotected", None), ("allow_unprotected", False),
                   ("run_id", "A" * 32), ("server_run_id", "b" * 31)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for key, value in changes:
                with self.subTest(key=key, value=value):
                    config = configuration(root)
                    if value is None:
                        config["libcoap_benchmark"].pop(key)
                    else:
                        config["libcoap_benchmark"][key] = value
                    result = invoke(root, config)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_peer_and_campaign_bounds_refuse_unscoped_or_unbounded_values(self):
        changes = [("peer_address", value) for value in ["0.0.0.0", "127.0.0.1", "8.8.8.8", "224.0.0.1", "::1"]]
        changes += [("peer_port", 0), ("peer_port", 65536), ("start_delay_ms", -1), ("start_delay_ms", 120001)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for key, value in changes:
                with self.subTest(key=key, value=value):
                    config = configuration(root)
                    config["libcoap_benchmark"][key] = value
                    result = invoke(root, config)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_other_chip_framework_toolchain_and_idf_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = configuration(root)
            selections = []
            for change in ["chip", "framework", "toolchain", "idf"]:
                config = copy.deepcopy(baseline)
                if change == "chip":
                    config["esp32"]["variant"] = "esp32c3"
                elif change == "framework":
                    config["esp32"]["framework"] = {"type": "arduino"}
                elif change == "toolchain":
                    config["esp32"]["toolchain"] = "platformio"
                else:
                    config["esp32"]["framework"]["version"] = "5.5.4"
                selections.append((change, config))
            for change, config in selections:
                with self.subTest(change=change):
                    result = invoke(root, config)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_competing_coaptic_worker_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = configuration(root)
            config["external_components"][0]["components"].append("coaptic_network")
            config["coaptic_network"] = {"run_id": "a" * 32, "qualification_only": True,
                                          "rust_runtime": "source", "allow_plaintext": True}
            result = invoke(root, config)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("cannot be used together", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
