import argparse
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

from esp32 import ESPHOME_CHIPS as CHIPS, record_captures
from host import binary_identity
from build_source import build_source

ROOT = Path(__file__).resolve().parents[2]
ESPHOME = "2026.9.1"
IDF = "5.5.5"


def configuration(chip, secured, run_id, build):
    if chip not in CHIPS:
        raise ValueError("unprepared chip")
    return {"esphome": {"name": f"coaptic-{chip}-" + ("oscore" if secured else "core"), "build_path": str(build)},
            "esp32": {"variant": chip, "framework": {"type": "esp-idf", "version": IDF}, "toolchain": "esp-idf"},
            "logger": {"hardware_uart": "USB_SERIAL_JTAG"},
            "external_components": [{"source": {"type": "local", "path": str(ROOT / "tools" / "esphome" / "components")},
                                     "components": ["coaptic_probe"]}],
            "coaptic_probe": {"run_id": run_id, "oscore": secured}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chip", choices=CHIPS, default="esp32c3")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-library-revision", required=True)
    parser.add_argument("--expected-suite-revision")
    parser.add_argument("--compile", action="store_true")
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--capture-core", type=Path)
    parser.add_argument("--capture-oscore", type=Path)
    args = parser.parse_args()
    args.output = args.output.resolve()
    if args.record:
        report = json.loads(args.output.read_text(encoding="utf-8"))
        if report.get("schema") != "coaptic-esphome-qualification/1":
            parser.error("invalid ESPHome build report")
        try:
            record_captures(report, args.output, [args.capture_core, args.capture_oscore],
                            expected_library_revision=args.expected_library_revision,
                            expected_suite_revision=args.expected_suite_revision)
        except ValueError as error:
            parser.error(str(error))
    else:
        try:
            source = build_source(args.expected_library_revision)
        except ValueError as error:
            parser.error(str(error))
        if version("esphome") != ESPHOME:
            parser.error(f"use esphome=={ESPHOME}")
        os.chdir(ROOT)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        report = {"schema": "coaptic-esphome-qualification/1", "chip": args.chip, "target": CHIPS[args.chip],
                  "esphome": ESPHOME, "esp_idf": IDF, "runtime_passed": False,
                  **source,
                  "scope": "Coaptic App loopback and optional OSCORE in one owned ESPHome FreeRTOS probe task",
                  "unqualified": ["hardware execution until captures", "networked CoAP component", "Taldra gateway",
                                  "radio", "platform entropy", "allocator stress", "flash durability"], "cases": []}
        for secured in [False, True]:
            directory = Path(tempfile.mkdtemp(prefix="esphome-", dir=args.output.parent))
            run_id = secrets.token_hex(16)
            config = directory / "probe.yaml"
            config.write_text(json.dumps(configuration(args.chip, secured, run_id, directory / "build"), indent=2), encoding="utf-8")
            command = [sys.executable, "-m", "esphome", "compile", str(config)]
            if not args.compile:
                command += ["--only-generate"]
            case = {"chip": args.chip, "target": CHIPS[args.chip], "oscore": secured, "run_id": run_id, "runtime_kind": "esphome",
                    "configuration": str(config), "command": command, "build_passed": False, "runtime_passed": False}
            try:
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=1800)
                case.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                            prepared=result.returncode == 0)
                if args.compile and result.returncode == 0:
                    if build_source(args.expected_library_revision) != source:
                        raise ValueError("source identity changed during firmware compilation")
                    images = list(directory.rglob("firmware.elf"))
                    if len(images) != 1:
                        raise ValueError("one fresh linked firmware ELF is required")
                    machine = 94 if args.chip == "esp32s3" else 243
                    if binary_identity(images[0].read_bytes()) != ("elf", 32, machine, "little"):
                        raise ValueError("firmware ISA does not match the selected chip")
                    name = args.chip + ("-esphome-oscore.elf" if secured else "-esphome-core.elf")
                    shutil.copyfile(images[0], args.output.parent / name)
                    factory = list(directory.rglob("firmware.factory.bin"))
                    if len(factory) != 1:
                        raise ValueError("one fresh ESPHome factory image is required")
                    flash_name = name.removesuffix(".elf") + ".factory.bin"
                    shutil.copyfile(factory[0], args.output.parent / flash_name)
                    case.update(firmware=name, firmware_sha256=hashlib.sha256(images[0].read_bytes()).hexdigest(),
                                flash_image=flash_name, flash_image_sha256=hashlib.sha256(factory[0].read_bytes()).hexdigest(),
                                build_passed=True)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                case["error"] = str(error)
                case["prepared"] = False
            report["cases"].append(case)
            passed = case["build_passed"] if args.compile else case["prepared"]
            print(("PASS " if passed else "FAIL ") + ("build " if args.compile else "configuration ") +
                  ("oscore" if secured else "core"), flush=True)
            if not passed:
                print(case.get("error", case.get("stderr", ""))[-4000:], flush=True)
        report["prepared"] = all(case["prepared"] for case in report["cases"])
        report["build_passed"] = all(case["build_passed"] for case in report["cases"])
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    field = "runtime_passed" if args.record else "build_passed" if args.compile else "prepared"
    return 0 if report[field] else 1


if __name__ == "__main__":
    sys.exit(main())
