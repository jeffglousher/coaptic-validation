import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

from esphome_probe import CHIPS, ESPHOME, ROOT, configuration
from host import binary_identity
from build_source import build_source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chip", choices=CHIPS, default="esp32s3")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-library-revision", required=True)
    parser.add_argument("--compile", action="store_true")
    args = parser.parse_args()
    if version("esphome") != ESPHOME:
        parser.error(f"use esphome=={ESPHOME}")
    try:
        source = build_source(args.expected_library_revision)
    except ValueError as error:
        parser.error(str(error))
    directory = args.output.resolve().parent
    directory.mkdir(parents=True, exist_ok=True)
    run_id = secrets.token_hex(16)
    ssid = "coaptic-" + run_id[:8]
    password = secrets.token_hex(12)
    config = configuration(args.chip, False, run_id, directory / "build")
    config["esphome"]["name"] = f"coaptic-{args.chip}-udp"
    config["external_components"][0]["components"] = ["coaptic_network"]
    del config["coaptic_probe"]
    config["coaptic_network"] = {"run_id": run_id, "qualification_only": True, "allow_plaintext": True}
    config["wifi"] = {"ap": {"ssid": ssid, "password": password}, "reboot_timeout": "0s"}
    config["logger"]["level"] = "INFO"
    path = directory / "network.yaml"
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (directory / "access.json").write_text(json.dumps({"ssid": ssid, "password": password}), encoding="utf-8")
    command = [sys.executable, "-m", "esphome", "compile", str(path)]
    if not args.compile:
        command.append("--only-generate")
    report = {"schema": "coaptic-esphome-network-build/1", "chip": args.chip, "run_id": run_id,
              **source,
              "esphome": ESPHOME, "build_passed": False, "runtime_passed": False,
              "scope": "IPv4 UDP qualification service; no OSCORE or device actuators"}
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=1800)
        log = (result.stdout + result.stderr).replace(password, "[redacted]")
        (directory / "compile.log").write_text(log, encoding="utf-8")
        report["exit_code"] = result.returncode
        report["prepared"] = result.returncode == 0
        if args.compile and result.returncode == 0:
            if build_source(args.expected_library_revision) != source:
                raise ValueError("source identity changed during firmware compilation")
            for name in ["firmware.elf", "firmware.factory.bin"]:
                matches = list((directory / "build").rglob(name))
                if len(matches) != 1:
                    raise ValueError(f"expected one fresh {name}")
                if name.endswith(".elf"):
                    machine = 94 if args.chip == "esp32s3" else 243
                    if binary_identity(matches[0].read_bytes()) != ("elf", 32, machine, "little"):
                        raise ValueError("wrong firmware ISA")
                shutil.copyfile(matches[0], directory / name)
                report[name + "_sha256"] = hashlib.sha256(matches[0].read_bytes()).hexdigest()
            report["build_passed"] = True
        if result.returncode:
            print(log[-6000:])
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report.get("build_passed" if args.compile else "prepared") else 1


if __name__ == "__main__":
    sys.exit(main())
