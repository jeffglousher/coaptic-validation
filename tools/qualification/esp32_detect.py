import argparse
import contextlib
import hashlib
from importlib.metadata import version
import io
import json
from pathlib import Path
import sys

from esp32 import ESPHOME_CHIPS as CHIPS

ESPTOOL = "5.4.0"


def chip_name(name):
    chip = name.lower().replace("-", "")
    if chip not in CHIPS:
        raise ValueError(f"no qualification image is prepared for {name}")
    return chip


def select_images(path, chip):
    chip = chip_name(chip)
    report = json.loads(path.read_text(encoding="utf-8"))
    schemas = {"coaptic-esp32-qualification/1", "coaptic-esphome-qualification/1"}
    if report.get("schema") not in schemas or report.get("chip", "esp32c3") != chip:
        raise ValueError("build report does not match the detected chip")
    if report.get("target", CHIPS[chip]) != CHIPS[chip]:
        raise ValueError("build target does not match the detected chip")
    cases = report.get("cases", [])
    if report.get("build_passed") is not True or len(cases) != 2:
        raise ValueError("both firmware builds must pass")
    selected = []
    for case, secured in zip(cases, [False, True], strict=True):
        if case.get("chip", "esp32c3") != chip or case.get("oscore") is not secured or case.get("build_passed") is not True:
            raise ValueError("firmware configuration does not match the detected chip")
        if case.get("target", CHIPS[chip]) != CHIPS[chip]:
            raise ValueError("firmware target does not match the detected chip")
        firmware = Path(case["firmware"])
        if not firmware.is_absolute():
            firmware = path.parent / firmware
        if hashlib.sha256(firmware.read_bytes()).hexdigest() != case["firmware_sha256"]:
            raise ValueError("firmware changed after build")
        image = {"oscore": secured, "firmware": str(firmware.resolve()), "run_id": case["run_id"]}
        if "flash_image" in case:
            flash_image = Path(case["flash_image"])
            if not flash_image.is_absolute():
                flash_image = path.parent / flash_image
            if hashlib.sha256(flash_image.read_bytes()).hexdigest() != case["flash_image_sha256"]:
                raise ValueError("flash image changed after build")
            image["flash_image"] = str(flash_image.resolve())
        selected.append(image)
    return selected


def identify(port, connector, reset):
    with connector(port=port, chip="auto", connect_attempts=3) as device:
        try:
            return {"chip": device.CHIP_NAME.lower().replace("-", ""), "description": device.get_chip_description()}
        finally:
            reset(device, "hard-reset")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--firmware-report", type=Path)
    args = parser.parse_args()
    if version("esptool") != ESPTOOL:
        parser.error(f"use esptool=={ESPTOOL}")
    from serial.tools import list_ports
    from esptool.cmds import connect_esp, reset_chip

    ports = [{"port": port.device, "description": port.description, "vid": port.vid, "pid": port.pid}
             for port in list_ports.comports()]
    report = {"schema": "coaptic-esp32-detection/1", "esptool": ESPTOOL, "ports": ports,
              "detected": False, "flash_written": False}
    transcript = io.StringIO()
    if args.port:
        report["port"] = args.port
        try:
            if args.port not in [port["port"] for port in ports]:
                raise ValueError("requested port is not connected")
            with contextlib.redirect_stdout(transcript), contextlib.redirect_stderr(transcript):
                report.update(identify(args.port, connect_esp, reset_chip))
            report["target"] = CHIPS.get(report["chip"])
            report["qualification_supported"] = report["chip"] in CHIPS
            report["detected"] = True
            if args.firmware_report:
                report["images"] = select_images(args.firmware_report.resolve(), report["chip"])
        except Exception as error:
            report["error"] = str(error)
    elif args.firmware_report:
        parser.error("--firmware-report requires --port")
    report["transcript"] = transcript.getvalue()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 1 if "error" in report else 0


if __name__ == "__main__":
    sys.exit(main())
