import argparse
from pathlib import Path
import time

from esptool.reset import HardReset
import serial


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600:
        parser.error("capture duration must be 1..3600 seconds")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    port = serial.Serial(port=None, baudrate=115200, timeout=0.2)
    port.port, port.dtr, port.rts = args.port, False, False
    pending = bytearray()
    captured = 0
    with port, args.output.open("wb") as capture:
        if args.reset:
            HardReset(port, uses_usb=True)()
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            chunk = port.read(port.in_waiting or 1)
            captured += len(chunk)
            if captured > 8_000_000:
                raise ValueError("console exceeded capture bound")
            capture.write(chunk)
            capture.flush()
            pending.extend(chunk)
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if b"COAPTIC_" in line:
                    print(line.decode("utf-8", errors="replace"), flush=True)
            if len(pending) > 8192:
                raise ValueError("console line exceeded capture bound")


if __name__ == "__main__":
    main()
