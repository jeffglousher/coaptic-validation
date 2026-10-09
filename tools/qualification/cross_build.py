import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from source_identity import source_identity

"""Pinned compile/code-generation evidence. No runtime or device claim."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

TOOLCHAIN = "1.97.1"
TARGETS = ("thumbv6m-none-eabi", "thumbv7em-none-eabi", "riscv32imac-unknown-none-elf", "wasm32-unknown-unknown")
FEATURES = ("core", "alloc", "oscore", "alloc,oscore")
ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    os.chdir(ROOT)
    rustc = subprocess.check_output(["rustc", "+" + TOOLCHAIN, "--version", "--verbose"], text=True)
    report = {"schema": "coaptic-cross-build/1", **source_identity(),
              "toolchain": rustc, "target": args.target, "cases": [],
              "scope": "Library and concrete bounded App code generation; not executable linking or execution",
              "unqualified": ["device/runtime behavior", "stack high-water", "allocator behavior", "transport/entropy integration", "big-endian execution"]}
    for features in FEATURES:
        command = ["cargo", "+" + TOOLCHAIN, "build", "--locked", "--release", "-p", "qualification-no-std", "--lib", "--no-default-features", "--target", args.target]
        if features != "core":
            command += ["--features", features]
        result = subprocess.run(command, capture_output=True, text=True)
        report["cases"].append({"features": features, "command": command,
                                "passed": result.returncode == 0, "exit_code": result.returncode,
                                "stdout": result.stdout, "stderr": result.stderr})
        print(("PASS" if result.returncode == 0 else "FAIL") + " " + args.target + " " + features, flush=True)
    report["passed"] = len(report["cases"]) == len(FEATURES) and all(case["passed"] for case in report["cases"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
