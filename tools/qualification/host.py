import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from source_identity import source_identity

"""Pinned host library execution evidence; no transport or device qualification."""
import argparse
import json
import hashlib
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2] / "coaptic"
TOOLCHAIN = "1.97.1"
CASES = (
    ("core", ["--no-default-features"]),
    ("all", ["--all-features"]),
    ("alloc", ["--no-default-features", "--features", "alloc"]),
    ("oscore", ["--no-default-features", "--features", "oscore"]),
    ("alloc,oscore", ["--no-default-features", "--features", "alloc,oscore"]),
    ("std", ["--no-default-features", "--features", "std"]),
)
SUMMARY = re.compile(r"test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;")


def text(value):
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else (value or "")


TARGETS = {"i686-pc-windows-msvc": ("pe", 32, 0x14c, "little"),
           "i686-unknown-linux-gnu": ("elf", 32, 3, "little"),
           "s390x-unknown-linux-gnu": ("elf", 64, 22, "big")}
EMULATED = "s390x-unknown-linux-gnu"
RUNNER = ["qemu-s390x", "-L", "/usr/s390x-linux-gnu"]
LINKER = "s390x-linux-gnu-gcc"


def binary_identity(data):
    """Read native image headers, not the host Python/OS architecture."""
    if len(data) >= 64 and data[:4] == b"\x7fELF":
        if data[4] not in (1, 2) or data[5] not in (1, 2):
            raise ValueError("invalid ELF class or byte order")
        endian = "little" if data[5] == 1 else "big"
        return ("elf", 32 if data[4] == 1 else 64, int.from_bytes(data[18:20], endian), endian)
    if len(data) >= 64 and data[:2] == b"MZ":
        offset = int.from_bytes(data[60:64], "little")
        if offset > len(data) - 26 or data[offset:offset + 4] != b"PE\0\0":
            raise ValueError("invalid PE header offset/signature")
        magic = int.from_bytes(data[offset + 24:offset + 26], "little")
        if magic not in (0x10b, 0x20b):
            raise ValueError("invalid PE optional header")
        return ("pe", 32 if magic == 0x10b else 64,
                int.from_bytes(data[offset + 4:offset + 6], "little"), "little")
    raise ValueError("unrecognized native executable")


def executable_evidence(stdout, target):
    paths = set()
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(event, dict) or event.get("reason") != "compiler-artifact":
            continue
        profile, executable = event.get("profile"), event.get("executable")
        if isinstance(profile, dict) and profile.get("test") and isinstance(executable, str) and executable:
            paths.add(executable)
    if not paths:
        raise ValueError("no compiled test executables reported")
    artifacts = []
    for name in sorted(paths):
        data = Path(name).read_bytes()
        identity = binary_identity(data)
        if identity != TARGETS[target]:
            raise ValueError(f"wrong executable architecture for {target}: {name}: {identity}")
        artifacts.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(),
                          "format": identity[0], "bits": identity[1], "machine": identity[2], "byte_order": identity[3]})
    return artifacts


def run_case(name, flags, execute=subprocess.run, *, target=None):
    command = ["cargo", "+" + TOOLCHAIN, "test", "--locked", "-p", "coaptic", *flags]
    if target is not None:
        if target not in TARGETS:
            raise ValueError("unsupported execution target")
        command += ["--target", target, "--message-format=json"]
    execution = {}
    if target == EMULATED:
        # Explicit user-mode emulation; rustdoc does not use this Cargo runner.
        command += ["--lib", "--tests", "--", "--test-threads=1"]
        environment = os.environ.copy()
        environment["CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER"] = " ".join(RUNNER)
        environment["CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER"] = LINKER
        execution["env"] = environment
    timed_out = False
    try:
        result = execute(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900, **execution)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code, stdout, stderr, timed_out = None, text(error.stdout), text(error.stderr), True
    except OSError as error:
        code, stdout, stderr = None, "", str(error)
    summaries = [(int(passed), int(ignored)) for passed, ignored in SUMMARY.findall(stdout)]
    executed = sum(passed for passed, _ in summaries)
    passed = code == 0 and executed > 0 and "test result: FAILED" not in stdout
    artifacts, artifact_error = [], None
    if target is not None:
        try:
            artifacts = executable_evidence(stdout, target)
        except (OSError, ValueError) as error:
            artifact_error = str(error)
            passed = False
    return {"features": name, "command": command, "target": target,
            "runner": RUNNER if target == EMULATED else None,
            "executables": artifacts, "executable_error": artifact_error,
            "passed": passed, "exit_code": code,
            "timed_out": timed_out, "executed": executed, "ignored": sum(ignored for _, ignored in summaries),
            "stdout": stdout, "stderr": stderr}


def run_matrix(execute=subprocess.run, *, target=None):
    cases = []
    for name, flags in CASES:
        result = run_case(name, flags, execute, target=target)
        cases.append(result)
        print(("PASS" if result["passed"] else "FAIL") + " " + name, flush=True)
    return cases


def emulation_tools(target):
    if target != EMULATED:
        return []
    evidence = []
    for command in ([RUNNER[0], "--version"], [LINKER, "--version"],
                    ["dpkg-query", "-W", "qemu-user", "gcc-s390x-linux-gnu", "libc6-dev-s390x-cross"]):
        try:
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
            evidence.append({"command": command, "exit_code": result.returncode,
                             "stdout": result.stdout, "stderr": result.stderr})
        except (OSError, subprocess.TimeoutExpired) as error:
            evidence.append({"command": command, "exit_code": None, "error": str(error)})
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=tuple(TARGETS))
    args = parser.parse_args()
    os.chdir(ROOT)
    report = {"schema": "coaptic-host-qualification/1",
              **source_identity(),
              "compiler": subprocess.check_output(["rustc", "+" + TOOLCHAIN, "--version", "--verbose"], text=True),
              "platform": platform.platform(), "machine": platform.machine(), "python": sys.version,
              "target": args.target, "emulation_tools": emulation_tools(args.target),
              "scope": "Library unit/integration execution under qemu-s390x in six feature configurations; big-endian ELF headers and nonzero executed tests required; rustdoc excluded" if args.target == EMULATED else "Library test execution in six feature configurations; explicit 32-bit targets require matching native test-image headers and nonzero executed tests" if args.target else "Library unit, integration and rustdoc execution in six feature configurations on this host",
              "unqualified": ["independent process/DTLS adapters on this host", "MSRV on this host", "device execution", "target stack high-water", "full RFC or branch coverage"],
              "cases": run_matrix(target=args.target)}
    report["passed"] = len(report["cases"]) == len(CASES) and all(case["passed"] for case in report["cases"]) and all(tool["exit_code"] == 0 for tool in report["emulation_tools"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
