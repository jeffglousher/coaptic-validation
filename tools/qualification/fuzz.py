import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from source_identity import source_identity

ROOT = Path(__file__).resolve().parents[2]
TOOLCHAIN = "nightly-2026-10-01"
TARGETS = ("datagram", "cbor", "oscore")
SEEDS = {"datagram": bytes.fromhex("41011234abb178"),
         "cbor": bytes.fromhex("a1206161"), "oscore": bytes.fromhex("000000000161")}
MAX_LOG_BYTES = 8 * 1024 * 1024


def snapshot():
    return {**source_identity(), "fuzz_lock_sha256": hashlib.sha256((ROOT / "fuzz/Cargo.lock").read_bytes()).hexdigest()}


def checked_snapshot(prepared_source=None, expected_revision=None, expected_suite_revision=None):
    if prepared_source is None:
        if expected_revision is not None or expected_suite_revision is not None:
            raise ValueError("prepared source identity requires --prepared-source")
        value = snapshot()
        if value["dirty"] or value["suite_dirty"]:
            raise ValueError("fuzz campaigns require clean library and suite source")
        return value
    if expected_revision is None or expected_suite_revision is None:
        raise ValueError("prepared source requires both immutable repository identities")
    from macro_lock_selection import verify_prepared
    verify_prepared(ROOT, ROOT / "coaptic", expected_revision, expected_suite_revision, prepared_source)
    return snapshot()


def run_campaign(command, seconds, directory, execute=subprocess.run, *, env=None):
    row = {"command": command, "passed": False}
    paths = {name: directory / (name + ".log") for name in ("stdout", "stderr")}
    try:
        with paths["stdout"].open("wb") as stdout, paths["stderr"].open("wb") as stderr:
            result = execute(command, stdout=stdout, stderr=stderr, timeout=seconds + 900, env=env)
        row["exit_code"] = result.returncode
        for name, path in paths.items():
            row[name + "_file"] = str(path)
            if path.stat().st_size > MAX_LOG_BYTES:
                raise ValueError("campaign log exceeds 8 MiB evidence bound")
            row[name] = path.read_text(encoding="utf-8", errors="replace")
        if result.returncode == 0:
            row["evidence"] = evidence(row["stderr"])
            row["passed"] = True
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        row["error"] = str(error)
    return row


def evidence(stderr):
    counters = re.findall(r"cov: (\d+) ft: (\d+)", stderr)
    executions = re.findall(r"stat::number_of_executed_units:\s*(\d+)", stderr)
    if not counters or not executions or int(executions[-1]) < 100:
        raise ValueError("missing coverage feedback or executed-input evidence")
    coverage, features = map(int, counters[-1])
    if coverage == 0 or features == 0:
        raise ValueError("empty coverage feedback")
    return {"coverage_points": coverage, "features": features, "executed_inputs": int(executions[-1])}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--asan-runtime-directory", type=Path,
                        help="Windows directory containing clang_rt.asan_dynamic-x86_64.dll")
    parser.add_argument("--prepared-source", type=Path,
                        help="Independently checked CI source-preparation receipt")
    parser.add_argument("--expected-revision", help="Full library SHA for the prepared checkpoint")
    parser.add_argument("--expected-suite-revision", help="Full suite SHA for the prepared checkpoint")
    args = parser.parse_args(argv)
    if not 1 <= args.seconds <= 3600:
        parser.error("--seconds must be in 1..3600")
    env = os.environ.copy()
    runtime = None
    if args.asan_runtime_directory is not None:
        dll = args.asan_runtime_directory.resolve() / "clang_rt.asan_dynamic-x86_64.dll"
        if not dll.is_file():
            parser.error("ASan runtime DLL is missing from the specified directory")
        env["PATH"] = str(dll.parent) + os.pathsep + env.get("PATH", "")
        runtime = {"path": str(dll), "sha256": hashlib.sha256(dll.read_bytes()).hexdigest()}
    if args.prepared_source is not None:
        args.prepared_source = args.prepared_source.resolve()
    def capture():
        return checked_snapshot(args.prepared_source, args.expected_revision, args.expected_suite_revision)
    before = capture()
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    os.chdir(ROOT)
    work = Path(tempfile.mkdtemp(prefix="coaptic-fuzz-", dir=args.output.parent))
    # cargo-fuzz has no --locked flag. Resolve with --locked first, then
    # refuse any source/lock change made during compilation or execution.
    subprocess.run(["cargo", "+" + TOOLCHAIN, "metadata", "--locked", "--format-version=1",
                    "--manifest-path", "fuzz/Cargo.toml"], check=True, stdout=subprocess.DEVNULL)
    if capture() != before:
        raise ValueError("source or prepared lockfiles changed during preflight")
    report = {"schema": "coaptic-fuzz/1", "passed": False,
              **before, "work_directory": str(work), "asan_runtime": runtime,
              "compiler": subprocess.check_output(["rustc", "+" + TOOLCHAIN, "--version", "--verbose"], text=True),
              "cargo_fuzz": subprocess.check_output(["cargo", "fuzz", "--version"], text=True).strip(),
              "scope": "Coverage-guided libFuzzer campaigns with address sanitizer and semantic oracles",
              "unqualified": ["exhaustive inputs", "RFC requirement completeness", "state-machine lifecycle fuzzing", "device execution"],
              "campaigns": []}
    for target in TARGETS:
        directory = work / target
        corpus = directory / "corpus"
        corpus.mkdir(parents=True)
        data = SEEDS[target]
        (corpus / hashlib.sha256(data).hexdigest()).write_bytes(data)
        command = ["cargo", "+" + TOOLCHAIN, "fuzz", "run", "--sanitizer", "address", target, str(corpus), "--",
                   f"-max_total_time={args.seconds}", "-runs=1000000", "-max_len=4096", "-timeout=10",
                   "-rss_limit_mb=1024", "-malloc_limit_mb=64", "-seed=9177", "-print_final_stats=1",
                   "-artifact_prefix=" + str(directory) + os.sep]
        row = {"target": target, **run_campaign(command, args.seconds, directory, env=env)}
        source_failure = False
        try:
            if capture() != before:
                raise ValueError("source or prepared lockfiles changed during campaign")
        except Exception as error:
            detail = "campaign source check: " + type(error).__name__ + ": " + str(error)[:1024]
            row.update(passed=False, source_error=detail)
            row.setdefault("error", detail)
            source_failure = True
        report["campaigns"].append(row)
        print(("PASS " if row["passed"] else "FAIL ") + target, flush=True)
        if source_failure:
            break
    report["not_run"] = list(TARGETS[len(report["campaigns"]):])
    report["passed"] = len(report["campaigns"]) == len(TARGETS) and all(row["passed"] for row in report["campaigns"])
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
