import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from source_identity import source_identity

"""Pinned LLVM counters and named contract execution evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

from host import SUMMARY, TOOLCHAIN, text
from contracts import load_and_evaluate

ROOT = Path(__file__).resolve().parents[2] / "coaptic"


def artifacts(stdout):
    found = set()
    for line in stdout.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("reason") == "compiler-artifact" and row.get("profile", {}).get("test") and row.get("executable"):
            found.add(row["executable"])
    if not found:
        raise ValueError("no executable test artifacts")
    return sorted(found)


def source_totals(export, root, require_branches=False):
    files = []
    for unit in export.get("data", []):
        for row in unit.get("files", []):
            path = Path(row["filename"]).resolve()
            if path.is_relative_to(root.resolve() / "src"):
                files.append({"path": path.relative_to(root.resolve()).as_posix(), "summary": row["summary"]})
    if not files or len({row["path"] for row in files}) != len(files):
        raise ValueError("missing or duplicate source-file coverage")
    totals = {}
    for metric in ("lines", "regions", "functions", *(("branches",) if require_branches else ())):
        count = covered = 0
        for row in files:
            value = row["summary"][metric]
            n, hit = value["count"], value["covered"]
            if type(n) is not int or type(hit) is not int or not 0 <= hit <= n:
                raise ValueError("invalid coverage counters")
            count += n
            covered += hit
        if count == 0:
            raise ValueError("empty coverage metric")
        totals[metric] = {"count": count, "covered": covered, "percent": 100 * covered / count}
    return files, totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--branches", action="store_true")
    args = parser.parse_args()
    os.chdir(ROOT)
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.work_root.mkdir(parents=True, exist_ok=True)
    # Fresh directory prevents stale profiles or cached artifacts passing a run.
    work = Path(tempfile.mkdtemp(prefix="coaptic-coverage-", dir=args.work_root.resolve()))
    env = os.environ.copy()
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    toolchain = "nightly-2026-10-01" if args.branches else TOOLCHAIN
    env.update(CARGO_TARGET_DIR=str(work / "build"), CARGO_INCREMENTAL="0",
               CARGO_PROFILE_TEST_DEBUG="2", CARGO_PROFILE_DEV_DEBUG="2",
               RUSTFLAGS="-C instrument-coverage", LLVM_PROFILE_FILE=str(work / "%p-%m.profraw"))
    if args.branches:
        env["RUSTFLAGS"] += " -Z coverage-options=branch"
    report = {"schema": "coaptic-source-coverage/1", "passed": False,
              **source_identity(),
              "platform": platform.platform(), "work_directory": str(work), "commands": [],
              "scope": "All-feature library unit/integration test execution; compiled src tree includes inline/unit-test modules",
              "unqualified": ["branch/condition coverage", "RFC requirement completeness", "other feature configurations", "rustdoc execution", "device execution", "exhaustive input space"]}
    if args.branches:
        report["schema"] = "coaptic-branch-coverage/1"
        report["unqualified"][0] = "condition/MC/DC coverage"

    def run(command, output=None):
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=900)
        row = {"command": command, "exit_code": result.returncode, "stderr": result.stderr}
        if output:
            output.write_text(result.stdout, encoding="utf-8")
            row["stdout_file"] = str(output)
        else:
            row["stdout"] = result.stdout
        report["commands"].append(row)
        if result.returncode:
            raise RuntimeError("command failed: " + command[0])
        return result.stdout

    try:
        compiler = run(["rustc", "+" + toolchain, "--version", "--verbose"])
        report["compiler"] = compiler
        host = next(line.split(": ", 1)[1] for line in compiler.splitlines() if line.startswith("host: "))
        sysroot = Path(run(["rustc", "+" + toolchain, "--print", "sysroot"]).strip())
        suffix = ".exe" if os.name == "nt" else ""
        llvm = sysroot / "lib" / "rustlib" / host / "bin"
        stdout = run(["cargo", "+" + toolchain, "test", "--locked", "-p", "coaptic", "--all-features",
                      "--lib", "--tests", "--message-format=json"])
        report["executed"] = sum(int(passed) for passed, _ in SUMMARY.findall(stdout))
        report["ignored"] = sum(int(ignored) for _, ignored in SUMMARY.findall(stdout))
        if not report["executed"]:
            raise ValueError("no executed tests")
        report["contracts"] = load_and_evaluate(stdout)
        if not report["contracts"]["passed"]:
            raise ValueError("missing named contract execution")
        objects = artifacts(stdout)
        report["test_binaries"] = [{"path": name, "sha256": hashlib.sha256(Path(name).read_bytes()).hexdigest()} for name in objects]
        profiles = sorted(str(p) for p in work.glob("*.profraw"))
        if not profiles:
            raise ValueError("no fresh profiles")
        merged = str(work / "merged.profdata")
        run([str(llvm / ("llvm-profdata" + suffix)), "merge", "-sparse", *profiles, "-o", merged])
        exported = args.output.with_name(args.output.stem + "-llvm.json")
        raw = run([str(llvm / ("llvm-cov" + suffix)), "export", objects[0],
                   *["-object=" + name for name in objects[1:]], "-instr-profile=" + merged], exported)
        report["files"], report["totals"] = source_totals(json.loads(raw), ROOT, args.branches)
        report["llvm_export"] = str(exported)
        report["passed"] = True
    except (OSError, ValueError, RuntimeError, StopIteration, KeyError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
        if isinstance(error, subprocess.TimeoutExpired):
            report["timeout"] = {"command": error.cmd, "stdout": text(error.stdout), "stderr": text(error.stderr)}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("passed", "totals", "error") if key in report}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
