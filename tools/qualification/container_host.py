"""Run protected fixed/heap host examples in a pinned, disposable Linux container."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from source_identity import LIBRARY, source_identity

# Official rust:1.97.1-bookworm manifest index, resolved before qualification.
IMAGE = "rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97"
SUCCESS = "OSCORE: received all 200 bytes"
CASES = (
    ("fixed-success", "fixed", [], None),
    ("fixed-unknown-argument", "fixed", ["--plaintext"], "usage: oscore_pair"),
    ("fixed-allocation-unavailable", "fixed", ["--alloc"], "--alloc requires building"),
    ("fixed-recovery", "fixed", [], None),
    ("heap-success", "heap", ["--alloc"], None),
    ("heap-unknown-argument", "heap", ["--plaintext"], "usage: oscore_pair"),
    ("heap-recovery", "heap", ["--alloc"], None),
)


def verdict(code, stdout, stderr, refusal):
    if refusal is None:
        return code == 0 and stdout.splitlines().count(SUCCESS) == 1
    # A crash or infrastructure failure must not count as the intended refusal.
    return code == 1 and refusal in stderr and SUCCESS not in stdout


def run(output):
    output = output.resolve()
    if output.exists():
        raise ValueError("output directory already exists; preserve earlier observations")
    output.mkdir(parents=True)
    identity = source_identity()
    report = {**identity, "image": IMAGE, "commands": [], "cases": [], "passed": False,
              "limitations": "localhost examples with fresh credentials; no enrollment, device, routed-network, load or durability qualification"}
    report["library_lock_sha256"] = hashlib.sha256((LIBRARY / "Cargo.lock").read_bytes()).hexdigest()
    name = "coaptic-qualification-" + uuid.uuid4().hex
    created = False

    def save():
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    def command(label, args, timeout=120):
        started = time.monotonic()
        stdout_path, stderr_path = output / (label + ".stdout"), output / (label + ".stderr")
        row = {"label": label, "command": args, "timeout_seconds": timeout}
        report["commands"].append(row)
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                proc = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
            row["exit_code"] = proc.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            row["error"] = str(error)
            raise
        finally:
            row["seconds"] = time.monotonic() - started
            save()
        return proc.returncode, stdout_path.read_text(encoding="utf-8", errors="replace"), stderr_path.read_text(encoding="utf-8", errors="replace")

    def require(label, args, timeout=120):
        code, stdout, _ = command(label, args, timeout)
        if code:
            raise RuntimeError(f"{label} failed with exit {code}; see retained logs")
        return stdout

    try:
        if identity["dirty"] or identity["suite_dirty"]:
            raise ValueError("qualification requires clean library and suite sources")
        require("pull", ["docker", "pull", IMAGE], 600)
        inspected = json.loads(require("image-inspect", ["docker", "image", "inspect", IMAGE]))[0]
        report["resolved_image"] = {key: inspected[key] for key in ("Id", "RepoDigests", "Architecture", "Os")}
        if inspected["Os"] != "linux":
            raise ValueError("expected a Linux image")
        require("create", ["docker", "create", "--name", name, "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "3g", "--cpus", "2",
                "--tmpfs", "/work:exec,size=2g", "--tmpfs", "/tmp:exec,size=128m",
                "--mount", f"type=bind,source={LIBRARY.resolve()},target=/source,readonly",
                "--workdir", "/source", "--env", "CARGO_HOME=/work/cargo", "--env", "CARGO_INCREMENTAL=0",
                "--env", "CARGO_BUILD_JOBS=2", "--env", "RUSTUP_TOOLCHAIN=1.97.1", IMAGE, "sleep", "2400"])
        created = True
        require("start", ["docker", "start", name])
        report["rustc"] = require("rustc", ["docker", "exec", name, "rustc", "-Vv"])
        report["cargo"] = require("cargo", ["docker", "exec", name, "cargo", "-V"])
        for mode, features in (("fixed", "std"), ("heap", "std,alloc")):
            require("build-" + mode, ["docker", "exec", name, "cargo", "build", "--locked", "--example", "oscore_pair",
                    "--features", features, "--target-dir", "/work/" + mode], 900)
            report[mode + "_binary_sha256"] = require("hash-" + mode, ["docker", "exec", name, "sha256sum",
                    f"/work/{mode}/debug/examples/oscore_pair"]).split()[0]
        # Dependency downloads are finished. Runtime cases have only container loopback.
        require("disconnect", ["docker", "network", "disconnect", "bridge", name])
        network = json.loads(require("network-inspect", ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", name]))
        if network:
            raise ValueError("container remains attached to an external network")
        report["runtime_networks"] = network
        for label, mode, args, refusal in CASES:
            code, stdout, stderr = command(label, ["docker", "exec", name, f"/work/{mode}/debug/examples/oscore_pair", *args], 30)
            passed = verdict(code, stdout, stderr, refusal)
            report["cases"].append({"name": label, "exit_code": code, "passed": passed, "expected_refusal": refusal})
            save()
            if not passed:
                raise RuntimeError(f"{label} failed its success/refusal oracle")
        if source_identity() != identity:
            raise ValueError("source identity changed during qualification")
        report["passed"] = True
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    finally:
        if created:
            # Only remove the unique container created by this invocation; retain images/caches.
            try:
                code, _, _ = command("cleanup", ["docker", "rm", "--force", name], 30)
                if code:
                    report["passed"] = False
                    report["cleanup_error"] = f"exit {code}"
            except (OSError, subprocess.TimeoutExpired) as error:
                report["passed"] = False
                report["cleanup_error"] = str(error)
        save()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    args = parser.parse_args()
    result = run(args.output)
    print(json.dumps({"passed": result["passed"], "cases": result["cases"], "error": result.get("error")}))
    raise SystemExit(0 if result["passed"] else 1)
