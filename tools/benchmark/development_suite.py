"""Prepared fixed-profile regression screen; never CPU/peak-memory qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import tomllib

from native_profiles import dimensions
from native_lock import native_lock
from suite_process import run_worker

HERE = Path(__file__).resolve().parent
SUITE = HERE.parents[1]
NATIVE = HERE / "native"
PROFILES = (("small-device", 32), ("small-blockwise", 4096),
            ("service-fixed", 16384), ("service-allocated", 16384))
SECURITY = ("unprotected", "oscore")
OPERATIONS, WARMUP = 32, 4
JSON_LIMIT = 2 * 1024 * 1024
BUILD_LIMIT = 16 * 1024 * 1024
BINARY_LIMIT = 128 * 1024 * 1024
PREPARED_LIMIT = 256 * 1024 * 1024
SCHEMA = "coaptic-development-suite/1"
SOURCES = ("development_suite.py", "suite_process.py", "native_profiles.py",
           "native_diagnostic.py", "native_check.py", "native_lock.py", "linux_cpu.py")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def fingerprint(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def save(path, value):
    data = encoded(value)
    if len(data) > JSON_LIMIT:
        raise ValueError("suite result exceeds 2 MiB")
    with Path(path).open("xb") as stream:
        stream.write(data)


def load(path, limit=JSON_LIMIT):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("suite input exceeds allowance")
    return json.loads(raw, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, timeout=15).strip()


def identity(root):
    root = Path(root).resolve()
    if git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("preparation requires clean committed sources: " + str(root))
    return dict(path=str(root), commit=git(root, "rev-parse", "HEAD"),
                tree=git(root, "rev-parse", "HEAD^{tree}"))


def harness_identity():
    return {name: digest(HERE / name) for name in SOURCES}


def configuration():
    return dict(version=1, profiles=[dimensions(p, n) for p, n in PROFILES],
                security=list(SECURITY), concurrency=1, message_type="con",
                server_kind="coaptic-mio", operations=OPERATIONS, warmup=WARMUP,
                core_operations=16, core_warmup=128, core_calibrations=4096,
                client_timeout_ms=1000, policy="spin",
                allocated_service_requested_pool_ceiling_bytes=282640,
                unsupported_core_profiles=["small-blockwise"])


def host_identity():
    import psutil
    return dict(platform=platform.platform(), machine=platform.machine(),
                processor=platform.processor(), hostname=platform.node(),
                logical_cpus=psutil.cpu_count(), python=sys.version,
                psutil=psutil.__version__)


def task(spec, timeout, limit=JSON_LIMIT):
    with tempfile.TemporaryDirectory(prefix="coaptic-suite-task-") as directory:
        path = Path(directory) / "task.json"
        save(path, spec)
        # Windows venv redirectors may spawn the real interpreter before the
        # ownership gate. Launch the base interpreter directly; retain this
        # environment's module search path for psutil and existing helpers.
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        result = run_worker([sys._base_executable, "-B", str(Path(__file__).resolve()),
                             "_task", str(path)], timeout=timeout, limit=limit,
                            cwd=str(SUITE), env=environment)
        if result.returncode:
            error = RuntimeError("suite worker refused: " + str(result.returncode))
            error.stdout, error.stderr = result.stdout, result.stderr
            raise error
        return result


def resolved_core():
    manifest = NATIVE / "servers/Cargo.toml"
    dependency = tomllib.loads(manifest.read_text())["dependencies"]["coaptic"]
    return (manifest.parent / dependency["path"]).resolve()


def prepare(output, expected_core):
    """Called only inside the selected agent-resources Cargo lease."""
    started = time.perf_counter()
    output = Path(output).resolve()
    output.mkdir()  # Refuse overwrite, including a previous failed preparation.
    record = dict(schema=SCHEMA, kind="prepared", passed=False)
    try:
        target = Path(os.environ["CARGO_TARGET_DIR"]).resolve()
        core = resolved_core()
        before = dict(core=identity(core), suite=identity(SUITE))
        if before["core"]["commit"] != expected_core:
            raise ValueError("resolved dependency does not match --expected-core")
        harness = harness_identity()
        compiler = subprocess.check_output(["rustc", "+1.99.0", "-Vv"], text=True, timeout=15)
        cargo = subprocess.check_output(["cargo", "+1.99.0", "-V"], text=True, timeout=15)
        flags = {k: os.environ.get(k) for k in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                  "CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")}
        if any(k.startswith("CARGO_PROFILE_") for k in os.environ):
            raise ValueError("profile overrides are not supported; use the committed native profile")
        if flags["CARGO_BUILD_TARGET"]:
            raise ValueError("quick preparation requires a native host target")
        command = ["cargo", "+1.99.0", "build", "--release", "--locked", "--manifest-path",
                   str(NATIVE / "Cargo.toml"), "-p", "bench-rust-server"]
        for name in ("bench-rust-server", "bench-native-client", "bench-core"):
            command += ["--bin", name]
        with native_lock(core) as selected:
            build = task(dict(kind="build", command=command), timeout=900, limit=BUILD_LIMIT)
            (output / "build.log").write_bytes(build.stdout + build.stderr)
            lock_input = dict(selected)
        if before != dict(core=identity(core), suite=identity(SUITE)) or harness != harness_identity():
            raise ValueError("source changed during preparation")
        bins, total = {}, 0
        suffix = ".exe" if os.name == "nt" else ""
        for role, name in (("server", "bench-rust-server"), ("client", "bench-native-client"),
                           ("core", "bench-core")):
            source = target / "release" / (name + suffix)
            size = source.stat().st_size
            if not 0 < size <= BINARY_LIMIT or total + size > PREPARED_LIMIT:
                raise ValueError("prepared binary allowance")
            wanted = digest(source)
            copied = output / source.name
            shutil.copyfile(source, copied)
            if digest(copied) != wanted or digest(source) != wanted:
                raise ValueError("binary changed during copy")
            copied.chmod(copied.stat().st_mode | 0o100)
            bins[role] = dict(file=copied.name, bytes=size, sha256=wanted)
            total += size
        record.update(passed=True, sources=before, harness=harness, binaries=bins,
                      compiler=compiler, cargo=cargo, flags=flags, lock=lock_input,
                      host=host_identity(), build_command=command,
                      build_profile="release; thin LTO; one codegen unit; incremental=0; jobs=2",
                      native_manifest_sha256=digest(NATIVE / "Cargo.toml"),
                      server_manifest_sha256=digest(NATIVE / "servers/Cargo.toml"),
                      prepared_binary_bytes=total, build_seconds=build.duration_seconds)
    except BaseException as error:
        record.update(error=type(error).__name__ + ": " + str(error)[:1024])
        for attr in ("stdout", "stderr"):
            raw = getattr(error, attr, b"")
            if raw:
                (output / ("failure-" + attr + ".log")).write_bytes(raw[:BUILD_LIMIT])
        raise
    finally:
        record["preparation_seconds"] = time.perf_counter() - started
        save(output / "prepared.json", record)


def verify_prepared(path):
    path = Path(path).resolve()
    value = load(path / "prepared.json")
    if value.get("schema") != SCHEMA or value.get("kind") != "prepared" or value.get("passed") is not True:
        raise ValueError("not a successful prepared receipt")
    if value.get("harness") != harness_identity():
        raise ValueError("prepared harness differs from the running harness")
    if value.get("host") != host_identity():
        raise ValueError("prepared host differs; prepare on this host")
    if set(value.get("binaries", {})) != {"server", "client", "core"}:
        raise ValueError("prepared binary roles")
    for row in value["binaries"].values():
        if Path(row["file"]).name != row["file"]:
            raise ValueError("prepared binary path escapes bundle")
        binary = path / row["file"]
        if binary.stat().st_size != row["bytes"] or digest(binary) != row["sha256"]:
            raise ValueError("prepared binary changed")
    return value, {k: str(path / v["file"]) for k, v in value["binaries"].items()}


def validate_core(value, profile, security):
    if (value.get("operations") != 16 or value.get("warmup") != 128
            or value.get("verified") != 144 or value.get("black_box") is not True
            or value.get("security") != security or value.get("concurrency") != 1
            or value.get("message_type") != "CON" or value.get("calibration_samples") != 4096
            or len(value.get("clock_calibration_ns", [])) != 4096):
        raise ValueError("incomplete core probe identity or verification")
    service = profile.startswith("service-")
    if (value.get("profile") != ("Service" if service else "SmallDevice")
            or value.get("storage") != ("allocated" if profile == "service-allocated" else "fixed")
            or value.get("payload_bytes") != (16384 if service else 32)):
        raise ValueError("mismatched core profile")
    samples = value.get("server_poll_wall_sum_ns" if service else "latencies_ns")
    if (not isinstance(samples, list) or len(samples) != 16
            or any(type(v) is not int or not 0 <= v < 2**64 for v in samples)):
        raise ValueError("core timing samples invalid")
    if any(type(v) is not int or not 0 <= v < 2**64 for v in value["clock_calibration_ns"]):
        raise ValueError("calibration samples invalid")
    if service:
        expected = dict(routes=32, populated_routes=1, calls=4, deferred=8, associations=1,
                        security_requests=4, rx_slots=32, tx_slots=32, datagram_bytes=1472,
                        dedup=64, observe=32, rx_body_slots=4, tx_body_slots=4,
                        body_bytes=16384, blockwise=True)
        if value.get("server_capacities") != expected:
            raise ValueError("core Service capacities differ")
        counts, sends = value.get("server_poll_counts"), value.get("sends", {})
        if (not isinstance(counts, list) or len(counts) != 16 or any(type(n) is not int or not 16 <= n <= 32 for n in counts)
                or sends.get("combined") != sends.get("client", -1) + sends.get("server", -1)
                or not 4608 <= sends["combined"] <= 60000):
            raise ValueError("core blockwise work accounting")
    else:
        expected = dimensions(profile, 32)
        for k in ("routes", "populated_routes", "calls", "deferred", "associations", "security_requests",
                  "rx_slots", "tx_slots", "rx_datagram_bytes", "tx_datagram_bytes", "dedup", "observe",
                  "rx_body_slots", "tx_body_slots", "blockwise"):
            if value.get(k) != expected[k]:
                raise ValueError("core SmallDevice capacity differs: " + k)
    if not isinstance(value.get("memory"), dict):
        raise ValueError("missing core owner ledger")
    return dict(median_ns=statistics.median(samples), maximum_ns=max(samples))


def run_suite(prepared, output, client_from=None):
    started = time.perf_counter()
    output = Path(output)
    if output.exists():
        raise ValueError("output exists; preserve prior runs")
    bundle, bins = verify_prepared(prepared)
    client_bundle, client_bins = verify_prepared(client_from or prepared)
    if any(bundle[k] != client_bundle[k] for k in ("harness", "host", "compiler", "cargo", "flags")):
        raise ValueError("frozen client preparation differs")
    bins["client"] = client_bins["client"]
    config, host = configuration(), host_identity()
    result = dict(schema=SCHEMA, kind="run", passed=False, configuration=config,
                  configuration_sha256=fingerprint(config), host=host, preparation=bundle,
                  client_preparation=client_bundle, cells=[], reliability=[],
                  not_run=[], limitation="development wall-time/owner regression signals only; no qualified CPU, extreme-tail, throughput, device timing or whole-memory claims")
    pending = [(p, s) for p, _ in PROFILES for s in SECURITY]
    active_phase = "independent reliability"
    try:
        # Reliability must complete before any performance interpretation.
        proof = task(dict(kind="reliability-common", **bins), timeout=10)
        result["reliability"].append(dict(kind="independent-body-corruption-and-security-recovery",
                                           passed=True, seconds=proof.duration_seconds,
                                           output=proof.stdout.decode(errors="replace")))
        for profile, size in PROFILES:
            active_phase = "profile reliability: " + profile
            proof = task(dict(kind="reliability-profile", profile=profile, size=size, **bins), timeout=10)
            ledgers = [json.loads(line) for line in proof.stdout.splitlines()]
            if len(ledgers) != 2 or {r["security"] for r in ledgers} != set(SECURITY):
                raise ValueError("profile reliability cells missing")
            result["reliability"].append(dict(profile=profile, passed=True,
                                              seconds=proof.duration_seconds, cells=ledgers))
        for profile, size in PROFILES:
            for security in SECURITY:
                elapsed = time.perf_counter() - started
                if elapsed >= 55:
                    raise TimeoutError("development suite budget exhausted before next cell")
                active_phase = "socket: " + profile + "/" + security
                cell = dict(profile=profile, security=security, status="running")
                result["cells"].append(cell)
                pending.remove((profile, security))
                spec = dict(kind="socket", profile=profile, size=size, security=security, **bins)
                observed = task(spec, timeout=min(10, 60 - elapsed))
                socket_value = json.loads(observed.stdout)
                ledger = socket_value["server_resources"]
                heap_ceiling = 282640 if profile == "service-allocated" else 0
                if not 0 <= ledger["app_requested_heap_bytes"] <= heap_ceiling:
                    raise ValueError("declared profile pool-heap ceiling exceeded")
                cell.update(socket=socket_value, socket_worker_seconds=observed.duration_seconds)
                if profile == "small-blockwise":
                    cell["core"] = dict(status="unsupported", reason="existing core probe has no SmallDevice blockwise mode")
                else:
                    active_phase = "core: " + profile + "/" + security
                    elapsed = time.perf_counter() - started
                    if elapsed >= 55:
                        raise TimeoutError("development suite budget exhausted before core cell")
                    core = task(dict(kind="core", profile=profile, security=security, **bins), timeout=min(10, 60 - elapsed))
                    raw = json.loads(core.stdout)
                    cell["core"] = dict(status="passed", report=raw,
                                        summary=validate_core(raw, profile, security),
                                        worker_seconds=core.duration_seconds)
                cell["status"] = "passed"
        verify_prepared(prepared)
        verify_prepared(client_from or prepared)
        result["passed"] = True
    except BaseException as error:
        result["failed_phase"] = active_phase
        if result["cells"] and result["cells"][-1]["status"] == "running":
            result["cells"][-1]["status"] = "failed"
        result["error"] = dict(type=type(error).__name__, reason=str(error)[:1024],
                               stdout=getattr(error, "stdout", b"")[:65536].decode(errors="replace"),
                               stderr=getattr(error, "stderr", b"")[:65536].decode(errors="replace"))
        raise
    finally:
        result["not_run"] = [dict(profile=p, security=s) for p, s in pending]
        result["total_seconds"] = time.perf_counter() - started
        result["within_minute"] = result["total_seconds"] <= 60
        result["core_warmup_limit"] = "128 verified warmups per core process; startup/warmup/calibration durations not separately instrumented"
        save(output, result)
    return result


def compare(before, after):
    a, b = load(before), load(after)
    for r in (a, b):
        if r.get("schema") != SCHEMA or r.get("kind") != "run" or r.get("passed") is not True:
            raise ValueError("comparison requires two complete successful runs")
        if r.get("configuration") != configuration() or r.get("configuration_sha256") != fingerprint(configuration()):
            raise ValueError("configuration mismatch")
        if len(r.get("cells", [])) != 8 or r.get("not_run"):
            raise ValueError("incomplete comparison rows")
        wanted = [(p, s) for p, _ in PROFILES for s in SECURITY]
        if [(c.get("profile"), c.get("security")) for c in r["cells"]] != wanted:
            raise ValueError("comparison must include every exact profile/security row")
        if any(c.get("status") != "passed" for c in r["cells"]):
            raise ValueError("comparison includes an unfinished cell")
        if (len(r.get("reliability", [])) != 5
                or any(v.get("passed") is not True for v in r["reliability"])):
            raise ValueError("comparison requires completed reliability checks")
        from native_diagnostic import validate_report
        for cell in r["cells"]:
            size = dict(PROFILES)[cell["profile"]]
            validate_report(cell["socket"]["report"], size, OPERATIONS, "spin", cell["security"])
            if cell["socket"]["report"]["warmup"] != WARMUP:
                raise ValueError("comparison warmup differs")
            ledger = cell["socket"]["server_resources"]
            for k, expected in dimensions(cell["profile"], size).items():
                if ledger.get(k) != expected:
                    raise ValueError("comparison capacities differ: " + k)
            if cell["profile"] == "small-blockwise":
                if cell["core"].get("status") != "unsupported":
                    raise ValueError("unsupported core cell misrepresented")
            elif (cell["core"].get("status") != "passed"
                    or cell["core"].get("summary") != validate_core(cell["core"]["report"], cell["profile"], cell["security"])):
                raise ValueError("comparison core verification differs")
    for key in ("host", "configuration_sha256"):
        if a[key] != b[key]:
            raise ValueError("comparison mismatch: " + key)
    for key in ("harness", "compiler", "cargo", "flags", "native_manifest_sha256", "server_manifest_sha256"):
        if a["preparation"][key] != b["preparation"][key]:
            raise ValueError("build/harness mismatch: " + key)
    if a["client_preparation"]["binaries"]["client"] != b["client_preparation"]["binaries"]["client"]:
        raise ValueError("comparison requires the same frozen loopback client")
    rows = []
    for left, right in zip(a["cells"], b["cells"]):
        if (left["profile"], left["security"]) != (right["profile"], right["security"]):
            raise ValueError("comparison row ordering differs")
        x, y = (v["socket"]["report"]["latencies_ns"] for v in (left, right))
        old, new = statistics.median(x), statistics.median(y)
        ledger_a, ledger_b = (v["socket"]["server_resources"] for v in (left, right))
        row = dict(profile=left["profile"], security=left["security"],
                   socket_median_ns_before=old, socket_median_ns_after=new,
                   socket_median_change_ns=new - old,
                   app_inline_bytes_before=ledger_a["app_including_adapter_bytes"],
                   app_inline_bytes_after=ledger_b["app_including_adapter_bytes"],
                   app_requested_pool_heap_bytes_before=ledger_a["app_requested_heap_bytes"],
                   app_requested_pool_heap_bytes_after=ledger_b["app_requested_heap_bytes"])
        if left["core"]["status"] == right["core"]["status"] == "passed":
            row.update(core_poll_median_ns_before=left["core"]["summary"]["median_ns"],
                       core_poll_median_ns_after=right["core"]["summary"]["median_ns"])
        rows.append(row)
    return dict(schema=SCHEMA, kind="comparison", rows=rows,
                before_core=a["preparation"]["sources"]["core"],
                after_core=b["preparation"]["sources"]["core"],
                interpretation="short-run descriptive differences, not a gain/regression acceptance verdict; original CPU and latency gates remain separate")


def worker(spec):
    if spec["kind"] == "build":
        environment = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2")
        return subprocess.call(spec["command"], cwd=SUITE, env=environment)
    if spec["kind"] == "core":
        args = [spec["core"], "16", spec["security"]]
        args += (["--small-device"] if spec["profile"] == "small-device" else
                 ["--" + spec["profile"], "16384"])
        return subprocess.call(args)
    if spec["kind"].startswith("reliability"):
        import native_check
        if spec["kind"] == "reliability-common":
            native_check.check(spec["server"], spec["client"])
        else:
            native_check.check_profile(spec["server"], spec["client"], spec["profile"], spec["size"])
        return 0
    from native_diagnostic import measure
    report = measure(spec["server"], spec["client"], spec["size"], OPERATIONS, WARMUP,
                     1000, "spin", spec["security"], server_kind="coaptic-mio",
                     resource_profile=spec["profile"], phase_timeout_seconds=3)
    print(json.dumps(report, allow_nan=False))
    return 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "_task":
        # The owner assigns containment before this gate opens. No child launches earlier.
        if sys.stdin.buffer.readline(4) != b"go\n":
            raise RuntimeError("worker ownership gate refused")
        return worker(load(sys.argv[2]))
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="mode", required=True)
    for mode in ("prepare", "_prepare"):
        s = sub.add_parser(mode)
        s.add_argument("--output", type=Path, required=True)
        s.add_argument("--expected-core", required=True)
        if mode == "prepare":
            s.add_argument("--build-lane", required=True)
    s = sub.add_parser("run")
    s.add_argument("--prepared", type=Path, required=True)
    s.add_argument("--client-from", type=Path)
    s.add_argument("--output", type=Path, required=True)
    s = sub.add_parser("compare")
    s.add_argument("--before", type=Path, required=True)
    s.add_argument("--after", type=Path, required=True)
    s.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.mode == "prepare":
        binary = shutil.which("agent-resources")
        if not binary:
            raise RuntimeError("agent-resources required for the registered Cargo lane")
        return subprocess.call([binary, "run", "--id", a.build_lane, "--directory", str(SUITE),
                                sys.executable, "-B", str(Path(__file__).resolve()), "_prepare",
                                "--expected-core", a.expected_core, "--output", str(a.output.resolve())])
    if a.mode == "_prepare":
        prepare(a.output, a.expected_core)
    elif a.mode == "run":
        result = run_suite(a.prepared, a.output, a.client_from)
        print(json.dumps(dict(passed=result["passed"], seconds=result["total_seconds"],
                              within_minute=result["within_minute"], socket_cells=8,
                              core_cells=6, unsupported_core_cells=2, result=str(a.output))))
    else:
        save(a.output, compare(a.before, a.after))
        print("Descriptive revision comparison written to " + str(a.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
