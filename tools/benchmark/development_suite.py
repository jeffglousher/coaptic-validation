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
PROFILES = (("small-device", 32), ("small-blockwise", 4096), ("small-observe", 4096),
            ("device-fixed", 4096), ("gateway-fixed", 8192), ("service-datagram", 1024),
            ("service-fixed", 16384), ("service-allocated", 16384))
CORE_PROFILES = ("small-device", "service-fixed", "service-allocated")
BINARIES = {"server": "bench-rust-server", "client": "bench-native-client",
            "core": "bench-core", "observe": "bench-observe-proof"}
SECURITY = ("unprotected", "oscore")
OPERATIONS, WARMUP = 32, 4
JSON_LIMIT = 2 * 1024 * 1024
BUILD_LIMIT = 16 * 1024 * 1024
BINARY_LIMIT = 32 * 1024 * 1024
PREPARED_LIMIT = 32 * 1024 * 1024
SCHEMA = "coaptic-development-suite/2"
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


def socket_options(profile):
    concurrency = (1 if profile.startswith("small-") else
                   2 if profile in ("device-fixed", "gateway-fixed") else 4)
    return dict(concurrency=concurrency, independent_endpoints=concurrency > 1,
                message_type="con")


def configuration():
    return dict(version=2, profiles=[dimensions(p, n) | socket_options(p) for p, n in PROFILES],
                security=list(SECURITY), server_kind="coaptic-mio", operations=OPERATIONS,
                warmup=WARMUP, core_operations=16, core_warmup=128, core_calibrations=4096,
                core_concurrency=1, core_scope="separate C1 supporting probes; not concurrent socket workload",
                client_timeout_ms=1000, policy="spin",
                observe_profile="small-observe", observe_payload_bytes=4096,
                observe_client_requested_pool_ceiling_bytes=32768,
                allocated_service_requested_pool_ceiling_bytes=282640,
                unsupported_core_profiles=[p for p, _ in PROFILES if p not in CORE_PROFILES])


def host_identity():
    import psutil
    return dict(platform=platform.platform(), machine=platform.machine(),
                processor=platform.processor(), hostname=platform.node(),
                logical_cpus=psutil.cpu_count(), python=sys.version,
                psutil=psutil.__version__)


def task(spec, timeout, limit=JSON_LIMIT):
    base = Path(tempfile.gettempdir()).resolve()
    directory = Path(tempfile.mkdtemp(prefix="coaptic-suite-task-", dir=base)).resolve()
    primary = None
    try:
        path = directory / "task.json"
        save(path, spec)
        # Windows venv redirectors may spawn the real interpreter before the
        # ownership gate. Launch the base interpreter directly; retain this
        # environment's module search path for psutil and existing helpers.
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path),
                           TMP=str(directory), TEMP=str(directory), TMPDIR=str(directory))
        result = run_worker([sys._base_executable, "-B", str(Path(__file__).resolve()),
                             "_task", str(path)], timeout=timeout, limit=limit,
                            cwd=str(SUITE), env=environment,
                            settle_build_auxiliaries=spec["kind"] == "build")
        if result.returncode:
            error = RuntimeError("suite worker refused: " + str(result.returncode))
            error.stdout, error.stderr = result.stdout, result.stderr
            raise error
        return result
    except BaseException as error:
        primary = error
        raise
    finally:
        if primary is not None and getattr(primary, "cleanup_unresolved", False):
            primary.temporary_directory = str(directory)
        else:
            try:
                # Only the exact owned directory, after group/job settlement.
                if directory.resolve() != directory or directory.parent != base or not directory.name.startswith("coaptic-suite-task-"):
                    raise RuntimeError("temporary cleanup target identity changed")
                shutil.rmtree(directory)
            except BaseException as cleanup:
                if primary is None:
                    cleanup.temporary_directory = str(directory)
                    raise
                primary.temporary_directory = str(directory)
                primary.add_note("temporary cleanup: " + str(cleanup)[:512])


def resolved_core():
    manifest = NATIVE / "servers/Cargo.toml"
    dependency = tomllib.loads(manifest.read_text())["dependencies"]["coaptic"]
    return (manifest.parent / dependency["path"]).resolve()


def cargo_inputs():
    """A deliberately narrow build contract, not an effective-config guess."""
    allowed = {"CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS"}
    if any(k.startswith("CARGO_") and k not in allowed for k in os.environ):
        raise ValueError("unsupported ambient CARGO_* setting; use the recorded native build contract")
    if any(os.environ.get(k) for k in ("RUSTC", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP")):
        raise ValueError("compiler overrides/wrappers are not supported by preparation")
    home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).resolve()
    locations = [p / ".cargo" / n for p in (SUITE, *SUITE.parents) for n in ("config", "config.toml")]
    locations += [home / n for n in ("config", "config.toml")]
    configs = {}
    for path in dict.fromkeys(locations):
        if not path.exists():
            continue
        if path.stat().st_size > 65536:
            raise ValueError("Cargo configuration exceeds preparation bound")
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
        if set(parsed) - {"registry", "registries", "source", "net", "http", "credential-alias", "alias"}:
            raise ValueError("unsupported Cargo build/target/profile/env configuration: " + str(path))
        configs[str(path.resolve())] = digest(path)
    return dict(config_files=configs, rustflags={k: os.environ.get(k) for k in
                ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")})


def toolchain():
    tools = {}
    for name in ("rustc", "cargo"):
        path = Path(subprocess.check_output(["rustup", "which", "--toolchain", "1.99.0", name],
                                            text=True, timeout=15).strip()).resolve()
        tools[name] = dict(path=str(path), sha256=digest(path))
    compiler = subprocess.check_output([tools["rustc"]["path"], "-Vv"], text=True, timeout=15)
    cargo = subprocess.check_output([tools["cargo"]["path"], "-V"], text=True, timeout=15)
    return compiler, cargo, tools


def cargo_artifacts(raw, target):
    artifacts, finished = {}, False
    wanted = set(BINARIES.values())
    target = Path(target).resolve()
    for line in raw.splitlines():
        if not line.startswith(b"{"):
            continue  # Build-script output need not be Cargo JSON.
        row = json.loads(line)
        if row.get("reason") == "build-finished":
            if row.get("success") is not True:
                raise ValueError("Cargo did not report a successful build")
            finished = True
        if row.get("reason") != "compiler-artifact":
            continue
        name = row.get("target", {}).get("name")
        if name not in wanted or "bin" not in row.get("target", {}).get("kind", []):
            continue
        value = row.get("executable")
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError("Cargo executable artifact path missing")
        path = Path(value).resolve()
        if not path.is_relative_to(target):
            raise ValueError("Cargo artifact outside registered target")
        if name in artifacts and artifacts[name] != path:
            raise ValueError("ambiguous Cargo executable artifacts")
        artifacts[name] = path
    if not finished or set(artifacts) != wanted:
        raise ValueError("Cargo executable artifact receipts incomplete")
    return artifacts


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
        flags = cargo_inputs()
        compiler, cargo, tools = toolchain()
        command = [tools["cargo"]["path"], "build", "--release", "--locked",
                   "--message-format=json-render-diagnostics", "--manifest-path",
                   str(NATIVE / "Cargo.toml"), "-p", "bench-rust-server"]
        for name in BINARIES.values():
            command += ["--bin", name]
        record.update(sources=before, harness=harness, compiler=compiler, cargo=cargo,
                      flags=flags, tools=tools, host=host_identity(), build_command=command)
        with native_lock(core) as selected:
            record["lock"] = dict(selected)
            build = task(dict(kind="build", command=command, rustc=tools["rustc"]["path"]), timeout=900, limit=BUILD_LIMIT)
            record["build_auxiliaries_settled"] = build.descendants_settled
            (output / "build.log").write_bytes(build.stdout + build.stderr)
            lock_input = dict(selected)
        if (before != dict(core=identity(core), suite=identity(SUITE))
                or harness != harness_identity() or flags != cargo_inputs()):
            raise ValueError("source changed during preparation")
        if any(digest(t["path"]) != t["sha256"] for t in tools.values()):
            raise ValueError("compiler/Cargo changed during preparation")
        artifacts = cargo_artifacts(build.stdout, target)
        bins, total = {}, 0
        for role, name in BINARIES.items():
            source = artifacts[name]
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
        if getattr(error, "temporary_directory", None):
            record["retained_temporary_directory"] = error.temporary_directory
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
    if set(value.get("binaries", {})) != set(BINARIES):
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


def validate_socket(value, profile, security):
    from native_diagnostic import validate_report, validate_endpoint_report
    options = socket_options(profile)
    validate_report(value["report"], dict(PROFILES)[profile], OPERATIONS, "spin", security,
                    **options)
    if value["report"]["warmup"] != WARMUP:
        raise ValueError("suite warmup differs")
    if options["independent_endpoints"]:
        validate_endpoint_report(value["report"], options["concurrency"], True, require_overlap=True)
    for key, expected in dimensions(profile, dict(PROFILES)[profile]).items():
        if value["server_resources"].get(key) != expected:
            raise ValueError("suite capacity differs: " + key)
    requested = value["server_resources"].get("app_requested_heap_bytes")
    if type(requested) is not int or not 0 <= requested <= (282640 if profile == "service-allocated" else 0):
        raise ValueError("declared profile pool-heap ceiling exceeded")


def validate_profile_reliability(rows, profile):
    size = dict(PROFILES)[profile]
    if not isinstance(rows, list) or [r.get("security") for r in rows] != list(SECURITY):
        raise ValueError("profile reliability security cohorts differ")
    expected = dimensions(profile, size)
    for row in rows:
        if (row.get("profile") != profile or row.get("size") != size or row.get("completed") != 2
                or row.get("oversized_bytes") != expected["rx_datagram_bytes"] + 1
                or row.get("expected_client_refusals") != (2 if row["security"] == "oscore" else 1)):
            raise ValueError("profile reliability/refusal evidence incomplete")
        if any(row.get("ledger", {}).get(k) != v for k, v in expected.items()):
            raise ValueError("profile reliability capacities differ")


def validate_observe(value, security):
    if (value.get("schema") != "coaptic-native-observe-proof/1"
            or value.get("cohort") != "small-device-blockwise-observe"
            or value.get("security") != security or value.get("success") is not True
            or value.get("functional_only") is not True):
        raise ValueError("Observe lifecycle proof identity incomplete")
    expected = dict(body_bytes=4096, completed=6, verified_bytes=24576,
                    initial_registrations=1, changed_notifications=1, recovery_registrations=1,
                    fresh_gets=1, deregistrations=2, local_cancellations=1,
                    controlled_undelivered_datagrams=1, call_capacity_refusals=2)
    if any(type(value.get(k)) is not int or value[k] != n for k, n in expected.items()):
        raise ValueError("Observe lifecycle verification incomplete")
    if value.get("bounds") != dict(rounds_per_operation=128, deadline_ms_per_operation=3000,
                                   combined_send_limit=256, combined_receive_limit=256,
                                   json_limit_bytes=16384):
        raise ValueError("Observe lifecycle bounds differ")
    server = value.get("server", {})
    capacities = dimensions("small-observe", 4096)
    for key in ("routes", "populated_routes", "calls", "deferred", "associations", "security_requests",
                "observe", "dedup", "rx_slots", "tx_slots", "rx_body_slots", "tx_body_slots",
                "rx_body_bytes", "tx_body_bytes", "blockwise", "storage"):
        if server.get(key) != capacities[key]:
            raise ValueError("Observe server capacity differs: " + key)
    if server.get("datagram_bytes") != 1152:
        raise ValueError("Observe datagram capacity differs")
    counts = value.get("counts", {})
    for key in ("server_sent", "server_received", "client_sent", "client_received",
                "server_protected_sent", "client_protected_sent", "client_controls_sent"):
        if type(counts.get(key)) is not int or not 0 <= counts[key] <= 256:
            raise ValueError("Observe datagram accounting missing")
    if (counts["server_sent"] != counts["client_received"]
            or counts["client_sent"] != counts["server_received"]
            or not 48 <= counts["server_sent"] + counts["client_sent"] <= 256
            or counts["client_controls_sent"] < 1
            or any((counts[k] > 0) != (security == "oscore") for k in
                   ("server_protected_sent", "client_protected_sent"))):
        raise ValueError("Observe send/receive/security accounting differs")
    if type(value.get("poll_calls")) is not int or not 1 <= value["poll_calls"] <= 3 * 128 * 8:
        raise ValueError("Observe poll budget missing")
    memory = value.get("memory", {})
    if (memory.get("server_pool_requested_heap_bytes") != 0
            or type(memory.get("client_pool_requested_heap_bytes")) is not int
            or not 0 < memory["client_pool_requested_heap_bytes"] <= 32768
            or any(type(memory.get(k)) is not int or memory[k] <= 0 for k in
                   ("server_app_including_transport_inline_bytes", "client_app_including_transport_inline_bytes",
                    "each_transport_nested_in_app_inline_bytes"))):
        raise ValueError("Observe pool/owner accounting missing")


def run_suite(prepared, output, client_from=None):
    started = time.perf_counter()
    output = Path(output)
    if output.exists():
        raise ValueError("output exists; preserve prior runs")
    bundle, bins = verify_prepared(prepared)
    client_bundle, client_bins = verify_prepared(client_from or prepared)
    if any(bundle[k] != client_bundle[k] for k in ("harness", "host", "compiler", "cargo", "flags")):
        raise ValueError("frozen client preparation differs")
    if bundle.get("tools") != client_bundle.get("tools"):
        raise ValueError("frozen client toolchain differs")
    if bundle["sources"]["suite"]["tree"] != client_bundle["sources"]["suite"]["tree"]:
        raise ValueError("frozen client native fixture tree differs")
    bins["client"] = client_bins["client"]
    config, host = configuration(), host_identity()
    result = dict(schema=SCHEMA, kind="run", passed=False, configuration=config,
                  configuration_sha256=fingerprint(config), host=host, preparation=bundle,
                  client_preparation=client_bundle, cells=[], reliability=[], observe=[],
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
            validate_profile_reliability(ledgers, profile)
            result["reliability"].append(dict(profile=profile, passed=True,
                                              seconds=proof.duration_seconds, cells=ledgers))
        for security in SECURITY:
            active_phase = "Observe lifecycle: " + security
            proof = task(dict(kind="observe", security=security, **bins), timeout=10)
            observed = json.loads(proof.stdout)
            validate_observe(observed, security)
            result["observe"].append(dict(security=security, passed=True, report=observed,
                                          worker_seconds=proof.duration_seconds))
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
                cell.update(socket=socket_value, socket_worker_seconds=observed.duration_seconds)
                validate_socket(socket_value, profile, security)
                if profile not in CORE_PROFILES:
                    cell["core"] = dict(status="unsupported", reason="no existing core probe for this exact configured profile")
                else:
                    active_phase = "core: " + profile + "/" + security
                    elapsed = time.perf_counter() - started
                    if elapsed >= 55:
                        raise TimeoutError("development suite budget exhausted before core cell")
                    core = task(dict(kind="core", profile=profile, security=security, **bins), timeout=min(10, 60 - elapsed))
                    raw = json.loads(core.stdout)
                    cell["core"] = dict(status="passed", concurrency=1, report=raw,
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
                               retained_temporary_directory=getattr(error, "temporary_directory", None),
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
        if len(r.get("cells", [])) != len(PROFILES) * len(SECURITY) or r.get("not_run"):
            raise ValueError("incomplete comparison rows")
        wanted = [(p, s) for p, _ in PROFILES for s in SECURITY]
        if [(c.get("profile"), c.get("security")) for c in r["cells"]] != wanted:
            raise ValueError("comparison must include every exact profile/security row")
        if any(c.get("status") != "passed" for c in r["cells"]):
            raise ValueError("comparison includes an unfinished cell")
        if (len(r.get("reliability", [])) != len(PROFILES) + 1
                or any(v.get("passed") is not True for v in r["reliability"])):
            raise ValueError("comparison requires completed reliability checks")
        if (r["reliability"][0].get("kind") != "independent-body-corruption-and-security-recovery"
                or [v.get("profile") for v in r["reliability"][1:]] != [p for p, _ in PROFILES]):
            raise ValueError("comparison reliability profile coverage differs")
        for proof in r["reliability"][1:]:
            validate_profile_reliability(proof.get("cells"), proof["profile"])
        if [x.get("security") for x in r.get("observe", [])] != list(SECURITY):
            raise ValueError("Observe proof cohort incomplete")
        for observed in r["observe"]:
            if observed.get("passed") is not True:
                raise ValueError("Observe lifecycle proof failed")
            validate_observe(observed["report"], observed["security"])
        for cell in r["cells"]:
            size = dict(PROFILES)[cell["profile"]]
            validate_socket(cell["socket"], cell["profile"], cell["security"])
            if cell["socket"]["report"]["warmup"] != WARMUP:
                raise ValueError("comparison warmup differs")
            ledger = cell["socket"]["server_resources"]
            for k, expected in dimensions(cell["profile"], size).items():
                if ledger.get(k) != expected:
                    raise ValueError("comparison capacities differ: " + k)
            if cell["profile"] not in CORE_PROFILES:
                if cell["core"].get("status") != "unsupported":
                    raise ValueError("unsupported core cell misrepresented")
            elif (cell["core"].get("status") != "passed" or cell["core"].get("concurrency") != 1
                    or cell["core"].get("summary") != validate_core(cell["core"]["report"], cell["profile"], cell["security"])):
                raise ValueError("comparison core verification differs")
    for key in ("host", "configuration_sha256"):
        if a[key] != b[key]:
            raise ValueError("comparison mismatch: " + key)
    for key in ("harness", "compiler", "cargo", "flags", "native_manifest_sha256", "server_manifest_sha256"):
        if a["preparation"][key] != b["preparation"][key]:
            raise ValueError("build/harness mismatch: " + key)
    if a["preparation"].get("tools") != b["preparation"].get("tools"):
        raise ValueError("actual compiler/Cargo executable identity differs")
    if a["preparation"]["sources"]["suite"]["tree"] != b["preparation"]["sources"]["suite"]["tree"]:
        raise ValueError("native fixture companion tree differs")
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
                before_result_sha256=digest(before), after_result_sha256=digest(after),
                before_core=a["preparation"]["sources"]["core"],
                after_core=b["preparation"]["sources"]["core"],
                interpretation="short-run descriptive differences, not a gain/regression acceptance verdict; original CPU and latency gates remain separate")


def worker(spec):
    if spec["kind"] == "build":
        environment = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2", RUSTC=spec["rustc"])
        return subprocess.call(spec["command"], cwd=SUITE, env=environment)
    if spec["kind"] == "observe":
        return subprocess.call([spec["observe"], spec["security"]])
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
                     resource_profile=spec["profile"], phase_timeout_seconds=3,
                     **socket_options(spec["profile"]))
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
                              within_minute=result["within_minute"], socket_cells=len(result["cells"]),
                              core_cells=sum(c["core"]["status"] == "passed" for c in result["cells"]),
                              unsupported_core_cells=sum(c["core"]["status"] == "unsupported" for c in result["cells"]),
                              observe_lifecycle_cells=len(result["observe"]), result=str(a.output))))
    else:
        save(a.output, compare(a.before, a.after))
        print("Descriptive revision comparison written to " + str(a.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
