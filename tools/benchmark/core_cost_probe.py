"""Fixed socket-free #650 diagnosis. Only the manual Linux workflow runs this.

Whole bench-process CPU includes client crypto, setup, clocks and JSON output.
Poll clocks are wall time. App ancestry must be reviewed before attributing
samples; neither metric proves server CPU/op, transport share or a 50% saving.
No raw perf parser, automatic hotspot ranking or performance acceptance here.
"""
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

from linux_cpu import (FLAGS, SUITE, bounded_bytes, bounded_read, command, digest,
                       hardware, identity, run_logged, run_owned)

MIB = 1024 * 1024
CORE = "ff08926422d570602069d2231a555559d1154f3f"
OPERATIONS, WARMUP = 50_000, 128
PLAN = (("u-before", "unprotected", 1), ("os-before", "oscore", 1),
        ("u-profile", "unprotected", 8), ("os-profile", "oscore", 8),
        ("os-after", "oscore", 1), ("u-after", "unprotected", 1))
META, BENCH, DATA, ELF = 64 * 1024, MIB // 2, 4 * MIB, 64 * MIB
LIMITS = {"perf.data": DATA, "perf-command.log": DATA,
          "perf-report.txt": 2 * MIB, "callers.txt": DATA, "samples.txt": 8 * MIB,
          "build.log": 2 * MIB, "bench-core": ELF, "index.json": 2 * META}
SCOPE = ("Whole benchmark-process lifetime CPU, including exec/setup, calibration, "
         "warmups, client prepare/crypto/verify, App, loop clocks and JSON writes; "
         "not isolated server CPU. Poll samples are wall time; calibration is never subtracted.")
REVIEW = {"status": "inconclusive; requires source-guided App-root/callchain review",
          "minimum_app_samples_per_mode": 200, "minimum_per_four_process_half": 50,
          "minimum_hotspot_self_samples": 30,
          "rules": "Keep unknown/loss/throttle evidence. Shared crypto names do not identify server work. "
                   "Count each sample once; do not sum Children or multiply shares by whole-process CPU.",
          "evidence_limits": "Text readouts do not establish zero throttling or explicit CPU mode; "
                             "floor prerequisites remain unknown. Linux UID drop, exec inheritance, limits, "
                             "groups and symbolization remain unverified until integration.",
          "both_50_percent_targets": "OPEN"}


def save_new(path, value):
    with Path(path).open("xb") as stream:
        stream.write(bounded_bytes(value, META))


def load(path):
    return json.loads(bounded_read(path, META))


def proc_identity(pid):
    fields = bounded_read(f"/proc/{pid}/stat", 4096).decode().rsplit(")", 1)[1].split()
    return {"pid": pid, "pgrp": int(fields[2]), "session": int(fields[3]),
            "starttime": int(fields[19])}


def validate_credentials(text, uid, gid):
    fields = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
    if (uid <= 0 or gid <= 0 or fields["Uid"].split() != [str(uid)] * 4
            or fields["Gid"].split() != [str(gid)] * 4 or fields["Groups"].strip()
            or fields["NoNewPrivs"].strip() != "1"
            or any(int(fields[name], 16) for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))):
        raise ValueError("refusing benchmark with unexpected credentials/capabilities")
    return fields


def cleanup_group(marker):
    """Only a fixed worker's pre-child, owned group receipt authorizes signaling.

    The group remains reserved while members exist after its leader exits.
    A surviving leader must still match starttime/session; any ambiguity is fatal.
    """
    if not marker.exists():
        return  # No worker receipt means the worker never reached child activity.
    owned = load(marker)
    pid = owned["pid"]
    if type(pid) is not int or pid <= 1 or owned["pgrp"] != pid or pid == os.getpgrp():
        raise RuntimeError("cleanup unresolved: invalid owned worker group")
    try:
        if proc_identity(pid) != {key: owned[key] for key in ("pid", "pgrp", "session", "starttime")}:
            raise RuntimeError("cleanup unresolved: worker PID identity changed")
    except FileNotFoundError:
        pass
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pid, sig)
        except ProcessLookupError:
            return
        for _ in range(20):
            try:
                os.killpg(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(.05)
    raise RuntimeError("cleanup unresolved: owned worker group survives KILL")


def validate_bench(raw, security):
    value = json.loads(raw)
    if (type(value.get("operations")) is not int or value["operations"] != OPERATIONS
            or type(value.get("warmup")) is not int or value["warmup"] != WARMUP
            or value.get("security") != security or value.get("black_box") is not True
            or not isinstance(value.get("measurement"), str)):
        raise ValueError("incomplete or mismatched benchmark receipt")
    for key, count in (("latencies_ns", OPERATIONS), ("clock_calibration_ns", 4096)):
        samples = value.get(key)
        if (not isinstance(samples, list) or len(samples) != count
                or any(type(n) is not int or not 0 <= n < 2**128 for n in samples)):
            raise ValueError("invalid raw clock samples: " + key)


def usage():
    import resource
    raw = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {key: getattr(raw, "ru_" + key) for key in
            ("utime", "stime", "minflt", "majflt", "nvcsw", "nivcsw")}


def cpu_receipt(before, after):
    delta = {key: after[key] - before[key] for key in before}
    if any(not math.isfinite(value) or value < 0 for value in delta.values()):
        raise ValueError("invalid child resource delta")
    return {"before": before, "after": after, "delta": delta, "scope": SCOPE}


def worker(root, phase):
    import resource
    name, security, count = PLAN[phase]
    config = load(root / "build.json")
    directory = root / name
    uid, gid = config["uid"], config["gid"]
    credentials = bounded_read("/proc/self/status", META).decode()
    validate_credentials(credentials, uid, gid)
    # Bound worker tracebacks/metadata, retaining headroom for the benchmark's
    # own lower hard limit. The unmodified fixture cannot enlarge its limit.
    resource.setrlimit(resource.RLIMIT_FSIZE, (META, resource.getrlimit(resource.RLIMIT_FSIZE)[1]))
    if os.getpgrp() != os.getpid():
        os.setpgid(0, 0)
    owned = proc_identity(os.getpid())
    owned.update(credentials=credentials, phase=name)
    save_new(directory / "worker.json", owned)  # Before ANY benchmark child.
    binary = config["binary"]
    if digest(binary) != config["binary_sha256"]:
        raise ValueError("benchmark binary identity changed")

    def interrupted(signum, frame):
        raise InterruptedError(f"worker signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    deadline = time.monotonic() + (45 if count == 8 else 10)
    for number in range(count):
        receipt = {"complete": False, "security": security, "operations": OPERATIONS,
                   "warmup": WARMUP, "scope": SCOPE}
        child = None
        started = time.monotonic_ns()
        before = usage()
        try:
            with (directory / f"bench-{number}.jsonlog").open("xb") as stream:
                # Deliberately inherit this recorded worker group. spawn() would
                # create a separate session, defeating parent failure cleanup.
                child = subprocess.Popen([binary, str(OPERATIONS), security], stdin=subprocess.DEVNULL,
                                         stdout=stream, stderr=subprocess.STDOUT,
                                         preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (BENCH, BENCH)))
                receipt["pid"] = child.pid
                receipt["returncode"] = child.wait(timeout=min(5, max(.001, deadline - time.monotonic())))
                receipt.update(cpu_receipt(before, usage()), wall_ns=time.monotonic_ns() - started)
                if child.returncode:
                    raise subprocess.CalledProcessError(child.returncode, child.args)
            validate_bench(bounded_read(directory / f"bench-{number}.jsonlog", BENCH), security)
            delta = receipt["delta"]
            receipt["whole_process_cpu_ns_per_verified_exchange"] = (
                delta["utime"] + delta["stime"]) * 1e9 / (OPERATIONS + WARMUP)
            receipt["complete"] = True
        finally:
            try:
                if child is not None and child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=1)
            except BaseException:
                receipt["cleanup_unresolved"] = True
                raise
            finally:
                save_new(directory / f"bench-{number}.json", receipt)
        if time.monotonic() > deadline:
            raise TimeoutError("worker deadline")


def prefix(quota, seconds):
    return ["sudo", "-n", "--", "prlimit", f"--fsize={quota}:{quota}",
            "--as=536870912:536870912", "--", "timeout", "--signal=TERM",
            "--kill-after=5", str(seconds)]


def phase_command(root, phase, uid, gid):
    name, _, count = PLAN[phase]
    argv = prefix(DATA, 60 if count == 8 else 10)
    if count == 8:
        # Upstream perf-record: per-thread disables inheritance; --uid is not setuid.
        argv += ["perf", "record", "-e", "cpu-clock", "-F", "997", "--call-graph", "fp,64",
                 "--inherit", "-m", "128", "--no-buildid-cache", "-o", str(root / name / "perf.data"), "--"]
    return argv + ["setpriv", f"--reuid={uid}", f"--regid={gid}", "--clear-groups",
                   "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--",
                   "env", f"CORE_COST_PHASE={phase}", f"CORE_COST_ROOT={root}",
                   str(Path(sys.executable).resolve()), "-B", str(Path(__file__).resolve())]


def capture_access(directory, uid, gid, log, state):
    """Hand only this terminated recorder's regular, singly linked file to its runner."""
    path = directory / "perf.data"
    try:
        before = path.lstat()
    except FileNotFoundError:
        state.update(present=False, readable=False)
        return
    state.update(present=True, readable=False, owner_before=before.st_uid,
                 mode_before=stat.S_IMODE(before.st_mode), bytes=before.st_size)
    if (uid <= 0 or gid <= 0 or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid not in (0, uid) or before.st_size > DATA):
        raise ValueError("refusing ownership transfer of unexpected capture")
    if (before.st_uid, before.st_gid) != (uid, gid):
        argv = prefix(META, 5) + ["chown", "--no-dereference", "--", f"{uid}:{gid}", str(path)]
        state["command"] = argv
        state["returncode"] = run_owned(argv, timeout=15, check=False, elevated=True,
            file_limit=META, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        if state["returncode"]:
            raise PermissionError("capture ownership transfer refused")
    after = path.lstat()
    if ((before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size)
            or not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
            or (after.st_uid, after.st_gid) != (uid, gid)):
        raise ValueError("capture identity/ownership changed during handoff")
    with path.open("rb") as stream:
        stream.read(1)  # Prove actual runner access, not just a successful chown status.
    state.update(readable=True, owner_after=after.st_uid)


def execute_phase(directory, record, count, uid, gid, log):
    primary, recorder_settled = None, False

    def failure(error, label):
        nonlocal primary
        record[label] = {"error": type(error).__name__, "reason": str(error)[:512]}
        unresolved = "cleanup unresolved" in str(error) or getattr(error, "cleanup_unresolved", False)
        if primary is None:
            primary = error
        else:
            primary.add_note(label + ": " + str(error)[:512])
        if unresolved:
            primary.cleanup_unresolved = True

    try:
        record["returncode"] = run_owned(record["command"], timeout=70 if count == 8 else 20,
            check=False, elevated=True, file_limit=DATA, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        recorder_settled = True
    except BaseException as error:
        recorder_settled = not ("cleanup unresolved" in str(error) or getattr(error, "cleanup_unresolved", False))
        failure(error, "recorder_error")
    try:
        cleanup_group(directory / "worker.json")
    except BaseException as error:
        failure(error, "worker_cleanup_error")
    if count == 8:
        access = record["capture_access"] = {"recorder_settled": recorder_settled}
        try:
            if recorder_settled:
                capture_access(directory, uid, gid, log, access)
            else:
                access["reason"] = "handoff not attempted: recorder termination unresolved"
        except BaseException as error:
            failure(error, "capture_access_error")
        try:
            save_new(directory / "capture-access.json", access)
        except Exception as error:
            failure(error, "capture_access_retention_error")
    if primary is not None:
        raise primary


def flat_report(directory, quota, log):
    """Local fixed variant of linux_cpu.perf_report with a post-sudo AS limit.

    Keep its version query, 25/30-second watchdogs, fsize, flat options and
    refusal/cleanup metadata. No global executor patch or framework/API change.
    """
    path = directory / "perf-report.txt"
    argv = prefix(quota, 25) + ["env", "DEBUGINFOD_URLS=", "perf", "report", "--stdio", "--header",
        "--show-nr-samples", "--show-total-period", "--sort", "dso,symbol", "--no-children",
        "--call-graph", "none", "--percent-limit", "0", "--stdio-color", "never", "--no-inline",
        "--demangle", "--force", "--input", str(directory / "perf.data")]
    version = ["perf", "--version"]
    state = dict(available=False, command=argv, version_command=version, output_file=str(path),
                 file_size_limit_bytes=quota, address_space_limit_bytes=512 * MIB,
                 timeout_seconds=30, version_timeout_seconds=5,
                 interpretation="flat sampled self costs; no stage timings; attribution inconclusive")
    try:
        with path.open("xb") as stream:
            state["version_returncode"] = run_owned(version, timeout=5, check=False,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, file_limit=quota)
            state["returncode"] = run_owned(argv, timeout=30, check=False, elevated=True,
                stdin=subprocess.DEVNULL, stdout=stream, stderr=stream, file_limit=quota,
                env={**os.environ, "DEBUGINFOD_URLS": ""})
    except Exception as error:
        state.update(error_type=type(error).__name__, reason=str(error)[:512])
        if isinstance(error, subprocess.TimeoutExpired):
            state["deadline_exceeded"] = True
        if getattr(error, "cleanup_unresolved", False):
            state["cleanup_unresolved"] = True
            state["cleanup_reason"] = "; ".join(getattr(error, "__notes__", []) or [str(error)])[:512]
    finally:
        try:
            state["output_bytes"] = path.stat().st_size
            state["command_log_bytes"] = os.fstat(log.fileno()).st_size
        except OSError as error:
            state.setdefault("error_type", type(error).__name__)
            state.setdefault("reason", str(error)[:512])
    state["available"] = (not state.get("error_type") and state.get("returncode") == 0
                          and 0 < state.get("output_bytes", 0) < quota
                          and state.get("command_log_bytes", quota) < quota)
    return state


def reports(directory, receipts, log):
    result = {"flat": flat_report(directory, 2 * MIB, log)}
    save_new(directory / "flat-status.json", result["flat"])
    if result["flat"].get("cleanup_unresolved"):
        raise RuntimeError("cleanup unresolved: flat perf report")
    pids = ",".join(str(item["pid"]) for item in receipts)
    commands = (("callers.txt", DATA, ["report", "--stdio", "--header", "--show-nr-samples",
                 "--show-total-period", "--sort", "pid,dso,symbol", "--children", "--call-graph",
                 "graph,0,caller", "--inline", "--percent-limit", "0", "--percentage", "absolute",
                 "--stdio-color", "never", "--demangle", "--pid", pids]),
                ("samples.txt", 8 * MIB, ["script", "--ns", "--demangle", "--inline",
                 "--show-task-events", "--show-lost-events", "-F", "comm,pid,tid,time,event,period,ip,sym,dso"]))
    for filename, quota, options in commands:
        argv = prefix(quota, 25) + ["env", "DEBUGINFOD_URLS=", "perf", *options,
                                  "--force", "--input", str(directory / "perf.data")]
        with (directory / filename).open("xb") as stream:
            code = run_owned(argv, timeout=35, check=False, elevated=True, file_limit=quota,
                             stdin=subprocess.DEVNULL, stdout=stream, stderr=stream)
        result[filename] = {"command": argv, "returncode": code}
    return result


def inventory(root):
    """Fixed per-file caps bound total retained evidence even on a failed phase."""
    rows, total, non_elf = [], 0, 0
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unexpected evidence file type")
        quota = LIMITS.get(path.name, BENCH if path.suffix == ".jsonlog" else META)
        if path.name == "perf-command.log" and not path.parent.name.endswith("profile"):
            quota = META
        if info.st_size > quota:
            raise ValueError("evidence exceeds quota: " + str(path))
        total += info.st_size
        non_elf += info.st_size if path.name != "bench-core" else 0
        if total > 128 * MIB - 2 * META or non_elf > 64 * MIB - 2 * META or len(rows) >= 100:
            raise ValueError("aggregate evidence quota")
        rows.append({"path": str(path.relative_to(root)), "bytes": info.st_size, "sha256": digest(path)})
    return {"files": rows, "bytes_before_index": total, "index_excludes_itself": True}


def directory_bytes(root):
    total, count = 0, 0
    for parent, _, names in os.walk(root):
        for name in names:
            count += 1
            if count > 100_000:
                raise ValueError("build lane entry budget")
            try:
                total += (Path(parent) / name).lstat().st_size
            except FileNotFoundError:
                pass  # Cargo can replace temporary files during this observation.
    return total


def build(root, lane, env, host):
    """Reuse bounded build logging; one marker permits the narrow lane watchdog."""
    done, errors = threading.Event(), []
    marker = root / "builder.json"
    if directory_bytes(lane) > 4 * 1024 * MIB:
        raise ValueError("build lane exceeds 4 GiB before build")

    def watch():
        while not done.wait(.5):
            try:
                if directory_bytes(lane) > 4 * 1024 * MIB:
                    raise ValueError("build lane exceeds 4 GiB")
            except Exception as error:
                errors.append(str(error))
                try:
                    cleanup_group(marker)
                except Exception as cleanup:
                    errors.append("cleanup unresolved: " + str(cleanup))
                return

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        with (root / "build.log").open("xb") as stream:
            run_logged([sys.executable, "-B", str(Path(__file__).resolve())], stream, timeout=900,
                       limit=2 * MIB, cwd=SUITE,
                       env={**env, "CORE_COST_BUILD": str(root), "CORE_COST_HOST": host})
    finally:
        done.set()
        watcher.join(timeout=5)
        if watcher.is_alive():
            raise RuntimeError("cleanup unresolved: build watchdog")
        if errors:
            raise RuntimeError("; ".join(errors))
    if directory_bytes(lane) > 4 * 1024 * MIB:
        raise ValueError("build lane exceeds 4 GiB")


def run(root, lane):
    if (sys.platform != "linux" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.getuid() <= 0 or os.getgid() <= 0):
        raise ValueError("manual Linux runner with nonzero original UID required")
    uid, gid = os.getuid(), os.getgid()
    root.mkdir(mode=0o700)
    state = {"complete": False, "scope": SCOPE, "review": REVIEW, "plan": PLAN, "phases": [],
             "budget": {"processes": 20, "measured_operations": 1_000_000, "warmup_operations": 2560,
                        "internal_datagrams": 2_005_120, "udp_datagrams": 0, "fresh_oscore_pairs": 10,
                        "artifact_bytes": 128 * MIB, "lane_bytes": 4 * 1024 * MIB}}
    primary = None
    try:
        source = {"suite": identity(SUITE), "core": identity(SUITE / "coaptic")}
        if any(value["status"] for value in source.values()) or source["core"]["revision"] != CORE:
            raise ValueError("clean source identities do not match fixed core")
        machine = hardware()
        page = os.sysconf("SC_PAGE_SIZE")
        if not 1 <= os.cpu_count() <= 16 or page > 4096:
            raise ValueError("perf ring budget requires <=16 CPUs and <=4096-byte pages")
        tools = {name: command([name, "--version"], timeout=5) for name in
                 ("perf", "prlimit", "timeout", "setpriv", "nm")}
        save_new(root / "setup.json", {"source": source, "machine": machine, "tools": tools,
                                      "page_bytes": page, "ring_bound_bytes": 2 * os.cpu_count() * 129 * page,
                                      "owner": "root650/Coaptic", "release": "review settled and no users"})
        lane.mkdir(exist_ok=True)
        env = dict(os.environ, **FLAGS, CARGO_TARGET_DIR=str(lane.resolve()))
        for key in list(env):
            if (key.startswith("CARGO_PROFILE_RELEASE_") and key not in FLAGS
                    or key in ("CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")):
                del env[key]
        versions = {name: command([name, "-Vv"], env=env, timeout=10) for name in ("rustc", "cargo")}
        for name, value in versions.items():
            if (re.findall(r"^release: (.+)$", value, re.M) != [FLAGS["RUSTUP_TOOLCHAIN"]]
                    or len(re.findall(r"^commit-hash: [0-9a-f]{40}$", value, re.M)) != 1):
                raise ValueError("unexpected toolchain identity: " + name)
        hosts = re.findall(r"^host: ([A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+)$", versions["rustc"], re.M)
        if len(hosts) != 1:
            raise ValueError("one explicit host target required")
        save_new(root / "toolchain.json", {"versions": versions, "flags": FLAGS, "host": hosts[0]})
        build(root, lane, env, hosts[0])
        binary = lane.resolve() / hosts[0] / "release/bench-core"
        if binary.stat().st_size > ELF:
            raise ValueError("ELF exceeds 64 MiB")
        config = {"uid": uid, "gid": gid, "binary": str(binary), "binary_sha256": digest(binary),
                  "source": source, "source_hashes": {str(path.relative_to(SUITE)): digest(path) for path in
                      (SUITE / "tools/benchmark/native/Cargo.lock", SUITE / "tools/benchmark/native/Cargo.toml",
                       SUITE / "tools/benchmark/native/servers/Cargo.toml",
                       SUITE / "tools/benchmark/native/servers/src/bin/bench-core.rs", SUITE / "coaptic/Cargo.lock")}}
        save_new(root / "build.json", config)
        shutil.copyfile(binary, root / "bench-core")
        for phase, (name, _, count) in enumerate(PLAN):
            directory = root / name
            directory.mkdir(mode=0o700)
            record = {"name": name, "command": phase_command(root, phase, uid, gid), "complete": False}
            state["phases"].append(record)
            phase_error = None
            try:
                with (directory / "perf-command.log").open("xb") as log:
                    execute_phase(directory, record, count, uid, gid, log)
                    receipts = [load(directory / f"bench-{i}.json") for i in range(count)]
                    record["benchmarks"] = receipts
                    if count == 8 and (directory / "perf.data").exists():
                        record["reports"] = reports(directory, receipts, log)
                    if (record["returncode"] or not all(r["complete"] for r in receipts)
                            or count == 8 and (not record.get("reports", {}).get("flat", {}).get("available")
                                or any(r["returncode"] for key, r in record["reports"].items() if key != "flat"))):
                        raise ValueError("phase/refusal/readout failure: " + name)
                record["complete"] = True
            except BaseException as error:
                phase_error = error
                raise
            finally:
                try:
                    save_new(directory / "phase.json", record)
                    inventory(root)
                except Exception as error:
                    if phase_error is None:
                        raise
                    phase_error.add_note("phase retention: " + str(error)[:512])
        if digest(binary) != config["binary_sha256"] or source != {"suite": identity(SUITE), "core": identity(SUITE / "coaptic")}:
            raise ValueError("source/binary identity changed during probe")
        state["complete"] = True
    except BaseException as error:
        primary = error
        state.update(error=type(error).__name__, reason=str(error)[:512],
                     notes=[str(note)[:512] for note in getattr(error, "__notes__", [])[:4]],
                     cleanup_unresolved="cleanup unresolved" in str(error) or getattr(error, "cleanup_unresolved", False))
        raise
    finally:
        try:
            save_new(root / "summary.json", state)
            index = bounded_bytes(inventory(root), 2 * META)  # Before creating index.json itself.
            with (root / "index.json").open("xb") as stream:
                stream.write(index)
        except Exception as error:
            if primary is None:
                raise
            primary.add_note("final inventory: " + str(error)[:512])
            try:
                save_new(root / "index-error.json", {"error": type(error).__name__, "reason": str(error)[:512]})
            except Exception as retention:
                primary.add_note("index failure receipt: " + str(retention)[:512])


def main():
    if sys.platform != "linux":
        raise ValueError("Linux only; importing for isolated tests is supported")
    if "CORE_COST_BUILD" in os.environ:
        root = Path(os.environ["CORE_COST_BUILD"])
        save_new(root / "builder.json", proc_identity(os.getpid()))
        argv = ["cargo", "build", "--release", "--locked", "--target", os.environ["CORE_COST_HOST"],
                "--manifest-path", "tools/benchmark/native/Cargo.toml", "-p", "bench-rust-server", "--bin", "bench-core"]
        os.execvpe(argv[0], argv, os.environ)
    elif "CORE_COST_PHASE" in os.environ:
        phase = int(os.environ["CORE_COST_PHASE"])
        if not 0 <= phase < len(PLAN):
            raise ValueError("invalid private phase")
        worker(Path(os.environ["CORE_COST_ROOT"]), phase)
    else:
        temporary = Path(os.environ["RUNNER_TEMP"])
        run(temporary / "core-cost-probe-evidence/probe", temporary / "cpu-build-lane")


if __name__ == "__main__":
    main()
