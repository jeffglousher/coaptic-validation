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
import select
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

from linux_cpu import (FLAGS, SUITE, bounded_bytes, bounded_read, command, digest,
                       hardware, identity, run_logged, run_owned, ProcessCpuClock,
                       process_clock_delta, spawn, OwnedProcess)

MIB = 1024 * 1024
CORE = "ff08926422d570602069d2231a555559d1154f3f"
BATCH_CORE = "b9b83d8663cbdcb7a80bf143670a05019f25cf25"
OPERATIONS, WARMUP = 50_000, 128
PLAN = (("u-before", "unprotected", 1), ("os-before", "oscore", 1),
        ("u-profile", "unprotected", 8), ("os-profile", "oscore", 8),
        ("os-after", "oscore", 1), ("u-after", "unprotected", 1))
BATCH_PLAN = (("batch-u-before", "unprotected", 1), ("batch-os-before", "oscore", 1),
              ("batch-os-after", "oscore", 1), ("batch-u-after", "unprotected", 1))
BATCH_OPERATIONS, WORK_BATCHES, EMPTY_GATES = 10_000, 5, 16
BATCH_SCOPE = ("server-App driver CPU window; includes monotonic clock/gates/loop and receive/send "
               "copies plus all App::poll work; excludes client preparation/verification and socket "
               "wakeups. Empty controls retained, never subtracted. Reported resolution is not accuracy. "
               "No pure-App CPU, socket acceptance, UDP subtraction, overhead or scheduler-cause claim.")
BATCH_LIFETIME_SCOPE = ("Whole benchmark-process lifetime CPU including exec/setup, fixture allocation, "
                        "warmups, client prepare/crypto/verify, App, gates/loop clocks and JSON writes; "
                        "not isolated server CPU and not the server-App driver CPU window.")
META, BENCH, DATA, ELF = 64 * 1024, MIB // 2, 4 * MIB, 64 * MIB
LIMITS = {"perf.data": DATA, "perf-command.log": DATA,
          "perf-report.txt": 2 * MIB, "callers.txt": DATA, "samples.txt": 8 * MIB,
          "build.log": 2 * MIB, "bench-core": ELF, "index.json": 2 * META}
# Worst-case retained batch allowance: 800 KiB including the workflow's 64 KiB
# test log, plus one <=64 MiB ELF; 46 files. Never use the old perf quotas here.
BATCH_LIMITS = {"build.log": META, "setup.json": 32 * 1024, "toolchain.json": 32 * 1024,
                "build.json": 32 * 1024, "summary.json": META, "index.json": 32 * 1024,
                "index-error.json": 2 * 1024, "builder.json": 2 * 1024, "bench-core": ELF,
                "perf-command.log": 32 * 1024, "bench-0.jsonlog": 16 * 1024,
                "bench-stderr.log": 8 * 1024, "cpu-windows.json": 32 * 1024,
                "bench-0.json": 4 * 1024, "worker.json": 8 * 1024,
                "owned-child.json": 2 * 1024, "launch-intent.json": 1024, "phase.json": 16 * 1024}
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


def save_batch(path, value):
    raw = bounded_bytes(value, BATCH_LIMITS[Path(path).name])
    with Path(path).open("xb") as stream:
        stream.write(raw)


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


def batch_pidfds_required():
    if not callable(getattr(os, "pidfd_open", None)) or not callable(getattr(signal, "pidfd_send_signal", None)):
        raise RuntimeError("batch cleanup requires Python Linux pidfd APIs; no numeric PID fallback")


def batch_stop_fd(fd):
    # A pidfd remains bound to the original process through exit and PID reuse.
    # This is a single-process stop, not a claim of arbitrary tree containment.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if select.select([fd], [], [], 0)[0]:
            return
        try:
            signal.pidfd_send_signal(fd, sig)
        except ProcessLookupError:
            return  # The bound process exited; never retry against its number.
        if select.select([fd], [], [], 1)[0]:
            return
    raise RuntimeError("cleanup unresolved: pidfd process did not exit")


class BatchLifetime:
    """Batch-only direct child ownership; no poll or signals after reaping."""
    def __init__(self, child):
        batch_pidfds_required()
        if (not isinstance(child, OwnedProcess) or child.returncode is not None
                or child.stopped or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
            raise RuntimeError("cleanup unresolved: batch requires an unreaped owned direct child")
        # Fresh Python process, default SIGCHLD, one waiter and no poll(): the
        # direct child's PID is reserved until this lifetime's wait reaps it.
        self.child, self.settled = child, False
        self.fd = os.pidfd_open(child.pid, 0)

    def wait(self, timeout):
        code = self.child.wait(timeout=timeout)
        self.settled = True
        self.child.stopped = True
        return code

    def stop(self):
        if self.settled:
            return
        if self.child.returncode is not None:
            raise RuntimeError("cleanup unresolved: batch child reaped outside its lifetime")
        if self.fd is None:
            raise RuntimeError("cleanup unresolved: batch pidfd closed before settlement")
        batch_stop_fd(self.fd)
        self.wait(1)

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)


def batch_cleanup_marker(marker):
    """Acquire live identity plus pidfd; a stale file alone authorizes nothing."""
    if not marker.exists():
        return
    batch_pidfds_required()
    owned = load(marker)
    pid = owned["pid"]
    if type(pid) is not int or pid <= 1 or pid == os.getpid() or owned["pgrp"] != pid:
        raise RuntimeError("cleanup unresolved: invalid batch process marker")
    expected = {key: owned[key] for key in ("pid", "pgrp", "session", "starttime")}
    try:
        before = proc_identity(pid)
    except FileNotFoundError:
        return  # No signal, and these fixed processes spawn only the separately registered native child.
    if before != expected:
        raise RuntimeError("cleanup unresolved: batch marker identity changed")
    try:
        fd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return
    try:
        # A departure/recycle during acquisition cannot redirect a pidfd. Refuse
        # an identity mismatch instead of authorizing the newly numbered task.
        if proc_identity(pid) != expected:
            raise RuntimeError("cleanup unresolved: batch marker changed during pidfd acquisition")
        batch_stop_fd(fd)
    finally:
        os.close(fd)


def cleanup_batch(directory, worker_settled):
    if worker_settled:
        # The fixed privilege/timeout chain waited for the worker, which has
        # already settled its sole native child. Never revisit stale PID files.
        receipt = load(directory / "bench-0.json")
        if receipt.get("child_cleanup_settled") is True:
            return
        raise RuntimeError("cleanup unresolved: missing native child settlement")
    # Stop worker spawning FIRST, then attempt its one registered child even if
    # worker ownership was lost. Default inherited-group cleanup is unchanged.
    primary = None
    try:
        batch_cleanup_marker(directory / "worker.json")
    except BaseException as error:
        primary = error
    child_marker = directory / "owned-child.json"
    try:
        if child_marker.exists():
            child = load(child_marker)
            worker = load(directory / "worker.json")
            if (child.get("parent_pid") != worker["pid"] or child.get("session") != child.get("pid")
                    or child.get("phase") != directory.name):
                raise RuntimeError("cleanup unresolved: invalid registered child custody")
            batch_cleanup_marker(child_marker)
        elif not worker_settled and (directory / "launch-intent.json").exists():
            # Control EOF releases the unregistered native startup. Missing PID
            # evidence still prevents a claim of settled cleanup.
            raise RuntimeError("cleanup unresolved: worker died during child registration; control EOF required")
    except BaseException as error:
        if primary is None:
            primary = error
        else:
            primary.add_note("registered child cleanup: " + str(error)[:512])
    if primary is not None:
        primary.cleanup_unresolved = True
        raise primary


def batch_run_command(argv, *, timeout, **kwargs):
    """Fixed batch privilege/timeout chain; never use generic post-reap stop."""
    batch_pidfds_required()  # Refuse before spawning if safe handles are unavailable.
    child, lifetime, primary = None, None, None
    try:
        child = spawn(argv, **kwargs)
        lifetime = BatchLifetime(child)
        return lifetime.wait(timeout)
    except BaseException as error:
        primary = error
        raise
    finally:
        if child is not None:
            cleanup_error = None
            if lifetime is None:
                # GNU timeout remains in this fixed chain; absent safe signaling
                # authority cannot be upgraded into numeric group ownership.
                cleanup_error = RuntimeError("cleanup unresolved: batch command pidfd was not acquired")
            else:
                for action in (lifetime.stop, lifetime.close):
                    try:
                        action()
                    except BaseException as error:
                        if cleanup_error is None:
                            cleanup_error = error
                        else:
                            cleanup_error.add_note("independent pidfd cleanup: " + str(error)[:512])
            if cleanup_error is not None:
                if primary is None:
                    cleanup_error.cleanup_unresolved = True
                    raise cleanup_error
                primary.cleanup_unresolved = True
                primary.add_note("batch command cleanup: " + str(cleanup_error)[:512])


def batch_read(child, deadline, stream):
    """Bounded unbuffered control line under ONE absolute child deadline."""
    raw = bytearray()
    while len(raw) < 2048:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([child.stdout], [], [], remaining)[0]:
            raise TimeoutError("batch control deadline")
        byte = os.read(child.stdout.fileno(), 1)
        if not byte:
            raise EOFError("batch control EOF/partial receipt")
        raw.extend(byte)
        if byte == b"\n":
            if stream.tell() + len(raw) > BATCH_LIMITS["bench-0.jsonlog"]:
                raise ValueError("batch control log bound")
            stream.write(raw)
            return json.loads(raw)
    raise ValueError("batch control line bound")


def batch_send(child, value):
    child.stdin.write(value)
    child.stdin.flush()


def batch_expect(value, event, kind, block, verified):
    expected = dict(event=event, kind=kind, block=block, verified=verified)
    if value != expected or any(type(value.get(key)) is not int for key in ("block", "verified")):
        raise ValueError("batch gate order/count mismatch")


def validate_fixture(value, security):
    fields = ("requested_bytes", "row_bytes", "row_metadata_bytes", "request_ref_bytes",
              "optional_request_ref_bytes", "wire_bytes", "app_heap_bytes", "app_inline_bytes",
              "fixture_inline_bytes", "scratch_allowance_bytes", "rows", "limit_bytes")
    if (set(value) != set(fields) | {"event", "security"}
            or value.get("event") != "fixture" or value.get("security") != security
            or any(type(value.get(key)) is not int or value[key] <= 0 for key in fields)
            or value["rows"] != BATCH_OPERATIONS or value["wire_bytes"] != 29_440_000
            or value["limit_bytes"] != 32 * MIB or value["scratch_allowance_bytes"] != 16 * 1024
            or value["row_metadata_bytes"] > 64
            or value["row_bytes"] != 2 * 1472 + value["row_metadata_bytes"]
            or not value["request_ref_bytes"] <= value["optional_request_ref_bytes"] <= value["row_metadata_bytes"]
            or value["requested_bytes"] != value["row_bytes"] * BATCH_OPERATIONS
                + sum(value[key] for key in ("app_heap_bytes", "app_inline_bytes", "fixture_inline_bytes",
                                            "scratch_allowance_bytes"))
            or value["requested_bytes"] >= 32 * MIB):
        raise ValueError("batch fixture budget/layout mismatch")


def validate_batch_complete(value, security):
    expected = dict(event="complete", mode="server-app-batch-cpu", security=security,
                    operations=OPERATIONS, warmup=WARMUP, verified=OPERATIONS + WARMUP,
                    work_batches=WORK_BATCHES, batch_operations=BATCH_OPERATIONS, empty_gates=EMPTY_GATES,
                    internal_datagrams=2 * (OPERATIONS + WARMUP), udp_datagrams=0, black_box=True)
    if value != expected or value.get("black_box") is not True or any(type(value.get(key)) is not int for key in expected
                               if type(expected[key]) is int):
        raise ValueError("incomplete/mismatched batch receipt")


def batch_dialogue(child, security, deadline, stream, evidence):
    batch_send(child, b"start\n")  # Registration precedes all native fixture work.
    fixture = batch_read(child, deadline, stream)
    validate_fixture(fixture, security)
    evidence["fixture"] = fixture
    clock = None
    verified = WARMUP
    for kind, blocks in (("empty", EMPTY_GATES), ("work", WORK_BATCHES)):
        for block in range(blocks):
            batch_expect(batch_read(child, deadline, stream), "ready", kind, block, verified)
            if clock is None:
                clock = ProcessCpuClock(child)  # Direct, unreaped OwnedProcess; no inherited Popen wrapper.
                evidence["clock"] = clock.status
            window = dict(kind=kind, block=block)
            evidence["windows"].append(window)
            window["before"] = clock.snapshot()
            batch_send(child, b"run\n")
            batch_expect(batch_read(child, deadline, stream), "measured", kind, block, verified)
            window["after"] = clock.snapshot()
            batch_send(child, b"verify\n")  # No native decode/crypto/validation before after-CPU.
            if kind == "work":
                verified += BATCH_OPERATIONS
            batch_expect(batch_read(child, deadline, stream), "verified", kind, block, verified)
    complete = batch_read(child, deadline, stream)
    validate_batch_complete(complete, security)
    evidence["native"] = complete
    batch_send(child, b"exit\n")
    child.stdin.close()


def batch_finish(child, lifetime, deadline):
    code = lifetime.wait(max(.001, deadline - time.monotonic()))
    # The protocol is small enough that an extra line cannot fill the pipe.
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not select.select([child.stdout], [], [], remaining)[0]:
        raise TimeoutError("batch trailing control deadline")
    if os.read(child.stdout.fileno(), 1):
        raise ValueError("extra native batch receipt")
    if code:
        raise subprocess.CalledProcessError(code, child.args)
    return code


def batch_release_child(child, lifetime):
    if child is None:
        return
    primary = None
    # Independent attempts retain EOF, exact-process settlement and fd closure
    # even if another step fails. No group query or signaling uses stale IDs.
    actions = [lambda: child.stdin.close() if not child.stdin.closed else None,
               lifetime.stop if lifetime is not None else lambda: child.wait(timeout=1),
               child.stdout.close]
    if lifetime is not None:
        actions.append(lifetime.close)
    for action in actions:
        try:
            action()
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary.add_note("independent native cleanup: " + str(error)[:512])
    if primary is not None:
        primary.cleanup_unresolved = True
        raise primary


def batch_interpret(evidence, receipt):
    """Called by controller only after child exit AND outer cleanup settlement."""
    result = dict(available=False, scope=BATCH_SCOPE, failed_conditions=[])
    failures = result["failed_conditions"]
    if (receipt.get("complete") is not True or type(receipt.get("returncode")) is not int
            or receipt["returncode"] != 0 or receipt.get("cleanup_settled") is not True
            or receipt.get("child_cleanup_settled") is not True
            or receipt.get("operations") != OPERATIONS or receipt.get("warmup") != WARMUP):
        failures.append("verification/exit/cleanup incomplete")
        return result
    validate_batch_complete(evidence["native"], receipt["security"])
    windows = evidence["windows"]
    expected = [(kind, block) for kind, count in (("empty", EMPTY_GATES), ("work", WORK_BATCHES))
                for block in range(count)]
    if [(w["kind"], w["block"]) for w in windows] != expected:
        raise ValueError("incomplete CPU window cohort")
    work, empty = [], []
    for window in windows:
        count = BATCH_OPERATIONS if window["kind"] == "work" else 1
        delta = process_clock_delta(window["before"], window["after"], count)
        if not delta["available"]:
            failures.append(f"{window['kind']}/{window['block']}: {delta['reason']}")
            continue
        cpu = delta["total_cpu_ns"]
        (work if window["kind"] == "work" else empty).append(cpu)
        if window["kind"] == "work":
            resolution = window["before"]["reported_resolution_seconds"] * 1e9
            if cpu < 10_000_000:
                failures.append(f"work/{window['block']}: below 10ms CPU minimum")
            if cpu < 100 * resolution:
                failures.append(f"work/{window['block']}: below 100 reported resolutions")
    result.update(work_cpu_ns=work, empty_gate_cpu_ns=empty,
                  minimum_work_cpu_ns=10_000_000, minimum_reported_resolutions=100,
                  maximum_empty_fraction=.01, calibration_subtracted=False)
    if len(work) == WORK_BATCHES and len(empty) == EMPTY_GATES and max(empty) > .01 * min(work):
        failures.append("largest empty gate exceeds 1% of smallest work CPU window")
    if not failures and len(work) == WORK_BATCHES and len(empty) == EMPTY_GATES:
        result.update(available=True, summed_cpu_ns=sum(work), verified_operations=OPERATIONS,
                      ns_per_verified_operation=sum(work) / OPERATIONS)
    return result


def batch_worker(root, phase):
    import resource
    name, security, _ = BATCH_PLAN[phase]
    directory = root / name
    config = load(root / "build.json")
    credentials = bounded_read("/proc/self/status", META).decode()
    validate_credentials(credentials, config["uid"], config["gid"])
    resource.setrlimit(resource.RLIMIT_FSIZE, (BATCH_LIMITS["cpu-windows.json"],
                                           resource.getrlimit(resource.RLIMIT_FSIZE)[1]))
    if os.getpgrp() != os.getpid():
        os.setpgid(0, 0)
    owned = proc_identity(os.getpid())
    owned.update(credentials=credentials, phase=name)
    save_batch(directory / "worker.json", owned)
    binary = config["binary"]
    if digest(binary) != config["binary_sha256"]:
        raise ValueError("benchmark binary identity changed")

    def interrupted(signum, frame):
        raise InterruptedError(f"worker signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    child, lifetime, primary = None, None, None
    evidence = dict(scope=BATCH_SCOPE, windows=[])
    receipt = dict(complete=False, security=security, operations=OPERATIONS, warmup=WARMUP,
                   scope=BATCH_LIFETIME_SCOPE)
    before, started = usage(), time.monotonic_ns()
    deadline = time.monotonic() + 5  # Same absolute one-child allowance as original single-process phases.
    batch_pidfds_required()
    try:
        with (directory / "bench-0.jsonlog").open("xb") as stream, (directory / "bench-stderr.log").open("xb") as errors:
            save_batch(directory / "launch-intent.json", dict(parent_pid=owned["pid"], phase=name))
            child = spawn([binary, str(OPERATIONS), security, "--batch-cpu"], file_limit=BATCH_LIMITS["bench-stderr.log"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, bufsize=0)
            lifetime = BatchLifetime(child)
            custody = proc_identity(child.pid)
            if custody["pgrp"] != child.pid or custody["session"] != child.pid:
                raise ValueError("batch child not in owned session")
            custody.update(parent_pid=owned["pid"], phase=name)
            save_batch(directory / "owned-child.json", custody)
            receipt["pid"] = child.pid
            batch_dialogue(child, security, deadline, stream, evidence)
            receipt["returncode"] = batch_finish(child, lifetime, deadline)
            receipt.update(cpu_receipt(before, usage(), scope=BATCH_LIFETIME_SCOPE), wall_ns=time.monotonic_ns() - started)
    except BaseException as error:
        primary = error
        receipt.update(error=type(error).__name__, reason=str(error)[:512])
        raise
    finally:
        try:
            batch_release_child(child, lifetime)
            receipt["child_cleanup_settled"] = True
        except BaseException as cleanup:
            receipt["cleanup_unresolved"] = True
            receipt["cleanup_errors"] = [str(value)[:256] for value in
                (cleanup, *getattr(cleanup, "__notes__", []))][:3]
            if primary is None:
                primary = cleanup
                raise
            primary.cleanup_unresolved = True
            primary.add_note("batch cleanup: " + str(cleanup)[:512])
            for note in getattr(cleanup, "__notes__", [])[:3]:
                primary.add_note(str(note)[:512])
        finally:
            receipt["complete"] = primary is None and receipt.get("returncode") == 0
            if receipt["complete"]:
                delta = receipt["delta"]
                receipt["whole_process_cpu_ns_per_verified_exchange"] = (
                    delta["utime"] + delta["stime"]) * 1e9 / (OPERATIONS + WARMUP)
            retention_primary = None
            for filename, value in (("cpu-windows.json", evidence), ("bench-0.json", receipt)):
                try:
                    save_batch(directory / filename, value)
                except BaseException as retention:
                    receipt["complete"] = False
                    receipt.pop("whole_process_cpu_ns_per_verified_exchange", None)
                    receipt["retention_error"] = filename + ": " + str(retention)[:512]
                    if primary is not None:
                        primary.add_note(receipt["retention_error"])
                    elif retention_primary is None:
                        retention_primary = retention
                    else:
                        retention_primary.add_note(receipt["retention_error"])
            if primary is None and retention_primary is not None:
                raise retention_primary


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


def cpu_receipt(before, after, *, scope=SCOPE):
    delta = {key: after[key] - before[key] for key in before}
    if any(not math.isfinite(value) or value < 0 for value in delta.values()):
        raise ValueError("invalid child resource delta")
    return {"before": before, "after": after, "delta": delta, "scope": scope}


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


def phase_command(root, phase, uid, gid, *, batch_cpu=False):
    name, _, count = (BATCH_PLAN if batch_cpu else PLAN)[phase]
    argv = prefix(BATCH_LIMITS["perf-command.log"] if batch_cpu else DATA, 60 if count == 8 else 10)
    if count == 8:
        # Upstream perf-record: per-thread disables inheritance; --uid is not setuid.
        argv += ["perf", "record", "-e", "cpu-clock", "-F", "997", "--call-graph", "fp,64",
                 "--inherit", "-m", "128", "--no-buildid-cache", "-o", str(root / name / "perf.data"), "--"]
    return argv + ["setpriv", f"--reuid={uid}", f"--regid={gid}", "--clear-groups",
                   "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--",
                   "env", f"CORE_COST_PHASE={phase}", f"CORE_COST_ROOT={root}",
                   *(["CORE_COST_BATCH_CPU=1"] if batch_cpu else []),
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


def execute_phase(directory, record, count, uid, gid, log, *, batch_cpu=False):
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
        if batch_cpu:
            record["returncode"] = batch_run_command(record["command"], timeout=20,
                file_limit=BATCH_LIMITS["perf-command.log"], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        else:
            record["returncode"] = run_owned(record["command"], timeout=70 if count == 8 else 20,
                check=False, elevated=True, file_limit=DATA,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        recorder_settled = True
    except BaseException as error:
        recorder_settled = not ("cleanup unresolved" in str(error) or getattr(error, "cleanup_unresolved", False))
        failure(error, "recorder_error")
    try:
        if batch_cpu:
            cleanup_batch(directory, recorder_settled and record.get("returncode") == 0)
            record["cleanup_settled"] = True
        else:
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


def inventory(root, *, batch_cpu=False):
    """Fixed per-file caps bound total retained evidence even on a failed phase."""
    rows, total, non_elf = [], 0, 0
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unexpected evidence file type")
        quota = BATCH_LIMITS[path.name] if batch_cpu else LIMITS.get(
            path.name, BENCH if path.suffix == ".jsonlog" else META)
        if path.name == "perf-command.log" and not path.parent.name.endswith("profile"):
            quota = META
        if info.st_size > quota:
            raise ValueError("evidence exceeds quota: " + str(path))
        total += info.st_size
        non_elf += info.st_size if path.name != "bench-core" else 0
        if total > 128 * MIB - 2 * META or non_elf > 64 * MIB - 2 * META or len(rows) >= 100:
            raise ValueError("aggregate evidence quota")
        if batch_cpu and (total > 65 * MIB - 2 * META or non_elf > MIB - 2 * META):
            raise ValueError("batch evidence exceeds 1 MiB non-ELF/65 MiB total reserve")
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
                       limit=META if env.get("CORE_COST_BATCH_CPU") == "1" else 2 * MIB, cwd=SUITE,
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


def run(root, lane, *, batch_cpu=False):
    if (sys.platform != "linux" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.getuid() <= 0 or os.getgid() <= 0):
        raise ValueError("manual Linux runner with nonzero original UID required")
    uid, gid = os.getuid(), os.getgid()
    root.mkdir(mode=0o700)
    state = {"complete": False, "scope": SCOPE, "review": REVIEW, "plan": PLAN, "phases": [],
             "budget": {"processes": 20, "measured_operations": 1_000_000, "warmup_operations": 2560,
                        "internal_datagrams": 2_005_120, "udp_datagrams": 0, "fresh_oscore_pairs": 10,
                        "artifact_bytes": 128 * MIB, "lane_bytes": 4 * 1024 * MIB}}
    plan, core = (BATCH_PLAN, BATCH_CORE) if batch_cpu else (PLAN, CORE)
    retain = save_batch if batch_cpu else save_new
    if batch_cpu:
        state.update(mode="server-app-batch-cpu", scope=BATCH_SCOPE, plan=plan,
                     review={"both_50_percent_targets": "OPEN", "performance_acceptance": False},
                     budget=dict(processes=4, worker_launches=4, maximum_live_benchmarks=1,
                                 measured_operations=200_000, warmup_operations=512,
                                 complete_exchanges=200_512, internal_datagrams=401_024, udp_datagrams=0,
                                 fresh_oscore_pairs=2, artifact_bytes=65 * MIB, non_elf_bytes=MIB,
                                 files=100, fixture_and_app_request_limit_bytes=32 * MIB,
                                 address_space_limit_bytes=512 * MIB, lane_bytes=4 * 1024 * MIB))
    primary = None
    try:
        source = {"suite": identity(SUITE), "core": identity(SUITE / "coaptic")}
        if any(value["status"] for value in source.values()) or source["core"]["revision"] != core:
            raise ValueError("clean source identities do not match fixed core")
        machine = hardware()
        page = os.sysconf("SC_PAGE_SIZE")
        if not batch_cpu and (not 1 <= os.cpu_count() <= 16 or page > 4096):
            raise ValueError("perf ring budget requires <=16 CPUs and <=4096-byte pages")
        tools = {name: command([name, "--version"], timeout=5) for name in
                 (("prlimit", "timeout", "setpriv", "nm") if batch_cpu else
                  ("perf", "prlimit", "timeout", "setpriv", "nm"))}
        retain(root / "setup.json", {"source": source, "machine": machine, "tools": tools,
                                      "page_bytes": page, "ring_bound_bytes": 0 if batch_cpu else 2 * os.cpu_count() * 129 * page,
                                      "owner": "root650/Coaptic", "release": "review settled and no users"})
        lane.mkdir(exist_ok=True)
        env = dict(os.environ, **FLAGS, CARGO_TARGET_DIR=str(lane.resolve()))
        if batch_cpu:
            env["CORE_COST_BATCH_CPU"] = "1"
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
        retain(root / "toolchain.json", {"versions": versions, "flags": FLAGS, "host": hosts[0]})
        build(root, lane, env, hosts[0])
        binary = lane.resolve() / hosts[0] / "release/bench-core"
        if binary.stat().st_size > ELF:
            raise ValueError("ELF exceeds 64 MiB")
        config = {"uid": uid, "gid": gid, "binary": str(binary), "binary_sha256": digest(binary),
                  "source": source, "source_hashes": {str(path.relative_to(SUITE)): digest(path) for path in
                      (SUITE / "tools/benchmark/native/Cargo.lock", SUITE / "tools/benchmark/native/Cargo.toml",
                       SUITE / "tools/benchmark/native/servers/Cargo.toml",
                       SUITE / "tools/benchmark/native/servers/src/bin/bench-core.rs", SUITE / "coaptic/Cargo.lock")}}
        if batch_cpu:
            config["mode"] = "server-app-batch-cpu"
        retain(root / "build.json", config)
        shutil.copyfile(binary, root / "bench-core")
        for phase, (name, _, count) in enumerate(plan):
            directory = root / name
            directory.mkdir(mode=0o700)
            record = {"name": name, "command": phase_command(root, phase, uid, gid, batch_cpu=True)
                      if batch_cpu else phase_command(root, phase, uid, gid), "complete": False}
            state["phases"].append(record)
            phase_error = None
            try:
                with (directory / "perf-command.log").open("xb") as log:
                    if batch_cpu:
                        execute_phase(directory, record, count, uid, gid, log, batch_cpu=True)
                    else:
                        execute_phase(directory, record, count, uid, gid, log)
                    receipts = [load(directory / f"bench-{i}.json") for i in range(count)]
                    record["benchmarks"] = receipts
                    if batch_cpu:
                        for receipt in receipts:
                            receipt["cleanup_settled"] = record.get("cleanup_settled", False)
                            if receipt.get("child_cleanup_settled") is not True:
                                raise RuntimeError("cleanup unresolved: missing child settlement receipt")
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
                    retain(directory / "phase.json", record)
                    inventory(root, batch_cpu=True) if batch_cpu else inventory(root)
                except Exception as error:
                    if phase_error is None:
                        raise
                    phase_error.add_note("phase retention: " + str(error)[:512])
        if digest(binary) != config["binary_sha256"] or source != {"suite": identity(SUITE), "core": identity(SUITE / "coaptic")}:
            raise ValueError("source/binary identity changed during probe")
        if batch_cpu:
            # Only now: all four native verifications, exits, group sweeps and
            # final source/binary guards have succeeded. Failures stay raw.
            state["server_app_driver_cpu"] = [
                dict(name=name, security=security, **batch_interpret(load(root / name / "cpu-windows.json"),
                     state["phases"][phase]["benchmarks"][0]))
                for phase, (name, security, _) in enumerate(plan)]
            state["interpretation"] = ("diagnostic only" if all(item["available"] for item in
                state["server_app_driver_cpu"]) else "inconclusive; fixed eligibility conditions failed")
        state["complete"] = True
    except BaseException as error:
        primary = error
        state.update(error=type(error).__name__, reason=str(error)[:512],
                     notes=[str(note)[:512] for note in getattr(error, "__notes__", [])[:4]],
                     cleanup_unresolved="cleanup unresolved" in str(error) or getattr(error, "cleanup_unresolved", False))
        raise
    finally:
        try:
            retain(root / "summary.json", state)
            index = bounded_bytes(inventory(root, batch_cpu=True) if batch_cpu else inventory(root),
                                  BATCH_LIMITS["index.json"] if batch_cpu else 2 * META)  # Before index.json itself.
            with (root / "index.json").open("xb") as stream:
                stream.write(index)
        except Exception as error:
            if primary is None:
                raise
            primary.add_note("final inventory: " + str(error)[:512])
            try:
                retain(root / "index-error.json", {"error": type(error).__name__, "reason": str(error)[:512]})
            except Exception as retention:
                primary.add_note("index failure receipt: " + str(retention)[:512])


def main():
    if sys.platform != "linux":
        raise ValueError("Linux only; importing for isolated tests is supported")
    if "CORE_COST_BUILD" in os.environ:
        root = Path(os.environ["CORE_COST_BUILD"])
        (save_batch if os.environ.get("CORE_COST_BATCH_CPU") == "1" else save_new)(
            root / "builder.json", proc_identity(os.getpid()))
        argv = ["cargo", "build", "--release", "--locked", "--target", os.environ["CORE_COST_HOST"],
                "--manifest-path", "tools/benchmark/native/Cargo.toml", "-p", "bench-rust-server", "--bin", "bench-core"]
        os.execvpe(argv[0], argv, os.environ)
    elif "CORE_COST_PHASE" in os.environ:
        phase = int(os.environ["CORE_COST_PHASE"])
        # A stale inherited environment variable cannot opt the original plan in.
        root = Path(os.environ["CORE_COST_ROOT"])
        batch_cpu = (os.environ.get("CORE_COST_BATCH_CPU") == "1"
                     and load(root / "build.json").get("mode") == "server-app-batch-cpu")
        if not 0 <= phase < len(BATCH_PLAN if batch_cpu else PLAN):
            raise ValueError("invalid private phase")
        (batch_worker if batch_cpu else worker)(root, phase)
    else:
        if sys.argv[1:] not in ([], ["--batch-cpu"]):
            raise ValueError("usage: core_cost_probe.py [--batch-cpu]")
        temporary = Path(os.environ["RUNNER_TEMP"])
        run(temporary / "core-cost-probe-evidence/probe", temporary / "cpu-build-lane",
            batch_cpu=sys.argv[1:] == ["--batch-cpu"])


if __name__ == "__main__":
    main()
