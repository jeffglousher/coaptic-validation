"""Manual, source-matched Linux process CPU qualification for core issue #650.

Builds mutate only the selected clean core checkout and ONE explicitly supplied
Cargo lane. Clean windows, perf record and perf stat passes never overlap.
See linux_cpu.md for bounds, interpretation and the manual workflow.
"""
import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import importlib.metadata
import itertools
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import select
import shutil
import signal
import socket
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time

from native_lock import native_lock
from native_profiles import validate_concurrency, PROFILE_SIZES, dimensions, validate_profile


MIB = 1024 * 1024
PERF_BUDGET = 256 * MIB
WHOLE_UPLOAD_BUDGET = 256 * MIB  # Evidence, copied binaries AND uploaded setup logs.
SETUP_LOG_BUDGET = 16 * MIB
METADATA_BUDGET = 96 * MIB
SUMMARY_LIMIT = 64 * 1024
WINDOW_LIMIT = 16 * 1024
PROCESS_CLOCK_LIMIT = 4096  # One optional clean-window sidecar.
ADMISSION_DIAGNOSTIC_LIMIT = 2048  # Carved from the existing fixed report reserve.
REPORT_BASE_FIELDS_LIMIT = SUMMARY_LIMIT - ADMISSION_DIAGNOSTIC_LIMIT
BUILD_LOG_LIMIT = 2 * MIB
WARMUP = 20
DATAGRAM_BUDGET = 60_000
PROFILE_SECONDS = 5
PERF_REPORT_SECONDS = 30
PERF_FILES_PER_SLOT = 5  # Data/stat, command log, flat report, inline callers/samples.
KINDS = ("coaptic-reusable", "coaptic-mio", "coaptic-ready")
EXPLICIT_KINDS = (*KINDS, "coaptic-async", "coaptic-blocking", "coaptic-staged-ready", "coaptic-staged-mio", "coaptic-mio-direct")
FLAGS = {"RUSTUP_TOOLCHAIN": "1.99.0", "RUSTC": "rustc",
         "RUSTFLAGS": "-C force-frame-pointers=yes", "CARGO_PROFILE_RELEASE_DEBUG": "1",
         "CARGO_PROFILE_RELEASE_STRIP": "none", "CARGO_INCREMENTAL": "0",
         "CARGO_BUILD_JOBS": "2"}
SUITE = Path(__file__).resolve().parents[2]


def sha40(value):
    if not re.fullmatch(r"[0-9a-fA-F]{40}", value):
        raise argparse.ArgumentTypeError("expected an immutable full hex40 commit SHA")
    return value.lower()


def selection(value, allowed=None):
    parts = value.split(",")
    if not parts or len(parts) > 3 or len(set(parts)) != len(parts):
        raise argparse.ArgumentTypeError("select one to three distinct comma-separated values")
    if allowed is not None and any(p not in allowed for p in parts):
        raise argparse.ArgumentTypeError("unsupported selection")
    return parts


def configuration(args):
    profile = getattr(args, "resource_profile", "host-control")
    if profile not in PROFILE_SIZES:
        raise ValueError("unknown resource profile")
    diagnostic = getattr(args, "admission_diagnostics", False)
    if type(diagnostic) is not bool:
        raise ValueError("admission diagnostics selection must be boolean")
    if diagnostic:
        if sha40(args.baseline_sha) != sha40(args.candidate_sha):
            raise ValueError("admission diagnostics require identical full core SHAs")
        if (args.candidate_server_kind is not None or args.server_kind not in EXPLICIT_KINDS
                or args.concurrency != 1 or args.perf):
            raise ValueError("admission diagnostics require one same adapter, paced C1 and perf disabled")
    if args.candidate_server_kind is not None:
        if (args.server_kind not in EXPLICIT_KINDS or args.candidate_server_kind not in EXPLICIT_KINDS
                or args.server_kind == args.candidate_server_kind):
            raise ValueError("adapter comparison requires two distinct explicit server kinds")
        if sha40(args.baseline_sha) != sha40(args.candidate_sha):
            raise ValueError("adapter comparison requires identical core SHAs; do not combine source and scheduling changes")
    validate_concurrency(args.concurrency, args.message_type, getattr(args, "independent_endpoints", False))
    sizes = [int(p) for p in selection(args.sizes, tuple(str(s) for s in PROFILE_SIZES[profile]))]
    for size in sizes:
        validate_profile(profile, args.server_kind, size, concurrency=args.concurrency,
                         message_type=args.message_type, admission_diagnostics=diagnostic,
                         independent_endpoints=getattr(args, "independent_endpoints", False))
        if profile != "host-control" and args.candidate_server_kind is not None:
            raise ValueError("representative profile requires same Mio on both labels")
    rates = [int(p) for p in selection(args.rates)]
    if len(set(rates)) != len(rates):
        raise ValueError("rates must be numerically distinct")
    kinds = list(KINDS) if args.server_kind == "all" else [args.server_kind]
    long_window = getattr(args, "long_window", False)
    security = getattr(args, "security_mode", "both")
    if type(long_window) is not bool or security not in ("both", "unprotected", "oscore"):
        raise ValueError("invalid long-window/security selection")
    if long_window:
        if (profile == "host-control" or len(sizes) != 1 or len(rates) != 1
                or security == "both" or args.server_kind != "coaptic-mio"
                or args.candidate_server_kind is not None or args.concurrency != 1
                or args.message_type != "con" or getattr(args, "independent_endpoints", False)
                or args.repeats != 4 or args.perf or diagnostic):
            raise ValueError("long windows require one representative profile/payload/rate/security, same Mio, C1 CON, four pairs, no perf/diagnostics/independent endpoints")
    elif security != "both":
        raise ValueError("individual security selection requires --long-window")
    low, high = (31, 1500) if long_window else (2, 30)
    if (not low <= args.seconds <= high or not 2 <= args.repeats <= 8
            or any(not 1 <= r <= 100_000 for r in rates) or args.server_kind not in (*EXPLICIT_KINDS, "all")):
        raise ValueError(f"seconds {low}..{high}, repeats 2..8, rates 1..100000, supported host adapter")
    cells = list(itertools.product(("unprotected", "oscore") if security == "both" else (security,), sizes, rates, kinds))
    windows = len(cells) * 2 * args.repeats
    samples = sum(rate * (2 * args.repeats * args.seconds + (4 * PROFILE_SECONDS if args.perf else 0))
                  for _, _, rate, _ in cells)
    window_limit, seconds_limit = (8, 12000) if long_window else (96, 1200)
    if windows > window_limit or windows * args.seconds > seconds_limit or samples > 2_000_000:
        raise ValueError(f"campaign exceeds {window_limit} clean windows, {seconds_limit} clean seconds or 2M latency samples")
    plan = rotation(args, cells)
    for mode, _, (_, size, rate, _), _ in plan:
        operations = rate * (args.seconds if mode == "clean" else PROFILE_SECONDS)
        if long_window and not 1 <= operations <= 60_000:
            raise ValueError("native operation count must be 1..60000")
        minimum = (WARMUP + operations) * math.ceil(size / 1024)
        if minimum > DATAGRAM_BUDGET:
            raise ValueError(f"{mode} {size}B {rate}/s: warmup plus operations require "
                             f"at least {minimum} datagrams; socket budget is {DATAGRAM_BUDGET}")
    metadata_allowance(plan, args.seconds)
    return cells


def measurement_timeout(seconds, long_window=False):
    if long_window:
        if type(seconds) is not int or not 31 <= seconds <= 1500:
            raise ValueError("long measurement duration must be 31..1500")
        return min(1600, math.ceil(seconds / .95) + 3 + 10)
    return 60


def upload_bytes(*roots):
    """Disjoint upload owners, counted once; refuse unexpected links/large trees."""
    roots = [Path(root).resolve() for root in roots if root is not None]
    if any(a.is_relative_to(b) or b.is_relative_to(a)
           for index, a in enumerate(roots) for b in roots[index + 1:]):
        raise ValueError("upload owners must be disjoint, not nested")
    total, entries = 0, 0
    for root in roots:
        if not root.is_dir():
            raise ValueError("upload owner directory missing")
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in (*dirs, *files):
                path = Path(directory) / name
                entries += 1
                if entries > 4096 or path.is_symlink() or not (path.is_dir() or path.is_file()):
                    raise ValueError("unexpected upload entry or entry bound exceeded")
                if path.is_file():
                    total += path.stat().st_size
    return total


def check_upload(out, setup_logs=None):
    if setup_logs is not None and upload_bytes(setup_logs) > SETUP_LOG_BUDGET:
        raise ValueError("setup logs exceed combined 16MiB allowance")
    actual = upload_bytes(out, setup_logs)
    if actual > WHOLE_UPLOAD_BUDGET:
        raise ValueError("whole upload exceeds 256MiB allowance")
    return actual


def upload_plan(out, setup_logs, metadata_bytes, perf_slots):
    # Metadata already owns build logs and all nested window metadata. Binaries
    # and the disjoint setup owner are added exactly once, never the whole out tree.
    check_upload(out, setup_logs)
    binaries = upload_bytes(out / "binaries")
    setup = SETUP_LOG_BUDGET if setup_logs is not None else 0
    remaining = WHOLE_UPLOAD_BUDGET - metadata_bytes - binaries - setup
    if remaining < 0 or (perf_slots and remaining < PERF_FILES_PER_SLOT * perf_slots):
        raise ValueError("planned whole upload exceeds 256MiB allowance before measurement")
    quota = min(8 * MIB, (PERF_BUDGET - METADATA_BUDGET) // max(1, PERF_FILES_PER_SLOT * perf_slots),
                remaining // max(1, PERF_FILES_PER_SLOT * perf_slots))
    return dict(whole_upload_budget_bytes=WHOLE_UPLOAD_BUDGET, copied_binary_bytes=binaries,
                setup_log_budget_bytes=setup, metadata_allowance_bytes=metadata_bytes,
                perf_file_quota_bytes=quota,
                planned_whole_upload_bytes=metadata_bytes + binaries + setup + PERF_FILES_PER_SLOT * perf_slots * quota)


def rotation(args, cells):
    plan = []
    for repeat in range(args.repeats):
        for cell_index, cell in enumerate(cells):
            labels = ("baseline", "candidate") if (repeat + cell_index) % 2 == 0 else ("candidate", "baseline")
            plan.extend(("clean", repeat, cell, label) for label in labels)
    if args.perf:
        for mode in ("record", "stat"):
            for cell in cells:
                plan.extend((mode, 0, cell, label) for label in ("baseline", "candidate"))
    return plan


def report_limit(operations):
    # u64 decimal <=20 bytes, plus comma/space. Optional diagnostics use 2KiB
    # inside the existing 64KiB fixed reserve; the campaign allowance is unchanged.
    return REPORT_BASE_FIELDS_LIMIT + ADMISSION_DIAGNOSTIC_LIMIT + 22 * operations


def metadata_allowance(plan, seconds):
    # Seven global JSON files, two build logs, one append-only index entry and
    # three bounded per-window files. Raw reports are retained exactly once.
    allowance = 7 * SUMMARY_LIMIT + 2 * BUILD_LOG_LIMIT
    for mode, _, cell, _ in plan:
        operations = cell[2] * (seconds if mode == "clean" else PROFILE_SECONDS)
        allowance += report_limit(operations) + 4 * WINDOW_LIMIT
        if mode == "clean":
            allowance += PROCESS_CLOCK_LIMIT
        if mode != "clean":
            allowance += WINDOW_LIMIT  # perf.json includes report status; output/log/report use separate quotas.
    if allowance > METADATA_BUDGET:
        raise ValueError("planned metadata exceeds 96MiB allowance")
    return allowance


def bounded_bytes(value, limit):
    # Incremental encoding stops before accumulating an oversized object. No file
    # is opened until its entire bounded encoding has been checked.
    data = bytearray()
    for chunk in json.JSONEncoder(allow_nan=False, ensure_ascii=True).iterencode(value):
        encoded = chunk.encode("ascii")
        if len(data) + len(encoded) + 1 > limit:
            raise ValueError("JSON metadata exceeds byte allowance")
        data.extend(encoded)
    data.extend(b"\n")
    return data


def bounded_read(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file exceeds byte allowance")
    return data


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            result.update(chunk)
    return result.hexdigest()


def save(path, value, limit=SUMMARY_LIMIT):
    Path(path).write_bytes(bounded_bytes(value, limit))


class ProcessCpuClock:
    """Optional owned-child CPU; never polls/reaps or derives clock IDs."""
    def __init__(self, child):
        self.child = child
        self.status = {"available": False}
        try:
            if sys.platform != "linux" or platform.machine() != "x86_64":
                raise OSError("process clock requires supported Linux x86_64")
            import ctypes
            if (ctypes.sizeof(ctypes.c_int), ctypes.sizeof(ctypes.c_long),
                    ctypes.sizeof(ctypes.c_void_p)) != (4, 8, 8):
                raise OSError("process clock requires Linux x86_64 LP64")
            if not all(callable(getattr(time, name, None)) for name in ("clock_gettime_ns", "clock_getres")):
                raise OSError("Python process-clock readers unavailable")
            self.pid = child.pid
            self.expected = self._identity()
            # glibc 2.39 x86 headers: pid_t/clockid_t are signed int32.
            # Python owns native timespec/time_t conversion; bind no such layout.
            self.libc = ctypes.CDLL(None)
            version = self.libc.gnu_get_libc_version
            version.argtypes, version.restype = [], ctypes.c_char_p
            self.status["glibc"] = version().decode("ascii")
            if self.status["glibc"] != "2.39":
                raise OSError("process clock requires reviewed glibc 2.39 ABI")
            resolve = self.libc.clock_getcpuclockid
            resolve.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
            resolve.restype = ctypes.c_int
            clock_id = ctypes.c_int()
            code = resolve(self.pid, ctypes.byref(clock_id))
            if type(code) is not int or code < 0:
                raise ValueError("invalid clock_getcpuclockid return code")
            if code:
                # Positive error number from this API; never consult errno.
                raise OSError(code, "clock_getcpuclockid")
            self.clock_id = clock_id.value
            resolution = time.clock_getres(self.clock_id)
            if (type(resolution) is not float or not math.isfinite(resolution)
                    or not 0 < resolution <= 1):
                raise ValueError("invalid process-clock resolution")
            if self._identity() != self.expected:
                raise ValueError("process identity changed during clock resolution")
            self.status.update(available=True, **self.expected, clock_id=self.clock_id,
                               reported_resolution_seconds=resolution)
        except (OSError, ValueError, TypeError, OverflowError, AttributeError, ImportError) as error:
            self._error(self.status, error)

    @staticmethod
    def _error(result, error):
        result.update(available=False, error_type=type(error).__name__, reason=str(error)[:128])
        if isinstance(error, OSError) and type(error.errno) is int:
            result["error_code"] = error.errno

    def _identity(self):
        child, pid = self.child, self.pid
        if (not isinstance(child, OwnedProcess) or type(pid) is not int
                or not 1 < pid < 2**31 or pid == os.getpid()
                or child.pid != pid or child.group != pid or child.stopped
                or child.returncode is not None):
            raise ValueError("process clock requires an unreaped owned child")
        raw = bounded_read(Path(f"/proc/{pid}/stat"), 4096)
        prefix, separator, rest = raw.partition(b" (")
        _, closing, tail = rest.rpartition(b") ")
        fields = tail.split()
        if (not separator or not closing or prefix != str(pid).encode("ascii")
                or len(fields) < 20 or fields[0] not in (b"R", b"S", b"D", b"T", b"t", b"W", b"K", b"P", b"I")
                or any(not fields[i].isdigit() for i in (1, 2, 3, 19))):
            raise ValueError("invalid process-clock source identity")
        ppid, group, session, start = (int(fields[i]) for i in (1, 2, 3, 19))
        if (ppid != os.getpid() or group != pid or session != pid or not 0 < start < 2**64):
            raise ValueError("process-clock source is not the owned child session")
        return dict(pid=pid, start_ticks=start, parent_pid=ppid, group=group, session=session)

    def snapshot(self):
        result = dict(self.status, available=False, snapshot_started_ns=time.monotonic_ns())
        try:
            if not self.status["available"]:
                return result
            if self._identity() != self.expected:
                raise ValueError("process-clock source identity changed")
            value = time.clock_gettime_ns(self.clock_id)
            if type(value) is not int or not 0 <= value < 2**63:
                raise ValueError("invalid process CPU nanoseconds")
            result["cpu_time_ns"] = value
            if self._identity() != self.expected:
                raise ValueError("process-clock source identity changed during read")
            result["available"] = True
        except (OSError, ValueError, TypeError, OverflowError, AttributeError) as error:
            self._error(result, error)
        finally:
            result["snapshot_finished_ns"] = time.monotonic_ns()
            if result["snapshot_finished_ns"] < result["snapshot_started_ns"]:
                result.update(available=False, reason="process-clock observation clock regressed")
        return result


def process_clock_delta(before, after, completed):
    """Supplement only; caller already validated complete operations."""
    result = {"available": False}
    if type(completed) is not int or completed <= 0:
        return {**result, "reason": "no verified denominator"}
    if not before["available"] or not after["available"]:
        return {**result, "reason": "process-clock snapshot unavailable"}
    identity = ("pid", "start_ticks", "parent_pid", "group", "session", "clock_id",
                "reported_resolution_seconds", "glibc")
    if any(before[key] != after[key] for key in identity):
        return {**result, "reason": "process-clock source changed"}
    if not (before["snapshot_started_ns"] <= before["snapshot_finished_ns"]
            <= after["snapshot_started_ns"] <= after["snapshot_finished_ns"]):
        return {**result, "reason": "process-clock snapshot order regressed"}
    value = after["cpu_time_ns"] - before["cpu_time_ns"]
    if value <= 0:
        return {**result, "reason": "nonpositive process CPU delta"}
    # All-thread CPU can exceed wall time; no attached-thread scheduler clamp.
    return dict(available=True, total_cpu_ns=value, verified_operations=completed,
                ns_per_verified_operation=value / completed)


def retain_process_clock(directory, evidence, result):
    # Index carries a filename, never another copy of raw readings.
    try:
        save(directory / "process-cpu-clock.json", evidence, PROCESS_CLOCK_LIMIT)
        result["process_cpu_clock_file"] = "process-cpu-clock.json"
    except (OSError, ValueError) as error:
        result["process_cpu_clock_error"] = {
            "available": False, "error_type": type(error).__name__, "reason": str(error)[:128]}


def scheduler_snapshot(pid):
    """Bounded attached-thread accounting, separate from process user/system CPU."""
    result = {"available": False, "snapshot_started_ns": time.monotonic_ns()}
    try:
        if sys.platform != "linux":
            raise OSError("schedstat requires Linux")
        if type(pid) is not int or pid <= 1:
            raise ValueError("invalid scheduler target PID")

        def identity():
            raw = bounded_read(Path(f"/proc/{pid}/stat"), 4096)
            prefix, separator, rest = raw.partition(b" (")
            _, closing, tail = rest.rpartition(b") ")
            fields = tail.split()
            if (not separator or not closing or prefix != str(pid).encode("ascii")
                    or len(fields) < 20 or not fields[17].isdigit() or not fields[19].isdigit()):
                raise ValueError("invalid scheduler target identity")
            threads, start = int(fields[17]), int(fields[19])
            if not 0 < threads < 2**32 or not 0 < start < 2**64:
                raise ValueError("scheduler identity outside bounds")
            return {"pid": pid, "start_ticks": start, "threads": threads}

        before = identity()
        fields = bounded_read(Path(f"/proc/{pid}/schedstat"), 128).split()
        if len(fields) != 3 or any(not field.isdigit() for field in fields):
            raise ValueError("invalid scheduler counters")
        values = [int(field) for field in fields]
        if any(value >= 2**64 for value in values):
            raise ValueError("scheduler counter outside bounds")
        after = identity()
        if before != after:
            raise ValueError("scheduler target identity changed during read")
        result.update(available=True, **before, runtime_ns=values[0], runqueue_wait_ns=values[1],
                      timeslices=values[2])
    except (OSError, ValueError) as error:
        result.update(error_type=type(error).__name__, reason=str(error)[:128])
    result["snapshot_finished_ns"] = time.monotonic_ns()
    if result["snapshot_finished_ns"] < result["snapshot_started_ns"]:
        result.update(available=False, error_type="ValueError", reason="scheduler snapshot clock regressed")
    return result


def scheduler_delta(before, after):
    """Refuse invalid accounting without replacing the established CPU metric."""
    result = {"available": False, "scope": "attached thread; not descendants or whole-machine CPU"}
    if not before["available"] or not after["available"]:
        return {**result, "reason": "scheduler snapshot unavailable"}
    if any(before[key] != after[key] for key in ("pid", "start_ticks", "threads")):
        return {**result, "reason": "scheduler target identity changed"}
    if before["threads"] != 1:
        return {**result, "reason": "multi-thread process; attached-thread/process scopes differ"}
    if after["snapshot_started_ns"] < before["snapshot_finished_ns"]:
        return {**result, "reason": "scheduler snapshot order regressed"}
    counters = ("runtime_ns", "runqueue_wait_ns", "timeslices")
    delta = {key: after[key] - before[key] for key in counters}
    if any(value < 0 for value in delta.values()):
        return {**result, "reason": "scheduler counters regressed"}
    if delta["runtime_ns"] == 0:
        return {**result, "reason": "no positive scheduler runtime"}
    envelope = after["snapshot_finished_ns"] - before["snapshot_started_ns"]
    if delta["runtime_ns"] > envelope:
        return {**result, "reason": "scheduler runtime exceeds observation envelope"}
    return {**result, "available": True, **delta, "observation_envelope_ns": envelope}


def retain_report(path, raw, operations):
    data = (raw + "\n").encode("utf-8")
    if len(data) > report_limit(operations):
        raise ValueError("native report exceeds byte allowance")
    Path(path).write_bytes(data)


class OwnedProcess:
    """Fresh-session child with non-reaping exit observations.

    One owner/waiter must retain the direct child through stop's final group
    signals and member exit observation. A pidfd reserves a process, not its
    numeric process group; keeping the unreaped leader reserves both identifiers
    even after leader exit.
    Callers must not poll/wait the underlying Popen outside final settlement.
    This does not contain descendants that leave the session/group.
    """
    def __init__(self, process):
        self.process = process
        self.group = process.pid
        self.stopped = False
        self._exitcode = None

    def __getattr__(self, name):
        return getattr(self.process, name)

    @property
    def returncode(self):
        return self.process.returncode if self.process.returncode is not None else self._exitcode

    def _reserved(self):
        if self.stopped or self.process.returncode is not None:
            raise RuntimeError("cleanup unresolved: owned leader already reaped")
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise RuntimeError("cleanup unresolved: default SIGCHLD required to reserve leader")
        # ECHILD also refuses an external waitpid or automatic reaping. Never
        # infer ownership from a cached PID or an empty-group observation.
        try:
            status = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError as error:
            raise RuntimeError("cleanup unresolved: owned leader no longer waitable") from error
        if status is not None:
            self._exitcode = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
        return self._exitcode

    def poll(self):
        if self.stopped:
            return self.process.returncode
        return self._reserved()

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while (code := self.poll()) is None:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise subprocess.TimeoutExpired(self.args, timeout)
            time.sleep(.01 if remaining is None else min(.01, remaining))
        return code


def spawn(argv, *, file_limit=WINDOW_LIMIT, **kwargs):
    if (sys.platform != "linux" or not callable(getattr(os, "pidfd_open", None))
            or not callable(getattr(os, "waitid", None)) or not hasattr(os, "WNOWAIT")
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise RuntimeError("owned process groups require Linux pidfds, waitid WNOWAIT and default SIGCHLD")
    def limit_output():
        import resource
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    if file_limit is not None:
        kwargs["preexec_fn"] = limit_output
    return OwnedProcess(subprocess.Popen(argv, start_new_session=True, **kwargs))


def signal_group(child, sig, elevated):
    if not isinstance(child, OwnedProcess) or child.group <= 1 or child.group == os.getpgrp():
        raise ValueError("refusing to signal an unowned process group")
    child._reserved()
    try:
        os.killpg(child.group, sig)
    except ProcessLookupError:
        if not elevated:
            return
    except PermissionError:
        if not elevated:
            raise
    if elevated:
        # killpg success means at least one member received the signal, not
        # every member. A caller-owned leader can mask surviving root-owned
        # perf/sudo descendants. Always signal with privilege while the original
        # leader still reserves the group; helper refusal/failure is fatal.
        # Only explicitly elevated owned groups may invoke this helper.
        child._reserved()
        run_owned(["sudo", "-n", "--", "kill", f"-{signal.Signals(sig).name[3:]}",
                   "--", f"-{child.group}"], timeout=5, stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL)


# These are host-side cleanup ceilings, not automatically growing inventories.
GROUP_SCAN_ENTRIES, GROUP_MEMBERS, GROUP_EXIT_SECONDS = 4096, 64, 5


def _group_proc_visible():
    """Refuse a filtered/wrong-namespace proc census rather than infer emptiness."""
    if os.readlink("/proc/self") != str(os.getpid()):
        raise RuntimeError("cleanup unresolved: proc PID namespace differs")
    lines = bounded_read("/proc/mounts", 64 * 1024).split(b"\n", 257)
    if len(lines) > 257:
        raise RuntimeError("cleanup unresolved: proc mount census capacity")
    mounts = []
    for line in lines:
        fields = line.split(None, 6)
        if not fields:
            continue
        if len(fields) != 6:
            raise ValueError("cleanup unresolved: malformed proc mounts")
        if fields[1] == b"/proc":
            mounts.append(fields)
    if len(mounts) != 1 or mounts[0][2] != b"proc":
        raise RuntimeError("cleanup unresolved: missing unique proc mount")
    for option in mounts[0][3].split(b","):
        if option.startswith(b"hidepid") and option not in (b"hidepid=0", b"hidepid=off"):
            raise RuntimeError("cleanup unresolved: filtered proc mount")


def _group_stat(stream, pid):
    # The open stat inode stays bound to its original task across PID reuse.
    raw = stream.read(4097)
    if len(raw) > 4096 or not raw.endswith(b"\n"):
        raise ValueError("cleanup unresolved: proc stat byte allowance/completeness")
    head, separator, tail = raw.rpartition(b")")
    fields = tail.split()
    if (not separator or not head.startswith(str(pid).encode() + b" (")
            or not 20 <= len(fields) <= 64 or len(fields[0]) != 1
            or fields[0] not in b"RSDZTWtXxKIP"
            or any(not fields[index].isdigit() for index in (2, 3, 19))):
        raise ValueError("cleanup unresolved: malformed proc stat")
    group, session, start = (int(fields[index]) for index in (2, 3, 19))
    if not 0 <= group < 2**31 or not 0 <= session < 2**31 or not 0 <= start < 2**64:
        raise ValueError("cleanup unresolved: proc identity outside bounds")
    return pid, group, session, start


def wait_group_exit(child):
    """Observe exit of the killed, inherited group before releasing its leader.

    Scope: the fresh session's original group in this PID namespace, under one
    owner/waiter. No escaped groups/sessions, namespace changes or external joins
    are supported. Successful final group KILL prevents its members completing
    new forks (Linux copy_process checks fatal signals under tasklist/sighand
    locks); the second complete census refuses newly discovered membership.
    This is not an arbitrary-descendant containment or atomic /proc snapshot.

    Two scans: <=8192 directory entries, <=4096 bytes/stat, <=64 process pidfds
    plus one stat and one directory handle; <=64KiB mount input. One five-second
    deadline includes scans/polling; each proc read and parse is size bounded.
    Flags=0 observes the entire thread group, even with a zombie TGID leader.
    No per-PID signals, and an observation never authorizes a later signal.
    """
    if (not isinstance(child, OwnedProcess) or child.group <= 1 or child.group == os.getpgrp()
            or sys.platform != "linux" or not callable(getattr(os, "pidfd_open", None))):
        raise RuntimeError("cleanup unresolved: group exit requires owned Linux group and pidfds")
    child._reserved()
    deadline = time.monotonic() + GROUP_EXIT_SECONDS
    observed, handles, primary = {}, [], None

    def budget():
        child._reserved()
        if time.monotonic() >= deadline:
            raise TimeoutError("cleanup unresolved: owned group exit deadline")

    def scan(final):
        leader_seen = False
        with os.scandir("/proc") as entries:
            for count, entry in enumerate(entries, 1):
                budget()
                if count > GROUP_SCAN_ENTRIES or len(entry.name) > 64:
                    raise RuntimeError("cleanup unresolved: proc census capacity")
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                pid = int(entry.name)
                if not 0 < pid < 2**31:
                    raise ValueError("cleanup unresolved: invalid proc PID")
                try:
                    stream = Path(entry.path, "stat").open("rb")
                except FileNotFoundError:
                    continue  # This proc entry already disappeared; never signal its number.
                with stream:
                    try:
                        identity = _group_stat(stream, pid)
                    except ProcessLookupError:
                        continue  # Already-open proc inode lost its exited task.
                    if identity[1] != child.group:
                        continue
                    if identity[2] != child.group or identity[3] <= 0:
                        raise RuntimeError("cleanup unresolved: group session/identity changed")
                    leader_seen |= pid == child.pid
                    if pid in observed:
                        if identity != observed[pid][0]:
                            raise RuntimeError("cleanup unresolved: group member identity changed")
                        continue
                    if final:
                        raise RuntimeError("cleanup unresolved: group membership changed after exit census")
                    if len(observed) >= GROUP_MEMBERS:
                        raise RuntimeError("cleanup unresolved: owned group member capacity")
                    # Keep the original open proc inode across acquisition. A
                    # path reread/starttime comparison alone cannot exclude a
                    # recycled PID within the same clock tick. Races fail closed.
                    fd = os.pidfd_open(pid, 0)
                    handles.append(fd)  # Close independently even if validation fails.
                    stream.seek(0)
                    if _group_stat(stream, pid) != identity:
                        raise RuntimeError("cleanup unresolved: member changed during pidfd acquisition")
                    observed[pid] = identity, fd
        budget()
        if not leader_seen:
            raise RuntimeError("cleanup unresolved: reserved leader missing from proc census")

    try:
        _group_proc_visible()
        scan(False)
        pending = set(handles)
        poller = select.poll()
        for fd in pending:
            poller.register(fd, select.POLLIN | select.POLLHUP)
        while pending:
            budget()
            remaining_ms = max(1, min(50, int((deadline - time.monotonic()) * 1000)))
            for fd, events in poller.poll(remaining_ms):
                if fd not in pending or events & (select.POLLERR | select.POLLNVAL):
                    raise RuntimeError("cleanup unresolved: pidfd observation failed")
                if events & (select.POLLIN | select.POLLHUP):
                    pending.remove(fd)
                    poller.unregister(fd)
        scan(True)
    except BaseException as error:
        primary = error
    finally:
        for fd in handles:
            try:
                os.close(fd)
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note("independent observer close: " + str(error)[:128])
    if primary is not None:
        primary.cleanup_unresolved = True
        raise primary


def stop(child, *, elevated=False):
    if child is None:
        return
    if not isinstance(child, OwnedProcess):
        raise ValueError("refusing to stop an unowned process")
    if child.stopped:
        return
    try:
        child._reserved()  # Refuse before any numeric group query/signal.
    except BaseException as error:
        error.cleanup_unresolved = True
        raise
    primary = None
    actions = (lambda: signal_group(child, signal.SIGTERM, elevated),
               lambda: child.wait(timeout=5),
               lambda: signal_group(child, signal.SIGKILL, elevated),
               lambda: wait_group_exit(child),
               lambda: child.process.wait(timeout=5))
    for index, action in enumerate(actions):
        try:
            action()
        except subprocess.TimeoutExpired as error:
            # A live leader after TERM is expected; final reap timeout is fatal.
            if index == 1:
                continue
            if primary is None:
                primary = error
            else:
                primary.add_note("independent cleanup: " + str(error)[:512])
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary.add_note("independent cleanup: " + str(error)[:512])
    if primary is not None:
        primary.cleanup_unresolved = True
        raise primary
    child.stopped = True


def run_owned(argv, *, timeout, check=True, elevated=False, **kwargs):
    child = spawn(argv, **kwargs)
    try:
        code = child.wait(timeout=timeout)
        if check and code:
            raise subprocess.CalledProcessError(code, argv)
    except BaseException as error:
        try:
            stop(child, elevated=elevated)
        except BaseException as cleanup:
            error.add_note(f"owned process cleanup: {type(cleanup).__name__}: {str(cleanup)[:512]}")
            error.cleanup_unresolved = True
            for note in getattr(cleanup, "__notes__", [])[:4]:
                error.add_note("independent owned cleanup: " + str(note)[:512])
        raise
    else:
        try:
            stop(child, elevated=elevated)
        except BaseException as error:
            error.cleanup_unresolved = True
            raise
        return code


def run_logged(argv, stream, *, timeout, limit=BUILD_LOG_LIMIT, cancel=None, **kwargs):
    """Cap output; an optional Event requests cancellation from the sole owner."""
    remaining = limit - stream.tell()
    if remaining < 0:
        raise ValueError("build log exceeds byte allowance")
    child = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                  file_limit=None, **kwargs)
    overflow = threading.Event()
    abandon_output = threading.Event()
    reader_errors = []

    def copy_output():
        nonlocal remaining
        try:
            read = getattr(child.stdout, "read1", child.stdout.read)
            while data := read(65536):
                if abandon_output.is_set():
                    return
                kept = data[:remaining]
                stream.write(kept)
                stream.flush()
                remaining -= len(kept)
                if len(kept) < len(data):
                    overflow.set()
        except Exception as error:
            reader_errors.append(type(error).__name__)
            overflow.set()

    reader = threading.Thread(target=copy_output, daemon=True)
    primary = None
    try:
        reader.start()
        deadline = time.monotonic() + timeout
        while True:
            if cancel is not None and cancel.is_set():
                raise InterruptedError("logged command cancelled")
            if overflow.is_set():
                raise ValueError("build log exceeded byte allowance or output reader failed")
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            try:
                code = child.wait(timeout=min(.1, remaining_seconds))
                if cancel is not None and cancel.is_set():
                    raise InterruptedError("logged command cancelled")
                break
            except subprocess.TimeoutExpired:
                continue
        if code:
            raise subprocess.CalledProcessError(code, argv)
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup = None
        # Reader settlement remains independent of stop/reap failure.
        for action in (lambda: stop(child), lambda: reader.join(timeout=1)):
            try:
                action()
            except BaseException as error:
                if cleanup is None:
                    cleanup = error
                else:
                    cleanup.add_note("independent log cleanup: " + str(error)[:512])
        try:
            if reader.is_alive():
                abandon_output.set()  # Refuse further output at the next read boundary.
                raise TimeoutError("build output reader cleanup deadline")
            child.stdout.close()
        except BaseException as error:
            if cleanup is None:
                cleanup = error
            else:
                cleanup.add_note("output reader cleanup: " + str(error)[:512])
        if cleanup is not None:
            cleanup.cleanup_unresolved = True
            if primary is None:
                raise cleanup
            primary.cleanup_unresolved = True
            primary.add_note("owned log cleanup: " + str(cleanup)[:512])
            for note in getattr(cleanup, "__notes__", [])[:4]:
                primary.add_note("independent log cleanup: " + str(note)[:512])
    if overflow.is_set() or reader_errors:
        raise ValueError("build log exceeded byte allowance or output reader failed")


def command(argv, *, cwd=SUITE, timeout=60, env=None):
    with tempfile.TemporaryFile() as stream:
        run_logged(argv, stream, cwd=cwd, env=env, timeout=timeout, limit=SUMMARY_LIMIT)
        stream.seek(0)
        data = stream.read(SUMMARY_LIMIT + 1)
        if len(data) > SUMMARY_LIMIT:
            raise ValueError("command output exceeds byte allowance")
        return data.decode("utf-8").strip()


def identity(root):
    return {"revision": command(["git", "rev-parse", "HEAD"], cwd=root),
            "tree": command(["git", "rev-parse", "HEAD^{tree}"], cwd=root),
            "status": command(["git", "--no-optional-locks", "status", "--porcelain"], cwd=root)}


def hardware():
    info = {"platform": platform.platform(), "python": sys.version,
            "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "cpu_affinity": sorted(os.sched_getaffinity(0)),
            "cpu_count": os.cpu_count(), "load_average": os.getloadavg()}
    for name, path in {"cpuinfo": "/proc/cpuinfo", "meminfo": "/proc/meminfo",
                       "perf_event_paranoid": "/proc/sys/kernel/perf_event_paranoid",
                       "governor": "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
                       "clocksource": "/sys/devices/system/clocksource/clocksource0/current_clocksource"}.items():
        try:
            info[name] = bounded_read(path, 16 * 1024).decode("utf-8")
        except ValueError:
            with Path(path).open("rb") as stream:
                info[name] = stream.read(16 * 1024).decode("utf-8", errors="replace")
        except OSError as error:
            info[name] = str(error)
    return info


def build(args, label, revision, out, *, expected=None):
    core = SUITE / "coaptic"
    suite_before = identity(SUITE)
    if suite_before["status"]:
        raise ValueError("refusing to build a dirty suite checkout")
    if identity(core)["status"]:
        raise ValueError("refusing to replace a dirty core checkout")
    log = out / f"build-{label}.log"
    env = dict(os.environ, **FLAGS, CARGO_TARGET_DIR=str(args.build_lane.resolve()))
    # No RUSTC_WRAPPER/cache, encoded flags or profile overrides inherited silently.
    for key in list(env):
        if (key.startswith("CARGO_PROFILE_RELEASE_") and key not in FLAGS
                or key in ("CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")):
            del env[key]
    # Retain exact identities even on refusal, before checkout or compilation.
    versions = {"RUSTUP_TOOLCHAIN": env["RUSTUP_TOOLCHAIN"]}
    version_path = out / f"build-{label}.json"
    save(version_path, versions)
    for tool in ("rustc", "cargo"):
        versions[tool] = command([tool, "-Vv"], cwd=SUITE, env=env)
        save(version_path, versions)
    rustc, cargo = versions["rustc"], versions["cargo"]
    hosts = [line[6:] for line in rustc.splitlines() if line.startswith("host: ")]
    if len(hosts) != 1 or not re.fullmatch(r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+", hosts[0]):
        raise ValueError("rustc -Vv must identify one valid host target")
    host = hosts[0]
    for tool in ("rustc", "cargo"):
        lines = versions[tool].splitlines()
        releases = [line.removeprefix("release: ") for line in lines if line.startswith("release: ")]
        commits = [line.removeprefix("commit-hash: ") for line in lines if line.startswith("commit-hash: ")]
        if releases != [env["RUSTUP_TOOLCHAIN"]]:
            raise ValueError(f"{tool} release does not match selected RUSTUP_TOOLCHAIN {env['RUSTUP_TOOLCHAIN']}")
        if len(commits) != 1 or not re.fullmatch(r"[0-9a-f]{40}", commits[0]):
            raise ValueError(f"{tool} -Vv must identify one full commit hash")
    if expected is not None:
        for field, actual in (("rustc", rustc), ("cargo", cargo), ("target", host), ("flags", FLAGS)):
            if actual != expected[field]:
                raise ValueError("build configuration differs before build: " + field)
    with log.open("wb") as stream:
        def invoke(argv):
            line = (json.dumps(argv) + "\n").encode("utf-8")
            if stream.tell() + len(line) > BUILD_LOG_LIMIT:
                raise ValueError("build log exceeds byte allowance")
            stream.write(line)
            stream.flush()
            run_logged(argv, stream, cwd=SUITE, env=env, timeout=900)
        for argv in (["git", "-C", str(core), "fetch", "--depth", "1", "origin", revision],
                     ["git", "-C", str(core), "checkout", "--detach", revision]):
            invoke(argv)
        source = identity(core)
        if source["revision"] != revision or source["status"]:
            raise ValueError("selected core identity differs before build")
        with native_lock(core, SUITE / "tools/benchmark/native") as lock_input:
            versions["native_lock_input"] = lock_input
            save(version_path, versions)
            invoke(["cargo", "build", "--release", "--locked", "--target", host, "--manifest-path",
                    "tools/benchmark/native/Cargo.toml", "-p", "bench-rust-server",
                    "--bin", "bench-rust-server", "--bin", "bench-native-client"])
    # The selected lock is restored and verified before source/binary acceptance.
    source = identity(core)
    if source["revision"] != revision or source["status"]:
        raise ValueError("core identity changed during build")
    suite_after = identity(SUITE)
    if suite_after != suite_before:
        raise ValueError("suite identity changed during build")
    destination = out / "binaries" / label
    destination.mkdir(parents=True)
    binaries = {}
    for name in ("bench-rust-server", "bench-native-client"):
        origin = args.build_lane / host / "release" / name
        if origin.stat().st_size > 128 * MIB:
            raise ValueError("binary exceeds 128MiB copy budget")
        target = destination / name
        shutil.copy2(origin, target)
        binaries[name] = {"path": str(target), "sha256": digest(target), "bytes": target.stat().st_size}
    record = {"core": source, "suite": suite_after, "binaries": binaries,
              "native_lock_sha256": lock_input["selected_sha256"], "native_lock_input": lock_input,
              "core_lock_sha256": digest(core / "Cargo.lock"), "flags": FLAGS,
              "native_manifest_sha256": digest(SUITE / "tools/benchmark/native/Cargo.toml"),
              "target": host, "rustc": rustc, "cargo": cargo}
    save(out / f"build-{label}.json", record)
    return record


def matching_lock_inputs(baseline, candidate):
    """Both builds must select from the same validated, committed input pair."""
    for build_record in (baseline, candidate):
        selected = build_record["native_lock_input"]
        requirement = selected["syn_requirement"]
        if requirement not in ("2", "3"):
            raise ValueError("unsupported recorded native lock requirement")
        expected = selected["canonical_base_sha256"] if requirement == "2" else selected["syn3_sha256"]
        if (selected["selected_sha256"] != expected
                or build_record["native_lock_sha256"] != expected):
            raise ValueError("recorded native lock differs from selected input")
    for field in ("canonical_base_sha256", "syn3_sha256"):
        if baseline["native_lock_input"][field] != candidate["native_lock_input"][field]:
            raise ValueError("native lock input pair differs: " + field)


def perf_command(mode, pid, seconds, output, quota, *, event="cpu-clock", control_paths=None):
    # Apply a hard RLIMIT_FSIZE after sudo so sudo policy cannot reset the bound.
    prefix = ["sudo", "-n", "--", "prlimit", f"--fsize={quota}:{quota}", "--",
              "timeout", "--signal=TERM", "--kill-after=5",
              str(PROFILE_SECONDS + 10 if mode == "record" else seconds + 10), "perf"]
    if mode == "record":
        if event not in ("cpu-clock", "task-clock"):
            raise ValueError("record event must be cpu-clock or task-clock")
        if (control_paths is None or len(control_paths) != 2
                or any(not str(path) or any(c in str(path) for c in ",\n\r") for path in control_paths)):
            raise ValueError("record requires two unambiguous control FIFO paths")
        return prefix + ["record", "-e", event, "-F", "997", "--call-graph", "fp",
                         "-m", "128", "--no-buildid-cache", "-o", str(output), "-p", str(pid),
                         "-D", "-1", "--control", "fifo:" + ",".join(map(str, control_paths))]
    else:
        options = ["stat", "-x", ";", "-e", "task-clock,cycles,instructions,context-switches,cpu-migrations,page-faults",
                   "-o", str(output)]
    return prefix + options + ["-p", str(pid), "--", "sleep", str(seconds)]


class PerfCapture(dict):
    """Serializable capture metadata; private handles never become mapping keys.

    The record ACK fences command processing, not representative sampling or
    success of every kernel enable operation. No control state affects clean/stat.
    """
    def __init__(self, mode, seconds, target=None):
        super().__init__(mode=mode, window_seconds=seconds,
                         boundary="attach after warmup; bounded wall window; may include idle/control overhead; never clean timing")
        self.deadline = None
        self._target = target
        self._recorder = None
        self._control_dir = None
        self._directory_id = None
        self._control_paths = None
        self._fifo_ids = ()
        self._fds = ()
        self._optional_nul = False
        self._phase = 0
        self._enabled = False
        self._finish_attempted = False
        self._control_log = None
        self._log_tail = b""

    def _observe_log(self, *, final=False):
        """Bounded observations of existing stderr; these are never ACKs."""
        if self._control_log is None:
            return
        quota = self["file_size_limit_bytes"]
        try:
            for _ in range((quota + 4095) // 4096 if final else 1):
                remaining = quota - self.get("control_log_observed_bytes", 0)
                if remaining <= 0:
                    break
                data = self._control_log.read(min(4096, remaining))
                if not data:
                    break
                self["control_log_observed_bytes"] = self.get("control_log_observed_bytes", 0) + len(data)
                observed = time.monotonic()
                text = self._log_tail + data
                lines = text.split(b"\n")
                for marker, key in ((b"Events disabled", "events_disabled_observed_monotonic"),
                                    (b"Events enabled", "events_enabled_observed_monotonic"),
                                    (b"perf record has started", "record_start_observed_monotonic")):
                    if marker in lines[:-1]:
                        self.setdefault(key, observed)
                tail = lines[-1]
                self._log_tail = tail if len(tail) <= 64 else b"\0" + tail[-63:]
        except Exception as error:
            self.update(control_log_observation_error=type(error).__name__,
                        control_log_observation_reason=str(error)[:512])

    def _open_control(self, directory):
        # Special files must remain outside artifact traversal, including when
        # unresolved process cleanup requires retaining the owned control paths.
        self._control_dir = Path(tempfile.mkdtemp(prefix="coaptic-perf-control-"))
        info = self._control_dir.lstat()
        self._directory_id = (info.st_dev, info.st_ino)
        self._control_dir.chmod(0o700)
        info = self._control_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("private record control directory refused")
        self._control_paths = tuple(self._control_dir / name for name in ("ctl", "ack"))
        for path in self._control_paths:
            os.mkfifo(path, 0o600)
            info = path.lstat()
            self._fifo_ids += ((info.st_dev, info.st_ino),)
            path.chmod(0o600)
            fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
            self._fds += (fd,)
            opened = os.fstat(fd)
            if (not stat.S_ISFIFO(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600
                    or (opened.st_dev, opened.st_ino) != self._fifo_ids[-1]):
                raise RuntimeError("owned record control FIFO refused")

    def _cleanup_failure(self, error):
        self.update(cleanup_unresolved=True, cleanup_error=type(error).__name__,
                    cleanup_reason=(self.get("cleanup_reason", "") + "; " + str(error))[-512:])

    def _close_control(self, *, remove):
        # Attempt every close after recorder cleanup, even if a previous close fails.
        for fd in self._fds:
            try:
                os.close(fd)
            except OSError as error:
                self._cleanup_failure(error)
        self._fds = ()
        if self._control_dir is None:
            return
        if remove:
            try:
                info = self._control_dir.lstat()
                if ((info.st_dev, info.st_ino) != self._directory_id
                        or not stat.S_ISDIR(info.st_mode)):
                    raise RuntimeError("record control directory ownership changed")
                for path, identity in zip(self._control_paths or (), self._fifo_ids):
                    info = path.lstat()
                    if (not stat.S_ISFIFO(info.st_mode)
                            or (info.st_dev, info.st_ino) != identity):
                        raise RuntimeError("record control FIFO ownership changed")
                    path.unlink()
                self._control_dir.rmdir()  # Refuse unexpected contents; never recursive.
            except OSError as error:
                self._cleanup_failure(error)
            except RuntimeError as error:
                self._cleanup_failure(error)
        if not remove or self.get("cleanup_unresolved"):
            self["retained_control_directory"] = str(self._control_dir)

    def _check_alive(self, *, recorder=True):
        if self._target is not None and self._target.poll() is not None:
            raise RuntimeError("record target exited during control")
        if recorder and self._recorder.poll() is not None:
            raise RuntimeError("recorder exited during control")

    @staticmethod
    def _remaining(deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("record control deadline")
        return remaining

    def _read_ack(self):
        allowance = min(8, 64 - self["control_ack_bytes"])
        if allowance <= 0:
            raise RuntimeError("record ACK byte allowance exceeded")
        data = os.read(self._fds[1], allowance)
        if not data:
            raise RuntimeError("record ACK channel ended")
        self["control_ack_bytes"] += len(data)
        observed = time.monotonic()
        self.setdefault("control_first_reply_observed_monotonic", observed)
        self["control_last_reply_observed_monotonic"] = observed
        self["control_reply_prefix_hex"] = data.hex()
        if len(data) > allowance:
            raise RuntimeError("record ACK byte allowance exceeded")
        return data

    def _retain_late_reply(self):
        # Observe only after reap, never acknowledge or reopen a refused gate.
        while self["control_ack_bytes"] < 64:
            try:
                data = self._read_ack()
            except BlockingIOError:
                return
            except Exception as error:
                self.update(control_late_read_error=type(error).__name__, control_late_read_reason=str(error)[:512])
                return
            observed = self["control_last_reply_observed_monotonic"]
            self.setdefault("control_late_first_observed_monotonic", observed)
            self["control_late_last_observed_monotonic"] = observed
            self["control_late_reply_bytes"] = self.get("control_late_reply_bytes", 0) + len(data)
            self["control_late_reply_hex"] = self.get("control_late_reply_hex", "") + data.hex()
        self["control_reply_allowance_exhausted"] = True

    def _drain_padding(self):
        # One optional NUL may arrive after the preceding newline, including
        # across command boundaries. Everything else before a command is stale.
        while True:
            try:
                data = self._read_ack()
            except BlockingIOError:
                return
            if not self._optional_nul or data != b"\0":
                raise RuntimeError("stale or extra record ACK bytes")
            self._optional_nul = False

    def _command(self, command):
        commands = ("enable", "disable", "stop")
        if self._phase >= len(commands) or command != commands[self._phase]:
            raise ValueError("record control command order")
        attempted = time.monotonic()
        end = min(self.deadline, attempted + 2)
        self[command + "_attempt_monotonic"] = attempted
        self[command + "_ack_deadline_monotonic"] = end
        try:
            self._observe_log()
            self._remaining(end)
            self._check_alive()
            self._drain_padding()
            self._remaining(end)
            message = (command + "\n").encode("ascii")
            if os.write(self._fds[0], message) != len(message):
                raise RuntimeError("short record control write")
            self["control_commands_sent"] += 1
            self[command + "_sent_monotonic"] = time.monotonic()
            position, padding = 0, self._optional_nul
            self._optional_nul = False
            trailing_nul = False
            while True:
                self._remaining(end)
                self._observe_log()
                remaining = self._remaining(end)
                try:
                    data = self._read_ack()
                except BlockingIOError:
                    self._check_alive()
                    select.select([self._fds[1]], [], [], min(remaining, .05))
                    continue
                for byte in data:
                    if padding:
                        padding = False
                        if byte == 0:
                            continue
                    if position < 4:
                        if byte != b"ack\n"[position]:
                            raise RuntimeError("malformed record ACK")
                        position += 1
                    elif byte == 0 and not trailing_nul:
                        trailing_nul = True
                    else:
                        raise RuntimeError("extra record ACK bytes")
                if position == 4:
                    self._observe_log()
                    self._optional_nul = not trailing_nul
                    self._drain_padding()
                    self._remaining(end)
                    # A recorder may exit normally immediately after stop ACK.
                    self._check_alive(recorder=command != "stop")
                    self[command + "_ack_monotonic"] = time.monotonic()
                    self["control_acks"] += 1
                    self._phase += 1
                    return
        except BaseException as error:
            self._observe_log()
            refused = time.monotonic()
            self.update(control_error=type(error).__name__, control_reason=str(error)[:512],
                        control_refused_command=command, control_refused_monotonic=refused,
                        control_ack_bytes_at_refusal=self["control_ack_bytes"])
            if isinstance(error, TimeoutError):
                self["deadline_exceeded"] = True
                self["control_timeout_boundary"] = "capture" if end == self.deadline else "ACK"
                self["capture_deadline_exceeded"] = refused >= self.deadline
            raise

    def finish_recording(self):
        """Disable then stop once; cleanup still reaps the owned recorder."""
        if self["mode"] != "record" or self._finish_attempted or not self._enabled:
            return
        self._finish_attempted = True
        self._command("disable")
        self._command("stop")
        self["record_finished"] = True


def perf_report(directory, quota, log):
    """Read our completed capture on its runner while live kernel/ELF symbols exist."""
    path = directory / "perf-report.txt"
    # Flat self costs avoid cumulative double counting and unbounded callchain
    # expansion. Keep headers, unknown symbols and stderr warnings verbatim.
    # --force permits our sudo-owned capture; it does not grant read permission.
    # Reapply bounds after sudo and leave five seconds for the inner KILL.
    # This watchdog also bounds perf if sudo/timeout separates its process group;
    # signaling our launch group alone cannot prove containment of descendants.
    argv = ["sudo", "-n", "--", "prlimit", f"--fsize={quota}:{quota}", "--",
            "timeout", "--signal=TERM", "--kill-after=5", str(PERF_REPORT_SECONDS - 5),
            "env", "DEBUGINFOD_URLS=",
            "perf", "report", "--stdio", "--header", "--show-nr-samples", "--show-total-period",
            "--sort", "dso,symbol", "--no-children", "--call-graph", "none", "--percent-limit", "0",
            "--stdio-color", "never", "--no-inline", "--demangle", "--force",
            "--input", str(directory / "perf.data")]
    version = ["perf", "--version"]
    state = dict(available=False, command=argv, version_command=version, output_file=str(path),
                 file_size_limit_bytes=quota, timeout_seconds=PERF_REPORT_SECONDS, version_timeout_seconds=5,
                 interpretation="flat sampled self costs; capture headers/counts/warnings as exposed by perf; no stage timings")
    try:
        with path.open("wb") as stream:
            state["version_returncode"] = run_owned(version, timeout=5, check=False,
                                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                                    file_limit=quota)
            state["returncode"] = run_owned(argv, timeout=PERF_REPORT_SECONDS, check=False, elevated=True,
                                           stdin=subprocess.DEVNULL, stdout=stream, stderr=stream,
                                           file_limit=quota, env={**os.environ, "DEBUGINFOD_URLS": ""})
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


def perf_attribution(directory, quota, log, pid):
    """Retain bounded inline readouts, not App eligibility or cost conclusions."""
    if type(pid) is not int or pid <= 0:
        raise ValueError("attribution requires a positive server PID")
    result = dict(available=False, pid=pid,
                  interpretation="readout availability only; App ancestry, inline completeness, eligible sample counts and CPU attribution require review")
    commands = (("callers", "perf-callers.txt", ["report", "--stdio", "--header", "--show-nr-samples",
                 "--show-total-period", "--sort", "pid,dso,symbol", "--children", "--call-graph",
                 "graph,0,caller", "--inline", "--percent-limit", "0", "--percentage", "absolute",
                 "--stdio-color", "never", "--demangle"]),
                ("samples", "perf-samples.txt", ["script", "--ns", "--demangle", "--inline",
                 "--show-task-events", "--show-lost-events", "-F", "comm,pid,tid,time,event,period,ip,sym,dso"]))
    skipped = None
    for name, filename, options in commands:
        path = directory / filename
        argv = ["sudo", "-n", "--", "prlimit", f"--fsize={quota}:{quota}", "--",
                "timeout", "--foreground", "--signal=TERM", "--kill-after=5", str(PERF_REPORT_SECONDS - 5),
                "env", "DEBUGINFOD_URLS=", "perf", *options, "--pid", str(pid),
                "--force", "--input", str(directory / "perf.data")]
        state = result[name] = dict(available=False, command=argv, output_file=str(path), pid=pid,
                                   file_size_limit_bytes=quota, timeout_seconds=PERF_REPORT_SECONDS)
        if skipped is not None:
            state["skipped"] = skipped
            continue
        stream = None
        try:
            stream = path.open("xb")
            state["returncode"] = run_owned(argv, timeout=PERF_REPORT_SECONDS, check=False, elevated=True,
                                           stdin=subprocess.DEVNULL, stdout=stream, stderr=stream,
                                           file_limit=quota, env={**os.environ, "DEBUGINFOD_URLS": ""})
        except Exception as error:
            state.update(error_type=type(error).__name__, reason=str(error)[:512])
            if isinstance(error, subprocess.TimeoutExpired):
                state["deadline_exceeded"] = True
            if getattr(error, "cleanup_unresolved", False):
                state["cleanup_unresolved"] = True
                state["cleanup_reason"] = "; ".join(getattr(error, "__notes__", []) or [str(error)])[:512]
        finally:
            # Closing/stat failures must not replace a primary timeout or its
            # independent process-cleanup evidence. Never truncate prior output.
            if stream is not None:
                try:
                    stream.close()
                except OSError as error:
                    state.update(close_error=type(error).__name__, close_reason=str(error)[:512],
                                 cleanup_unresolved=True)
            try:
                state["output_bytes"] = path.stat().st_size
                state["command_log_bytes"] = os.fstat(log.fileno()).st_size
            except OSError as error:
                state.update(metadata_error=type(error).__name__, metadata_reason=str(error)[:512])
        state["available"] = (not any(state.get(key) for key in
                                      ("error_type", "close_error", "metadata_error", "cleanup_unresolved"))
                              and state.get("returncode") == 0
                              and 0 < state.get("output_bytes", 0) < quota
                              and state.get("command_log_bytes", quota) < quota)
        if state.get("cleanup_unresolved"):
            result["cleanup_unresolved"] = True
        if not state["available"]:
            skipped = "previous attribution readout unavailable; no retry"
    result["available"] = all(result[name]["available"] for name, _, _ in commands)
    return result


@contextmanager
def perf_pass(mode, pid, seconds, directory, quota, *, event="cpu-clock", target=None, attribution=False):
    if type(attribution) is not bool or (attribution and (type(pid) is not int or pid <= 0)):
        raise ValueError("attribution requires a boolean request and a positive server PID")
    state = PerfCapture(mode, seconds, target)
    if mode == "clean":
        yield state
        return
    if mode == "record" and event not in ("cpu-clock", "task-clock"):
        raise ValueError("record event must be cpu-clock or task-clock")
    path = directory / ("perf.data" if mode == "record" else "perf-stat.txt")
    state["file_size_limit_bytes"] = quota
    with (directory / "perf-command.log").open("w") as log:
        child = primary = finish_error = None
        reaped = True
        try:
            if mode == "record":
                state.deadline = time.monotonic() + PROFILE_SECONDS + 10
                state.update(capture_deadline_monotonic=state.deadline, control_ack_bytes=0,
                             control_commands_sent=0, control_acks=0,
                             control_ack_limit_bytes=64, control_ack_timeout_seconds=2,
                             control_interpretation="ACK fences processing, not representative sampling")
                # A separate open file description cannot move the recorder's
                # inherited stderr write offset. No pipe, thread or extra output.
                state._control_log = (directory / "perf-command.log").open("rb")
                try:
                    state._open_control(directory)
                except BaseException as error:
                    state.update(control_error=type(error).__name__, control_reason=str(error)[:512])
                    raise
            argv = perf_command(mode, pid, seconds, path, quota, event=event,
                                control_paths=state._control_paths)
            state["command"] = argv
            if mode == "record":
                state["recorder_spawn_started_monotonic"] = time.monotonic()
            child = spawn(argv, stdout=log, stderr=log, file_limit=quota)
            state._recorder = child
            if mode == "record":
                state["recorder_spawned_monotonic"] = time.monotonic()
                state._command("enable")
                state._enabled = True
            yield state
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                try:
                    state.finish_recording()
                except BaseException as error:
                    finish_error = error
                    if primary is not None:
                        primary.add_note("record finish: " + str(error)[:512])
                if child is not None:
                    try:
                        remaining = (max(0, state.deadline - time.monotonic())
                                     if state.deadline is not None else seconds + 10)
                        state["returncode"] = child.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        state["deadline_exceeded"] = True
                        if mode == "record":
                            state["capture_deadline_exceeded"] = True
                    except BaseException as error:
                        state._cleanup_failure(error)
                        if primary is not None:
                            primary.add_note("record wait: " + str(error)[:512])
                        elif finish_error is None:
                            finish_error = error
                    finally:
                        try:
                            stop(child, elevated=True)
                            if mode == "record":
                                state["recorder_reaped_monotonic"] = time.monotonic()
                        except BaseException as error:
                            reaped = False
                            state._cleanup_failure(error)
                        state["returncode"] = child.returncode
            finally:
                if mode == "record":
                    state._observe_log(final=True)
                    if reaped and state.get("control_error") and len(state._fds) == 2:
                        state._retain_late_reply()
                if mode == "record" and reaped and state.get("record_finished"):
                    try:
                        # After reap, no recorder can append a delayed extra ACK.
                        # A single late trailing NUL remains permitted padding.
                        state._drain_padding()
                    except BaseException as error:
                        state.update(control_error=type(error).__name__, control_reason=str(error)[:512],
                                     control_refused_command="stop")
                        if primary is not None:
                            primary.add_note("record final ACK bytes: " + str(error)[:512])
                        elif finish_error is None:
                            finish_error = error
                state._close_control(remove=reaped)
                if state._control_log is not None:
                    try:
                        state._control_log.close()
                    except OSError as error:
                        state._cleanup_failure(error)
                    state._control_log = None
                # Retain output independently of termination, including refusals.
                try:
                    if path.exists():
                        run_owned(["sudo", "-n", "--", "chmod", "a+r", str(path)],
                                  stdout=log, stderr=log, timeout=5, check=False, file_limit=quota)
                        state["output_bytes"] = path.stat().st_size
                except Exception as error:
                    state.update(output_error=type(error).__name__, output_reason=str(error)[:512])
                    if getattr(error, "cleanup_unresolved", False):
                        state["cleanup_unresolved"] = True
                finally:
                    state["available"] = (not state.get("deadline_exceeded") and not state.get("cleanup_error")
                                          and not state.get("output_error") and not state.get("control_error")
                                          and (mode != "record" or state.get("record_finished", False))
                                          and state.get("returncode") == 0
                                          and 0 < state.get("output_bytes", 0) < quota)
                    if mode == "record" and state["available"]:
                        state["report"] = perf_report(directory, quota, log)
                        if state["report"].get("cleanup_unresolved"):
                            state["cleanup_unresolved"] = True
                    if mode == "record" and attribution:
                        state["attribution"] = dict(available=False, pid=pid,
                                                    skipped="capture/flat report unavailable or window failed")
                        if (primary is None and finish_error is None
                                and not unresolved_cleanup({"perf": state})
                                and state["available"] and state.get("report", {}).get("available")):
                            state["attribution"] = perf_attribution(directory, quota, log, pid)
                            if state["attribution"].get("cleanup_unresolved"):
                                state["cleanup_unresolved"] = True
                    try:
                        save(directory / "perf.json", state, WINDOW_LIMIT)
                    except Exception as error:
                        if primary is not None or finish_error is not None:
                            (primary if primary is not None else finish_error).add_note(
                                "perf metadata retention: " + str(error)[:512])
                        else:
                            raise
                    finally:
                        # __enter__ can fail before a caller receives this mapping.
                        # Carry only metadata, never the capture's process/FD attrs.
                        error = primary if primary is not None else finish_error
                        if error is not None:
                            error.perf_capture = dict(state)
                            if unresolved_cleanup({"perf": state}):
                                error.cleanup_unresolved = True
            if finish_error is not None and primary is None:
                raise finish_error


def report_summary(report):
    if not isinstance(report, dict):
        raise ValueError("native report must be an object")
    summary = {key: value for key, value in report.items() if key != "latencies_ns"}
    if "admission_diagnostics" in summary:
        bounded_bytes({key: value for key, value in summary.items() if key != "admission_diagnostics"},
                      WINDOW_LIMIT // 2 - ADMISSION_DIAGNOSTIC_LIMIT)
    bounded_bytes(summary, WINDOW_LIMIT // 2)
    values = report.get("latencies_ns", [])
    if (not isinstance(values, list)
            or any(type(v) is not int or not 0 <= v < 2**64 for v in values)):
        raise ValueError("native latency samples must be u64")
    return summary


def stderr_tail(child, limit):
    # Cleanup can fail; never block evidence retention waiting for an open pipe.
    os.set_blocking(child.stderr.fileno(), False)
    return (child.stderr.read(limit) or "").encode("utf-8")[:limit]


def unresolved_cleanup(result):
    return bool(result.get("cleanup_unresolved") or result.get("cleanup_errors")
                or result.get("perf", {}).get("cleanup_unresolved")
                or result.get("perf", {}).get("cleanup_error")
                or result.get("syscall_trace", {}).get("cleanup_unresolved"))


def save_window(directory, result):
    try:
        save(directory / "result.json", result, WINDOW_LIMIT)
    except ValueError:
        # The raw report/log files remain in this directory even if summary
        # fields exceed their allowance. Retain a small explicit failed result.
        identity_fields = {key: result[key] for key in
                           ("mode", "security", "bytes", "rate", "server_kind", "operations",
                            "concurrency", "message_type", "cleanup_errors", "revision_label",
                            "core_sha", "repeat", "index", "comparison_type", "admission_diagnostics",
                            "long_window", "measurement_timeout_seconds", "paced_span_limit_seconds",
                            "operation_deadline_ms", "outbound_datagram_limit")
                           if key in result}
        if unresolved_cleanup(result):
            identity_fields["cleanup_unresolved"] = True
            identity_fields["perf"] = {key: value for key, value in result.get("perf", {}).items()
                                       if key in ("cleanup_unresolved", "cleanup_error", "cleanup_reason", "returncode",
                                                  "output_error", "output_reason", "retained_control_directory")}
        result.clear()
        result.update(identity_fields, passed=False, reason="window metadata exceeded byte allowance",
                      raw_evidence="client.json, server.log, client.stderr; perf.json if profiling")
        save(directory / "result.json", result, WINDOW_LIMIT)


def window(server, client, cell, operations, directory, mode="clean", quota=8 * MIB,
           *, concurrency=1, message_type="con", admission_diagnostics=False,
           resource_profile="host-control", independent_endpoints=False, long_window=False, syscall_observer=None):
    security, size, rate, kind = cell
    if syscall_observer is not None and (mode != "clean" or kind != "coaptic-mio"
            or concurrency != 1 or message_type != "con" or admission_diagnostics
            or independent_endpoints or long_window):
        raise ValueError("syscall diagnostic requires ordinary Mio, C1 CON, no other instrumentation")
    if security not in ("unprotected", "oscore"):
        raise ValueError("unsupported profile security")
    validate_profile(resource_profile, kind, size, concurrency=concurrency,
                     message_type=message_type, security=security, independent_endpoints=independent_endpoints,
                     admission_diagnostics=admission_diagnostics)
    duration = operations // rate if type(rate) is int and rate > 0 else 0
    wait_seconds = measurement_timeout(duration, long_window)
    if long_window and (mode != "clean" or resource_profile == "host-control" or kind != "coaptic-mio"
                        or concurrency != 1 or message_type != "con" or independent_endpoints
                        or admission_diagnostics or operations != duration * rate
                        or not 1 <= operations <= 60_000
                        or (operations + WARMUP) * math.ceil(size / 1024) > DATAGRAM_BUDGET):
        raise ValueError("invalid long measurement partition")
    if type(admission_diagnostics) is not bool or (admission_diagnostics and
            (mode != "clean" or concurrency != 1 or type(cell[2]) is not int or cell[2] <= 0)):
        raise ValueError("admission diagnostics require an unprofiled paced C1 window")
    # Import lazily: argument validation/aggregation tests do not require psutil.
    import psutil
    import native_diagnostic as native
    result = {"passed": False, "mode": mode, "security": security, "bytes": size,
              "rate": rate, "server_kind": kind, "operations": operations,
              "concurrency": concurrency, "message_type": message_type,
              "resource_profile": resource_profile, "independent_endpoints": independent_endpoints,
              "long_window": long_window, "measurement_timeout_seconds": wait_seconds,
              "paced_span_limit_seconds": 1500 if long_window else 120,
              "operation_deadline_ms": 3000, "outbound_datagram_limit": DATAGRAM_BUDGET,
              "load_before": os.getloadavg()}
    if admission_diagnostics:
        result["admission_diagnostics"] = True
    if syscall_observer is not None:
        result["syscall_diagnostic"] = True
    sut = child = None
    clock_evidence = ({"schema": "coaptic-linux-process-cpu-clock/1",
                       "backend": "clock_getcpuclockid + time.clock_gettime_ns/clock_getres",
                       "scope": "whole process, all threads; excludes descendants and whole-machine work",
                       "setup": None, "before": None, "after": None, "delta": None}
                      if mode == "clean" else None)
    directory.mkdir()
    with tempfile.TemporaryDirectory(prefix="coaptic-cpu-key-") as temporary:
        credentials = Path(temporary) / "credentials"
        # This directory is never beneath the upload path. Never serialize key bytes.
        credentials.touch(mode=0o600)
        credentials.write_bytes(secrets.token_bytes(24))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        rx_bytes = dimensions(resource_profile, size)["rx_datagram_bytes"]
        server_args = [str(server), kind, "127.0.0.1", str(port), str(size), str(rx_bytes)]
        client_args = [str(client), str(port), str(size), str(operations), str(WARMUP), "3000", "spin", security,
                       "--cpu-gated", "--rate", str(rate),
                       "--concurrency", str(concurrency), "--message-type", message_type]
        if independent_endpoints:
            client_args.append("--independent-endpoints")
        if long_window:
            client_args.append("--long-window")
        if admission_diagnostics:
            client_args.append("--admission-diagnostics")
        if security == "oscore":
            server_args.append(str(credentials))
            client_args.insert(8, str(credentials))
        if resource_profile != "host-control":
            server_args += ["--resource-profile", resource_profile]
        with (directory / "server.log").open("w+b") as server_log, (directory / "client.stderr").open("wb") as client_log:
            try:
                sut = spawn(server_args, stdout=server_log, stderr=server_log)
                for _ in range(100):
                    if sut.poll() is not None:
                        raise RuntimeError("server exited before bind")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        try:
                            probe.bind(("127.0.0.1", port))
                        except OSError:
                            break
                    time.sleep(.01)
                else:
                    raise RuntimeError("server bind deadline")
                if syscall_observer is not None:
                    syscall_observer.prepare_target(sut, directory)
                child = spawn(client_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
                def gate(expected, deadline=None, *, long_measurement=False):
                    timeout = (PerfCapture._remaining(deadline) if long_measurement else
                               60 if deadline is None else min(60, PerfCapture._remaining(deadline)))
                    line = native.control_line(child.stderr, timeout)
                    data = (line + "\n").encode("utf-8")
                    if client_log.tell() + len(data) > WINDOW_LIMIT:
                        raise ValueError("client log exceeds byte allowance")
                    client_log.write(data)
                    client_log.flush()
                    if line != expected:
                        raise RuntimeError("client gate: " + line)
                gate("ready")
                result["server_resources"] = native.server_resources(
                    directory / "server.log", kind, deadline=time.monotonic() + 60, server=sut,
                    resource_profile=resource_profile, size=size, security=security, rx_bytes=rx_bytes)
                peers = {"server": psutil.Process(sut.pid), "client": psutil.Process(child.pid)}
                clocks = ({name: ProcessCpuClock(proc) for name, proc in
                           (("server", sut), ("client", child))} if mode == "clean" else {})
                if clocks:
                    clock_evidence["setup"] = {name: clock.status for name, clock in clocks.items()}
                trace_context = (syscall_observer(sut, directory) if syscall_observer is not None else nullcontext(None))
                with perf_pass(mode, sut.pid, PROFILE_SECONDS, directory, quota, target=sut,
                               attribution=(mode == "record")) as perf, trace_context as trace:
                    result["perf"] = perf
                    if trace is not None:
                        result["syscall_trace"] = trace
                        trace.enable()
                    if clocks:
                        clock_evidence["before"] = {name: clock.snapshot() for name, clock in clocks.items()}
                    before = {name: native.snapshot(proc) for name, proc in peers.items()}
                    if mode == "record":
                        result["scheduler_before"] = scheduler_snapshot(sut.pid)
                    started = time.perf_counter_ns()
                    if perf.deadline is not None:
                        PerfCapture._remaining(perf.deadline)
                    # One deadline before releasing the client, including every
                    # partial pipe read. control_line waits once for the full line.
                    deadline = time.monotonic() + wait_seconds if long_window else perf.deadline
                    child.stdin.write("run\n")
                    child.stdin.flush()
                    gate("measured", deadline, long_measurement=long_window)
                    after = {name: native.snapshot(proc) for name, proc in peers.items()}
                    resource_ns = time.perf_counter_ns() - started
                    if clocks:
                        clock_evidence["after"] = {name: clock.snapshot() for name, clock in clocks.items()}
                    if mode == "record":
                        result["scheduler_after"] = scheduler_snapshot(sut.pid)
                        result["scheduler_delta"] = scheduler_delta(result["scheduler_before"],
                                                                    result["scheduler_after"])
                    perf.finish_recording()
                    if trace is not None:
                        trace.finish()
                    child.stdin.write("report\n")
                    child.stdin.flush()
                    raw = native.control_line(child.stdout, 15, report_limit(operations) - 1)
                    retain_report(directory / "client.json", raw, operations)
                    result["report_file"] = str(directory / "client.json")
                    report = json.loads(raw)
                    result["report"] = report_summary(report)
                    native.validate_report(report, size, operations, "spin", security, rate,
                                           concurrency, message_type, admission_diagnostics, independent_endpoints=independent_endpoints)
                    if long_window and any(type(report.get(key)) is not type(value) or report[key] != value
                                           for key, value in (("long_window", True), ("paced_span_limit_seconds", 1500),
                                                              ("operation_deadline_ms", 3000),
                                                              ("outbound_datagram_limit", DATAGRAM_BUDGET),
                                                              ("minimum_planned_datagrams", (operations + WARMUP) * math.ceil(size / 1024)))):
                        raise ValueError("mismatched long native limits")
                    if report["warmup"] != WARMUP:
                        raise ValueError("mismatched warmup")
                    if sut.poll() is not None:
                        raise RuntimeError("server exited during window")
                    result.update(before=before, after=after, resource_window_ns=resource_ns,
                                  cpu_cost=native.cpu_cost(before, after, report["completed"]))
                    if clocks:
                        clock_evidence["delta"] = {
                            name: process_clock_delta(clock_evidence["before"][name],
                                                      clock_evidence["after"][name], report["completed"])
                            for name in clocks}
                    child.stdin.write("exit\n")
                    child.stdin.flush()
                    if child.wait(timeout=5):
                        raise RuntimeError("native client failed after report")
                result["passed"] = True
            except Exception as error:
                result.update(error_type=type(error).__name__, reason=str(error)[:512],
                              accounting="failed window; no verified denominator unless raw report present")
                if hasattr(error, "perf_capture"):
                    result["perf"] = error.perf_capture
                if hasattr(error, "syscall_capture"):
                    result["syscall_trace"] = error.syscall_capture
                if getattr(error, "cleanup_unresolved", False):
                    result["cleanup_unresolved"] = True
            finally:
                try:
                    if syscall_observer is not None:
                        try:
                            syscall_observer.close()
                        except Exception as error:
                            result["passed"] = False
                            result.setdefault("cleanup_errors", []).append(
                                {"process": "syscall-helper", "type": type(error).__name__, "reason": str(error)[:512]})
                    for name, process in (("client", child), ("server", sut)):
                        try:
                            stop(process)
                        except Exception as error:
                            result["passed"] = False
                            result.setdefault("cleanup_errors", []).append(
                                {"process": name, "type": type(error).__name__, "reason": str(error)[:512]})
                    try:
                        if child is not None:
                            client_log.write(stderr_tail(child, WINDOW_LIMIT - client_log.tell()))
                    except Exception as error:
                        result["stderr_retention_error"] = type(error).__name__
                finally:
                    if unresolved_cleanup(result):
                        result.update(passed=False, cleanup_unresolved=True)
                    try:
                        result["load_after"] = os.getloadavg()
                    except OSError as error:
                        result["load_after_error"] = type(error).__name__
                    if clock_evidence is not None:
                        retain_process_clock(directory, clock_evidence, result)
                    save_window(directory, result)
    return result


def accepted(result, tick):
    if (not result.get("passed") or result["mode"] != "clean"
            or result.get("syscall_diagnostic", False) is not False
            or result.get("admission_diagnostics", False) is not False
            or "admission_diagnostics" in result.get("report", {})):
        return False
    try:
        validate_profile(result.get("resource_profile", "host-control"), result["server_kind"],
                         result["bytes"], concurrency=result.get("concurrency"),
                         message_type=result.get("message_type"), security=result["security"],
                         independent_endpoints=result.get("independent_endpoints", False))
        from native_diagnostic import validate_endpoint_report
        validate_endpoint_report(result["report"], result.get("concurrency"), result.get("independent_endpoints", False), require_overlap=True)
    except ValueError:
        return False
    report = result["report"]
    concurrency, message_type = result.get("concurrency"), result.get("message_type")
    return (type(concurrency) is int and 1 <= concurrency <= 4
            and message_type in ("con", "non") and (concurrency == 1 or message_type == "non" or result.get("independent_endpoints") is True)
            and type(report.get("concurrency")) is int and report["concurrency"] == concurrency
            and report.get("message_type") == message_type
            and type(report.get("peak_pending")) is int and 1 <= report["peak_pending"] <= concurrency
            and abs(report["achieved_ops_per_second"] / result["rate"] - 1) <= .05
            and report["pacing_missed_period_operations"] <= max(1, report["completed"] // 100)
            and result["cpu_cost"]["server"]["total_seconds"] >= 20 * tick)


def report_latencies(result):
    # Profiling samples stay on disk. Only eligible clean comparisons load raw
    # samples, one bounded report at a time, without reserializing them elsewhere.
    raw = bounded_read(result["report_file"], report_limit(result["operations"]))
    report = json.loads(raw)
    report_summary(report)
    values = report["latencies_ns"]
    if (len(values) != result["report"]["completed"]
            or report.get("concurrency") != result.get("concurrency")
            or report.get("message_type") != result.get("message_type")
            or ("endpoint_transport" in report) != result.get("independent_endpoints", False)):
        raise ValueError("retained latency count changed")
    return values


def aggregate(results, repeats, tick, *, campaign_complete=True, adapter_pair=None):
    """Never pool security/body/load/adapter strata, partial pairs or perf timings."""
    groups = {}
    for item in results:
        if item["mode"] == "clean":
            key = (item["security"], item["bytes"], item["rate"],
                   adapter_pair[0] if adapter_pair else item["server_kind"],
                   item.get("concurrency"), item.get("message_type"),
                   item.get("resource_profile", "host-control"), item.get("independent_endpoints", False))
            groups.setdefault(key, []).append(item)
    output = []
    cleanup_failed = any(unresolved_cleanup(item) for item in results)
    diagnostic = any(item.get("admission_diagnostics", False) is not False
                     or "admission_diagnostics" in item.get("report", {}) for item in results)
    for key, items in groups.items():
        record = dict(zip(("security", "bytes", "rate", "server_kind", "concurrency", "message_type",
                           "resource_profile", "independent_endpoints"), key))
        labels = {label: [i for i in items if i["revision_label"] == label]
                  for label in ("baseline", "candidate")}
        kinds = dict(zip(("baseline", "candidate"), adapter_pair or (key[3], key[3])))
        record.update(server_kinds=kinds,
                      comparison_type="application_scheduling" if adapter_pair else "core_revision")
        # Keep the observed peak of every bounded repeat visible even when a
        # window is ineligible. A configured limit does not prove overlap.
        record["observed_peak_pending"] = {
            label: [i.get("report", {}).get("peak_pending")
                    for i in sorted(group, key=lambda i: i["repeat"])]
            for label, group in labels.items()}
        valid = campaign_complete and not cleanup_failed and not diagnostic and all(
                    len(group) == repeats and {i["repeat"] for i in group} == set(range(repeats))
                    and all(accepted(i, tick) for i in group) for group in labels.values())
        long_partition = any(i.get("long_window", False) for i in items)
        if long_partition:
            valid = valid and repeats == 4 and all(i.get("long_window") is True for i in items)
        if adapter_pair:
            valid = valid and all(i["server_kind"] == kinds[label]
                                  for label, group in labels.items() for i in group)
            sources = {i.get("core_sha") for i in items}
            valid = valid and len(sources) == 1 and all(
                isinstance(source, str) and re.fullmatch(r"[0-9a-f]{40}", source) for source in sources)
        for repeat in range(repeats):
            pair = [i for i in items if i["repeat"] == repeat and i.get("passed")]
            if len(pair) != 2:
                valid = False
            elif abs(pair[0]["report"]["achieved_ops_per_second"] / pair[1]["report"]["achieved_ops_per_second"] - 1) > .05:
                valid = False
        record.update(comparable=valid, server_cpu_ratio=None,
                      eligibility="complete campaign; resolved cleanup; all rotated pairs complete; achieved rates within5%; <=1% missed periods (minimum1); server CPU >=20 ticks/window")
        if diagnostic:
            record.update(admission_diagnostics=True,
                          eligibility="admission instrumentation present; all CPU comparisons vetoed; no clean/diagnostic mixing")
        if valid:
            costs = {}
            for label, group in labels.items():
                completed = sum(i["report"]["completed"] for i in group)
                costs[label] = {who: {field.replace("_seconds", "_ns"): sum(i["cpu_cost"][who][field] for i in group) * 1e9 / completed
                                     for field in ("user_seconds", "system_seconds", "total_seconds")}
                                for who in ("server", "client")}
                latencies = sorted(v for i in group for v in report_latencies(i))
                costs[label].update(verified_operations=completed,
                                    median_latency_ns=statistics.median(latencies),
                                    p99_latency_ns=latencies[math.ceil(len(latencies) * .99) - 1])
            record.update(cpu_ns_per_verified_operation=costs,
                          server_cpu_ratio=costs["candidate"]["server"]["total_ns"] / costs["baseline"]["server"]["total_ns"])
            if long_partition:
                # Single-security evidence still needs EVERY pair and pooled
                # latency guard. Keep failed statistics; withhold qualified ratios.
                def guard(baseline, candidate):
                    delta = {key: candidate[key] - baseline[key]
                             for key in ("median_latency_ns", "p99_latency_ns")}
                    return dict(**delta, passed=delta["median_latency_ns"] <= 2000
                                and delta["p99_latency_ns"] <= 10000)
                pair_guards = []
                for repeat in range(4):
                    statistics_by_label = {}
                    for label, group in labels.items():
                        values = sorted(report_latencies(next(i for i in group if i["repeat"] == repeat)))
                        statistics_by_label[label] = dict(median_latency_ns=statistics.median(values),
                                                         p99_latency_ns=values[math.ceil(len(values) * .99) - 1])
                    pair_guards.append(dict(repeat=repeat, **guard(statistics_by_label["baseline"], statistics_by_label["candidate"])))
                pooled = guard(costs["baseline"], costs["candidate"])
                passed = pooled["passed"] and all(pair["passed"] for pair in pair_guards)
                record.update(partial_matrix=True, latency_pair_guards=pair_guards,
                              latency_pooled_guard=pooled, latency_guards_passed=passed)
                if not passed:
                    record.update(comparable=False, server_cpu_ratio=None)
        output.append(record)
    return output


def run(args):
    cells = configuration(args)
    profile = getattr(args, "resource_profile", "host-control")
    diagnostic = getattr(args, "admission_diagnostics", False)
    long_window = getattr(args, "long_window", False)
    security_mode = getattr(args, "security_mode", "both")
    setup_logs = getattr(args, "setup_logs", None)
    partition = dict(long_window=long_window, security_mode=security_mode,
                     partial_matrix=long_window, measurement_timeout_seconds=measurement_timeout(args.seconds, long_window),
                     paced_span_limit_seconds=1500 if long_window else 120,
                     operation_deadline_ms=3000, outbound_datagram_limit=DATAGRAM_BUDGET)
    adapter_pair = ((args.server_kind, args.candidate_server_kind)
                    if args.candidate_server_kind is not None else None)
    comparison_type = "admission_diagnostic" if diagnostic else ("application_scheduling" if adapter_pair else "core_revision")
    plan = rotation(args, cells)
    metadata_bytes = metadata_allowance(plan, args.seconds)
    perf_slots = sum(mode != "clean" for mode, _, _, _ in plan)
    quota = min(8 * MIB, (PERF_BUDGET - METADATA_BUDGET) // max(1, PERF_FILES_PER_SLOT * perf_slots))
    if sys.platform != "linux":
        raise ValueError("execution requires Linux; validation/tests are portable")
    if not args.build_lane.is_dir():
        raise ValueError("explicit build lane must already exist")
    if args.output.exists():
        raise ValueError("output already exists; choose a fresh evidence directory")
    output = args.output.resolve()
    lane = args.build_lane.resolve()
    if (output.is_relative_to(SUITE) or output.is_relative_to(lane)
            or lane.is_relative_to(output)):
        raise ValueError("evidence must be outside source and disjoint from the build lane")
    args.output = args.output.resolve()
    args.build_lane = args.build_lane.resolve()
    args.output.mkdir(parents=True)
    out = args.output
    results = []
    try:
        save(out / "request.json", {"baseline_sha": args.baseline_sha,
                                   "resource_profile": profile,
                                   "candidate_sha": args.candidate_sha, "cells": cells,
                                   "seconds": args.seconds, "repeats": args.repeats,
                                   **partition,
                                   "perf": args.perf, "concurrency": args.concurrency,
                                   "independent_endpoints": getattr(args, "independent_endpoints", False),
                                   "admission_diagnostics": diagnostic,
                                   "message_type": args.message_type,
                                   "candidate_server_kind": args.candidate_server_kind,
                                   "comparison_type": comparison_type,
                                   "RUSTUP_TOOLCHAIN": FLAGS["RUSTUP_TOOLCHAIN"]})
        suite_identity = identity(SUITE)
        if suite_identity["status"] or identity(SUITE / "coaptic")["status"]:
            raise ValueError("commit the source first; clean suite/core required")
        manifest = {"schema": "coaptic-linux-cpu/1", "baseline_sha": args.baseline_sha,
                **partition, "whole_upload_budget_bytes": WHOLE_UPLOAD_BUDGET,
                "resource_profile": profile,
                "profile_dimensions": [dimensions(profile, size) for size in sorted({c[1] for c in cells})],
                "native_profiles_sha256": digest(Path(__file__).with_name("native_profiles.py")),
                "candidate_sha": args.candidate_sha, "hardware": hardware(), "flags": FLAGS,
                "suite": suite_identity, "runner_sha256": digest(__file__),
                "psutil_version": importlib.metadata.version("psutil"),
                "diagnostic_sha256": digest(Path(__file__).with_name("native_diagnostic.py")),
                "build_lane": str(args.build_lane), "perf_budget_bytes": PERF_BUDGET,
                "metadata_budget_bytes": METADATA_BUDGET, "metadata_allowance_bytes": metadata_bytes,
                "perf_file_quota_bytes": quota,
                "perf_files_per_slot": PERF_FILES_PER_SLOT,
                "artifact_bound_bytes_excluding_binaries": metadata_bytes + PERF_FILES_PER_SLOT * perf_slots * quota,
                "cells": cells, "seconds": args.seconds, "repeats": args.repeats,
                "concurrency": args.concurrency, "message_type": args.message_type,
                "independent_endpoints": getattr(args, "independent_endpoints", False),
                "adapter_pair": adapter_pair, "comparison_type": comparison_type,
                "admission_diagnostics": diagnostic,
                "admission_diagnostic_limit_bytes": ADMISSION_DIAGNOSTIC_LIMIT,
                "report_base_fields_limit_bytes": REPORT_BASE_FIELDS_LIMIT,
                "admission_diagnostic_limits": "opt-in paced C1; pre-send attempts include send refusal; prior C carries earlier debt; residual/idle traversal are local intervals, not causal sleep/server/VM shares; no CPU comparison",
                "rotation": "AB/BA by repeat and cell; all clean windows precede all profiling passes",
                "limits": "selected resource profile and bounded concurrency/message type complete loopback GET; one App/context/global sender sequence per window; OSCORE established only; requested/inline memory owners do not prove whole memory; process CPU includes IPC boundaries/idle; no interrupt attribution, EDHOC, saturation, device or50% target proof"}
        save(out / "manifest.json", manifest)
        baseline = build(args, "baseline", args.baseline_sha, out)
        candidate = build(args, "candidate", args.candidate_sha, out, expected=baseline)
        matching_lock_inputs(baseline, candidate)
        for field in ("native_manifest_sha256", "target", "rustc", "cargo", "flags"):
            if baseline[field] != candidate[field]:
                raise ValueError("build configuration differs: " + field)
        # Use the SAME baseline client for both servers: core/client work cannot silently move.
        client = Path(baseline["binaries"]["bench-native-client"]["path"])
        builds = {"baseline": baseline, "candidate": candidate}
        # Actual copied binaries and bounded disjoint setup logs must fit with
        # all future metadata/captures before the first measurement can start.
        upload = upload_plan(out, setup_logs, metadata_bytes, perf_slots)
        quota = upload["perf_file_quota_bytes"]
        manifest.update(upload, artifact_bound_bytes_excluding_binaries=metadata_bytes + PERF_FILES_PER_SLOT * perf_slots * quota)
        save(out / "manifest.json", manifest)
        save(out / "rotation.json", plan)
        for index, (mode, repeat, cell, label) in enumerate(plan):
            print(f"{index + 1}/{len(plan)} {mode} {label} {cell}", flush=True)
            server = Path(builds[label]["binaries"]["bench-rust-server"]["path"])
            actual_cell = (*cell[:3], adapter_pair[1 if label == "candidate" else 0]) if adapter_pair else cell
            result = window(server, client, actual_cell, cell[2] * (args.seconds if mode == "clean" else PROFILE_SECONDS),
                            out / f"window-{index:03}", mode, quota,
                            concurrency=args.concurrency, message_type=args.message_type,
                            admission_diagnostics=diagnostic, resource_profile=profile,
                            independent_endpoints=getattr(args, "independent_endpoints", False), long_window=long_window)
            result.update(revision_label=label, core_sha=builds[label]["core"]["revision"], repeat=repeat,
                          server_sha256=digest(server), client_sha256=digest(client), index=index)
            result["comparison_type"] = comparison_type
            save_window(out / f"window-{index:03}", result)
            results.append(result)
            # Small append-only index survives later failures; each directory owns raw data.
            entry = bounded_bytes(result, WINDOW_LIMIT)
            with (out / "windows.jsonl").open("ab") as stream:
                if stream.tell() + len(entry) > len(plan) * WINDOW_LIMIT:
                    raise ValueError("window index exceeds planned byte allowance")
                stream.write(entry)
            if unresolved_cleanup(result):
                raise RuntimeError("owned process termination unresolved; campaign aborted")
        return (all(r["passed"] for r in results if r["mode"] == "clean")
                and (not long_window or all(row["comparable"] for row in
                     aggregate(results, args.repeats, 1 / os.sysconf("SC_CLK_TCK")))))
    except Exception as error:
        save(out / "failure.json", {"type": type(error).__name__, "reason": str(error)[:4096]})
        raise
    finally:
        cleanup_failed = any(unresolved_cleanup(result) for result in results)
        complete = len(results) == len(plan) and not cleanup_failed
        save(out / "summary.json", {"comparisons": aggregate(results, args.repeats, 1 / os.sysconf("SC_CLK_TCK"),
                                                            campaign_complete=complete,
                                                            adapter_pair=adapter_pair) if results else [],
                                   "comparison_type": comparison_type,
                                   **partition,
                                   "admission_diagnostics": diagnostic,
                                   "campaign_complete": complete, "cleanup_unresolved": cleanup_failed,
                                   "windows_recorded": len(results),
                                   "failed_windows": [r["index"] for r in results if not r["passed"]],
                                   "unavailable_profiles": [r["index"] for r in results if r["mode"] != "clean"
                                                            and not r.get("perf", {}).get("available")],
                                   "unavailable_reports": [r["index"] for r in results if r["mode"] == "record"
                                                           and r.get("perf", {}).get("available")
                                                           and not r["perf"].get("report", {}).get("available")],
                                   "interpretation": "ratios only for eligible complete pairs; raw failures and low-resolution/load-mismatched windows retained; no acceptance claim"})
        primary = sys.exception()
        try:
            check_upload(out, setup_logs)
        except Exception as error:
            if primary is not None:
                primary.add_note("final upload verification failed: " + str(error))
            else:
                raise


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-sha", required=True, type=sha40)
    parser.add_argument("--candidate-sha", required=True, type=sha40)
    parser.add_argument("--build-lane", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sizes", default="64,1024")
    parser.add_argument("--resource-profile", choices=tuple(PROFILE_SIZES), default="host-control")
    parser.add_argument("--rates", default="100,1000")
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--long-window", action="store_true", help="explicit single-security representative 31..1500s partition")
    parser.add_argument("--security-mode", choices=("both", "unprotected", "oscore"), default="both")
    parser.add_argument("--setup-logs", type=Path, help="disjoint uploaded setup owner, combined cap 16MiB")
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--server-kind", choices=(*EXPLICIT_KINDS, "all"), default="coaptic-reusable")
    parser.add_argument("--candidate-server-kind", choices=EXPLICIT_KINDS,
                        help="compare two adapters at identical core SHAs; otherwise both use --server-kind")
    parser.add_argument("--perf", action="store_true")
    parser.add_argument("--admission-diagnostics", action="store_true",
                        help="same-core, same-adapter paced C1 intervals; perf refused and CPU ratios vetoed")
    parser.add_argument("--concurrency", type=int, choices=range(1, 5), default=1)
    parser.add_argument("--message-type", choices=("con", "non"), default="con")
    parser.add_argument("--independent-endpoints", action="store_true")
    return parser


def main():
    parser = argument_parser()
    args = parser.parse_args()
    try:
        passed = run(args)
    except Exception as error:
        parser.exit(1, f"{type(error).__name__}: {error}\n")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
