"""Manual, source-matched Linux process CPU qualification for core issue #650.

Builds mutate only the selected clean core checkout and ONE explicitly supplied
Cargo lane. Clean windows, perf record and perf stat passes never overlap.
See linux_cpu.md for bounds, interpretation and the manual workflow.
"""
import argparse
from contextlib import contextmanager
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


MIB = 1024 * 1024
PERF_BUDGET = 256 * MIB
METADATA_BUDGET = 96 * MIB
SUMMARY_LIMIT = 64 * 1024
WINDOW_LIMIT = 16 * 1024
BUILD_LOG_LIMIT = 2 * MIB
WARMUP = 20
DATAGRAM_BUDGET = 60_000
PROFILE_SECONDS = 5
PERF_REPORT_SECONDS = 30
PERF_FILES_PER_SLOT = 3  # Data/stat output, command/version log, record report.
KINDS = ("coaptic-reusable", "coaptic-mio", "coaptic-ready")
EXPLICIT_KINDS = (*KINDS, "coaptic-async", "coaptic-blocking")
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
    if args.candidate_server_kind is not None:
        if (args.server_kind not in EXPLICIT_KINDS or args.candidate_server_kind not in EXPLICIT_KINDS
                or args.server_kind == args.candidate_server_kind):
            raise ValueError("adapter comparison requires two distinct explicit server kinds")
        if sha40(args.baseline_sha) != sha40(args.candidate_sha):
            raise ValueError("adapter comparison requires identical core SHAs; do not combine source and scheduling changes")
    if (type(args.concurrency) is not int or not 1 <= args.concurrency <= 4
            or args.message_type not in ("con", "non")
            or (args.concurrency > 1 and args.message_type != "non")):
        raise ValueError("concurrency 1..4; concurrent CON refused by per-endpoint NSTART=1; select NON explicitly")
    sizes = [int(p) for p in selection(args.sizes, ("64", "1024", "65536"))]
    rates = [int(p) for p in selection(args.rates)]
    if len(set(rates)) != len(rates):
        raise ValueError("rates must be numerically distinct")
    kinds = list(KINDS) if args.server_kind == "all" else [args.server_kind]
    if (not 2 <= args.seconds <= 30 or not 2 <= args.repeats <= 8
            or any(not 1 <= r <= 100_000 for r in rates) or args.server_kind not in (*EXPLICIT_KINDS, "all")):
        raise ValueError("seconds 2..30, repeats 2..8, rates 1..100000, supported host adapter")
    cells = list(itertools.product(("unprotected", "oscore"), sizes, rates, kinds))
    windows = len(cells) * 2 * args.repeats
    samples = sum(rate * (2 * args.repeats * args.seconds + (4 * PROFILE_SECONDS if args.perf else 0))
                  for _, _, rate, _ in cells)
    if windows > 96 or windows * args.seconds > 1200 or samples > 2_000_000:
        raise ValueError("campaign exceeds 96 clean windows, 1200 clean seconds or 2M latency samples")
    plan = rotation(args, cells)
    for mode, _, (_, size, rate, _), _ in plan:
        operations = rate * (args.seconds if mode == "clean" else PROFILE_SECONDS)
        minimum = (WARMUP + operations) * math.ceil(size / 1024)
        if minimum > DATAGRAM_BUDGET:
            raise ValueError(f"{mode} {size}B {rate}/s: warmup plus operations require "
                             f"at least {minimum} datagrams; socket budget is {DATAGRAM_BUDGET}")
    metadata_allowance(plan, args.seconds)
    return cells


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
    # u64 decimal <=20 bytes, plus comma/space; fixed fields get a separate 64KiB.
    return SUMMARY_LIMIT + 22 * operations


def metadata_allowance(plan, seconds):
    # Seven global JSON files, two build logs, one append-only index entry and
    # three bounded per-window files. Raw reports are retained exactly once.
    allowance = 7 * SUMMARY_LIMIT + 2 * BUILD_LOG_LIMIT
    for mode, _, cell, _ in plan:
        operations = cell[2] * (seconds if mode == "clean" else PROFILE_SECONDS)
        allowance += report_limit(operations) + 4 * WINDOW_LIMIT
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


def retain_report(path, raw, operations):
    data = (raw + "\n").encode("utf-8")
    if len(data) > report_limit(operations):
        raise ValueError("native report exceeds byte allowance")
    Path(path).write_bytes(data)


class OwnedProcess:
    """Only processes launched in a fresh session may be group-signalled."""
    def __init__(self, process):
        self.process = process
        self.group = process.pid
        self.stopped = False

    def __getattr__(self, name):
        return getattr(self.process, name)


def spawn(argv, *, file_limit=WINDOW_LIMIT, **kwargs):
    def limit_output():
        import resource
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    if file_limit is not None:
        kwargs["preexec_fn"] = limit_output
    return OwnedProcess(subprocess.Popen(argv, start_new_session=True, **kwargs))


def signal_group(child, sig, elevated):
    if not isinstance(child, OwnedProcess) or child.group <= 1 or child.group == os.getpgrp():
        raise ValueError("refusing to signal an unowned process group")
    try:
        os.killpg(child.group, sig)
    except ProcessLookupError:
        return
    except PermissionError:
        if not elevated:
            raise
        # Only owned perf capture/report groups opt into elevated signaling.
        run_owned(["sudo", "-n", "--", "kill", f"-{signal.Signals(sig).name[3:]}",
                   "--", f"-{child.group}"], timeout=5, stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL)


def group_alive(child):
    try:
        os.killpg(child.group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def stop(child, *, elevated=False):
    if child is None:
        return
    if not isinstance(child, OwnedProcess):
        raise ValueError("refusing to stop an unowned process")
    if child.stopped:
        return
    try:
        signal_group(child, signal.SIGTERM, elevated)
    finally:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        finally:
            # The leader can exit before rustc/linker or perf/sleep descendants.
            # Always escalate the owned group, then reap the direct child.
            try:
                if group_alive(child):
                    signal_group(child, signal.SIGKILL, elevated)
            finally:
                child.wait(timeout=5)
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
        except Exception as cleanup:
            error.add_note(f"owned process cleanup: {type(cleanup).__name__}: {str(cleanup)[:512]}")
            error.cleanup_unresolved = True
        raise
    else:
        try:
            stop(child, elevated=elevated)
        except Exception as error:
            error.cleanup_unresolved = True
            raise
        return code


def run_logged(argv, stream, *, timeout, limit=BUILD_LOG_LIMIT, **kwargs):
    """Cap retained output without limiting other files written by the child."""
    remaining = limit - stream.tell()
    if remaining < 0:
        raise ValueError("build log exceeds byte allowance")
    child = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                  file_limit=None, **kwargs)
    overflow = threading.Event()
    reader_errors = []

    def copy_output():
        nonlocal remaining
        try:
            while data := child.stdout.read(65536):
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
    reader.start()
    deadline = time.monotonic() + timeout
    try:
        while True:
            if overflow.is_set():
                raise ValueError("build log exceeded byte allowance or output reader failed")
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            try:
                code = child.wait(timeout=min(.1, remaining_seconds))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        try:
            stop(child)
        finally:
            reader.join(timeout=1)
            if not reader.is_alive():
                child.stdout.close()
    if reader.is_alive():
        raise TimeoutError("build output reader cleanup deadline")
    if overflow.is_set() or reader_errors:
        raise ValueError("build log exceeded byte allowance or output reader failed")
    if code:
        raise subprocess.CalledProcessError(code, argv)


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
        for argv in (["git", "-C", str(core), "fetch", "--depth", "1", "origin", revision],
                     ["git", "-C", str(core), "checkout", "--detach", revision],
                     ["cargo", "build", "--release", "--locked", "--target", host, "--manifest-path",
                      "tools/benchmark/native/Cargo.toml", "-p", "bench-rust-server",
                      "--bin", "bench-rust-server", "--bin", "bench-native-client"]):
            line = (json.dumps(argv) + "\n").encode("utf-8")
            if stream.tell() + len(line) > BUILD_LOG_LIMIT:
                raise ValueError("build log exceeds byte allowance")
            stream.write(line)
            stream.flush()
            run_logged(argv, stream, cwd=SUITE, env=env, timeout=900)
    source = identity(core)
    if source["revision"] != revision or source["status"]:
        raise ValueError("core identity changed during build")
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
    record = {"core": source, "suite": identity(SUITE), "binaries": binaries,
              "native_lock_sha256": digest(SUITE / "tools/benchmark/native/Cargo.lock"),
              "core_lock_sha256": digest(core / "Cargo.lock"), "flags": FLAGS,
              "native_manifest_sha256": digest(SUITE / "tools/benchmark/native/Cargo.toml"),
              "target": host, "rustc": rustc, "cargo": cargo}
    save(out / f"build-{label}.json", record)
    return record


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


@contextmanager
def perf_pass(mode, pid, seconds, directory, quota, *, event="cpu-clock", target=None):
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
                or result.get("perf", {}).get("cleanup_error"))


def save_window(directory, result):
    try:
        save(directory / "result.json", result, WINDOW_LIMIT)
    except ValueError:
        # The raw report/log files remain in this directory even if summary
        # fields exceed their allowance. Retain a small explicit failed result.
        identity_fields = {key: result[key] for key in
                           ("mode", "security", "bytes", "rate", "server_kind", "operations",
                            "concurrency", "message_type", "cleanup_errors", "revision_label",
                            "core_sha", "repeat", "index", "comparison_type")
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
           *, concurrency=1, message_type="con"):
    # Import lazily: argument validation/aggregation tests do not require psutil.
    import psutil
    import native_diagnostic as native
    security, size, rate, kind = cell
    result = {"passed": False, "mode": mode, "security": security, "bytes": size,
              "rate": rate, "server_kind": kind, "operations": operations,
              "concurrency": concurrency, "message_type": message_type,
              "load_before": os.getloadavg()}
    sut = child = None
    directory.mkdir()
    with tempfile.TemporaryDirectory(prefix="coaptic-cpu-key-") as temporary:
        credentials = Path(temporary) / "credentials"
        # This directory is never beneath the upload path. Never serialize key bytes.
        credentials.touch(mode=0o600)
        credentials.write_bytes(secrets.token_bytes(24))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        server_args = [str(server), kind, "127.0.0.1", str(port), str(size), "1472"]
        client_args = [str(client), str(port), str(size), str(operations), str(WARMUP), "3000", "spin", security,
                       "--cpu-gated", "--rate", str(rate),
                       "--concurrency", str(concurrency), "--message-type", message_type]
        if security == "oscore":
            server_args.append(str(credentials))
            client_args.insert(8, str(credentials))
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
                child = spawn(client_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
                def gate(expected, deadline=None):
                    timeout = 60 if deadline is None else min(60, PerfCapture._remaining(deadline))
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
                    directory / "server.log", kind, deadline=time.monotonic() + 60, server=sut)
                peers = {"server": psutil.Process(sut.pid), "client": psutil.Process(child.pid)}
                with perf_pass(mode, sut.pid, PROFILE_SECONDS, directory, quota, target=sut) as perf:
                    result["perf"] = perf
                    before = {name: native.snapshot(proc) for name, proc in peers.items()}
                    started = time.perf_counter_ns()
                    if perf.deadline is not None:
                        PerfCapture._remaining(perf.deadline)
                    child.stdin.write("run\n")
                    child.stdin.flush()
                    gate("measured", perf.deadline)
                    after = {name: native.snapshot(proc) for name, proc in peers.items()}
                    resource_ns = time.perf_counter_ns() - started
                    perf.finish_recording()
                    child.stdin.write("report\n")
                    child.stdin.flush()
                    raw = native.control_line(child.stdout, 15, report_limit(operations) - 1)
                    retain_report(directory / "client.json", raw, operations)
                    result["report_file"] = str(directory / "client.json")
                    report = json.loads(raw)
                    result["report"] = report_summary(report)
                    native.validate_report(report, size, operations, "spin", security, rate,
                                           concurrency, message_type)
                    if report["warmup"] != WARMUP:
                        raise ValueError("mismatched warmup")
                    if sut.poll() is not None:
                        raise RuntimeError("server exited during window")
                    result.update(before=before, after=after, resource_window_ns=resource_ns,
                                  cpu_cost=native.cpu_cost(before, after, report["completed"]))
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
                if getattr(error, "cleanup_unresolved", False):
                    result["cleanup_unresolved"] = True
            finally:
                try:
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
                    save_window(directory, result)
    return result


def accepted(result, tick):
    if not result.get("passed") or result["mode"] != "clean":
        return False
    report = result["report"]
    concurrency, message_type = result.get("concurrency"), result.get("message_type")
    return (type(concurrency) is int and 1 <= concurrency <= 4
            and message_type in ("con", "non") and (concurrency == 1 or message_type == "non")
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
            or report.get("message_type") != result.get("message_type")):
        raise ValueError("retained latency count changed")
    return values


def aggregate(results, repeats, tick, *, campaign_complete=True, adapter_pair=None):
    """Never pool security/body/load/adapter strata, partial pairs or perf timings."""
    groups = {}
    for item in results:
        if item["mode"] == "clean":
            key = (item["security"], item["bytes"], item["rate"],
                   adapter_pair[0] if adapter_pair else item["server_kind"],
                   item.get("concurrency"), item.get("message_type"))
            groups.setdefault(key, []).append(item)
    output = []
    cleanup_failed = any(unresolved_cleanup(item) for item in results)
    for key, items in groups.items():
        record = dict(zip(("security", "bytes", "rate", "server_kind", "concurrency", "message_type"), key))
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
        valid = campaign_complete and not cleanup_failed and all(
                    len(group) == repeats and {i["repeat"] for i in group} == set(range(repeats))
                    and all(accepted(i, tick) for i in group) for group in labels.values())
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
        output.append(record)
    return output


def run(args):
    cells = configuration(args)
    adapter_pair = ((args.server_kind, args.candidate_server_kind)
                    if args.candidate_server_kind is not None else None)
    comparison_type = "application_scheduling" if adapter_pair else "core_revision"
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
                                   "candidate_sha": args.candidate_sha, "cells": cells,
                                   "seconds": args.seconds, "repeats": args.repeats,
                                   "perf": args.perf, "concurrency": args.concurrency,
                                   "message_type": args.message_type,
                                   "candidate_server_kind": args.candidate_server_kind,
                                   "comparison_type": comparison_type,
                                   "RUSTUP_TOOLCHAIN": FLAGS["RUSTUP_TOOLCHAIN"]})
        suite_identity = identity(SUITE)
        if suite_identity["status"] or identity(SUITE / "coaptic")["status"]:
            raise ValueError("commit the source first; clean suite/core required")
        manifest = {"schema": "coaptic-linux-cpu/1", "baseline_sha": args.baseline_sha,
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
                "adapter_pair": adapter_pair, "comparison_type": comparison_type,
                "rotation": "AB/BA by repeat and cell; all clean windows precede all profiling passes",
                "limits": "selected bounded concurrency/message type complete loopback GET; Default/AllocMemory host fixture; one App/context/global sender sequence per window; OSCORE established only; process CPU includes IPC boundaries/idle; no interrupt attribution, EDHOC, saturation, device or50% target proof"}
        save(out / "manifest.json", manifest)
        baseline = build(args, "baseline", args.baseline_sha, out)
        candidate = build(args, "candidate", args.candidate_sha, out, expected=baseline)
        for field in ("native_lock_sha256", "native_manifest_sha256", "target", "rustc", "cargo", "flags"):
            if baseline[field] != candidate[field]:
                raise ValueError("build configuration differs: " + field)
        # Use the SAME baseline client for both servers: core/client work cannot silently move.
        client = Path(baseline["binaries"]["bench-native-client"]["path"])
        builds = {"baseline": baseline, "candidate": candidate}
        save(out / "rotation.json", plan)
        for index, (mode, repeat, cell, label) in enumerate(plan):
            print(f"{index + 1}/{len(plan)} {mode} {label} {cell}", flush=True)
            server = Path(builds[label]["binaries"]["bench-rust-server"]["path"])
            actual_cell = (*cell[:3], adapter_pair[1 if label == "candidate" else 0]) if adapter_pair else cell
            result = window(server, client, actual_cell, cell[2] * (args.seconds if mode == "clean" else PROFILE_SECONDS),
                            out / f"window-{index:03}", mode, quota,
                            concurrency=args.concurrency, message_type=args.message_type)
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
        return all(r["passed"] for r in results if r["mode"] == "clean")
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
                                   "campaign_complete": complete, "cleanup_unresolved": cleanup_failed,
                                   "windows_recorded": len(results),
                                   "failed_windows": [r["index"] for r in results if not r["passed"]],
                                   "unavailable_profiles": [r["index"] for r in results if r["mode"] != "clean"
                                                            and not r.get("perf", {}).get("available")],
                                   "unavailable_reports": [r["index"] for r in results if r["mode"] == "record"
                                                           and r.get("perf", {}).get("available")
                                                           and not r["perf"].get("report", {}).get("available")],
                                   "interpretation": "ratios only for eligible complete pairs; raw failures and low-resolution/load-mismatched windows retained; no acceptance claim"})


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-sha", required=True, type=sha40)
    parser.add_argument("--candidate-sha", required=True, type=sha40)
    parser.add_argument("--build-lane", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sizes", default="64,1024")
    parser.add_argument("--rates", default="100,1000")
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--server-kind", choices=(*EXPLICIT_KINDS, "all"), default="coaptic-reusable")
    parser.add_argument("--candidate-server-kind", choices=EXPLICIT_KINDS,
                        help="compare two adapters at identical core SHAs; otherwise both use --server-kind")
    parser.add_argument("--perf", action="store_true")
    parser.add_argument("--concurrency", type=int, choices=range(1, 5), default=1)
    parser.add_argument("--message-type", choices=("con", "non"), default="con")
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
