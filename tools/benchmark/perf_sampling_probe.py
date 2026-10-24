"""Four finite clock-sampling controls; manual Linux use, no protocol workload.

ACKs fence command processing, not representative coverage. Counts per measured
process CPU second are descriptive, never function shares or expected coverage.
The raw reader implements only the native little-endian perf v2 clock layout:
Linux UAPI perf_event.h and tools/perf/util/header.h (PERFILE2, 104-byte header).
Unsupported layouts are retained and refused, not guessed.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import time

from linux_cpu import bounded_bytes, command, perf_pass, sampling_frequency, spawn, stop

MIB = 1024 * 1024
OUTPUT_LIMIT = 64 * MIB
TEST_LOG_LIMIT = 4 * MIB  # Workflow test RLIMIT also covers its 3.5MiB corruption fixture.
QUOTA = 3_495_253
META_LIMIT = 64 * 1024
RECEIPT_LIMIT = 1024
LOG_LIMIT = 16 * 1024
TARGET_CPU_NS = 500_000_000
BLOCK_CPU_NS = 50_000
PERIOD_NS = 1_003_009
WALL_NS = 5_000_000_000
MAX_BLOCKS = 10_000
PLAN = (("cpu-clock", "continuous"), ("cpu-clock", "bursty"),
        ("task-clock", "continuous"), ("task-clock", "bursty"))
MODES = ("unknown", "kernel", "user", "hypervisor", "guest_kernel", "guest_user")
SAMPLE_TYPE = 295  # IP | TID | TIME | CALLCHAIN | PERIOD; UAPI order differs from bits.
SUITE = Path(__file__).resolve().parents[2]


def read_regular(path, limit):
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("nonregular, linked or oversized evidence")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
            raise ValueError("evidence identity changed")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(data) != info.st_size or len(data) > limit or after.st_size != info.st_size:
        raise ValueError("evidence size changed or exceeded bound")
    return data


def save_new(path, value, limit=META_LIMIT):
    data = bounded_bytes(value, limit)
    with Path(path).open("xb") as stream:
        stream.write(data)


def digest_file(path, limit=64 * MIB):
    # Installed Python and source identities only; never launch captured inputs.
    size = 0
    sha = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(64 * 1024):
            size += len(block)
            if size > limit:
                raise ValueError("identity file exceeds bound")
            sha.update(block)
    return {"bytes": size, "sha256": sha.hexdigest()}


def fresh_output(path):
    path = Path(os.path.abspath(path))
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or parent.is_symlink() or getattr(info, "st_reparse_tag", 0):
            raise ValueError("output parent must be an existing ordinary directory")
    path.mkdir(mode=0o700)  # Exclusive: no reuse, cleanup or overwrite.
    return path


def inventory(directory):
    files = []
    total = 0
    for parent, dirs, names in os.walk(directory, followlinks=False):
        for name in dirs:
            info = (Path(parent) / name).lstat()
            if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_reparse_tag", 0):
                raise ValueError("unexpected output directory type")
        for name in names:
            path = Path(parent) / name
            rel = path.relative_to(directory).as_posix()
            cap = QUOTA if name in ("perf.data", "perf-report.txt", "perf-command.log") else META_LIMIT
            data = read_regular(path, cap)
            total += len(data)
            if total > OUTPUT_LIMIT - TEST_LOG_LIMIT - META_LIMIT:  # Reserve the final index itself.
                raise ValueError("whole probe output allowance exceeded")
            files.append({"path": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    if len(files) > 64:
        raise ValueError("unexpected evidence file count")
    return {"files": sorted(files, key=lambda item: item["path"]), "bytes_before_index": total,
            "index_excludes_itself": True, "whole_output_limit_bytes": OUTPUT_LIMIT,
            "reserved_workflow_test_log_bytes": TEST_LOG_LIMIT}


def measure_control(pattern, *, cpu=time.process_time_ns, thread=time.thread_time_ns,
                    wall=time.monotonic_ns, sleep=time.sleep, usage=None, frequency_hz=997):
    """Scalar-only workload; injectable clocks allow tests without a timed run."""
    period_ns = 1_000_000_000 // sampling_frequency(frequency_hz)
    if pattern not in ("continuous", "bursty"):
        raise ValueError("unsupported work pattern")
    if usage is None:
        import resource
        usage = lambda: resource.getrusage(resource.RUSAGE_SELF)
    before = usage()
    started_wall = wall()
    started_cpu = cpu()
    started_thread = thread()
    blocks = iterations = maximum = over_period = sleeps = 0
    value = 1
    last_cpu = started_cpu
    while (last_cpu - started_cpu < TARGET_CPU_NS and blocks < MAX_BLOCKS
           and wall() - started_wall < WALL_NS):
        block_start = cpu()
        while True:
            value = (value * 1664525 + 1013904223) & 0xffffffff
            iterations += 1
            last_cpu = cpu()
            if last_cpu - block_start >= BLOCK_CPU_NS or wall() - started_wall >= WALL_NS:
                break
        block_ns = last_cpu - block_start
        blocks += 1
        maximum = max(maximum, block_ns)
        over_period += block_ns >= period_ns
        # Clock/loop/sleep overhead contributes to the total process CPU target.
        last_cpu = cpu()
        if (pattern == "bursty" and last_cpu - started_cpu < TARGET_CPU_NS
                and blocks < MAX_BLOCKS and wall() - started_wall + 200_000 < WALL_NS):
            sleep(.0002)
            sleeps += 1
    after = usage()
    elapsed_thread = thread() - started_thread
    elapsed_cpu = cpu() - started_cpu
    elapsed_wall = wall() - started_wall
    return {"schema": 1, "pid": os.getpid(), "pattern": pattern,
            "process_cpu_ns": elapsed_cpu, "thread_cpu_ns": elapsed_thread, "wall_ns": elapsed_wall,
            "iterations": iterations, "blocks": blocks, "max_block_cpu_ns": maximum,
            "blocks_at_or_above_period": over_period, "sleep_calls": sleeps,
            "voluntary_context_switches": after.ru_nvcsw - before.ru_nvcsw,
            "involuntary_context_switches": after.ru_nivcsw - before.ru_nivcsw,
            "completed": elapsed_cpu >= TARGET_CPU_NS, "deadline_hit": elapsed_wall >= WALL_NS,
            "block_limit_hit": blocks == MAX_BLOCKS and elapsed_cpu < TARGET_CPU_NS,
            "short_blocks_valid": over_period == 0}


def read_line(fd, deadline, limit=RECEIPT_LIMIT):
    """One finite line, no read-ahead state or unbounded pipe buffering."""
    result = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("IPC read deadline")
        if not select.select([fd], [], [], remaining)[0]:
            raise TimeoutError("IPC read deadline")
        piece = os.read(fd, 1)
        if not piece:
            raise EOFError("IPC ended before complete line")
        result.extend(piece)
        if len(result) > limit:
            raise ValueError("IPC line exceeds bound")
        if piece == b"\n":
            return bytes(result)


def write_gate(fd, gate, deadline):
    if gate not in (b"run\n", b"report\n", b"ready\n", b"measured\n"):
        raise ValueError("unsupported IPC gate")
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
        raise TimeoutError("IPC write deadline")
    if os.write(fd, gate) != len(gate):
        raise ValueError("partial IPC gate; command not retried")


def worker_main(pattern, *, frequency_hz=997):
    sampling_frequency(frequency_hz)
    if sys.platform != "linux":
        raise ValueError("helper requires Linux")
    input_fd, output_fd = sys.stdin.fileno(), sys.stdout.fileno()
    os.set_blocking(input_fd, False)
    os.set_blocking(output_fd, False)
    startup = time.monotonic() + 10
    write_gate(output_fd, b"ready\n", startup)
    if read_line(input_fd, startup, 16) != b"run\n":
        raise ValueError("expected run gate")
    report_deadline = time.monotonic() + 15
    receipt = measure_control(pattern, frequency_hz=frequency_hz)
    write_gate(output_fd, b"measured\n", report_deadline)
    if read_line(input_fd, report_deadline, 16) != b"report\n":
        raise ValueError("expected report gate")
    # Formatting is deliberately after the controller's disable/stop fence.
    data = bounded_bytes(receipt, RECEIPT_LIMIT)
    remaining = report_deadline - time.monotonic()
    if remaining <= 0 or not select.select([], [output_fd], [], remaining)[1]:
        raise TimeoutError("receipt write deadline")
    if os.write(output_fd, data) != len(data):
        raise ValueError("partial receipt write")
    return 0


def validate_receipt(value, pid, pattern, *, frequency_hz=997):
    period_ns = 1_000_000_000 // sampling_frequency(frequency_hz)
    numbers = ("process_cpu_ns", "thread_cpu_ns", "wall_ns", "iterations", "blocks",
               "max_block_cpu_ns", "blocks_at_or_above_period", "sleep_calls",
               "voluntary_context_switches", "involuntary_context_switches")
    booleans = ("completed", "deadline_hit", "block_limit_hit", "short_blocks_valid")
    if (not isinstance(value, dict) or set(value) != set(numbers + booleans + ("schema", "pid", "pattern"))
            or type(value["schema"]) is not int or value["schema"] != 1 or type(value["pid"]) is not int or value["pid"] != pid
            or value["pattern"] != pattern
            or any(type(value[key]) is not int or not 0 <= value[key] < 2**63 for key in numbers)
            or any(type(value[key]) is not bool for key in booleans)):
        raise ValueError("invalid helper receipt identity or scalar fields")
    if (not 1 <= value["blocks"] <= MAX_BLOCKS or value["iterations"] < value["blocks"]
            or value["blocks_at_or_above_period"] > value["blocks"]
            or value["sleep_calls"] > value["blocks"]
            or value["max_block_cpu_ns"] > value["process_cpu_ns"]
            or value["thread_cpu_ns"] > value["process_cpu_ns"] + 1_000_000
            or value["process_cpu_ns"] > value["wall_ns"] + 1_000_000
            or value["short_blocks_valid"] != (value["blocks_at_or_above_period"] == 0)
            or (value["max_block_cpu_ns"] >= period_ns) != bool(value["blocks_at_or_above_period"])
            or value["completed"] != (value["process_cpu_ns"] >= TARGET_CPU_NS)
            or value["deadline_hit"] != (value["wall_ns"] >= WALL_NS)):
        raise ValueError("inconsistent helper receipt")
    if (not value["completed"] or value["deadline_hit"] or value["block_limit_hit"]
            or (pattern == "continuous" and value["sleep_calls"] != 0)
            or (pattern == "bursty" and (not value["short_blocks_valid"]
                                         or value["sleep_calls"] < value["blocks"] - 1))):
        raise ValueError("control target, finite bound or short-burst condition not met")
    return value


def proc_snapshot(pid):
    with Path(f"/proc/{pid}/stat").open("rb") as stream:
        data = stream.read(4097)
    if len(data) > 4096 or not data.startswith(str(pid).encode() + b" ("):
        raise ValueError("invalid target proc identity")
    fields = data[data.rfind(b")") + 2:].split()
    if len(fields) < 20:
        raise ValueError("short target proc stat")
    return {"pid": pid, "user_ticks": int(fields[11]), "system_ticks": int(fields[12]),
            "start_ticks": int(fields[19]), "ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "executable": os.readlink(f"/proc/{pid}/exe")}


def parse_perf(data, event, pid, executable, *, frequency_hz=997):
    """Strict single-clock or observed clock+dummy/IDENTIFIER records only.

    No ELF, raw capture, callchain or symbol is executed. No symbol resolver is
    invoked here. Features are range checked but their contents are not decoded.
    """
    sampling_frequency(frequency_hz)
    if event not in ("cpu-clock", "task-clock") or type(pid) is not int or pid <= 1:
        raise ValueError("invalid expected event/PID")
    if not 104 <= len(data) <= QUOTA or data[:8] != b"PERFILE2":
        raise ValueError("unsupported/truncated native little-endian header")
    header_size, attr_stride, ao, az, do, dz, eo, ez = struct.unpack_from("<8Q", data, 8)
    if header_size != 104 or ez or eo:
        raise ValueError("unsupported perf header/event-types section")
    sections = [(0, 104, "header")]

    def section(offset, size, label, *, allow_empty=False):
        if (offset < 104 or offset > len(data) or size > len(data) - offset
                or (not size and not allow_empty)):
            raise ValueError("out-of-bounds " + label)
        if size:
            for start, end, _ in sections:
                if offset < end and start < offset + size:
                    raise ValueError("overlapping perf sections")
            sections.append((offset, offset + size, label))

    # Exactly two supported shapes: the earlier single clock/sample295, or
    # the observed perf6.17.13 clock+dummy shape with leading IDENTIFIER.
    identified = az == 2 * attr_stride and attr_stride == 152
    if not identified and (az != attr_stride or attr_stride not in (144, 152, 160)):
        raise ValueError("expected single clock or supported clock+tracking layout")
    section(ao, az, "attributes")
    section(do, dz, "data", allow_empty=True)
    attributes = []
    all_ids = set()
    for index in range(2 if identified else 1):
        offset = ao + index * attr_stride
        typ, declared = struct.unpack_from("<II", data, offset)
        config, freq, sample_type, read_format, flags = struct.unpack_from("<5Q", data, offset + 8)
        tracking = index == 1
        expected_config = 9 if tracking else (0 if event == "cpu-clock" else 1)
        expected_sample = SAMPLE_TYPE & ~32 if tracking else SAMPLE_TYPE
        if identified:
            expected_sample |= 1 << 16
        scope = flags & ((1 << 4) | (1 << 5) | (1 << 6))
        expected_scope = (1 << 5) | (1 << 6) if tracking else 0
        # Both identified events carry TID/TIME/IDENTIFIER metadata trailers.
        # Only the requested clock is sampled; dummy is metadata-only and has
        # the observed user-only exclusions, never a second CPU denominator.
        if (declared + 16 != attr_stride or typ != 1 or config != expected_config
                or freq != frequency_hz or sample_type != expected_sample or read_format != 20
                or not flags & (1 << 10) or (identified and not flags & (1 << 18))
                or scope != expected_scope):
            raise ValueError("unsupported event, frequency, scope or sample layout")
        io, iz = struct.unpack_from("<QQ", data, offset + declared)
        if not 8 <= iz <= 4096 * 8 or iz % 8:
            raise ValueError("invalid clock/tracking event ID table")
        section(io, iz, "event IDs")
        ids = set(struct.unpack_from("<" + "Q" * (iz // 8), data, io))
        if len(ids) != iz // 8 or 0 in ids or all_ids & ids:
            raise ValueError("duplicate, colliding or zero event ID")
        all_ids.update(ids)
        attributes.append({"ids": ids, "io": io, "iz": iz, "flags": flags})
    clock = attributes[0]
    event_ids = clock["ids"]
    tracking_ids = attributes[1]["ids"] if identified else set()
    feature_bits = int.from_bytes(data[72:104], "little")
    if feature_bits & ((1 << 0) | (1 << 24) | (1 << 27)) or feature_bits >> 35:
        raise ValueError("unsupported reserved, directory, compressed or future perf features")
    feature_count = feature_bits.bit_count()
    if feature_count:
        feature_directory = do + dz
        section(feature_directory, feature_count * 16, "feature directory")
        for i in range(feature_count):
            fo, fz = struct.unpack_from("<QQ", data, feature_directory + 16 * i)
            section(fo, fz, "feature", allow_empty=True)
    trailer_size = 24 if identified else (16 if clock["flags"] & (1 << 18) else 0)
    # UAPI SAMPLE_IDENTIFIER is first in SAMPLE but last in sample_id_all.
    # https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/perf_event.h
    # Synthetic MMAP/COMM/KSYMBOL/BPF metadata can have an all-zero trailer.
    # No such exception applies to samples, loss/throttle or task lifetime.
    synthetic_kinds = {1, 3, 10, 17, 18}
    loss_kinds = {2, 5, 6, 13}
    metadata_kinds = synthetic_kinds | loss_kinds | {4, 7}
    counts, modes, periods = Counter(), Counter(), Counter()
    lost = lost_samples = 0
    timestamp_min = timestamp_max = None
    executable_map = False
    map_count = callchain_max = foreign_metadata = 0
    synthetic_metadata = tracking_metadata = 0
    event_loss = {role: {"lost": 0, "lost_samples": 0, "throttle_records": 0,
                         "unthrottle_records": 0} for role in ("clock", "tracking")}
    offset, end = do, do + dz
    # These userspace records are opaque metadata, never interpreted as samples.
    opaque = {64, 65, 66, 67, 68, 69, 70, 71, 73, 74, 78, 79, 80, 82}
    while offset < end:
        if end - offset < 8:
            raise ValueError("truncated record header")
        kind, misc, size = struct.unpack_from("<IHH", data, offset)
        if size < 8 or size % 8 or size > end - offset:
            raise ValueError("invalid record length")
        body = memoryview(data)[offset + 8:offset + size]
        counts[kind] += 1
        trailer_id = None
        trailer_role = "clock"
        trailer_pid = trailer_tid = None
        if identified and kind in metadata_kinds:
            if len(body) < trailer_size:
                raise ValueError("truncated metadata identifier trailer")
            trailer_pid, trailer_tid, trailer_time, trailer_id = struct.unpack_from("<IIQQ", body, len(body) - 24)
            if trailer_id == 0:
                if kind not in synthetic_kinds or trailer_pid or trailer_tid or trailer_time:
                    raise ValueError("invalid synthetic metadata trailer")
                synthetic_metadata += 1
            elif trailer_id not in all_ids or not trailer_time:
                raise ValueError("unknown metadata identifier or timestamp")
            else:
                trailer_role = "tracking" if trailer_id in tracking_ids else "clock"
                if kind not in loss_kinds and trailer_role != "tracking":
                    raise ValueError("nontracking metadata identifier")
                tracking_metadata += trailer_role == "tracking"
                if kind in loss_kinds | {4, 7} and (trailer_pid != pid or trailer_tid != pid):
                    raise ValueError("metadata trailer PID mismatch")
        if kind == 9:
            prefix = 8 if identified else 0
            if len(body) < prefix + 40 or misc & 7 >= len(MODES):
                raise ValueError("unsupported sample CPU mode/length")
            if identified:
                sample_id = struct.unpack_from("<Q", body)[0]
                if sample_id in tracking_ids:
                    raise ValueError("tracking event SAMPLE is not a requested clock sample")
                if sample_id not in event_ids:
                    raise ValueError("unknown clock SAMPLE identifier")
            ip, sample_pid, tid, stamp, period, nr = struct.unpack_from("<QIIQQQ", body, prefix)
            if (sample_pid != pid or tid != pid or not stamp or not period or period > WALL_NS
                    or nr > 4096 or len(body) != prefix + 40 + nr * 8):
                raise ValueError("sample PID/period/callchain/length mismatch")
            mode = MODES[misc & 7]
            modes[mode] += 1
            periods[mode] += period
            callchain_max = max(callchain_max, nr)
            timestamp_min = stamp if timestamp_min is None else min(timestamp_min, stamp)
            timestamp_max = stamp if timestamp_max is None else max(timestamp_max, stamp)
        elif kind in loss_kinds:
            base = {2: 16, 5: 24, 6: 24, 13: 8}[kind]
            if len(body) != base + trailer_size:
                raise ValueError("invalid loss/throttle record length")
            if kind == 2:
                record_id, count = struct.unpack_from("<QQ", body)
                if record_id not in all_ids or (identified and record_id != trailer_id):
                    raise ValueError("LOST event ID mismatch")
                lost += count
                event_loss[trailer_role]["lost"] += count
            elif kind == 13:
                count = struct.unpack_from("<Q", body)[0]
                lost_samples += count
                event_loss[trailer_role]["lost_samples"] += count
            else:
                _, record_id, stream_id = struct.unpack_from("<QQQ", body)
                role_ids = tracking_ids if trailer_role == "tracking" else event_ids
                if record_id not in role_ids or stream_id not in role_ids or (identified and record_id != trailer_id):
                    raise ValueError("throttle event ID mismatch")
                event_loss[trailer_role]["throttle_records" if kind == 5 else "unthrottle_records"] += 1
        elif kind in (1, 3, 10):
            base = {1: 32, 3: 8, 10: 64}[kind]
            payload_size = len(body) - trailer_size
            if payload_size <= base or payload_size - base > 4096:
                raise ValueError("invalid mapping/comm length")
            rec_pid, rec_tid = struct.unpack_from("<II", body)
            if identified and trailer_id and (trailer_pid != rec_pid or trailer_tid != rec_tid):
                raise ValueError("mapping/comm trailer PID mismatch")
            # perf can synthesize its own COMM metadata (perf-exec). It is
            # counted separately, never accepted as a target SAMPLE or mapping.
            if (misc & 7 == 2 or kind == 3) and (rec_pid != pid or rec_tid != pid):
                foreign_metadata += 1
            name = bytes(body[base:payload_size])
            if b"\0" not in name:
                raise ValueError("unterminated mapping/comm name")
            name = name.split(b"\0", 1)[0]
            if kind in (1, 10):
                map_count += 1
                if kind == 10 and misc & (1 << 14) and body[32] > 20:
                    raise ValueError("invalid MMAP2 build ID length")
                if rec_pid == pid and name.decode("utf-8", "strict") == executable:
                    executable_map = True
        elif kind in (4, 7):
            if len(body) != 24 + trailer_size:
                raise ValueError("invalid fork/exit record length")
            rec_pid, ppid, tid, ptid = struct.unpack_from("<IIII", body)
            if rec_pid != pid or tid != pid:
                raise ValueError("unexpected target descendant")
        elif kind == 17:  # PERF_RECORD_KSYMBOL, fixed fields plus NUL-terminated name.
            if len(body) < 17 + trailer_size or b"\0" not in bytes(body[16:len(body) - trailer_size if trailer_size else len(body)]):
                raise ValueError("invalid ksymbol record")
        elif kind == 18:  # PERF_RECORD_BPF_EVENT fixed 16 bytes.
            if len(body) != 16 + trailer_size:
                raise ValueError("invalid BPF metadata length")
        elif kind not in opaque:
            raise ValueError("unsupported perf record type " + str(kind))
        offset += size
    return {"schema": 1, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "event": event, "event_id_count": len(event_ids),
            "event_ids_sha256": hashlib.sha256(data[clock["io"]:clock["io"] + clock["iz"]]).hexdigest(),
            "frequency_hz": frequency_hz, "inclusive": True,
            "sample_layout": "clock+tracking IDENTIFIER" if identified else "single clock295",
            "tracking_event_id_count": len(tracking_ids), "tracking_metadata_records": tracking_metadata,
            "synthetic_metadata_records": synthetic_metadata, "loss_by_event": event_loss,
            "pid": pid, "executable_mapping_matches": executable_map, "mapping_records": map_count,
            "foreign_userspace_metadata_records": foreign_metadata,
            "sample_records": counts[9], "samples_by_mode": {m: modes[m] for m in MODES},
            "periods_by_mode": {m: periods[m] for m in MODES}, "total_period": sum(periods.values()),
            "lost": lost, "lost_samples": lost_samples, "throttle_records": counts[5],
            "unthrottle_records": counts[6], "records_by_type": {str(k): v for k, v in sorted(counts.items())},
            "callchain_max_entries": callchain_max, "sample_time_min_ns": timestamp_min,
            "sample_time_max_ns": timestamp_max,
            "limits": "Only requested clock SAMPLEs accepted; tracking metadata/loss separate. Known opaque metadata counted only; no symbol shares. Observed loss records are not proof of complete delivery; sample timestamp span is not exposure."}


def report_counts(directory):
    result = {"warnings": [], "warning_count": 0, "samples": None, "period": None, "lost": None}
    for name in ("perf-report.txt", "perf-command.log"):
        text = read_regular(directory / name, QUOTA).decode("utf-8", "replace")
        if name == "perf-report.txt":
            for key, regex in (("samples", r"^# Samples:\s+([0-9,]+)\s+of event"),
                               ("period", r"^# Event count \(approx\.\):\s+([0-9,]+)"),
                               ("lost", r"^# Total Lost Samples:\s+([0-9,]+)")):
                match = re.search(regex, text, re.MULTILINE)
                result[key] = int(match[1].replace(",", "")) if match else None
        for line in text.splitlines():
            if name == "perf-report.txt" and re.match(r"^\s*[0-9.]+%", line):
                continue  # Never promote symbol/self percentages into this analysis.
            # Preserve all originals; derived warnings have an explicit fixed cap.
            if re.search(r"warn|lost|thrott|unknown|error|fail|invalid|unsupported|denied|unable|refus", line, re.I):
                result["warning_count"] += 1
                if len(result["warnings"]) < 24:
                    result["warnings"].append({"file": name, "text": line[:256]})
    result["warnings_omitted"] = max(0, result["warning_count"] - len(result["warnings"]))
    return result


def collect_control(event, pattern, directory, *, frequency_hz=997):
    sampling_frequency(frequency_hz)
    if (event, pattern) not in PLAN:
        raise ValueError("unsupported control")
    directory.mkdir(mode=0o700)
    result = {"event": event, "pattern": pattern, "frequency_hz": frequency_hz,
              "valid": False, "attempted": True}
    worker = capture = None
    try:
        with (directory / "worker.stderr").open("xb") as log:
            try:
                worker = spawn([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", pattern,
                                "--frequency-hz", str(frequency_hz)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                               file_limit=LOG_LIMIT)
                result["pid"] = worker.pid
                os.set_blocking(worker.stdin.fileno(), False)
                os.set_blocking(worker.stdout.fileno(), False)
                if read_line(worker.stdout.fileno(), time.monotonic() + 2, 16) != b"ready\n":
                    raise ValueError("worker not ready")
                with perf_pass("record", worker.pid, 5, directory, QUOTA, event=event, target=worker,
                               frequency_hz=frequency_hz) as capture:
                    deadline = capture.deadline
                    if not isinstance(deadline, (float, int)) or not math.isfinite(deadline) or not 0 < deadline - time.monotonic() <= 15:
                        raise ValueError("missing finite record deadline")
                    result["capture_yield_monotonic"] = time.monotonic()
                    before = proc_snapshot(worker.pid)
                    if before["executable"] != str(Path(sys.executable).resolve()):
                        raise ValueError("helper executable identity mismatch")
                    write_gate(worker.stdin.fileno(), b"run\n", deadline)
                    result["run_monotonic"] = time.monotonic()
                    if read_line(worker.stdout.fileno(), min(deadline, time.monotonic() + 6), 16) != b"measured\n":
                        raise ValueError("worker not measured")
                    after = proc_snapshot(worker.pid)
                    # First action after CPU snapshots: close the recording fence.
                    capture.finish_recording()
                    result["finish_monotonic"] = time.monotonic()
                    result["process_snapshots"] = {"before": before, "after": after}
                    if (before["start_ticks"] != after["start_ticks"] or before["pid"] != after["pid"]
                            or before["executable"] != after["executable"]
                            or any(after[k] < before[k] for k in ("user_ticks", "system_ticks"))):
                        raise ValueError("target process identity/counters changed")
                    write_gate(worker.stdin.fileno(), b"report\n", deadline)
                    raw = read_line(worker.stdout.fileno(), deadline)
                    # Preserve the original final receipt even if validation refuses it.
                    with (directory / "worker.json").open("xb") as stream:
                        stream.write(raw)
                    receipt = json.loads(raw)
                    result["receipt"] = receipt
                    validate_receipt(receipt, worker.pid, pattern, frequency_hz=frequency_hz)
                    if worker.wait(timeout=max(0, deadline - time.monotonic())) != 0:
                        raise ValueError("helper exited unsuccessfully")
                    if os.read(worker.stdout.fileno(), 1):
                        raise ValueError("extra helper output")
            finally:
                if worker is not None:
                    try:
                        stop(worker)
                    except Exception as error:
                        result["cleanup_unresolved"] = True
                        result["cleanup_error"] = str(error)[:256]
                    finally:
                        for stream in (worker.stdin, worker.stdout):
                            stream.close()
        if capture is None:
            raise ValueError("no capture metadata")
        result["perf"] = dict(capture)
        bounded_bytes(result["perf"], 16 * 1024)
        if (not capture.get("available") or not capture.get("report", {}).get("available")
                or capture.get("cleanup_unresolved") or capture.get("cleanup_error")
                or result.get("cleanup_unresolved")):
            raise ValueError("capture/report unavailable or cleanup unresolved")
        raw_audit = parse_perf(read_regular(directory / "perf.data", QUOTA), event, worker.pid,
                               str(Path(sys.executable).resolve()), frequency_hz=frequency_hz)
        result["raw"] = raw_audit
        headers = report_counts(directory)
        result["report_counts"] = headers
        if (not raw_audit["executable_mapping_matches"]
                or headers["samples"] != raw_audit["sample_records"]
                or headers["period"] != raw_audit["total_period"]
                or headers["lost"] != raw_audit["lost"] + raw_audit["lost_samples"]):
            raise ValueError("raw/report counts, periods, loss or executable mapping mismatch")
        cpu_seconds = result["receipt"]["process_cpu_ns"] / 1e9
        result["samples_per_process_cpu_second"] = raw_audit["sample_records"] / cpu_seconds
        result["valid"] = True
    except (Exception, KeyboardInterrupt) as error:
        result.update(error=type(error).__name__, reason=str(error)[:512])
        if getattr(error, "cleanup_unresolved", False):
            result["cleanup_unresolved"] = True
    finally:
        if capture is None and (directory / "perf.json").exists():
            try:
                capture = json.loads(read_regular(directory / "perf.json", LOG_LIMIT))
            except (ValueError, OSError) as error:
                result["perf_metadata_error"] = str(error)[:256]
        if capture is not None:
            result["perf"] = dict(capture)
            if capture.get("cleanup_unresolved") or capture.get("cleanup_error"):
                result["cleanup_unresolved"] = True
                result["valid"] = False
        save_new(directory / "control.json", result)
    return result


def run_probe(output, *, frequency_hz=997):
    sampling_frequency(frequency_hz)
    output = fresh_output(output)
    summary = {"schema": 1, "frequency_hz": frequency_hz,
               "plan": [dict(event=e, pattern=p) for e, p in PLAN],
               "valid": False, "controls": [], "limits":
               "Finite sampling suitability controls only. ACK is processing, not representative coverage; block CPU is not a scheduler slice. No function shares, application speedup or causal claim about prior captures."}
    try:
        if 4 * 3 * QUOTA + 32 * META_LIMIT + TEST_LOG_LIMIT > OUTPUT_LIMIT:
            raise ValueError("planned output exceeds whole probe bound")
        if sys.platform != "linux":
            raise ValueError("probe requires Linux")
        missing = [name for name in ("perf", "sudo", "prlimit", "timeout", "git") if not shutil.which(name)]
        if missing:
            raise ValueError("required existing tool unavailable: " + ", ".join(missing))
        manifest = {"schema": 1, "frequency_hz": frequency_hz,
                    "python": sys.version, "python_executable": str(Path(sys.executable).resolve()),
                    "python_identity": digest_file(Path(sys.executable).resolve()),
                    "helper_identity": digest_file(Path(__file__).resolve()),
                    "recorder_identity": digest_file(Path(__file__).with_name("linux_cpu.py")),
                    "suite_commit": command(["git", "rev-parse", "HEAD"], timeout=5),
                    "suite_tree": command(["git", "rev-parse", "HEAD^{tree}"], timeout=5),
                    "source_status": command(["git", "--no-optional-locks", "status", "--porcelain"], timeout=5),
                    "host": platform.platform(), "kernel": platform.release(), "controller_pid": os.getpid(),
                    "tools": {name: shutil.which(name) for name in ("perf", "sudo", "prlimit", "timeout")},
                    "target_cpu_ns": TARGET_CPU_NS, "block_cpu_ns": BLOCK_CPU_NS,
                    "period_ns": 1_000_000_000 // frequency_hz,
                    "wall_cap_ns": WALL_NS, "block_cap": MAX_BLOCKS, "per_perf_file_quota": QUOTA,
                    "whole_output_limit": OUTPUT_LIMIT, "workflow_test_log_allowance": TEST_LOG_LIMIT,
                    "no_symbol_downloads": True}
        save_new(output / "manifest.json", manifest)
        for index, (event, pattern) in enumerate(PLAN):
            result = collect_control(event, pattern, output / f"control-{index:03}",
                                     frequency_hz=frequency_hz)
            summary["controls"].append({
                "event": event, "pattern": pattern, "valid": result["valid"],
                "evidence": f"control-{index:03}/control.json",
                **{key: result[key] for key in ("reason", "error", "cleanup_unresolved",
                   "receipt", "raw", "samples_per_process_cpu_second") if key in result}})
            # No repeats, extensions or later controls after an invalid control.
            inventory(output)
            if not result["valid"]:
                break
        summary["valid"] = len(summary["controls"]) == 4 and all(c["valid"] for c in summary["controls"])
    except (Exception, KeyboardInterrupt) as error:
        summary.update(error=type(error).__name__, reason=str(error)[:512])
    summary["unattempted"] = [dict(event=e, pattern=p) for e, p in PLAN[len(summary["controls"]):]]
    try:
        index = inventory(output)
    except Exception as error:
        summary.update(valid=False, inventory_error=type(error).__name__, inventory_reason=str(error)[:512])
        index = {"complete": False, "reason": str(error)[:512], "whole_output_limit_bytes": OUTPUT_LIMIT}
    save_new(output / "summary.json", summary)
    if index.get("complete") is not False:
        index = inventory(output)  # Include the sealed summary, exclude only the index.
    save_new(output / "evidence-index.json", index)
    print(json.dumps({"valid": summary["valid"], "attempted": len(summary["controls"]),
                      "unattempted": len(summary["unattempted"]), "output": str(output)}, allow_nan=False))
    return 0 if summary["valid"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--output", type=Path, help="NEW directory; existing output is refused")
    choice.add_argument("--worker", choices=("continuous", "bursty"), help=argparse.SUPPRESS)
    parser.add_argument("--frequency-hz", type=int, choices=(997, 9970), default=997)
    args = parser.parse_args(argv)
    return (worker_main(args.worker, frequency_hz=args.frequency_hz) if args.worker
            else run_probe(args.output, frequency_hz=args.frequency_hz))


if __name__ == "__main__":
    raise SystemExit(main())
