"""Validate the finite ESPHome read-record stream offline.

Callers supply independent source expectations and retained build/install bindings.
Those records establish local attribution; logs do not attest firmware remotely.
Elapsed phases include suspension, scheduling and logging instrumentation costs.
"""
import json
import re
import statistics

MARKER = "COAPTIC_READ_RECORD "
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_RECORDS = 50
OPERATIONS = 24
TIMEOUT_NS = 5_000_000_000
PATHS = (("identity", 32), ("test", 7), ("large", 2000))
STAGES = ("prepare_ns", "poll_ns", "checkpoint_ns", "take_ns", "verify_ns", "wait_ns")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def number(value, maximum=2**64 - 1):
    require(type(value) is int and 0 <= value <= maximum, "invalid bounded integer")
    return value


def digest(value, length):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value),
            "invalid source/hash identity")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def parse_capture(text):
    """Extract records from raw log lines or existing {kind: log, line: ...} JSONL.

    Unrelated log lines are ignored. A line carrying the marker must decode fully;
    malformed or duplicate record JSON is never silently discarded. Enveloped
    captures require a successful, nonoverflowing capture_complete record.
    """
    require(isinstance(text, str) and len(text.encode("utf8")) <= MAX_CAPTURE_BYTES,
            "capture size bound")
    records = []
    enveloped = complete = False
    for line in text.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        if line.lstrip().startswith("{"):
            envelope = json.loads(line, object_pairs_hook=unique_object)
            require(isinstance(envelope, dict), "capture log envelope")
            if "kind" not in envelope and MARKER not in line:
                continue
            enveloped = True
            require(not complete, "capture events after completion")
            if envelope.get("kind") == "capture_complete":
                require(envelope.get("overflow") is False
                        and number(envelope.get("connections"), 100) > 0,
                        "capture incomplete/overflow")
                complete = True
                continue
            if envelope.get("kind") != "log":
                require(MARKER not in line, "capture log envelope")
                continue
            require(isinstance(envelope.get("line"), str), "capture log envelope")
            line = re.sub(r"\x1b\[[0-9;]*m", "", envelope["line"])
        if MARKER not in line:
            continue
        require(line.count(MARKER) == 1, "ambiguous read-record marker")
        record = json.loads(line.split(MARKER, 1)[1], object_pairs_hook=unique_object)
        require(isinstance(record, dict), "read-record shape")
        records.append(record)
        require(len(records) <= MAX_RECORDS, "record count bound")
    require(not enveloped or complete, "capture completion missing")
    return records


def source_binding(expected_source, build, installation, run_id, io_mode, security):
    require(isinstance(expected_source, dict) and isinstance(build, dict)
            and isinstance(installation, dict), "source binding shape")
    for key, length in (("core_revision", 40), ("suite_revision", 40), ("ota_sha256", 64)):
        expected = digest(expected_source.get(key), length)
        require(build.get(key) == expected, "build source/image mismatch")
    require(build.get("passed") is True and installation.get("passed") is True,
            "build/installation incomplete")
    require(build.get("run_id") == installation.get("run_id") == run_id,
            "build/installation run mismatch")
    require(installation.get("ota_sha256") == expected_source["ota_sha256"],
            "installed image mismatch")
    require(build.get("io_mode") == io_mode and build.get("security") == security,
            "build mode/security mismatch")


def analyze(records, *, expected_run_id, expected_io_mode, expected_security,
            expected_source, build, installation):
    """Refuse incomplete, mixed-mode, malformed or unbound campaign records.

    `expected_source` supplies core_revision, suite_revision and ota_sha256.
    `build` independently binds those fields, run_id, io_mode and security with
    passed=True. `installation` binds passed=True, run_id and ota_sha256. Their
    producer must verify actual artifacts; this parser never hashes log labels.
    Protected sender reservations remain separate from operation durations and
    may add at most one record before each of the 24 reads.
    """
    run_id = digest(expected_run_id, 32)
    require(expected_io_mode in ("sync", "async"), "expected I/O mode")
    require(expected_security in ("unprotected", "durable-oscore"), "expected security")
    source_binding(expected_source, build, installation, run_id,
                   expected_io_mode, expected_security)
    require(isinstance(records, list) and 26 <= len(records) <= MAX_RECORDS,
            "record count bound/incomplete campaign")
    protected = expected_security == "durable-oscore"
    words = []
    for record in records:
        require(isinstance(record, dict) and record.get("run_id") == run_id,
                "record run mismatch")
        require(type(record.get("mode")) is int and record["mode"] == (6 if protected else 7)
                and record.get("protected") is protected, "record security mismatch")
        require(record.get("io_mode") == expected_io_mode, "record I/O mode mismatch")
        row = record.get("words")
        require(isinstance(row, list) and len(row) == 16, "record word count")
        words.append([number(value) for value in row])
    preparation, terminal = words[0], words[-1]
    require(preparation[0] == 0 and all(value == 0 for value in preparation[11:]),
            "preparation record shape")
    require(preparation[10] == (1 if expected_io_mode == "async" else 0),
            "preparation I/O mode mismatch")
    require(0 < preparation[2] <= preparation[6] == 48 * 1024
            and preparation[3] == 4096 and preparation[4] == 128
            and 0 < preparation[7] <= 48 and preparation[8] == 1024
            and 0 < preparation[9] <= 128, "preparation layout/ceiling mismatch")
    require((0 < preparation[5] <= 1024) if protected else
            preparation[1] == preparation[5] == 0, "preparation security owner mismatch")
    require(terminal[:4] == [3, 1, OPERATIONS, len(words) - 1]
            and all(value == 0 for value in terminal[4:]), "terminal count/success mismatch")
    operations, reservations = [], []
    reserved = False
    previous_end = 0
    for row in words[1:-1]:
        if row[0] == 1:
            require(protected and not reserved and len(operations) < OPERATIONS
                    and all(value == 0 for value in row[2:]), "sender reservation placement/security")
            reservations.append(row[1])
            reserved = True
            continue
        require(row[0] == 2 and len(operations) < OPERATIONS
                and all(value == 0 for value in row[13:]), "operation record shape")
        index = len(operations)
        iteration, path_index = divmod(index, 3)
        path, size = PATHS[path_index]
        require(row[1:4] == [iteration, path_index, size], "operation index/path/size mismatch")
        start, elapsed = row[4:6]
        require(previous_end <= start and 0 < elapsed < TIMEOUT_NS
                and start + elapsed < 2**64, "operation ordering/deadline bound")
        require(1 <= row[12] <= 100_000, "operation poll bound")
        stages = dict(zip(STAGES, row[6:12]))
        require(sum(stages.values()) <= elapsed, "top-level intervals overlap")
        operations.append(dict(iteration=iteration, path=path, bytes=size,
                               start_ns=start, elapsed_ns=elapsed, polls=row[12], **stages))
        previous_end = start + elapsed
        reserved = False
    require(len(operations) == OPERATIONS and not reserved, "operation coverage incomplete")
    summary = []
    for path, size in PATHS:
        values = [op["elapsed_ns"] for op in operations if op["path"] == path]
        summary.append(dict(path=path, bytes=size, samples=len(values), min_ns=min(values),
                            median_ns=statistics.median(values), mean_ns=statistics.mean(values),
                            max_ns=max(values)))
    return dict(schema="coaptic-read-records/1", passed=True, run_id=run_id,
                io_mode=expected_io_mode, security=expected_security, source=dict(expected_source),
                records=len(records), completed=OPERATIONS, recovery_ns=preparation[1],
                components=dict(app_bytes=preparation[2], output_bytes=preparation[3],
                                record_bytes=preparation[4], security_owner_bytes=preparation[5],
                                app_ceiling_bytes=preparation[6], selection_bytes=preparation[7],
                                state_ceiling_bytes=preparation[8], observation_bytes=preparation[9]),
                sender_reservations=len(reservations), sender_reservation_ns=sum(reservations),
                operations=operations, summary=summary,
                limitations=["Local build/install binding is not remote firmware attestation",
                             "Elapsed phases include scheduling, suspension and instrumentation",
                             "Component sizes are not an additive or whole-memory peak",
                             "Eight reads per path do not qualify tails, throughput or CPU efficiency"])
