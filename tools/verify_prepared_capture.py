"""Emit capture provenance only for an independently checked prepared checkout.

This is an explicit alternative to the capture test's default clean-source path.
The prepare report is evidence, not authority: verify_prepared derives the allowed
lock bytes from immutable source and checks all other tracked and untracked input.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from macro_lock_selection import git, safe_path, verify_prepared
from source_identity import LOCKS

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "coaptic-prepared-capture-source/1"
REPORT_BYTES = 65_536
OUTPUT_BYTES = 16_384
CAPTURE_LOCKS = (*LOCKS, "fuzz/Cargo.lock")


def report_bytes(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > REPORT_BYTES:
        raise ValueError("prepared capture report must be a bounded regular file")
    with path.open("rb") as stream:
        data = stream.read(REPORT_BYTES + 1)
    if len(data) > REPORT_BYTES:
        raise ValueError("prepared capture report byte budget exceeded")
    return data


def capture_identity(suite, expected_core, expected_suite, prepared_report):
    for value in (expected_core, expected_suite):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError("prepared capture requires both immutable full revisions")
    suite = Path(suite).resolve()
    core = suite / "coaptic"
    prepared_report = Path(prepared_report)
    before = report_bytes(prepared_report)
    prepared_report = prepared_report.resolve()
    checkpoint = verify_prepared(suite, core, expected_core, expected_suite, prepared_report)
    if report_bytes(prepared_report) != before:
        raise ValueError("prepared capture report changed during verification")
    report = json.loads(before)
    if not isinstance(report, dict):
        raise ValueError("prepared capture report object required")
    suite_revision = git(suite, "rev-parse", "HEAD").decode().strip()
    core_revision = git(core, "rev-parse", "HEAD").decode().strip()
    suite_dirty = bool(git(suite, "status", "--porcelain").strip())
    core_dirty = bool(git(core, "status", "--porcelain").strip())
    if (suite_revision != expected_suite or core_revision != expected_core or core_dirty
            or type(report.get("suite_dirty")) is not bool or suite_dirty != report["suite_dirty"]):
        raise ValueError("capture identity changed from the verified prepared checkpoint")
    locks = {name: hashlib.sha256(safe_path(suite, name).read_bytes()).hexdigest()
             for name in CAPTURE_LOCKS}
    final_checkpoint = verify_prepared(suite, core, expected_core, expected_suite, prepared_report)
    if final_checkpoint != checkpoint or report_bytes(prepared_report) != before:
        raise ValueError("prepared capture checkpoint changed while collecting provenance")
    value = dict(schema=SCHEMA,
                 suite=dict(revision=suite_revision, dirty=suite_dirty,
                            prepared_checkpoint=dict(
                                verification=checkpoint,
                                report_sha256=hashlib.sha256(before).hexdigest(),
                                report_bytes=len(before), locks=locks)),
                 core=dict(revision=core_revision, dirty=core_dirty))
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > OUTPUT_BYTES:
        raise ValueError("prepared capture provenance byte budget exceeded")
    return encoded


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-core", required=True)
    parser.add_argument("--expected-suite", required=True)
    parser.add_argument("--prepared-report", type=Path, required=True)
    args = parser.parse_args(argv)
    value = capture_identity(ROOT, args.expected_core, args.expected_suite, args.prepared_report)
    print(value)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print("prepared capture refused: " + str(error)[:1024], file=sys.stderr)
        raise SystemExit(1) from error
