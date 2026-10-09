"""Bind firmware tooling to both exact, clean source repositories."""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from source_identity import LOCKS, source_identity


def revision(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("a full lowercase source commit SHA is required")
    return value


def build_source(expected_library_revision, identity=source_identity):
    expected_library_revision = revision(expected_library_revision)
    source = identity()
    if source["source"] != expected_library_revision:
        raise ValueError("library revision differs from the requested candidate")
    revision(source["suite_source"])
    if source["dirty"] or source["suite_dirty"]:
        raise ValueError("firmware builds require clean library and suite sources")
    lock_hashes(source)
    return source


def lock_hashes(report):
    locks = report.get("suite_locks")
    if (not isinstance(locks, dict) or set(locks) != set(LOCKS)
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                   for value in locks.values())):
        raise ValueError("firmware report is missing complete prepared lockfile hashes")


def verify_report_source(report, expected_library_revision, expected_suite_revision):
    if report.get("source") != revision(expected_library_revision):
        raise ValueError("firmware report has a different library revision")
    if report.get("suite_source") != revision(expected_suite_revision):
        raise ValueError("firmware report has a different suite revision")
    if report.get("dirty") is not False or report.get("suite_dirty") is not False:
        raise ValueError("firmware report is missing clean source provenance")
    lock_hashes(report)
