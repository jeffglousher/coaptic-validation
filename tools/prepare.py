"""Verify the library checkout and align only its path-package lock versions."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from source_identity import SUITE, LIBRARY, LOCKS, source_identity


def prepare(expected_revision, output=None):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_revision):
        raise ValueError("Expected a full library commit SHA")
    actual = subprocess.check_output(["git", "-C", str(LIBRARY), "rev-parse", "HEAD"], text=True).strip()
    if actual != expected_revision:
        raise ValueError("Library revision differs from the requested commit")
    if subprocess.check_output(["git", "-C", str(LIBRARY), "status", "--porcelain"], text=True).strip():
        raise ValueError("Library checkout has uncommitted changes")
    manifest = (LIBRARY / "Cargo.toml").read_text(encoding="utf-8")
    package = manifest.split("[package]", 1)[1].split("\n[", 1)[0]
    version = re.search(r'^version = "([^"\n]+)"$', package, re.MULTILINE).group(1)
    pattern = re.compile(r'(\[\[package\]\]\nname = "coaptic"\nversion = ")[^"\n]+(")')
    fixtures = {}
    relative_dir = Path("tests/plugtest/td-coap4")
    if {p.name for p in (SUITE / relative_dir).glob("*.yml")} != {p.name for p in (LIBRARY / relative_dir).glob("*.yml")}:
        raise ValueError("Plugtest fixture inventory differs from library checkout")
    for fixture in sorted((SUITE / "tests/plugtest/td-coap4").glob("*.yml")):
        relative = fixture.relative_to(SUITE)
        if fixture.read_bytes().replace(b"\r\n", b"\n") != (LIBRARY / relative).read_bytes().replace(b"\r\n", b"\n"):
            raise ValueError("Plugtest fixture differs from library checkout: " + str(relative))
        fixtures[str(relative)] = hashlib.sha256(fixture.read_bytes()).hexdigest()
    prepared = {}
    for name in LOCKS:
        lock = SUITE / name
        text, count = pattern.subn(lambda match: match[1] + version + match[2], lock.read_text(encoding="utf-8"))
        if count != 1:
            raise ValueError("Expected exactly one Coaptic path package: " + name)
        prepared[lock] = text
    for lock, text in prepared.items():
        lock.write_text(text, encoding="utf-8", newline="\n")
    report = {"library_revision": actual, "library_version": version, "lock_change": "Coaptic path-package version only; dependency pins retained", "fixtures": fixtures}
    if output is not None:
        report.update(source_identity())
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    prepare(arguments.expected_revision, arguments.output)
