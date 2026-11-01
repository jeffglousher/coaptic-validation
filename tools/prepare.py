"""Verify sources and prepare explicitly selected, checked lock inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from source_identity import SUITE, LIBRARY, LOCKS, source_identity


def _future_dirty(prepared):
    """Predict Git dirtiness without writing the prepared source buffers."""
    raw = subprocess.check_output(["git", "-C", str(SUITE), "status", "--porcelain", "-z", "--untracked-files=all"])
    names = {p.relative_to(SUITE).as_posix() for p in prepared}
    for row in raw.split(b"\0"):
        if not row:
            continue
        # Index changes, renames, unknown paths and untracked inputs remain dirty.
        if len(row) < 4 or row[:3] != b" M " or row[3:].decode("utf-8") not in names:
            return True
    for path, data in prepared.items():
        name = path.relative_to(SUITE).as_posix()
        head = subprocess.check_output(["git", "-C", str(SUITE), "show", "HEAD:" + name])
        if data.replace(b"\r\n", b"\n") != head.replace(b"\r\n", b"\n"):
            return True
    return False


def _prepare_macro_locks(expected_revision, output, version, fixtures, pattern):
    from copy import deepcopy
    from macro_lock_selection import digest, select

    selected, selection = select(SUITE, LIBRARY, expected_revision)
    initial_selection = deepcopy(selection)
    incoming, prepared = {}, {}
    for name in dict.fromkeys((*LOCKS, *selected)):
        path = SUITE / name
        incoming[path] = path.read_bytes()
        row = next((row for row in selection["locks"] if row["path"] == name), None)
        if row is not None and digest(incoming[path]) != row["incoming_sha256"]:
            raise ValueError("selected source changed before buffer preparation: " + name)
        text = selected.get(name, incoming[path]).decode("utf-8").replace("\r\n", "\n")
        text, count = pattern.subn(lambda match: match[1] + version + match[2], text)
        if count != 1:
            raise ValueError("Expected exactly one Coaptic path package: " + name)
        prepared[path] = text.encode("utf-8")
    for row in selection["locks"]:
        row["final_sha256"] = digest(prepared[SUITE / row["path"]])
    report = dict(library_revision=expected_revision, library_version=version,
                  lock_change="Coaptic path-package version plus checked macro Syn-major selection; other resolved dependency pins retained",
                  fixtures=fixtures, macro_lock_selection=selection)
    identity = None
    if output is not None:
        if Path(output).resolve() in {p.resolve() for p in prepared}:
            raise ValueError("provenance output overlaps a prepared lock")
        identity = source_identity()
        identity["suite_dirty"] = _future_dirty(prepared)
        identity["suite_locks"] = {
            name: digest(prepared[SUITE / name]) for name in LOCKS}
        report.update(identity)
    # Both serializations precede every source mutation. No reporting error may
    # hide that a selected lock was already staged.
    formatted, compact = json.dumps(report, indent=2) + "\n", json.dumps(report)
    fresh_selected, fresh_selection = select(SUITE, LIBRARY, expected_revision)
    if fresh_selected != selected or fresh_selection != initial_selection:
        raise ValueError("macro selection inputs changed before preparation")
    for path, data in incoming.items():
        if path.read_bytes() != data:
            raise ValueError("lock changed during exclusive preparation: " + str(path))
    for path, data in prepared.items():
        if path.read_bytes() != incoming[path]:
            raise ValueError("lock changed before preparation write: " + str(path))
        path.write_bytes(data)
    for path, data in prepared.items():
        if path.read_bytes() != data:
            raise ValueError("prepared lock verification failed: " + str(path))
    if output is not None:
        if source_identity() != identity:
            raise ValueError("prepared source provenance differs from preflight")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(formatted, encoding="utf-8")
    print(compact)


def prepare(expected_revision, output=None, *, select_macro_locks=False):
    if type(select_macro_locks) is not bool:
        raise ValueError("explicit macro-lock selection boolean required")
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
    if select_macro_locks:
        return _prepare_macro_locks(expected_revision, output, version, fixtures, pattern)
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
    parser.add_argument("--select-macro-locks", action="store_true",
                        help="prepare checked source-matched macro locks in an exclusively owned CI checkout")
    arguments = parser.parse_args()
    prepare(arguments.expected_revision, arguments.output, select_macro_locks=arguments.select_macro_locks)
