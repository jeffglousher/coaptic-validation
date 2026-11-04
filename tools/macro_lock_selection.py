"""Checked CI macro-lock inputs, without Cargo resolution or source writes.

The caller owns a dedicated checkout and opts in before prepare.py records its
provenance. Canonical Syn2 locks remain source inputs. Three checked alternates
select the macro's declared Syn major, removing a displaced Syn2 package only
when no other package uses it. All unrelated resolved packages are conserved.
Hosted Cargo --locked acceptance remains a separate qualification.
"""
from copy import deepcopy
from hashlib import sha256
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

MANIFEST = "crates/coaptic-io/Cargo.toml"
NATIVE = "tools/benchmark/native/Cargo.syn3.lock"
NATIVE_HASH = "3c25aa2229363f18f89f58783f431dafcd769a110fdb23c1b81ca343eb95f2c4"
# Canonical Git bytes, not a hash supplied by the checkout being prepared.
INPUTS = (
    ("Cargo.lock", "Cargo.syn3.lock",
     "f711ce82fa0c978951b004095f37ad2cc4b05c1ceabbff406646ba6c87ed934b",
     "b26481d282ef0c3355dd4c520079135c87107b359216dd19c0cb3a8856b85589"),
    ("tools/durable-host/Cargo.lock", "tools/durable-host/Cargo.syn3.lock",
     "201a985ddbb079b851b734371217185a62b8260710c5686a1f772655eb07643b",
     "011e7e4c565a0f6a8db6b0f7a62ab58c74525b0bc621d4b3117269fd3f9387fe"),
    ("fuzz/Cargo.lock", "fuzz/Cargo.syn3.lock",
     "a463590ec3555d76ad4a3b8996ca8cbc18b2c9f97502b7ba87f32d7dbc7386ee",
     "cb4fc3fda0fe9cda1db44985002e8ea5981a488172faf9c2ed4e308b71906513"),
)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
SYN_CHECKSUMS = {
    "2.0.119": "872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297",
    "3.0.5": "12df2e0110f65b775f769bb17ef989067a1d931b2eb822bd4346631eeada89f9",
    "3.0.9": "d78c8dee4c7bf0e14673097256fed6142ce9d3b85a408189d07482442145823b",
}


def digest(data):
    return sha256(data).hexdigest()


def parse(data):
    return tomllib.loads(data.decode("utf-8"))


def packages(value):
    rows = value.get("package")
    if not isinstance(rows, list) or not all(isinstance(p, dict) for p in rows):
        raise ValueError("lock package list required")
    if any(not isinstance(p.get("name"), str) or not isinstance(p.get("version"), str)
           or not isinstance(p.get("dependencies", []), list)
           or any(not isinstance(d, str) or not d.split() for d in p.get("dependencies", []))
           for p in rows):
        raise ValueError("malformed lock package or dependency")
    ids = [(p.get("name"), p.get("version"), p.get("source")) for p in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate lock package identity")
    return rows


def one(rows, name):
    found = [p for p in rows if p.get("name") == name]
    if len(found) != 1:
        raise ValueError("expected exactly one " + name + " package")
    return found[0]


def syn_rows(rows):
    found = [p for p in rows if p.get("name") == "syn"]
    for row in found:
        if (row.get("version") not in SYN_CHECKSUMS or row.get("source") != REGISTRY
                or row.get("checksum") != SYN_CHECKSUMS[row["version"]]
                or row.get("dependencies") != ["proc-macro2", "quote", "unicode-ident"]):
            raise ValueError("unexpected Syn package/source/checksum/dependencies")
    if len({p["version"] for p in found}) != len(found):
        raise ValueError("ambiguous Syn package source")
    return found


def expected_graph(base, native):
    """Move the macro edge, retaining Syn2 only while another package uses it."""
    value = deepcopy(parse(base))
    rows = packages(value)
    syns = syn_rows(rows)
    versions = sorted(p["version"] for p in syns)
    if versions not in (["2.0.119"], ["2.0.119", "3.0.5"]):
        raise ValueError("unsupported canonical Syn package set")
    io = one(rows, "coaptic-io")
    if io.get("version") != "0.0.10" or "source" in io:
        raise ValueError("unsupported macro lock identity")
    old_edge = "syn" if len(syns) == 1 else "syn 2.0.119"
    if [d for d in io.get("dependencies", []) if d.split()[0] == "syn"] != [old_edge]:
        raise ValueError("canonical macro must select Syn2 exactly once")
    native_rows = packages(parse(native))
    native_syn = syn_rows(native_rows)
    if sorted(p["version"] for p in native_syn) != ["2.0.119", "3.0.9"]:
        raise ValueError("unsupported trusted native Syn packages")
    if next(p for p in syns if p["version"] == "2.0.119") != next(
            p for p in native_syn if p["version"] == "2.0.119"):
        raise ValueError("canonical Syn2 differs from trusted package")
    native_io = one(native_rows, "coaptic-io")
    if [d for d in native_io.get("dependencies", []) if d.split()[0] == "syn"] != ["syn 3.0.9"]:
        raise ValueError("trusted native macro must select Syn3")
    target = "3.0.5" if len(syns) == 2 else "3.0.9"
    for row in rows:
        for edge in row.get("dependencies", []):
            if edge.split()[0] == "syn" and edge not in (
                    ("syn",) if len(syns) == 1 else ("syn 2.0.119", "syn 3.0.5")):
                raise ValueError("ambiguous or foreign Syn dependency edge")
        if "dependencies" in row:
            row["dependencies"] = [
                "syn " + target if row is io and d == old_edge else
                "syn 2.0.119" if len(syns) == 1 and d == "syn" else d
                for d in row["dependencies"]]
    if len(syns) == 1:
        added = deepcopy(next(p for p in native_syn if p["version"] == target))
        for dependency in added["dependencies"]:
            one(rows, dependency)
        rows.insert(rows.index(syns[0]) + 1, added)
        if not any("syn 2.0.119" in row.get("dependencies", []) for row in rows):
            # The fuzz graph used Syn2 only through coaptic-io. Remove its
            # displaced package as part of the checked lock transition; no
            # other resolved package is pruned.
            rows.remove(syns[0])
            for row in rows:
                if "dependencies" in row:
                    row["dependencies"] = ["syn" if d == "syn " + target else d
                                           for d in row["dependencies"]]
    return value


def validate_graph(base, alternate, native):
    actual = parse(alternate)
    packages(actual)
    if actual != expected_graph(base, native):
        raise ValueError("alternate changes other packages, pins or resolved edges")


def declared_major(data):
    value = parse(data)
    if value.get("package", {}).get("name") != "coaptic-io" or value["package"].get("version") != "0.0.10":
        raise ValueError("unsupported macro manifest identity")
    syn = value.get("dependencies", {}).get("syn")
    if (not isinstance(syn, dict) or syn.get("version") not in ("2", "3")
            or any(k in syn for k in ("git", "path", "registry", "package", "workspace"))):
        raise ValueError("unsupported explicit Syn requirement/source")

    def count_rows(node):
        if not isinstance(node, dict):
            return 0
        return sum((key == "syn" or isinstance(child, dict) and child.get("package") == "syn")
                   + count_rows(child) for key, child in node.items())

    if count_rows(value) != 1:
        raise ValueError("multiple or aliased Syn dependency rows")
    return syn["version"]


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def safe_path(root, name):
    path = root
    for part in Path(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("symlink source input: " + name)
    if not path.resolve().is_relative_to(root):
        raise ValueError("source input escapes checkout")
    return path


def checked(root, name):
    path = safe_path(root, name)
    current = path.read_bytes()
    head = git(root, "show", "HEAD:" + name)
    if current.replace(b"\r\n", b"\n") != head.replace(b"\r\n", b"\n"):
        raise ValueError("modified source input: " + name)
    staged = subprocess.run(["git", "-C", str(root), "diff", "--cached", "--quiet", "HEAD", "--", name])
    if staged.returncode:
        raise ValueError("modified index input: " + name)
    return current, head


def _source_inputs(suite, core, expected_core):
    if (not re.fullmatch(r"[0-9a-f]{40}", expected_core)
            or git(core, "rev-parse", "HEAD").decode().strip() != expected_core):
        raise ValueError("core identity differs from requested full SHA")
    if git(core, "status", "--porcelain").strip():
        raise ValueError("core checkout is dirty")
    for name in ("tools/macro_lock_selection.py", "tools/prepare.py"):
        checked(suite, name)
    source, _ = checked(core, MANIFEST)
    major = declared_major(source)
    _, native = checked(suite, NATIVE)
    if digest(native) != NATIVE_HASH:
        raise ValueError("trusted native lock hash differs")
    return major, source, native


def select(suite, core, expected_core):
    """Return checked buffers and provenance. This function never writes a file."""
    suite, core = Path(suite).resolve(), Path(core).resolve()
    major, source, native = _source_inputs(suite, core, expected_core)
    selected, locks = {}, []
    for name, alternate, base_hash, alternate_hash in INPUTS:
        incoming, base = checked(suite, name)
        actual_alternate, alt = checked(suite, alternate)
        if digest(base) != base_hash or digest(alt) != alternate_hash or actual_alternate != alt:
            raise ValueError("frozen lock hash/LF bytes differ")
        validate_graph(base, alt, native)
        data = base if major == "2" else alt
        selected[name] = data
        locks.append(dict(path=name, alternate=alternate, canonical_sha256=base_hash,
                          alternate_sha256=alternate_hash, incoming_sha256=digest(incoming),
                          selected_sha256=digest(data)))
    return selected, dict(purpose="CI macro lock compatibility; Cargo --locked qualification is separate",
                          suite_revision=git(suite, "rev-parse", "HEAD").decode().strip(),
                          core_revision=expected_core, macro_manifest_sha256=digest(source),
                          declared_syn_major=major, native_lock_sha256=digest(native), locks=locks)


def _align(data, version):
    pattern = rb'(\[\[package\]\]\nname = "coaptic"\nversion = ")[^"\n]+(")'
    aligned, count = re.subn(pattern, lambda m: m[1] + version.encode() + m[2], data.replace(b"\r\n", b"\n"))
    if count != 1:
        raise ValueError("expected one Coaptic path version in prepared input")
    return aligned


def _expected_prepared(suite, core, expected_core, expected_suite):
    from source_identity import LOCKS

    if (not re.fullmatch(r"[0-9a-f]{40}", expected_suite)
            or git(suite, "rev-parse", "HEAD").decode().strip() != expected_suite):
        raise ValueError("suite identity differs from requested full SHA")
    major, source, native = _source_inputs(suite, core, expected_core)
    manifest, _ = checked(core, "Cargo.toml")
    package = parse(manifest).get("package", {})
    version = package.get("version")
    if package.get("name") != "coaptic" or not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z.+-]+", version):
        raise ValueError("unsupported Coaptic path version")
    expected, records = {}, []
    for name in LOCKS:
        expected[name] = _align(git(suite, "show", "HEAD:" + name), version)
    for name, alternate, base_hash, alternate_hash in INPUTS:
        base = git(suite, "show", "HEAD:" + name)
        actual_alt, alt = checked(suite, alternate)
        if digest(base) != base_hash or digest(alt) != alternate_hash or actual_alt != alt:
            raise ValueError("frozen checkpoint lock hash/LF bytes differ")
        validate_graph(base, alt, native)
        selected = base if major == "2" else alt
        expected[name] = _align(selected, version)
        records.append(dict(path=name, alternate=alternate, canonical_sha256=base_hash,
                            alternate_sha256=alternate_hash, selected_sha256=digest(selected),
                            final_sha256=digest(expected[name])))
    # ESPHome has its own source-aware preselector. Most jobs do not build that
    # target; accept only HEAD or its independently checked Syn2 preparation.
    esphome = "tools/esphome/rust/Cargo.lock"
    actual = safe_path(suite, esphome).read_bytes()
    if actual != expected[esphome]:
        if major != "2":
            raise ValueError("unexpected ESPHome checkpoint")
        checked(suite, "tools/esphome/lock_selection.py")
        from esphome import lock_selection as esphome_selection
        base = git(suite, "show", "HEAD:" + esphome)
        alternate, head_alt = checked(suite, esphome_selection.ALTERNATE)
        native_base = git(suite, "show", "HEAD:" + esphome_selection.NATIVE)
        if (digest(base) != esphome_selection.BASE_HASH or alternate != head_alt
                or digest(head_alt) != esphome_selection.ALTERNATE_HASH):
            raise ValueError("unknown ESPHome source inputs")
        esphome_selection.validate_graph(base, head_alt, native_base)
        selected = _align(head_alt, version)
        if actual != selected:
            raise ValueError("foreign prepared ESPHome bytes")
        expected[esphome] = selected
    return expected, records, major, source, version


def verify_prepared(suite, core, expected_core, expected_suite, report_path, *, native_active=False):
    """Independently verify a declared prepared checkpoint, never a clean claim."""
    from source_identity import LOCKS

    suite, core = Path(suite).resolve(), Path(core).resolve()
    expected, records, major, source, version = _expected_prepared(suite, core, expected_core, expected_suite)
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    for key, value in dict(library_revision=expected_core, library_version=version,
                           source=expected_core, suite_source=expected_suite).items():
        if report.get(key) != value:
            raise ValueError("prepared report source identity differs")
    if report.get("dirty") is not False:
        raise ValueError("prepared core source was not clean")
    original_hashes = {name: digest(expected[name]) for name in LOCKS}
    if report.get("suite_locks") != original_hashes:
        raise ValueError("prepared report lock hashes differ from independent source")
    dirty = any(data.replace(b"\r\n", b"\n") != git(suite, "show", "HEAD:" + name).replace(b"\r\n", b"\n")
                for name, data in expected.items())
    if type(report.get("suite_dirty")) is not bool or report["suite_dirty"] != dirty:
        raise ValueError("prepared report dirtiness differs from known checkpoint")
    selection = report.get("macro_lock_selection", {})
    for key, value in dict(suite_revision=expected_suite, core_revision=expected_core,
                           macro_manifest_sha256=digest(source), declared_syn_major=major,
                           native_lock_sha256=NATIVE_HASH).items():
        if selection.get(key) != value:
            raise ValueError("prepared macro selection identity differs")
    observed = selection.get("locks")
    if not isinstance(observed, list) or len(observed) != len(records):
        raise ValueError("prepared macro selection census differs")
    for actual, wanted in zip(observed, records):
        if not isinstance(actual, dict) or any(actual.get(k) != v for k, v in wanted.items()):
            raise ValueError("prepared macro selection hash differs")
    if native_active and major == "3":
        # Existing native_lock validates the sole edge substitution and stages
        # these actual checked source bytes; the report still describes entry.
        expected["tools/benchmark/native/Cargo.lock"] = checked(suite, NATIVE)[0]
    for name, data in expected.items():
        if safe_path(suite, name).read_bytes() != data:
            raise ValueError("prepared input bytes changed: " + name)
    if git(suite, "ls-files", "--others", "--exclude-standard", "-z"):
        raise ValueError("foreign untracked source in prepared checkpoint")
    index = subprocess.run(["git", "-C", str(suite), "diff", "--cached", "--quiet", "HEAD", "--"])
    if index.returncode:
        raise ValueError("foreign index edit in prepared checkpoint")
    checked(suite, ".gitattributes")
    entries = git(suite, "ls-tree", "-r", "-z", "HEAD").split(b"\0")
    tracked = []
    for entry in entries:
        if not entry:
            continue
        meta, raw_name = entry.split(b"\t", 1)
        mode, kind, sha = meta.split()
        name = raw_name.decode("utf-8")
        if (mode not in (b"100644", b"100755") or kind != b"blob"
                or any(c in name for c in ('\n', '\r', '"'))):
            raise ValueError("unsupported tracked checkpoint source")
        safe_path(suite, name)
        tracked.append((name, sha.decode()))
    if len({name.casefold() for name, _ in tracked}) != len(tracked):
        raise ValueError("case-ambiguous tracked checkpoint source")
    # Git applies the repository's real clean filters, including -text and LF
    # rules. --stdin-paths hashes files read-only; it does not write objects.
    hashes = subprocess.check_output(["git", "-C", str(suite), "hash-object", "--stdin-paths"],
                                    input="".join(name + "\n" for name, _ in tracked).encode()).decode().splitlines()
    if len(hashes) != len(tracked):
        raise ValueError("tracked checkpoint hash census differs")
    for (name, wanted), actual in zip(tracked, hashes):
        if name not in expected and actual != wanted:
            raise ValueError("foreign tracked source edit: " + name)
    return dict(core=expected_core, suite=expected_suite, prepared_files=len(expected),
                tracked_files=len(tracked), native_active=native_active)


def native_commands(group):
    manifest = "tools/benchmark/native/Cargo.toml"
    if group == "profile":
        return [
            ["cargo", "fmt", "--manifest-path", manifest, "-p", "bench-profile", "--", "--check"],
            ["cargo", "clippy", "--locked", "--manifest-path", manifest, "-p", "bench-profile", "--all-targets", "--", "-D", "warnings"],
            ["cargo", "test", "--locked", "--manifest-path", manifest, "-p", "bench-profile"],
        ]
    if group == "fixtures":
        return [
            ["cargo", "fmt", "--manifest-path", manifest, "-p", "bench-rust-server", "--", "--check"],
            ["cargo", "clippy", "--locked", "--manifest-path", manifest, "-p", "bench-rust-server", "--all-targets", "--", "-D", "warnings"],
            ["cargo", "test", "--locked", "--manifest-path", manifest, "-p", "bench-rust-server", "--bin", "bench-native-client"],
            ["cargo", "build", "--release", "--locked", "--manifest-path", manifest, "-p", "bench-rust-server"],
            [sys.executable, "tools/benchmark/protected/network_check.py", "--server", "target/benchmark-native/release/bench-rust-server"],
            [sys.executable, "tools/benchmark/native_check.py", "--server", "target/benchmark-native/release/bench-rust-server", "--client", "target/benchmark-native/release/bench-native-client"],
        ]
    raise ValueError("unknown fixed native check group")


def run_native_checks(group, suite, expected_core, expected_suite, report_path):
    suite = Path(suite).resolve()
    core = suite / "coaptic"
    commands = native_commands(group)
    verify_prepared(suite, core, expected_core, expected_suite, report_path)
    # Source verification precedes importing the existing context implementation.
    sys.path.insert(0, str(suite / "tools/benchmark"))
    try:
        from native_lock import native_lock
    finally:
        sys.path.pop(0)
    primary = None
    try:
        with native_lock(core, suite / "tools/benchmark/native"):
            verify_prepared(suite, core, expected_core, expected_suite, report_path, native_active=True)
            for command in commands:
                subprocess.run(command, cwd=suite, check=True)
                verify_prepared(suite, core, expected_core, expected_suite, report_path, native_active=True)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            checkpoint = verify_prepared(suite, core, expected_core, expected_suite, report_path)
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note("native prepared checkpoint finally: " + str(error))
    print(json.dumps(dict(native_checks=group, restored_prepared_checkpoint=checkpoint)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-checks", choices=("profile", "fixtures"), required=True)
    parser.add_argument("--suite", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-suite-revision", required=True)
    parser.add_argument("--prepared-report", type=Path, required=True)
    args = parser.parse_args()
    run_native_checks(args.native_checks, args.suite, args.expected_revision,
                      args.expected_suite_revision, args.prepared_report)
