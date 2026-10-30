"""Explicit ESPHome CI lock preparation, without Cargo resolution.

Caller exclusively owns a dedicated source-only CI checkout through prepare.py.
No mutable previous state is authority: HEAD Syn3 bytes and the checked Syn2
alternate define both known inputs. Run BEFORE prepare.py; its version rewrites
are deliberately not accepted on reentry. No protocol/device behavior changes.
The hand-derived Syn2 graph still requires hosted Cargo --locked qualification.
"""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

CANONICAL = "tools/esphome/rust/Cargo.lock"
ALTERNATE = "tools/esphome/rust/Cargo.syn2.lock"
NATIVE = "tools/benchmark/native/Cargo.lock"
MANIFEST = "crates/coaptic-io/Cargo.toml"
BASE_HASH = "635288d6175f7b7233bd62cd5af8d5deb5babc327341a27bd6c913b2845dd3aa"
ALTERNATE_HASH = "a97052da34f06d6a627a0a0ee9e7c52ca38dee2196c8a5fcbb4491a97bb0cee0"
SYN2_CHECKSUM = "872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297"
SYN3_CHECKSUM = "d78c8dee4c7bf0e14673097256fed6142ce9d3b85a408189d07482442145823b"


def digest(data):
    return sha256(data).hexdigest()


def parse(data):
    return tomllib.loads(data.decode("utf-8"))


def one(packages, name):
    rows = [p for p in packages if p.get("name") == name]
    if len(rows) != 1:
        raise ValueError("expected exactly one " + name + " package")
    return rows[0]


def validate_graph(base, alternate, native):
    """Conserve every package field/edge except the explicit Syn substitution."""
    original = parse(base)
    expected = deepcopy(original)
    packages = expected["package"]
    syns = [p for p in packages if p.get("name") == "syn"]
    if sorted(p["version"] for p in syns) != ["2.0.119", "3.0.9"]:
        raise ValueError("unexpected Syn pins")
    for version, checksum in (("2.0.119", SYN2_CHECKSUM), ("3.0.9", SYN3_CHECKSUM)):
        row = next(p for p in syns if p["version"] == version)
        if row.get("checksum") != checksum or row.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
            raise ValueError("unexpected Syn source/checksum")
    io = one(packages, "coaptic-io")
    if io.get("version") != "0.0.10" or "source" in io or [d for d in io.get("dependencies", []) if d.split()[0] == "syn"] != ["syn 3.0.9"]:
        raise ValueError("unexpected macro package/edge")
    for p in packages:
        for edge in p.get("dependencies", []):
            if edge.split()[0] == "syn" and (edge not in ("syn 2.0.119", "syn 3.0.9") or (edge == "syn 3.0.9" and p is not io)):
                raise ValueError("ambiguous Syn edge or extra Syn3 user")
    native_packages = parse(native)["package"]
    native_syn2 = [p for p in native_packages if p.get("name") == "syn" and p.get("version") == "2.0.119"]
    if native_syn2 != [next(p for p in syns if p["version"] == "2.0.119")] or "syn 2.0.119" not in one(native_packages, "coaptic-io").get("dependencies", []):
        raise ValueError("native known Syn2 pin differs")
    io["dependencies"] = ["syn 2.0.119" if d == "syn 3.0.9" else d for d in io["dependencies"]]
    packages.remove(next(p for p in syns if p["version"] == "3.0.9"))
    for p in packages:
        if "dependencies" in p:
            p["dependencies"] = ["syn" if d == "syn 2.0.119" else d for d in p["dependencies"]]
    if parse(alternate) != expected:
        raise ValueError("alternate changes other packages, pins, checksums or edges")


def declared_major(source):
    manifest = parse(source)
    package = manifest.get("package", {})
    if package.get("name") != "coaptic-io" or package.get("version") != "0.0.10":
        raise ValueError("unsupported macro package identity/version")
    syn = manifest.get("dependencies", {}).get("syn")
    if not isinstance(syn, dict) or syn.get("version") not in ("2", "3") or any(k in syn for k in ("git", "path", "registry", "package", "workspace")):
        raise ValueError("unsupported explicit Syn requirement/source")
    # Aliases or target/dev/build rows could introduce a second macro pin.
    def syn_rows(value):
        if not isinstance(value, dict):
            return 0
        return sum((key == "syn" or (isinstance(child, dict) and child.get("package") == "syn"))
                   + syn_rows(child) for key, child in value.items())
    if syn_rows(manifest) != 1:
        raise ValueError("multiple Syn dependency rows")
    return syn["version"]


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def checked(root, path):
    data = (root / path).read_bytes()
    if data.replace(b"\r\n", b"\n") != git(root, "show", "HEAD:" + path).replace(b"\r\n", b"\n"):
        raise ValueError("modified source input: " + path)
    return data


def select(suite, expected_suite, expected_core, *, ci_prepare=False):
    if not ci_prepare:
        raise ValueError("explicit caller-owned CI preparation required")
    suite = Path(suite).resolve()
    core = suite / "coaptic"
    for root, expected in ((suite, expected_suite), (core, expected_core)):
        if not re.fullmatch(r"[0-9a-f]{40}", expected) or git(root, "rev-parse", "HEAD").decode().strip() != expected:
            raise ValueError("checkout identity differs from requested full SHA")
    if git(core, "status", "--porcelain").strip():
        raise ValueError("core checkout is dirty")
    source = checked(core, MANIFEST)
    checked(suite, "tools/esphome/lock_selection.py")
    base = git(suite, "show", "HEAD:" + CANONICAL)
    if digest(base) != BASE_HASH:
        raise ValueError("unsupported canonical HEAD lock hash")
    alternate = checked(suite, ALTERNATE)
    if digest(alternate) != ALTERNATE_HASH:
        raise ValueError("unsupported alternate lock hash (LF required)")
    native = git(suite, "show", "HEAD:" + NATIVE)
    validate_graph(base, alternate, native)
    major = declared_major(source)
    selected = alternate if major == "2" else base
    target = suite / CANONICAL
    incoming = target.read_bytes()
    if target.is_symlink() or incoming not in (base, alternate):
        raise ValueError("unexpected incoming canonical lock; preserve edits (run before prepare.py)")
    report = {"purpose": "ESPHome CI source/lock compatibility; hosted --locked qualification pending",
              "suite_source": expected_suite, "core_source": expected_core,
              "core_manifest_sha256": digest(source), "declared_major": major,
              "original_lock_sha256": digest(base), "alternate_lock_sha256": digest(alternate),
              "selected_lock_sha256": digest(selected),
              "selection": "coaptic-io -> Syn2; remove unused Syn3; dequalify Syn2 edges" if major == "2" else "canonical Syn3 graph unchanged"}
    # Serialize before staging: a reporting failure must not mutate the lock.
    encoded = json.dumps(report, sort_keys=True)
    if incoming != selected:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".lock-selection-", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(selected)
                stream.flush()
                os.fsync(stream.fileno())
            if target.read_bytes() != incoming or temporary.read_bytes() != selected:
                raise ValueError("lock changed during exclusive preparation")
            os.replace(temporary, target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return encoded


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--expected-suite-revision", required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--ci-prepare", action="store_true")
    args = parser.parse_args(argv)
    print(select(args.suite, args.expected_suite_revision, args.expected_revision, ci_prepare=args.ci_prepare))


if __name__ == "__main__":
    main()
