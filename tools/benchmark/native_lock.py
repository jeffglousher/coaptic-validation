"""Source-matched native benchmark lock inputs; no Cargo resolution or updates.

The caller must require a clean suite/core BEFORE entry, exclusively own the
native build lane and these files through exit, and run Cargo with --locked
inside the context. Exit (including restoration/verification) must succeed
BEFORE clean-suite identity capture or measurement. Abrupt process death may
leave Cargo.lock dirty: the next caller's clean-source gate must refuse it.
This is not a lock, a concurrent-writer protocol, or crash recovery.
"""
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import re
import tomllib


def _toml(data):
    return tomllib.loads(data.decode("utf-8"))


def _expected_syn3(base):
    """Validate pinned packages and change only the coaptic-io syn edge."""
    packages = _toml(base)["package"]
    for version in ("2.0.119", "3.0.9"):
        if sum(p.get("name") == "syn" and p.get("version") == version
               for p in packages) != 1:
            raise ValueError("native lock requires exactly one syn " + version)
    ios = [p for p in packages if p.get("name") == "coaptic-io"]
    if len(ios) != 1 or [d for d in ios[0].get("dependencies", [])
                         if d == "syn" or d.startswith("syn ")] != ["syn 2.0.119"]:
        raise ValueError("canonical lock requires one coaptic-io -> syn 2.0.119 edge")
    blocks = re.split(rb"(?m)(?=^\[\[package\]\]\r?$)", base)
    for index, block in enumerate(blocks):
        if block.startswith(b"[[package]]") and re.search(
                rb'^name = "coaptic-io"\r?$', block, re.M):
            old = b'"syn 2.0.119"'
            if block.count(old) != 1:
                raise ValueError("canonical coaptic-io edge bytes are ambiguous")
            blocks[index] = block.replace(old, b'"syn 3.0.9"')
            return b"".join(blocks)
    raise ValueError("canonical coaptic-io package bytes missing")


def _unchanged(path, expected):
    if path.read_bytes() != expected:
        raise ValueError("native lock input changed: " + str(path))


def _restore(canonical, selected, base, inputs):
    failures = []
    try:
        # Never overwrite an unexpected edit, even when Cargo itself made it.
        _unchanged(canonical, selected)
        if selected != base:
            canonical.write_bytes(base)
        _unchanged(canonical, base)
    except BaseException as error:
        failures.append(error)
    # Check independent inputs even after a restoration refusal/failure.
    for path, expected in inputs:
        try:
            _unchanged(path, expected)
        except BaseException as error:
            failures.append(error)
    if failures:
        error = RuntimeError("native lock restoration/verification failed: " +
                             "; ".join(str(e) for e in failures))
        raise error from failures[0]


@contextmanager
def native_lock(core, native=None):
    """Yield paths/SHA256s for exact coaptic-io syn.version '2' or '3'.

    ``core`` is the selected core checkout; ``native`` defaults to the sibling
    native workspace. Only Cargo.lock is temporarily written, when needed.
    selected_path identifies the input; selected_sha256 hashes its actual bytes,
    also verified at canonical_path on entry. EOL differences from normal Git
    checkout are ignored ONLY for input relationship validation; no input bytes
    are normalized when staging, hashing, or restoring. No baseline is updated.
    """
    native = (Path(native) if native is not None else
              Path(__file__).parent / "native").resolve()
    manifest = Path(core).resolve() / "crates/coaptic-io/Cargo.toml"
    canonical, alternate = native / "Cargo.lock", native / "Cargo.syn3.lock"
    base, syn3, source = canonical.read_bytes(), alternate.read_bytes(), manifest.read_bytes()
    expected = _expected_syn3(base)
    if syn3.replace(b"\r\n", b"\n") != expected.replace(b"\r\n", b"\n"):
        raise ValueError("Cargo.syn3.lock must differ only in the coaptic-io syn edge (and checkout EOL)")
    syn = _toml(source).get("dependencies", {}).get("syn")
    requirement = syn.get("version") if isinstance(syn, dict) else None
    if requirement not in ("2", "3"):
        raise ValueError("unsupported coaptic-io syn.version: " + repr(requirement))
    selected_path, selected = (canonical, base) if requirement == "2" else (alternate, syn3)
    inputs = ((alternate, syn3), (manifest, source))
    for path, data in ((canonical, base), *inputs):
        _unchanged(path, data)
    primary = None
    try:
        if selected != base:
            canonical.write_bytes(selected)
        _unchanged(canonical, selected)
        yield {"syn_requirement": requirement,
               "selected_path": str(selected_path), "selected_sha256": sha256(selected).hexdigest(),
               "canonical_path": str(canonical), "canonical_base_sha256": sha256(base).hexdigest(),
               "syn3_path": str(alternate), "syn3_sha256": sha256(syn3).hexdigest(),
               "core_manifest_path": str(manifest), "core_manifest_sha256": sha256(source).hexdigest()}
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            _restore(canonical, selected, base, inputs)
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note(str(error))
