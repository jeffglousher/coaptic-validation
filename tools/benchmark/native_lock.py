"""Source-matched native benchmark lock inputs; no Cargo resolution or updates.

The caller must require a clean suite/core OR independently verify a declared
prepared checkpoint against immutable sources before entry. A prepared suite is
not clean: every changed lock must have independently derived expected bytes,
with no foreign tracked, indexed or untracked source edits. The caller must
exclusively own the native build lane and these files through exit, and run Cargo
with --locked inside the context. Exit (including restoration/verification) must succeed
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


# Pinned by the original #650 core b8f44fa Cargo.lock.
_HISTORICAL_AES_CHECKSUM = b"35f0f96ce78e38c3dc6d8948aa8163d06385be74000f3c7a95bf1eef35d3ea32"


def _expected_historical_aes(base):
    packages = _toml(base)["package"]
    current = [p for p in packages if p["name"] == "aes" and p["version"] == "0.9.4"]
    if (len(current) != 1
            or current[0].get("source") != "registry+https://github.com/rust-lang/crates.io-index"
            or not isinstance(current[0].get("checksum"), str)):
        raise ValueError("canonical lock requires the registry AES 0.9.4 package")
    checksum = current[0]["checksum"].encode("ascii")
    if (not re.fullmatch(rb"[0-9a-f]{64}", checksum) or base.count(checksum) != 1
            or base.count(b'"aes 0.9.4"') != 1):
        raise ValueError("canonical AES package checksum or coaptic lock edge is ambiguous")
    updated, count = re.subn(rb'(name = "aes"\r?\nversion = ")0\.9\.4"', rb'\g<1>0.9.3"', base)
    if count != 1:
        raise ValueError("canonical AES lock package bytes are ambiguous")
    return updated.replace(checksum, _HISTORICAL_AES_CHECKSUM).replace(b'"aes 0.9.4"', b'"aes 0.9.3"')


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
    """Yield exact native lock paths and digests for the declared Syn and AES pins.

    ``core`` is the selected core checkout; ``native`` defaults to the sibling
    native workspace. Only Cargo.lock is temporarily written, when needed.
    selected_path identifies the input; selected_sha256 hashes its actual bytes,
    also verified at canonical_path on entry. EOL differences from normal Git
    checkout are ignored ONLY for input relationship validation; no input bytes
    are normalized when staging, hashing, or restoring. No baseline is updated.
    """
    native = (Path(native) if native is not None else
              Path(__file__).parent / "native").resolve()
    core = Path(core).resolve()
    manifest = core / "crates/coaptic-io/Cargo.toml"
    root_manifest = core / "Cargo.toml"
    canonical, alternate = native / "Cargo.lock", native / "Cargo.syn3.lock"
    historical = native / "Cargo.aes093.lock"
    base, syn3, old_aes = canonical.read_bytes(), alternate.read_bytes(), historical.read_bytes()
    source, root_source = manifest.read_bytes(), root_manifest.read_bytes()
    expected = _expected_syn3(base)
    if syn3.replace(b"\r\n", b"\n") != expected.replace(b"\r\n", b"\n"):
        raise ValueError("Cargo.syn3.lock must differ only in the coaptic-io syn edge (and checkout EOL)")
    expected = _expected_historical_aes(base)
    if old_aes.replace(b"\r\n", b"\n") != expected.replace(b"\r\n", b"\n"):
        raise ValueError("Cargo.aes093.lock must differ only in the pinned AES version, checksum and edge")
    syn = _toml(source).get("dependencies", {}).get("syn")
    requirement = syn.get("version") if isinstance(syn, dict) else None
    if requirement not in ("2", "3"):
        raise ValueError("unsupported coaptic-io syn.version: " + repr(requirement))
    aes = _toml(root_source).get("dependencies", {}).get("aes")
    aes_requirement = aes.get("version") if isinstance(aes, dict) else None
    if aes_requirement == "=0.9.3" and requirement == "2":
        selected_path, selected = historical, old_aes
    elif aes_requirement == "=0.9.4":
        selected_path, selected = (canonical, base) if requirement == "2" else (alternate, syn3)
    else:
        raise ValueError(f"unsupported native lock pins: Syn {requirement!r}, AES {aes_requirement!r}")
    inputs = ((alternate, syn3), (historical, old_aes), (manifest, source), (root_manifest, root_source))
    for path, data in ((canonical, base), *inputs):
        _unchanged(path, data)
    primary = None
    try:
        if selected != base:
            canonical.write_bytes(selected)
        _unchanged(canonical, selected)
        yield {"syn_requirement": requirement, "aes_requirement": aes_requirement,
               "selected_path": str(selected_path), "selected_sha256": sha256(selected).hexdigest(),
               "canonical_path": str(canonical), "canonical_base_sha256": sha256(base).hexdigest(),
               "syn3_path": str(alternate), "syn3_sha256": sha256(syn3).hexdigest(),
               "historical_aes_path": str(historical), "historical_aes_sha256": sha256(old_aes).hexdigest(),
               "core_manifest_path": str(manifest), "core_manifest_sha256": sha256(source).hexdigest(),
               "core_root_manifest_path": str(root_manifest),
               "core_root_manifest_sha256": sha256(root_source).hexdigest()}
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
