"""Materialize an exact candidate; never build or execute it.

Usage: python -B prepare.py CORE_REPO NEW_OUTPUT VARIANT
VARIANT: baseline, borrowed-handler, unified-reply, response-metadata, borrowed-response-origin.
"""
from pathlib import Path
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
BASELINE = "fd7d18a72f795779e352443ebdeef9533be7fb27"


def fixture_inputs():
    """Read the original seven files and verify their exact retained bytes."""
    result = {}
    expected = json.loads((ROOT / "original-fixture-sha256.json").read_text())
    for name, sha in expected.items():
        name = name.replace("\\", "/")
        data = (ROOT.parent / "dispatch-scratch-20261104/fixture" / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha, name
        base = "probe" if name in ("Cargo.toml", "Cargo.lock", "retained.rs") else "tools/benchmark/native/servers/src/bin"
        result[base + "/" + name] = data
    return result


def adapt_fixture(files):
    """Apply only the recorded generic-bound and callback-lifetime edits."""
    result = dict(files)
    for name in ("probe/retained.rs", "tools/benchmark/native/servers/src/bin/bench-core.rs"):
        data = result[name]
        for token in (b"P::Token", b"Token", b"coaptic::message::Token"):
            for space in (b" = ", b"="):
                old = b"AppStorage<Token" + space + token + b">"
                data = data.replace(old, old + b" + coaptic::storage::ReplyPartition")
        if name == "probe/retained.rs":
            data = data.replace(b"-> Response<'static> {", b"-> Response<'_> {")
        result[name] = data
    expected = json.loads((ROOT / "adapted-fixture-sha256.json").read_text())
    assert len(expected) == len(result) == 7
    for name, sha in expected.items():
        assert hashlib.sha256(result[name.replace("\\", "/")]).hexdigest() == sha, name
    return result


def main():
    repo, destination, variant = sys.argv[1:]
    assert variant in ("baseline", "borrowed-handler", "unified-reply", "response-metadata", "borrowed-response-origin")
    output = Path(destination).resolve()
    assert not output.exists(), "Refuse to overwrite existing inputs"
    core = output / "coaptic"
    core.mkdir(parents=True)
    data = subprocess.check_output(["git", "-C", repo, "archive", BASELINE])
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(core, filter="data")
    if variant != "baseline":
        patch = ROOT / (variant + "-candidate.patch")
        subprocess.run(["git", "apply", str(patch)], cwd=core, check=True)
        source = json.loads((ROOT / (variant + "-source-verification.json")).read_text())
        assert hashlib.sha256(patch.read_bytes()).hexdigest() == source["patch_sha256"]
        for name, sha in source["source_file_hashes"].items():
            assert hashlib.sha256((core / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() == sha, name
    files = fixture_inputs()
    if variant in ("borrowed-handler", "unified-reply"):
        files = adapt_fixture(files)
    for name, data in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    print(output / "probe")


if __name__ == "__main__":
    main()
