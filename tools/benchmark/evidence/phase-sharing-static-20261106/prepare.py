"""Materialize exact probe inputs; compilation uses the caller's existing lane.

Usage: python prepare.py CORE_REPO NEW_OUTPUT VARIANT
Does not create a Git worktree or modify the supplied repository.
"""
from pathlib import Path
import io
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
repo, output, variant = sys.argv[1:]
assert variant in ("baseline", "candidate")
output = Path(output).resolve()
assert not output.exists(), "Use a new source directory; existing inputs are preserved"
core = output / "coaptic"
core.mkdir(parents=True)
archive = subprocess.check_output([
    "git", "-C", repo, "archive", "bd63199b652193b4c0a882e5840e72d992cf1362"])
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(core, filter="data")
if variant != "baseline":
    subprocess.run(["git", "apply", str(ROOT / (variant + ".patch"))], cwd=core, check=True)
# Git archive/apply can honor a host CRLF policy. Native inputs were LF.
record = json.loads((ROOT / "source-verification.json").read_text(encoding="utf-8"))
for name, digest in record["source_file_hashes"].items():
    path = core / name
    if not path.exists() and variant == "baseline":
        continue
    data = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(data)
    if variant == "candidate":
        assert hashlib.sha256(data).hexdigest() == digest, name
probe = output / "probe"
probe.mkdir()
for name in ("Cargo.toml", "Cargo.lock", "retained.rs"):
    shutil.copyfile(ROOT.parent / "dispatch-scratch-20261104/fixture" / name, probe / name)
bins = output / "tools/benchmark/native/servers/src/bin"
bins.mkdir(parents=True)
shutil.copyfile(ROOT.parent / "dispatch-scratch-20261104/fixture/bench-core.rs", bins / "bench-core.rs")
shutil.copytree(ROOT.parent / "dispatch-scratch-20261104/fixture/bench_core", bins / "bench_core")
print(probe)
