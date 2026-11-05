"""Materialize exact probe inputs; compilation uses the caller's existing lane.

Usage: python prepare.py CORE_REPO NEW_OUTPUT VARIANT
Does not create a Git worktree or modify the supplied repository.
"""
from pathlib import Path
import io
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
repo, output, variant = sys.argv[1:]
assert variant in ("baseline", "scratch", "layout", "body-measured", "body", "integrated")
output = Path(output).resolve()
assert not output.exists(), "Use a new source directory; existing inputs are preserved"
core = output / "coaptic"
core.mkdir(parents=True)
archive = subprocess.check_output([
    "git", "-C", repo, "archive", "dcf82cbb75d903bd9ab44ccd64ba3e6584bd6f93"])
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(core, filter="data")
if variant != "baseline":
    subprocess.run(["git", "apply", str(ROOT / (variant + ".patch"))], cwd=core, check=True)
probe = output / "probe"
probe.mkdir()
for name in ("Cargo.toml", "Cargo.lock", "retained.rs"):
    shutil.copyfile(ROOT / "fixture" / name, probe / name)
bins = output / "tools/benchmark/native/servers/src/bin"
bins.mkdir(parents=True)
shutil.copyfile(ROOT / "fixture/bench-core.rs", bins / "bench-core.rs")
shutil.copytree(ROOT / "fixture/bench_core", bins / "bench_core")
print(probe)
