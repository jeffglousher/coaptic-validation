"""Materialize exact source and probes without building or modifying a checkout.

Usage: python -B prepare.py CORE_REPO NEW_OUTPUT VARIANT
VARIANT: baseline, candidate, precursor, precursor2, precursor3, failed-cohort, failed-cohort2,
failed-cohort3, failed-cohort4, failed-cohort5, failed-cohort6, failed-cohort7, or failed-cohort8.
Use an existing compatible Cargo lane when compiling the resulting probe.
"""
from pathlib import Path
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from verify import verify_source_manifest

ROOT = Path(__file__).resolve().parent
BASELINE = "fd7d18a72f795779e352443ebdeef9533be7fb27"
baseline_record = json.loads((ROOT.parent / "phase-sharing-static-20261106/source-verification.json").read_bytes())
repo, output, variant = sys.argv[1:]
assert variant in ("baseline", "candidate", "precursor", "precursor2", "precursor3", "failed-cohort", "failed-cohort2", "failed-cohort3", "failed-cohort4", "failed-cohort5", "failed-cohort6", "failed-cohort7", "failed-cohort8")
output = Path(output).resolve()
assert not output.exists(), "Preserve existing sources; choose a new directory"
core = output / "coaptic"
core.mkdir(parents=True)
archive = subprocess.check_output(["git", "-C", repo, "archive", BASELINE])
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(core, filter="data")
if variant in ("precursor", "precursor2", "precursor3", "failed-cohort", "failed-cohort2", "failed-cohort3", "failed-cohort4", "failed-cohort5", "failed-cohort6", "failed-cohort7", "failed-cohort8"):
    with zipfile.ZipFile(ROOT / (variant + ".zip")) as z:
        record = json.loads(z.read("source-verification.json"))
        patch = z.read("candidate.patch")
        fixture_hashes = json.loads(z.read("fixture-sha256.json"))
elif variant == "candidate":
    record = json.loads((ROOT / "source-verification.json").read_bytes())
    patch = (ROOT / "candidate.patch").read_bytes()
    fixture_hashes = json.loads((ROOT / "fixture-sha256.json").read_bytes())
else:
    record = baseline_record
    patch = None
    fixture_hashes = json.loads((ROOT.parent / "phase-sharing-static-20261106/fixture-sha256.json").read_bytes())
verify_source_manifest(record["source_file_hashes"], baseline_record["source_file_hashes"], patch)
if patch is not None:
    assert record["baseline"] == BASELINE
    assert hashlib.sha256(patch).hexdigest() == record["patch_sha256"]
    subprocess.run(["git", "apply", "-"], input=patch, cwd=core, check=True)
for name, expected in record["source_file_hashes"].items():
    path = core / name
    data = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(data)
    assert hashlib.sha256(data).hexdigest() == expected, name
fixture = ROOT.parent / "dispatch-scratch-20261104/fixture"
probe = output / "probe"
probe.mkdir()
for name in ("Cargo.toml", "Cargo.lock", "retained.rs"):
    shutil.copyfile(fixture / name, probe / name)
bins = output / "tools/benchmark/native/servers/src/bin"
bins.mkdir(parents=True)
shutil.copyfile(fixture / "bench-core.rs", bins / "bench-core.rs")
shutil.copytree(fixture / "bench_core", bins / "bench_core")
assert len(fixture_hashes) == 7
for name, expected in fixture_hashes.items():
    name = name.replace("\\", "/")
    path = (bins if name == "bench-core.rs" or name.startswith("bench_core/") else probe) / name
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, name
print(probe)
