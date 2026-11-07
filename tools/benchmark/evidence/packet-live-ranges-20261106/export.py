"""Export a completed native root; never build, measure, or replace prior evidence.

Usage: python -B export.py NATIVE_ROOT
Wait until the cohort and intended qualification/diagnostic records are final.
Then run verify.py separately to recompute the actual verdict.
"""
from pathlib import Path
import hashlib
import json
import sys
import zipfile
from verify import BASELINE, BASIC_RESPONSE_SOURCE, EXPORTED

ROOT = Path(__file__).resolve().parent
BUDGET = 192 * 1024 * 1024


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def main(native):
    native = Path(native).resolve()
    assert native.is_dir() and native != ROOT
    source = json.loads((native / "source-verification.json").read_bytes())
    measurement = json.loads((native / "measurement.json").read_bytes())
    decision = json.loads((native / "result.json").read_bytes())
    assert source["source"] == decision["candidate"] == BASIC_RESPONSE_SOURCE
    assert source["baseline"] == decision["baseline"] == BASELINE
    assert measurement["status"] == "complete"
    assert decision["runtime_accepted"] == measurement["runtime_accepted"]
    exports = {name: (native / name).read_bytes() for name in EXPORTED if (native / name).is_file()}
    for name in ("source-verification.json", "candidate.patch", "METHOD-BEFORE.json",
                 "METHOD.json", "measurement.json", "preflight-host.json",
                 "dispatch-preflight.json", "memory-preflight.json", "review.json",
                 "TRADEOFF-BEFORE.json", "result.json", "qualification.json",
                 "fmt-check.json", "test-counts.json"):
        assert name in exports, name
    targets = ["observations.zip", "observation-sha256.json", "archives.json", *exports]
    assert all(not (ROOT / name).exists() for name in targets), "Preserve existing evidence"
    files = []
    excluded = []
    for path in sorted(native.rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(native).as_posix()
        if (path.name == "OWNER.json" or path.name.endswith("-notice.json")
                or path.name == "timing-resource-status.json" or "__pycache__" in path.parts):
            excluded.append(name)
            continue
        assert not path.is_symlink(), name
        files.append((name, path))
    manifest = {}
    total = 0
    archive = ROOT / "observations.zip"
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name, path in files:
            data = path.read_bytes()
            if name in exports:
                assert data == exports[name], "Native metadata changed during export"
            manifest[name] = hashlib.sha256(data).hexdigest()
            total += len(data)
            info = zipfile.ZipInfo(name, (2026, 11, 7, 0, 0, 0))
            output.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    metadata = {"members": len(manifest), "uncompressed_bytes": total,
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    exports["observation-sha256.json"] = encoded(manifest)
    exports["archives.json"] = encoded(metadata)
    size = sum(p.stat().st_size for p in ROOT.rglob("*") if p.is_file())
    assert size + sum(map(len, exports.values())) <= BUDGET, "Preserve output and resolve corpus budget"
    for name, data in exports.items():
        with (ROOT / name).open("xb") as output:
            output.write(data)
    print(json.dumps({**metadata, "compressed_bytes": archive.stat().st_size,
                      "corpus_bytes": size + sum(map(len, exports.values())),
                      "excluded": excluded}, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
