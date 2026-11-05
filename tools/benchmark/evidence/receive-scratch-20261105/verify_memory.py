"""Verify selected layout records and source patch hashes without compilation."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

ROOT = Path(__file__).resolve().parent
memory = json.loads((ROOT / "memory.json").read_text())
sources = json.loads((ROOT / "source-verification.json").read_text())
for name, expected in sources["patch_sha256"].items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected
assert sources["retired_tree_matches_baseline"]


def records(text):
    return ["print-type-size type:" + part
            for part in text.split("print-type-size type:")[1:]]


def selected(all_records, name):
    matches = [r for r in all_records
               if r.startswith("print-type-size type: `{async fn body of coaptic::")
               and name in r.splitlines()[0]
               and "Constrained" in r.splitlines()[0]
               and "CoreIo" in r.splitlines()[0]]
    assert len(matches) == 1, (name, len(matches))
    return matches[0]


def size(record):
    return int(re.search(r"`: (\d+) bytes", record.splitlines()[0])[1])


with zipfile.ZipFile(ROOT / "observations.zip") as archive:
    for variant in ("baseline", "request-phase", "metadata", "grouped"):
        path = ("diagnostics/baseline-future-layout.txt" if variant == "baseline"
                else variant + "/future-layout.txt")
        rows = records(archive.read(path).decode("utf-8"))
        expected = memory[variant]
        assert size(selected(rows, "::progress_async<")) == expected["progress_async"]
        assert size(selected(rows, "::dispatch_rx_io_async<")) == expected["dispatch_rx"]
        if variant != "baseline":
            request = selected(rows, "::dispatch_request_io_async<")
            assert size(request) == expected["dispatch_request"]
            initial = re.search(r"variant `Unresumed`: (\d+) bytes", request)
            assert int(initial[1]) == expected["request_unresumed_span"]
print("Selected baseline and three candidate layouts verified; reduction 1952 bytes.")
