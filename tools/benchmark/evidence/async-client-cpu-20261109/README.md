# Rejected four-pair complete-App CPU development screen

This package retains **all 280 processes and 917,952 used CPU-cycle samples**:
917,504 measured operations from 224 processes plus 448 qualification operations
from 56 processes. It also retains all 819,200 separate calibration samples and
all other emitted CPU/count vectors and eligibility/memory fields. Original
stdout/stderr packed and expanded SHA256 commitments remain attached to each
process. No sample trimming, replacement, successful-cell filtering or old-cohort
pooling is used.

Run with Python3.10+ and its standard library:

```text
python -B verify.py
python -B test_export.py
```

The standalone verifier derives every process sum/count, all 112 paired means and
ratios, all 28 cell points, all 9 mode/suite aggregates and the actual continuation
decision from the full vectors. Gzip raw/packed hashes and the exact final source
patch are checked. The four fixed process-pair orders are AB/BA/BA/AB. Qualification
vectors are retained but excluded from measured ratios. Calibration is retained
separately and never subtracted. Used samples and repeated per-operation values
are nested inside four process pairs; they are not 917,504 independent replicates.

The **continuation signal fails**. Sync's point ratio is **0.98156356085**, while
async is **1.00909948513**. The three failed cell points are small-device/plain/async
**1.0264373**, retained/fixed/plain/async **1.1295772**, and retained/allocated/plain/sync
**1.0212497**. The prospective development condition requires both overall mode
points<=0.995 and every cell point<=1.02. A lower sync point does not override the
async or cell failures. This is **four-pair development evidence**: no full 64-pair
one-sided confidence qualification, regression acceptance, adoption, completed goal
or comparison against libcoap follows. No further timing of the unchanged rejected
source is implied.

The CPU boundary is complete in-memory server App drive thread cycles, using
actual synchronous poll and asynchronous wait+progress. Counter-call overhead
is retained. Bridge/client preparation, authentication, assembly and verification
are outside the server interval as declared by each producer record. These are
not wall times, Wi-Fi/MCU/socket latencies, executor-only costs or a new cross-language
comparison. Security, capacities, storage and resident ledgers are preserved;
unavailable whole/peak memory remains unknown. Separate timing/calibration arrays
and nested transport/pool owners must not be added twice to App memory.

## Exact source and static tradeoffs

CPU production source is `84a785f075cb86bf805d0e1fe8a1eabcaae3218f`, against baseline
`a85c51e689607051e36e450567fe051f8f85dc2b`. The supplied final source patch is a85 to
`4f434952ba86df35245fa9736f8a5a341de88bf0`, covering **all six Rust files**, including
the corrected new cancellation regression. The84-to4f difference is solely
`src/app/async_server_tests.rs`; timed production inputs remain 84. The corrected
test does not create a newly timed source. Production 84 remains rejected and
unadopted. Compiler version/binary hashes, flags, fixture-plan commitments and
original raw hashes are preserved. The original wrapper naming refusal occurred
before a benchmark process started; its hash/status and corrected wrapper hash
remain in provenance. Original private outputs and independent numeric audit are
retained.

The separate retained Xtensa Os/fat archive comparison reports Runtime 88->88 B,
selected root Future 9896->10120 B (**+224 B**), main dispatch text+literal 25068->23259 B
(**-1809 B**), selected unique code 62448->64973 B (+2525 B), and whole-archive
code 772026->776517 B (**+4491 B**). Main local frame 13200->9568 B has separate empty
and client helper frames 5344/6224 B. These are different static owners, not peak
stack or a released task reservation. Large copies remain: 4972 B moves to the cold
client helper, 3812->3810 B remains a continuation transfer, and a 5216 B aggregate
setup is observed statically. Constructor copy elimination is **not established**;
call-site sizes are not per-GET dynamic counts. Static target tradeoffs and host
CPU measurements are separate scopes, with original producer hashes retained.

The public package contains numeric/raw-CPU eligibility projections and source
patches, without user paths, addresses, run/session identities, credentials, raw
API, configuration, firmware, ELF or NVS. Compiler/fixture/binary and behavioral
producer joins remain retained attestations; this is not an independent build kit.
Previous host/Wi-Fi/MCU and failed CPU evidence remains separate and unchanged.

`export.py` reads explicit private inputs and explicit immutable Git refs after
`--parent-clocks-released`; it refuses existing `package/` output and enforces a
**1 MiB combined private preparation plus package cap**. It performs no build, clock,
network, hardware, Git mutation or cleanup. Full vectors fit the cap, so there is
no sufficient-statistics fallback or missing CPU-tail-vector reconstruction claim.
Available per-operation vectors do not establish a confidence or tail-regression
acceptance from four process pairs. To repeat extraction in a fresh private tools
folder with the retained inputs:

```text
python -B export.py --native-root PRIVATE_ROOT --core-repo CORE_REPO --parent-clocks-released
```

The verifier pins the exact 28-cell order, complete required raw key inventories,
and all 56 qualification/measured identity, capacity, send-limit and memory ledgers
in `fixtures.json.gz`. These are immutable observed producer records, not a fresh
measurement. Ordinary records omit `mode`; their sync/async selection is a compiled
runner/label attestation, while retained records also supply a checked raw mode.
All six unique source paths and every patch header are pinned. Target static facts
remain retained producer attestations, with no independently rebuilt firmware or
newly compiled layout claim. The separately delivered cancellation test is core
PR #751 (`f7a1e8f5021d361230b067fd0ad83b7ac23db1fb`); it does not adopt production 84.
