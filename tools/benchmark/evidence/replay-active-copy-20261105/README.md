# Replay writes and fixed expiry: rejected integrations

Neither measured candidate meets the frozen complete-App runtime requirements.
Production changes are retired. The earlier shared-owner and owned-scan failures
remain in [replay-storage-20261105](../replay-storage-20261105/README.md).
Do not rerun an unchanged candidate, discard samples or relax the gates.

## Source and decisions

Baseline is core `bd63199b652193b4c0a882e5840e72d992cf1362` (#741).
Its reused native binaries were built from `f84f3c199763910e246d8599aca0e29077a73ad1`;
[packet-dispatch source verification](../packet-dispatch-20261104/source-verification.json)
records production equivalence. All new native candidates use the same seven-file
dispatch fixture, Rust 1.99.1/LLVM 23.1.1, Windows MSVC release, thin LTO,
one codegen unit, debug=1 and forced frame pointers. Absolute build paths differ.

The retained assembly identifies a real copy, but removing it does not establish
a complete-App speedup:

- Baseline reply retention copies a 320-byte row even for a TX-only replay.
  The earlier shared enum still copies 304 bytes; separate inline-array staging
  increases the selected fixed/allocated retention frames from 384/376 to 616/624
  bytes. These are selected emitted frame records, not peak stack measurements.
- `d62d3ac7e736d28a7d3b19800595a3a20d809bb7` (`active.patch`) tries active-variant
  writes. LLVM still emits a 264-byte copy for TX. The initial interpretation
  that the copy disappeared was incorrect; assembly and the correction are kept.
  Its 264 storage tests pass. No runtime cohort was run.
- `9af2f075d345147a4f471c41a7fdb4fad7c4786b` (`direct-fill.patch`) fills inline
  replay in its destination. The selected retention frames become 368/368 bytes,
  but the TX copy remains. Its 924 alloc+oscore library tests pass. No runtime
  cohort was run.
- `2e9acd1902d27c6fa0b38f2df3f29a33c0ae45bf` (`scalar-pin.patch`) adds a private
  non-inlined scalar constructor for TX rows. Its emitted helper uses tag, pin,
  key and deadline stores, with no memcpy; inline replay retains its full copy.
  The single runtime cohort fails. Its 924 alloc+oscore tests pass.
- `1c6cee94e8c4a181be48c986da614e9043ea2e3a` (`fixed-expiry.patch`) adds a
  conservative fixed-table deadline bound to that integration, refreshed during
  the existing App expiry walk. Unlike the rejected pre-#731 fixed cache, it adds
  no separate refresh scan. Its single runtime cohort also fails. Its 926
  alloc+oscore tests pass. `2244b31` adds only the passing duplicate-key App
  regression (`fixed-expiry-tests.patch`); the measured fixture remains 1c6cee9.

General read-only source reviews found no actionable correctness/security defect.
The final review's test gap was closed by the duplicate-key App regression:
removing an earlier matching key must not hide the surviving due row during
refresh. No broad feature qualification, new complete-future layout measurement
or merge acceptance is inferred from those checks.

## Frozen complete-App comparison

Each candidate has one 28-cell cohort: 20 ordinary SmallDevice32 and Service
fixed/allocated1024/16384 cells, plus eight retained Q-Block2 11264-byte cells.
Every group includes unprotected and established OSCORE, actual synchronous poll
and asynchronous wait+progress. The shared fixture fixes routes, Calls, deferred,
security, body and pool capacities. The verifier compares reported capacity
fields, including SmallDevice pools; retained outputs omit a capacity ledger,
so their unchanged capacities are established by the pinned fixture/source.

Four paired processes use AB, BA, BA, AB, CPU0 with inherited/restored affinity,
128 warmup operations, 8192 measured operations for ordinary32/1024 and 1024
for large/retained cells. QueryThreadCycleTime covers complete server-App drive;
client preparation/authentication, bridge and response checks are outside it.
Async uses the existing immediate-ready memory transport, pending timer and
manual polling. This is not sockets, executor scheduling, device or peak memory.

All ordinary and all-28 sync/async one-sided upper95 ratio bounds must be below
1; every cell point ratio must be at most 1.02. Equal-weight process-mean log
ratios use Student-t df3 factor 2.3533634348. No trimming, sample replacement,
pooled rescue or unchanged repetition is permitted. Memory must independently
shrink with unchanged capacities and no undeclared ledger growth.

Scalar-pin fails ordinary-sync (ratio 1.000035, upper 1.003649) and all-sync
(1.002097, upper 1.008035); both async aggregates pass. Two point guards fail:
ordinary fixed Service unprotected sync1024 (1.036688) and retained allocated
unprotected sync11264 (1.028473).

Fixed-expiry fails ordinary-sync (0.984015, upper 1.008888), ordinary-async
(0.986074, upper 1.000020) and all-sync (0.994783, upper 1.008736).
All-async passes (0.983014, upper 0.997782). Five point guards fail, including
SmallDevice unprotected sync (1.032707) and async (1.022878). The complete failed
cell list, process rows and bounds are retained; favorable point estimates do
not override failed bounds.

## Memory and diagnostic limits

Scalar-pin reduces SmallDevice App 14936 to14872 bytes, fixed Service App
315656 to314632, and allocated Service requested pool heap 282512 to281488.
Allocated App stays35672; client requested pool heap37060 to36932.
Retained fixed App112728 to112472; retained allocated App42704 is unchanged.

Fixed-expiry adds one eight-byte bound to every fixed table, including empty
tables. Net sizes are SmallDevice App14880, fixed Service App314640 and retained
fixed App112480; allocated sizes are the same as scalar-pin. All other recorded
ledger fields match baseline. This is object/requested-heap accounting, not
allocator overhead, reserved stack, peak RAM or executable-size acceptance.
Shared replay also changes equality/hash to active logical state; it does not
zeroize inactive physical bytes. The tx_pin receiver changes from value to
reference, which can affect UFCS function-pointer types.

The archived third baseline diagnostic instruments complete drive, retention
and expiry with nested Instant guards and fixed atomic counters. Fixed Service
expiry is above the empty-guard floor, while SmallDevice and allocated expiry
are near it. Retention is material in both Service modes. These inclusive wall
timings are perturbed diagnostics, not CPU shares, additive costs or acceptance
measurements. The diagnostic motivated the fixed-expiry integration; its runtime
failure remains authoritative. The earlier fixed-cache failure is documented in
core `architecture/requirements/DEDUP-EXPIRY-20261103.md`.

## Reproduce without resampling

Run `python verify.py scalar-pin` and `python verify.py fixed-expiry`. Standard
library only: verify all 1192 archive members and source/fixture hashes, recompute
448 timing outputs across both cohorts, compare reported memory/capacity fields and
reproduce the rejected decisions. Source-verification setup mistakes are recorded;
they changed neither source nor observed samples.
The evidence review found that the original report overstated capacity-ledger
coverage. SmallDevice comparisons were added and retained-output limits clarified;
neither original decision changed and no native measurement was repeated.

`python prepare.py CORE_REPO NEW_OUTPUT VARIANT` materializes baseline plus one
exact source patch and the original fixture. Supported variants are baseline,
active, direct-fill, scalar-pin, fixed-expiry and fixed-expiry-tests. Build
`NEW_OUTPUT/probe/Cargo.toml` with the existing compatible Cargo lane; ordinary
uses `--bin dispatch-probe`, retained uses `--bin retained-probe --features
oscore,alloc`. Set `CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=1` and
`RUSTFLAGS=-Cforce-frame-pointers=yes`. Compilation is separate from offline
verification and is not authorization to repeat failed cohorts.

Archived producers preserve their original paths, source pins and overwrite
refusals. For diagnostic reproduction, materialize baseline and apply archived
`diagnostic3/diagnostic3.patch` at NEW_OUTPUT (its paths include coaptic/probe/tools).
Build the ordinary probe, then use the archived diagnostic producer separately
from timing. `codegen/inspect.py` accepts EXE, PDB and output prefix and uses
llvm-pdbutil/llvm-objdump to retain selected routines.

Original EXE/PDB files remain in their owned local evidence roots; hashes and
sizes are in `native-binary-sha256.json`. This portable package contains source,
assembly, logs and raw observations, not native binaries. Neither cohort proves
a new optimization is ready to merge. Next work must target a distinct material
cost, keeping these failures and the original baseline intact.
