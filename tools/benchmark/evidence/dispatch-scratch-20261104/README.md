# Integrated dispatch and response scratch, November 4, 2026

The final batch passes its declared complete-App CPU-cycle criteria in actual
synchronous and asynchronous execution. It combines receive-scratch reuse,
validated wire-layout rebinding, reuse of the OSCORE-option selection result,
and a smaller private response-option builder when both Location lists are empty.
Location responses retain both eight-entry lists and all metadata. No public
capacity, persistent pool, authentication, replay or checkpoint policy changes.

Baseline: `dcf82cbb75d903bd9ab44ccd64ba3e6584bd6f93`.
Measured candidate: `d2d4484cc5c6beb66856511e6d86ce75ce3cefd2`.
The patches reconstruct every measured mechanism from the public baseline,
including rejected body borrowing; they survive squash history. Documentation
and evidence changes after the candidate do not constitute another measurement.

## Runtime result and limits

Across the 28-cell declared mix, the geometric mean of complete-operation
process-mean ratios is 0.9914867457 for sync (0.85% fewer cycles) and
0.9864243475 for async (1.36% fewer cycles). One-sided 95% upper ratios are
0.9968455900 and 0.9917282395. The original 20 ordinary controls separately pass:
sync 0.9917414901 / upper 0.9978287654; async 0.9858266850 / upper 0.9898558051.
All 28 point ratios meet the declared 1.02 regression guard. This is a point
guard per cell, **not** a confidence-bound non-regression claim for every cell.
The retained Q-Block groups also have upper bounds below parity in both modes.

The frozen method requires both mode upper bounds below parity for **both** the
original 20 and all 28 groups, plus every individual point ratio at most 1.02.
Four process pairs use AB, BA, BA, AB. Group weights are equal across workloads
within each pair; intervals operate on four paired log ratios with Student-t
df3, one-sided 95%. No trimming, replacement samples, calibration subtraction or
pooling with earlier cohorts. The final short cells use 8,192 operations/process;
16 KiB ordinary and 11 KiB retained cells use 1,024, all after 128 warmups.
The increased short-cell count was selected before the new source's first run.
All 56 qualifiers and 224 timing processes completed.

Windows x86_64 MSVC, Ryzen 7 5800X3D, CPU0 affinity inherited by probe children;
parent affinity restored after the run. Rust 1.99.1
(`58cf8f9c3`, LLVM 23.1.1), thin LTO, one codegen unit, release debug1,
`-Cforce-frame-pointers=yes`, incremental off, two build jobs. Locked dependencies
and library features `std,alloc,oscore` are identical; diagnostics are disabled.
The timer is Windows `QueryThreadCycleTime`, including counter overhead and
server fixture receive/send copies, maintenance, dispatch, body and crypto work.
Client request preparation, bridge, authentication, assembly and verification
are outside the counter. Service calibration arrays are retained, not subtracted.
Cycles are not converted to elapsed time, throughput or CPU seconds.

Async really calls `wait_async` and `progress_async`/`progress_with_async`, with
immediately ready in-memory transport and a pending timer; the root future is
manually polled. This measures complete server App work, **not** executor
scheduling, sockets, device latency, peak stack or a production traffic mix.
It does not establish universal improvement: Location-response runtime remains
unmeasured, and all four process pairs are one finite local comparison.

## Matched workloads and memory owners

- SmallDevice: Constrained, routes4/populated1, Calls1/deferred0, association1/
  security bindings4, RX/TX2x1152, dedup4, Observe2, no bodies; 32-byte reply.
- Ordinary Service fixed/allocated: routes32/populated1, Calls4/deferred8,
  association1/bindings4, RX/TX32x1472, dedup64, Observe32,
  RX/TX bodies4x16384; 1,024-byte single response or complete 16,384-byte Block2.
- Retained Q-Block fixed/allocated: routes1, Calls4/deferred2, association1/
  bindings4, RX/TX4x1472, dedup16, Observe1, RX/TX bodies2x12288.
  Each 11,264-byte operation uses two requests and 11 verified data packets;
  body and RX occupancy return to zero. Allocation guards surround App work.

Each profile runs unprotected and established OSCORE in both modes. Exact
server/client capacity and owner ledgers are in the raw qualifier JSON. All
paired inline App and requested pool-heap measurements remain equal; nested
payload/transport fields must not be added twice. Static representation and
verification/timing owners are separately identified. No capacity was reduced.

The existing release all-feature Constrained/routes1/blockwise=false test measures
the complete concrete `progress_async` future at 17,128 bytes in the baseline and
15,952 bytes in the candidate: 1,176 bytes (6.87%) less. The future is separate
from the borrowed App; this reduction is not a reduction in App fields or pools.
It is not a peak stack, task stack reservation or whole-system RAM measurement.
`memory.json` records the sources, commands, hashes and separate owners.

Selected emitted Constrained response frames shrink from 1,472 to 768 bytes
(async error type) and 1,456 to 736 bytes (sync error type). The ordinary options
initialization/copy shrinks from 576 to 192 bytes. These are PDB/disassembly
observations, not measured high-water stack. The Location path tail-jumps after
restoring the ordinary frame in the inspected async instantiation: do not add
the two frames. The complete multi-profile probe executable grows from
2,672,128 to 2,734,080 bytes (+61,952, 2.32%). This is executable size, not a
firmware flash estimate or a persistent RAM increase. See the core report for
the separately measured complete progress-future owner and regression checks.

## Failures stay failed

`observations.zip` retains all five source-specific comparisons and their original
scripts, not just the accepted result:

1. Root: receive-scratch reuse `3ceca41`, 12 cells; runtime gate failed.
2. `validated-layout/`: `bef9798`, 12 cells; runtime gate failed.
3. `body-borrow/`: `f8d0f9e`, 20 cells; runtime gate failed. The added ordinary
   16 KiB transfers use the existing borrowed-classic path. They are controls,
   **not** evidence about retained-body staging removal.
4. `retained-body/`: `07c616e` (same body implementation with a minimal-feature
   cfg repair), eight actual retained-Q cells. Diagnostic counters prove removal
   of 11,264 staged bytes per operation with other copy counts unchanged, but
   sync/async upper ratios 1.013682/1.010484 fail to establish a runtime gain.
   The body borrowing/storage API experiment was therefore removed.
5. `response-scratch/`: final integrated `d2d4484`, 28 cells; accepted as above.

An earlier lexical-only Q scratch scope experiment left the future size unchanged
and was reverted. Original failed compilations and preparation errors are retained
locally with the binary/PDB set; no failed measurement is silently replaced.

## Verify and reproduce

Run `python verify.py` (standard library only). It checks every archived byte's
SHA-256, fixture hashes, counts, payload sizes, matched memory/capacity qualifiers,
all 112 paired raw means, 28 cell statistics and nine group statistics, then
recomputes the final acceptance decision. It never runs new samples. Raw files
inside the ZIP are original bytes; `METHOD.json` and `measurement.json` outside
the ZIP are convenient exact copies of the final records.

`fixture/` contains the exact sources/lock/manifest used, including ordinary probe
modules and the retained probe derived from baseline `tests/deferred_qblock2.rs`.
The original relative layout is preserved by:

```text
python prepare.py PATH_TO_CORE_REPO NEW_SOURCE_DIRECTORY baseline
python prepare.py PATH_TO_CORE_REPO ANOTHER_NEW_SOURCE_DIRECTORY integrated
```

Use an existing compatible build lane, never a fresh target per arm. In each
generated `probe/` directory, with the environment listed above, build:

```text
cargo build --locked --offline --release --bin dispatch-probe
cargo build --locked --offline --release --bin retained-probe --features oscore,alloc
```

Copy each resulting executable before building the other arm. Do not enable the
probe's local `oscore,alloc` features for the ordinary binary: those gate fixture
source, whereas dependency features are already fixed in the manifest. For the
separate diagnostic-only retained proof, add `diagnostics`; never time that build.

To run a **new** comparison, install Python `psutil`, put an unmodified `measure.py`
in a fresh `response-scratch/` directory, with the two candidate executables in
its `B/`, the ordinary baseline in sibling `A/dispatch-probe.exe`, and retained
baseline in sibling `retained-body/A/retained-probe.exe`. Run the script on Windows
without competing builds. It refuses to overwrite `measurement.json`, records
fresh binary hashes, pins/restores affinity and verifies complete exchanges.
New binary hashes can vary with source paths/toolchain; new observations do not
replace these historical results. The original scripts for earlier cohorts stay
in the archive with their original limits and decisions.

Reconstruction of the integrated variant was checked against all 371 tracked core
files: 332 require only the configured Windows CRLF normalization; all probe
inputs match byte-for-byte. An initial overly strict Git-blob comparison stopped
on the first CRLF file; checking line-ending normalization resolved that evidence
check without changing or rebuilding the measured sources.

Original executables/PDBs, build/check logs and failed preparation inputs remain
owned under `D:/CoapticCurrent/dispatch-memory-20261104`, capped at 128 MiB through
merge settlement. This portable evidence export is below 5 MiB. Shared compiler
caches and device/runtime state are preserved.
