# Replay scan index and direct retained-chunk initialization

**Rejected; no production merge.** One CPU bound fails (fixed Service OSCORE
sync1024, upper1.0205255); all-sync point+0.16%, all-async-0.53%. A separate
32-bit audit also finds a memory regression: SmallDevice+16 bytes and fixed
Service+256 bytes on Thumbv7EM. The 64-bit reductions below do not generalize.

This is the measured integration at `9fa0e459e0ac1ff57c7cec5038852f0541c61651`
against pinned baseline `bd63199b652193b4c0a882e5840e72d992cf1362`.
The final decision and complete table are in `measurement.json` and
`comparison.html`. No earlier failed experiment inherits this result.

## Change and measured boundaries

Compact replay owners and a12-byte MID/deadline scan array reduce net configured
replay storage by4 bytes per row. Exact endpoint/scope/association comparisons
remain required after a MID match. Fixed expiry preserves duplicate-key removal;
allocated expiry preserves its conservative bound. Replacing an unused pin Vec
header with the scan Vec header keeps allocated App headers unchanged.

For full1024-byte retained chunks, the encoder now initializes its one staging
array directly from the body. It skips the old1024-byte clear. Short final chunks
retain zero initialization; checked offset+length, body and chunk limits remain.
Diagnostics count the same copied bytes. The body slice ends before TX mutation;
no body borrow crosses a send. This adds no storage trait/API or borrowing shim.

Pinned baseline disassembly shows the clear then copy. The final disassembly
branches around the clear for a full chunk and copies into the same local array.
Selected fixed Service encoder frames remain1280 bytes sync and1296 with async
transport. Each inspected encoder adds32 instruction bytes. These are static
code/frame observations, not a dynamic CPU fraction or whole-stack peak claim.

SmallDevice fixed App14936 ->14920 bytes. Service fixed App315656 ->315400.
Service allocated App35672 stays equal; requested pool heap282512 ->282256.
The Default fixture client App16944 stays equal and heap37060 ->37028. Retained
fixed App112728 ->112664; allocated42704 stays equal. Selected complete progress
futures remain15952 SmallDevice and16912 Service fixed/allocated. App figures
include fixture transport; do not add nested pools twice.

A nonempty allocated replay table adds one bounded startup allocation. Requested
heap excludes allocator bookkeeping/rounding; total allocator-owned memory is
unmeasured. No steady-state allocation, automatic growth or capacity reduction.
These are small owner reductions, not a claim to close the whole memory gap to C.

## Method

`METHOD-BEFORE.json` freezes64 pairs per28 cells, AB/BA/BA/AB repeated16 times,
CPU0,128 warmups and all acceptance rules before timing. Ordinary32/1024-byte
cells use8192 measured operations; ordinary16384-byte and retained11264-byte
cells use1024. No trimming, early stopping or sample replacement. Paired ratios
use per-process means, log/geometric means and a one-sided95% Student df63
bound with conservative factor1.67.

Every cell plus ordinary/all sync and async upper CPU ratios must be at most1.02,
with unchanged capacities and matched memory reduction. Small or nonsignificant
differences alone do not establish preservation. Earlier cohorts retain their
original decisions. The replay-only c181cdf cohort failed five cell bounds.

Thread-cycle intervals cover complete server App drive work. Client preparation,
authentication, bridge and verification are outside the interval; counter
calibration is separate and never subtracted. Sync and actual async paths are
measured with immediate-ready memory transport and a pending timer. This is not
socket latency, maximum throughput, peak device RAM or a new libcoap ranking.

SmallDevice: routes4, Calls1, deferred0, security requests1, associations1,
dedup4, RX/TX2x1152, Observe2, no bodies. Service: routes32 (one populated),
Calls4, deferred8, security requests4, associations1, dedup64, RX/TX32x1472,
Observe32, four RX and four TX body slots of16384 bytes. Reported capacity fields
are compared directly. Retained capacity identity also follows the unchanged
fixture pin; retained output does not print a full capacity ledger.

## Preserved failures and checks

Two source forms were rejected before runtime timing:59fc4d5 returned an owned
Result array and added1024 encoder-frame bytes; e5868c2 used a borrowed source
but its branch-result array still added992. Their sources, native binaries/PDBs,
assembly, layouts and logs are in `diagnostics.zip`. Final9fa0e45 assigns both
branches into one destination and matches the baseline frame sizes. The complete
future sizes alone would have missed the earlier frame growth.

59fc4d5 passes926 alloc+oscore library,27 retained-Q and13 footprint tests.
Final9fa0e45 passes27 retained-Q and13 footprint checks, diagnostics compilation
and formatting. Inherited c181cdf replay code passes11 allocation/refusal/failure
injection checks; its earlier count-expectation failures remain in adjacent
`replay-scan-index-20261106` evidence. No unchanged failed performance hypothesis
was resampled. General review c181cdf ->e5868c2 found no actionable source issue;
parent inline review covered the final five-line destination repair. No specialized
Bugbot reviewer was available. Archived review.txt states the exact scopes.

The earlier replay-only capture had an unexplained process timeout, preserved
in adjacent evidence with its separate completed failed cohort. This integration
uses the established explicit process-exit logger. No older observations are
reused. All complete-cohort stdout/stderr, binary identities and exit records
are retained in `observations.zip`.

## Reproduce

Run `python -B verify.py` offline. It hashes patches, fixtures, observations and
diagnostics, verifies process exits, capacity fields, exact owner changes and
selected future records, then independently rebuilds all3584 process means,
28 cell bounds and9 aggregates. It does not build, execute probes or resample.

Run `python -B prepare.py CORE_REPO NEW_OUTPUT baseline` or `candidate` to
materialize the pinned source and seven fixtures reused from adjacent
`dispatch-scratch-20261104`. The supplied repository must contain bd63199.
Source normalized hashes, toolchain and patch identity are recorded. Compile
in an existing compatible registered Cargo lane with CARGO_INCREMENTAL=0,
CARGO_BUILD_JOBS=1 and RUSTFLAGS=-Cforce-frame-pointers=yes:

- `cargo build --locked --offline --release --bin dispatch-probe`
- `cargo build --locked --offline --release --bin retained-probe --features oscore,alloc`

Copy each EXE/PDB before later builds and before diagnostic -Zprint-type-sizes
builds. Exact native binaries are archived. Archived measure.py records host
paths; adjust locations only and use a new owned output directory. Results are
host/compiler-dependent; offline verification is portable. Baseline future
layout is an incomplete capture prefix with complete selected records; candidate
capture is complete, as recorded in memory-comparison.json.

`python -B render.py` regenerates the standalone comparison without measurement.

## 32-bit memory failure

`layout32-comparison.json` and hashed `layout32.zip` retain the matched static
Thumbv7EM build. The current toolchain/installed target and registered compiler
lane are reused; no new platform adapter, firmware migration or device claim.
The probe instantiates the actual core App and table types with unit transport.
SmallDevice11304 ->11320 bytes; fixed Service307504 ->307760; allocated App28184
is unchanged. Replay row312 ->304 saves8 bytes, while the scan row costs12;
this explains the extra4 bytes per entry. Table growth is16/256 bytes at4/64
entries. Allocator-owned heap was not run on target; this is object layout.
All source hashes, probe input, lockfile, build logs, selected type records and
constant LLVM IR output remain. The verifier reproduces the failure. The next
candidate must remove this growth before another acceptance measurement.
