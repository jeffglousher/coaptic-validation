# Replay scan index and compact replay owners

**Rejected; no production merge.** The complete cohort lowers aggregate CPU
cost 0.98% sync and0.40% async, but five cell upper bounds exceed1.02.
Ordinary sync/async improve1.47%/1.00%; retained async increases1.12%.
Those aggregate gains and smaller owners do not override per-cell failures.

Candidate `c181cdf3ae223043dabaad58f1aed83c901c98b9` combines a compact
MID/deadline scan array, mutually exclusive inline/TX replay owners, scalar TX
owner writes and removal of an unused allocated pin-vector header. The pinned
baseline is `bd63199b652193b4c0a882e5840e72d992cf1362`; current accepted production
at `820f3a3` is source-equivalent in src/crates/Cargo.

## Method and decision

See `measurement.json` and `comparison.html` for the final decision, all 28
cells, aggregates and exact owner sizes. `METHOD-BEFORE.json` records the rule
before this cohort: every cell plus ordinary/all sync and async one-sided 95%
upper CPU ratio must be at most 1.02, with matched memory reduction and capacities.
A small or statistically unresolved difference alone does not prove preservation.
The existing 2% bound was not changed. Earlier rejected sources stay rejected.

64 process pairs per workload use AB, BA, BA, AB repeated 16 times. Ordinary
32/1024-byte cells run 8192 measured operations; ordinary 16384-byte and retained
11264-byte cells run 1024. Each has 128 warmups. CPU0 affinity and Windows server
thread-cycle intervals cover complete App drive work. Each interval retains
counter overhead. Client preparation, authentication, bridge and verification
are outside the interval. Ratios use process means; the reported point is a
geometric mean, with Student df63 one-sided critical factor 1.67. All samples
remain, including outliers. No trimming, optional stopping or replacement.

Sync and async are actual App paths. Async uses immediate-ready memory transport,
a pending timer and manual polling, not a network executor latency claim. The
retained case uses two requests and eleven data packets per operation. This is
not a maximum throughput, socket latency, device, peak RAM or libcoap ranking.

## Memory and capacities

Replay rows shrink 320 to 304 bytes, while a new scan row costs 12 bytes: net
4 bytes per configured replay row. SmallDevice fixed App shrinks 14936 to14920
bytes; Service fixed App315656 to315400. Service allocated App stays35672;
requested pool heap282512 to282256. The allocated Default client App stays16944
and pool heap37060 to37028. Retained fixed App112728 to112664; allocated42704
stays equal. Selected complete progress futures stay15952 SmallDevice /16912
Service fixed and allocated. App sizes include fixture transport.

The new scan vector costs **one extra bounded startup allocation** for nonempty
allocated replay tables. Requested heap includes the declared scan storage but
excludes allocator bookkeeping/rounding; those total-system costs are unmeasured.
No steady-state allocation, pool growth or capacity reduction was introduced.
The unused empty pin Vec header is replaced by the scan Vec header, so allocated
App headers do not grow. Fixed storage needs no heap.

The fixture and source pin unchanged SmallDevice routes4, Calls1, deferred0,
security requests1, associations1, dedup4, RX/TX2x1152, Observe2 and no bodies.
Service has routes32 (one populated), Calls4, deferred8, security requests4,
associations1, dedup64, RX/TX32x1472, Observe32, and four RX plus four TX body
slots of16384 bytes. `verify.py` compares every capacity field reported by the
qualifiers. Retained capacity identity additionally follows the unchanged pinned
fixture; its output does not print a full capacity ledger.

Compiler layouts describe objects, not peak stack. Nested pool owners already
belong to fixed Apps. The baseline layout archive is an incomplete broad prefix
whose three selected future records are complete; the new narrow capture is
complete. Its provenance is in `memory-comparison.json`.

## Failures and checks

The first capture stopped after353 paired rows on a15-second process-exit timeout
in candidate allocated OSCORE sync16384. It retained708 stdout files; the final
file contains1024 samples and1152 verified exchanges, but the process exit was
not confirmed. No performance verdict is assigned to this partial run. The
cause is unknown. One bounded diagnostic for both binaries returned exit0 in
about0.17seconds. All initial outputs, method and failed result are preserved in
`diagnostics.zip`, together with that diagnostic. None were reused in the final
cohort. The fresh capture adds explicit process-exit/timeout-state logging,
retains the same15-second and1200-second bounds, and uses the same binaries,
workloads,64pairs and acceptance rules. `process-exits.jsonl` is archived.

926 alloc+oscore library tests pass, including replay transitions, index cache
coherence, same-MID/different-address lookup, fixed duplicate-key expiry,
zero/u64-max/reversed deadlines and compact occupancy parity. The first allocation
suite failed four stale allocation-count assertions; requested byte accounting
already matched. Test-only c181cdf explicitly raises startup request counts by
one for nonzero Dedup. All11 allocation/refusal/failure-injection checks and13
footprint checks then pass. Initial failures and successful rerun logs remain.
General read-only review of exact c181cdf found no actionable issue; see archived
`review.txt`. No specialized Bugbot reviewer was available. Exact association
and scope equality after the MID filter was confirmed in source review.

## Reproduce

Run `python -B verify.py` offline to hash source patches, fixtures, diagnostics,
all raw observations, selected future layouts and exact owner deltas, then
independently reconstruct every process mean, paired interval and decision.
It does not run native binaries or create replacement measurements.

`python -B prepare.py CORE_REPO NEW_OUTPUT baseline` (or `candidate`) materializes
the pinned core source and unchanged fixtures. The baseline commit must exist
in CORE_REPO. Candidate patch includes tests; it applies to the pinned baseline.
The seven fixture inputs are reused from adjacent `dispatch-scratch-20261104`.
Source normalized hashes and exact toolchain are in `source-verification.json`.

Use an existing compatible registered Cargo lane, CARGO_INCREMENTAL=0,
CARGO_BUILD_JOBS=1 and RUSTFLAGS=-Cforce-frame-pointers=yes. Build ordinary
`cargo build --locked --offline --release --bin dispatch-probe`, then retained
`cargo build --locked --offline --release --bin retained-probe --features oscore,alloc`.
Copy each EXE/PDB before building the other and before layout diagnostics. Native
binaries are retained in observations.zip with SHA256 identities. The complete
capture's archived measure.py records local paths; adjust only source/output
locations to reproduce on another host and use a new owned output directory.
Native figures depend on host/compiler; offline verification is portable.

Run `python -B render.py` to regenerate the self-contained table/chart artifact
from retained results. No measurements are performed by that command.
