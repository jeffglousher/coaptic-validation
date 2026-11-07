# Packet preparation, retained replies and response ownership

This evidence follows the accepted phase-sharing batch. The CPU baseline is
merged core `fd7d18a72f795779e352443ebdeef9533be7fb27`; its reused executables
were built from `3e592adb1fd52c5e6918af1b4e810bb874413bad`, whose 148 core input
files are identical to that merge. The seven original probe inputs are unchanged.

Final integration status is pending. Do not infer acceptance from the rejected
variants below or from a source build.

## Rejected direct-body integration

Source `bf8581249fbbb591067c46e85ef4c9dc19be120a` combines shorter packet
preparation lifetimes, an 8-byte Q selector descriptor reference, borrowed
completed deferred metadata and compact received-response identity. Retained
body encoding now borrows the filled body and a separate TX buffer together.
A compile-time callback specializes ordinary byte-slice versus retained-body
encoding; it adds no runtime payload-selector enum. Nonempty protected packet replacement
keeps the existing transactional staging fallback.

`BodyDatagramSlots` is an explicit new capability for custom App backends.
Standalone `BodySlots` bounds are unchanged. Fixed/allocated implementations
preserve lengths, sidecars, occupancy, cursors and pin state and refuse pinned
TX writes. Capacities remain independent. No unsafe code was added.

The new source passes 1,228 all-feature library tests and both strict Clippy
configurations. The initial no-default lint found a new Debug test requiring
`std::format`; its std feature guard was corrected and the failure retained.
Tests compare exact encoded bytes and sender-sequence consumption against the
existing staged encoder, including zero/short/full bodies, actual-capacity
refusal, inactive contexts with nonzero association and missing bindings.

Before timing, the instrumented retained fixture verified zero
`block_tx_staged_bytes` for all eight storage/security/mode combinations, 136
verified operations each. Unprotected encoded payload counts remain exactly
136 x 11,264 bytes. This confirms path/work removal, not CPU attribution.
The selected encoder frames are 288 bytes versus 1,296/1,280 baseline. Complete
progress futures remain 2,536 bytes smaller; App/pool owners and selected
Thumbv7EM layouts do not grow. Selected SmallDevice polling code grows 4,094
bytes; this is a native symbol-size tradeoff, not a device flash measurement.
The complete runtime cohort failed five workload bounds. This source is rejected;
passing prequalification and removed staging do not establish acceptance.

## Preserved attempts

- `precursor.zip`: `572036f9d6af2c3d48e957ea531974edeb137bc8`. Narrowed Q
  request metadata, borrowed completed deferred snapshots and moved borrowed
  classic packet preparation before suspension. Complete futures shrank 2,296
  bytes, but two selected native polling frames grew 16 bytes. Rejected before
  timing; no CPU result.
- `precursor2.zip`: `1705cbb27f7e3d2bd832410aacfe11aef4281e32`. Also moved
  retained classic encoding before suspension and borrowed its send metadata.
  Its helper future shrank from 1,504 to 648 bytes, but the complete future and
  failing native frames did not improve further. Rejected before timing.
- `precursor3.zip`: `5ef69ac78cdedd013cecb58f3b7a2b1aa8f0d824`.
  The body-access guard integration passed the memory preflight but was
  deliberately superseded before CPU measurement by a follow-up adding lazy
  Location initialization. No cohort ran, so this is neither a CPU failure nor
  an accepted optimization. Its decision must retain the supersession reason
  and `cohort_status: superseded-before-timing`; all previous failures stand.
  Its guard diagnostic is retained separately from the earlier constructor
  diagnostic, which compares `bf858124` rather than this guard source. Both
  strict Clippy lanes passed on the final precursor; the 1,228-test library run
  preceded one final test-only unpin assertion, which Clippy typechecked but did
  not execute. No final-source full-suite claim follows from that earlier run.
- A full `ParsedMessage` pointer was rejected during static review: it would
  require a user token to be `Sync` for a previously `Send` App. Its source patch
  and passing library log remain in `failed-cohort.zip`; passing tests alone did
  not establish that contract. The corrected nongeneric options-descriptor
  reference includes a public App compile assertion using a Send-but-not-Sync
  token.
- `failed-cohort.zip`: `b9985804ed1c31e44d461850e03a2080cb85099b`. The
  nongeneric descriptor reference passed memory checks: complete futures shrank
  2,320 bytes. Its full CPU cohort failed four workload confidence bounds.
  Aggregate async improvement did not override those failures.
- `failed-cohort2.zip`: `0ec8618cfac85929922ff2f96d70a7403be654ec`. Combined
  packet lifetimes with compact received-response metadata. Complete futures
  shrank 2,536 bytes; aggregate CPU ratios were 0.987398 sync and 0.986236 async.
  Three retained allocated confidence bounds failed: unprotected async
  1.023413, OSCORE sync 1.021069, OSCORE async 1.022096. Point estimates within
  2% do not establish the frozen noninferiority requirement. No adoption.
- `failed-cohort3.zip`: `717156e906b3449821b9bf66b997f3735dbee240`. Added
  direct full-block initialization to the preceding integration. Memory guards,
  1,222 library tests and prequalification Clippy passed. The complete CPU
  cohort still failed three upper bounds: ordinary fixed Service unprotected
  1,024-byte sync 1.022358 and async 1.034183, and retained allocated unprotected
  11,264-byte sync 1.021993. Aggregate ratios of 0.988755 sync and 0.989648 async
  do not override these failures. This candidate remains rejected; the Clippy
  result is not full qualification or optimization acceptance.
- `failed-cohort4.zip`: `bf8581249fbbb591067c46e85ef4c9dc19be120a`. Added
  direct retained-body/TX borrowing and its explicit storage capability. The
  instrumented eight-case diagnostic confirms zero block-TX staging; it is
  separate from the CPU cohort. Five CPU upper bounds failed: ordinary
  SmallDevice unprotected sync32 1.021361; allocated Service unprotected and
  OSCORE async1024 1.025467 and 1.025468; retained fixed OSCORE async11264
  1.020320; retained allocated unprotected sync11264 1.024478. Both strict Clippy
  configurations and the reused 1,228-test all-features result do not override
  these failures. The initial no-default failure and std-guard correction are
  retained. No final qualification or adoption.
- `failed-cohort5.zip`: `378515e10b0980a3deb0442d3aa1d7f152cb3d38`. Combined
  the admitted body-access guard with safe lazy Location initialization. Final
  constructor assembly records 320 to 80 explicit store bytes, and the separate
  instrumented eight-case diagnostic still records zero block-TX staging.
  Neither diagnostic establishes CPU acceptance. Memory guards, 1,229 library
  tests and both strict Clippy configurations passed, but eight CPU cell bounds
  failed: SmallDevice sync32 in both security modes; allocated Service
  unprotected sync1024; retained fixed unprotected sync and OSCORE sync/async;
  and retained allocated unprotected sync/async. The largest upper bound is
  1.042225 for retained fixed unprotected sync. All-workload ratios are 1.002848
  sync and 0.997076 async. This source remains rejected; no final qualification.
- `failed-cohort6.zip`: `97d0c9b03171993e67378e2be6d8992f8114bfa0`. Restored
  the staged-body implementation while retaining lazy Location initialization.
  Original retained-body staging remains; no zero-staging claim applies to this
  source. Its constructor comparison is pinned to `fd7d18a` and records 333 to
  80 explicit store bytes, separately from CPU measurements. Memory checks,
  1,223 library tests and both strict Clippy lanes passed. Three CPU upper bounds
  failed: allocated Service OSCORE async1024 1.032176, retained fixed unprotected
  sync11264 1.028107, and retained allocated unprotected sync11264 1.028889.
  Aggregate ratios 0.994461 sync and 0.993372 async do not override those failures.
  The initial restoration compiler failure and its exact patch/hash records are
  retained. A separate sidecar diagnostic found scalarized field access, not a
  688-byte BlockTransfer copy, in the inspected synchronous fixed/allocated
  deferred and selection paths; no implementation followed that disproved copy
  hypothesis. This source is rejected without final qualification.

Earlier response-ownership and replay/chunk experiments retain their original
rejections in their sibling evidence directories. Combining selected source
changes in a new measured integration does not reclassify an old result.

## Method and boundaries

The fixed cohort contains 20 ordinary cells and eight retained Q-Block2 cells.
Ordinary responses use SmallDevice 32-byte and Service 1,024/16,384-byte payloads;
retained transfers select eleven 1,024-byte packets from an 11,264-byte body.
Each storage/security/mode combination has 64 paired processes, with AB, BA, BA,
AB repeated sixteen times. Each process performs 128 warmups, then 8,192 measured
ordinary small/1,024-byte operations or 1,024 large/retained operations. No
trimming, replacement, early stopping or unchanged failed-cohort reruns.

The metric is Windows server-thread CPU cycles around complete memory-transport
App processing: synchronous poll or asynchronous wait/progress. Client setup,
authentication preparation and response verification are outside the clock.
The geometric mean weights each workload equally. One-sided 95% confidence
bounds use 64 paired log ratios and a conservative t(63) factor of 1.67. Every
cell and both original-20/all-28 sync/async aggregate upper bounds must be at
most 1.02. A CPU improvement claim additionally needs aggregate upper bounds
below 1. These are scoped noninferiority bounds, not proof of exact equivalence.

Memory checks keep all capacities, allocation counts, owner ledgers and whole
App ceilings. Both selected Service complete progress futures must shrink;
selected App/pool owners, other futures, native encoder/reclaim/polling frames
and Thumbv7EM owners must not grow. Resident App and external requested pool
heap are disjoint; nested payload/transport/security owners are not added again.
Future sizes and selected native frames remain separate observations, not a
whole-program peak-memory or stack-reservation claim. No network latency,
throughput, hardware, executor or equivalent-capability libcoap result is claimed.

## Matched configured capacities

- SmallDevice/Constrained ordinary: 4 routes, 1 Call, 0 deferred rows,
  4 security requests, 1 association, 2 RX and 2 TX datagrams of 1,152 bytes,
  4 dedup entries, 2 observations, no body pools.
- Service ordinary, fixed and allocated: 32 routes (1 populated), 4 Calls,
  8 deferred rows, 4 security requests, 1 association, 32 RX and 32 TX
  datagrams of 1,472 bytes, 64 dedup entries, 32 observations, 4 RX and 4 TX
  bodies of 16,384 bytes. Client capacities and separate timing/verification
  owners are retained in every ordinary raw output.
- Retained Q uses its original custom `Buffers` fixture: 1 route, 4 Calls,
  2 deferred rows, 4 security requests, 1 association, 4 RX and 4 TX datagrams
  of 1,472 bytes, 16 dedup entries, 1 observation, 2 RX and 2 TX bodies of
  12,288 bytes. It is not the Service profile. Each operation verifies all
  eleven selected payloads and asserts no allocations during request work.

## Verification and reconstruction

`python -B verify.py --failures-only` verifies the retained rejected and superseded attempts
without executing native code. The verifier checks archive SHA256 and every
member, source-manifest/patch coherence, baseline executable identity, fixture identity,
selected layouts/frames, capacity/owner ledgers, all process exits and every
paired ratio. It recomputes failures from the raw outputs.
An explicitly superseded precursor may have passed memory checks, but must
contain a reason and no cohort samples or process-exit log. It cannot establish
integration acceptance. The original two preflight rejections remain failures.

`prepare.py CORE_REPO NEW_OUTPUT VARIANT` reconstructs exact sources and probes
without modifying a checkout. Variants include baseline, candidate, precursor,
precursor2, precursor3 and failed-cohort through failed-cohort6. Reconstruction checks every
complete source-file hash: 148 for staged-body variants, 149 for the direct-body
variants including their new test module. Baseline membership stays fixed at 148;
added Rust inputs require complete creation patches and matching hashes.
Reconstruction requires the baseline commit in
CORE_REPO and an absent output directory. Use a compatible existing Cargo lane;
no private target directory is required. Native scripts and command records
retain the original Windows paths. Adapt paths only when replaying on another
host; keep toolchain, features, force-frame-pointers, fixtures, capacities and
cohort settings fixed. Matching source/input hashes does not promise identical
performance on another machine.

The prospective evidence-corpus budget is 160 MiB. Earlier rejected evidence
is retained unchanged when adding an untimed precursor or a final integration.
