# Packet staging and request metadata, November 4, 2026

The integrated batch reduces complete server App thread cycles by 5.06% in
synchronous execution and 4.40% in actual asynchronous execution across the
declared 28-cell mix. It reuses metadata from the existing request-option
validation walk and seals OSCORE plaintext directly in the final packet tail.
Configured capacities, security and retained-packet transactions are preserved.
The initial direct-sealing-only comparison failed; its observations remain here.

Baseline: `36f9c55635b6a53a7db4c95b9d99624095895124` (core #740).
Measured integrated source: `f84f3c199763910e246d8599aca0e29077a73ad1`.
The later `d828163da9a7f1869434b053d194fb21cfa8bd42` adds only repeated-Size1
oracle cases; production source is identical. Patches reconstruct the measured
sources after squash merge. The baseline executables are reused from the previous
batch's `d2d4484cc5c6beb66856511e6d86ce75ce3cefd2`: its production source and
probe inputs match #740, whose only subsequent differences were documentation.

## Runtime and scope

All-workload sync ratio is 0.9493599274, one-sided 95% upper ratio 0.9653095449;
async is 0.9560346921, upper 0.9617326318. Original 20 ordinary controls separately
pass: sync 0.9420083197 / upper 0.9644730991; async 0.9522404906 / upper 0.9578390652.
Retained Q-Block groups: sync 0.9679909353 / upper 0.9786347450; async 0.9655864687 /
upper 0.9777006912. Every individual point ratio is at most 1.02. This last rule
is a point guard, not a confidence-bound non-regression claim for every workload.

Both sources used the same frozen method: four process pairs in AB, BA, BA, AB
order, equal workload weights within each pair, Student-t df3 intervals over
paired log ratios, no trimming, calibration subtraction or replacement samples.
Acceptance requires upper bounds below parity for both sync and async in both
the ordinary-20 and all-28 groups, plus every cell point ratio at most 1.02.
Each cohort has 56 qualifiers and 224 measured processes. Short ordinary cells
use 8,192 operations, large ordinary and retained cells 1,024; all have 128 warmups.

The exact unchanged fixture, lock and manifest live in
[`../dispatch-scratch-20261104/fixture`](../dispatch-scratch-20261104/fixture).
Windows x86_64 MSVC, Ryzen 7 5800X3D, rustc 1.99.1 (`58cf8f9c3`, LLVM 23.1.1),
release thin LTO, one codegen unit, debug1, `-Cforce-frame-pointers=yes`, two build
jobs, incremental off. CPU0 affinity is inherited and restored; no concurrent
build ran during measurement. These execution controls are producer-attested.
Dependency features are `std,alloc,oscore`; diagnostics are disabled.

`QueryThreadCycleTime` surrounds the complete server App drive, including fixture
receive/send copies, dispatch, maintenance, blockwise and crypto work. Client
preparation, bridging, authentication and verification occur outside the counter.
Async calls `wait_async` and `progress_async`/`progress_with_async` with immediately
ready in-memory transport, a pending timer and manual root polling. These are
complete App CPU-cycle comparisons, not socket, executor latency, elapsed-time,
throughput, device or universal traffic claims. Calibration arrays remain raw.

## Workloads and owners

- SmallDevice: Constrained, routes4/populated1, Calls1/deferred0, association1/
  bindings4, RX/TX2x1152, dedup4, Observe2, no bodies; 32-byte response.
- Ordinary Service fixed/allocated: routes32/populated1, Calls4/deferred8,
  association1/bindings4, RX/TX32x1472, dedup64, Observe32,
  RX/TX bodies4x16384; 1,024-byte response or complete 16,384-byte Block2.
- Retained Q-Block fixed/allocated: routes1, Calls4/deferred2, association1/
  bindings4, RX/TX4x1472, dedup16, Observe1, RX/TX bodies2x12288.
  An 11,264-byte operation uses two requests and 11 verified data packets;
  RX/body occupancy returns to zero. Allocation guards surround App work.

Every profile runs unprotected and established OSCORE, sync and async. Raw
qualifiers retain exact paired server/client capacities, inline App and requested
pool-heap ledgers. These remain equal; no capacity reduction funds the result.
Nested owners are not added twice. See `memory.json` for separate future, emitted
stack-frame and executable accounting, including the refusal-path tradeoff.

The complete selected release Constrained progress future grows from 15,952 to
15,984 bytes (+32). The successful response's selected emitted frame chain
shrinks from 1,608 to 536 bytes (-1,072, counting the new nested call return),
while the staged-refusal chain grows to 1,784 bytes (+176). The seal helper
restores its frame before tail-jumping to the fallback, so those two frames are
not added. These named frame reservations exclude surrounding and crypto/encoder
callees and are not a measured peak. The complete host probe executable shrinks
from 2,734,080 to 2,729,984 bytes (-4,096). This establishes a scoped successful
path scratch reduction, not a universal or whole-system memory reduction.

## Mechanisms and failures

The ordinary one-Uri-Path GET path previously rewalked options seven times for
absent block metadata and Q-selection checks after the validation walk. Reusing
its results removes those walks and later Observe-presence lookups. This is a
source-path count, not sampled CPU attribution. No extra persistent cache exists.

Direct sealing removes the successful path's 1,280-byte plaintext staging buffer,
its zero initialization and ciphertext-to-packet copy. The original staged
encoder remains a cold fallback so capacity/error precedence, nonce consumption
and binding admission retain their behavior. Refusals can do extra encoding work
and use more selected stack-frame storage. Error-buffer contents may differ,
including partial plaintext; callers must honor Err. App TX lengths commit only
on success, and occupied TX replacement remains transactional. This change does
not promise zeroization. Crypto algorithms, authentication and replay policy are
unchanged. Differential checks compare success bytes and refusal results across
output and inner-message boundaries, not buffer contents on error.

`staging/` in `observations.zip` preserves the first direct-sealing-only source
`4ca4057`: ordinary-sync upper ratio 1.0006156789 fails the benefit guard; two
unprotected async point ratios (SmallDevice 1.0261061157 and retained allocated
1.0268657900) exceed 1.02. It remains failed, with no unchanged resampling.
`integrated/` contains the distinct metadata-reuse source and its passing cohort.
The combined gain is not attributed separately to either mechanism. An initial
premeasurement type-inference compilation failure is also retained.

## Verification and reproduction

`python verify.py` and `python verify.py staging` use only the standard library.
They hash every archived original byte and fixture input, verify capacities,
operation counts and raw process means, and independently recompute all 28 cell
and nine group statistics and the respective pass/fail decisions. The scripts
never execute a probe or replace samples. Outside JSON files are exact convenient
copies of the archived method/result records.

Materialize inputs with `python prepare.py CORE_REPO NEW_DIRECTORY integrated`
(or `baseline` / `staging`). It archives the pinned baseline and applies the
selected patch, without creating a Git worktree or changing the source repo.
Use an existing compatible target lane and the environment above. In `probe/`:

```text
cargo build --locked --offline --release --bin dispatch-probe
cargo build --locked --offline --release --bin retained-probe --features oscore,alloc
```

Copy executables between builds. The ordinary binary must not enable local
probe features: dependency features are already fixed in the manifest. To make
a new comparison, extract the original `integrated/measure.py` into a fresh
directory, supply its `B/` binaries and edit only its two baseline binary paths
to your reconstructed baseline. Python `psutil` is required. The script refuses
to overwrite `measurement.json`, pins/restores affinity and records executable
hashes. Paths/toolchains can change binary hashes; new observations never replace
these retained results.

Checks and the general read-only code review are recorded in `checks.json`.
Original executables/PDBs and sources remain under
`D:/CoapticCurrent/oscore-packet-staging-20261104` (64 MiB cap); baseline binaries
remain in the previous owned 128 MiB evidence root. This export has an 8 MiB
budget, owned by agent `26ae589e-9989-4d42-abf3-4dcc0c960925` for this companion
project, retained as reproducible evidence. Shared compiler lanes are preserved.
