# Completed speed investigation: host, CPU and ESP32 Wi-Fi

This package preserves the 7 November 2026 host refresh and subsequent completed
CPU/native comparisons through 9 November UTC. It adopts
**no new optimization** and does not establish the goal of beating pinned libcoap
in both actual synchronous and asynchronous ESP32 operation. Unmeasured follow-up
images and their pending startup qualification are outside this package.

The accepted core baseline is `a85c51e689607051e36e450567fe051f8f85dc2b`.
The suite baseline is `e602a261fac18d839e92def713ae410f7c78d15d`.
Each CPU candidate and native source is named inside its dataset and source patch.
The native source is `c0151713fc187a4a2b8ed3cba1eb0b12df597d00`, with runtime
`32f8fcac22fc16b1957c35f4f145df6be3a72532`. Its host expansion matches the
accepted baseline; retained host timings are not invented new timings for it.

## Regrade without running a benchmark

Use Python 3.10 or newer from this directory:

```sh
python -B verify.py
python -B test_export.py
```

The verifier checks every compressed-file digest, every included source patch,
the source fixture/input hashes, all 64 CPU process pairs in all 28 cells for each
of eight candidates, the whole
252-cell host grid, and every operation in both complete Wi-Fi screens. It
recomputes aggregate ratios, all CPU confidence bounds, Wi-Fi cell medians and
both boot-order comparisons. Exact integer cycle sums/counts are retained; floating
regrades use relative tolerance 1e-12 and absolute tolerance 1e-9. No executable, network, firmware, private
configuration, API connection or device action is involved.

The checked-in verification result records the complete result of this regrade.
A passing verifier confirms the retained comparisons, including their failures;
it does not turn them into accepted optimizations.

## Host: seven implementations

The accepted-source host cohort completed **564,480 verified operations**, with
zero failures: seven implementations, four body sizes (64/1,024/16,384/65,536
bytes), three concurrency levels (1/16/64), and three rounds, giving 252 cells.
All complete-operation latency samples are included in `host.json.gz`.

| Implementation | Geometric goodput / libcoap |
| --- | ---: |
| Coaptic spin | 1.4900 |
| Coaptic Mio | 1.2962 |
| Coaptic async | 1.1197 |
| coap-rs | 0.9465 |
| libcoap | 1.0000 |
| Go plgd/coap | 0.5265 |
| Python aiocoap | 0.0963 |

These are geometric goodput ratios across the declared matched cell mix, not
isolated CPU cost or a universal language ranking. Spin consumes a busy core
while idle. At 64 bytes and concurrency one, async goodput is almost tied with C
and async latency is worse. The dataset retains all cells and resource snapshots;
post-load process memory is not library memory or a peak-memory requirement.

## CPU: eight rejected source integrations

Each complete Windows thread-cycle cohort has 28 cells, 64 paired processes per
cell, 3,584 measured processes and 56 qualification processes. Together they cover
117,440,512 measured App operations, plus separate qualification operations.
Actual sync/native async, unprotected/established OSCORE and fixed/allocated
storage remain separate cells. Client work is outside the server-App clocks;
fixture copies, clock-call overhead, dispatch, maintenance and crypto remain in
scope. Empty/calibration cost is not subtracted.

| Candidate | Sync cost change | Async cost change | Failed cell bounds /28 |
| --- | ---: | ---: | ---: |
| Body borrowing and terminal snapshot | -0.22% | +0.36% | 4 |
| Terminal snapshot only | +0.75% | +0.52% | 9 |
| Broad poll boundaries | -0.16% | +9.19% | 14 |
| Cold poll boundaries | -0.01% | +0.55% | 5 |
| Compact expiry reasons | -0.29% | +0.29% | 7 |
| Packet views and path filling | -0.53% | -0.67% | 2 |
| Borrowed handler input | -0.79% | -0.98% | 2 |
| In-place request context | -1.44% | -1.18% | 1 |

Ratios compare each candidate with the same pinned Rust baseline, not libcoap.
The frozen interval uses log process-pair ratios and a one-sided multiplier 1.67
on 64 pairs. The preservation limit is 1.02, applied to every cell and declared
ordinary/all aggregate. No family-wise confidence claim is made. Aggregate gains
never replace a failed cell, and no process or observation was trimmed/replaced.

For the final in-place request-context integration, the retained fixed,
unprotected synchronous cell has a 1.59% higher point estimate and upper95 bound
1.03137, above 1.02. The source remains unadopted even though its aggregate
ratios improve. The candidate's selected complete future stays 13,448 bytes;
local constructor/route/dispatch frames are separate observations, not peak RAM.

### Exact sufficient statistics, with explicit limits

Every original process is represented by its **exact integer cycle sum and sample
count**, its minimum/maximum, original report digest, exit result, qualification
flags, populated route counts, send counts/limits and numeric capacity/memory fields. Those are sufficient to reproduce every
process mean, all 64-pair ratios, aggregate ratios and acceptance bounds exactly.
They preserve all statistical units and all 117,440,512 operations in their sums.

Individual operation cycle vectors, calibration arrays and full producer reports
remain in the private retained corpus. This compact package cannot reconstruct
those full reports and makes no per-operation CPU-tail or calibration-distribution
claim. It does not independently attest CPU affinity, source execution or physical
hardware behavior. Those remain producer attestations tied to original digests.

## ESP32-S3: two complete Wi-Fi screens

Host Ethernet through the access point to ESP32-S3 Wi-Fi is inside these timings.
RSSI and boot variation are observations, not removal of Wi-Fi effects. Both
actual Rust server modes run against both Windows client modes in opposite boot
orders. Every included operation verifies the complete 32-byte identity, 7-byte
test response or 2,000-byte Block2 representation.

| Closed screen | Reads | Boots | Result |
| --- | ---: | ---: | --- |
| Hot packet placement | 1,536 | 16 | Selected sync/async ratios versus strongest C: 1.04694 /1.16078; all candidates fail promotion |
| Larger pipeline/cache16 | 1,152 | 12 | Sync 0.91852 but two cells fail; async cache16 1.55056; both profiles unadopted |

These are separate cohorts. Their observations are never pooled, and a ratio
change between screens is not an isolated implementation effect. Fresh
contemporaneous Rust controls remain inside each screen.

In the latest screen, sync is 8.15% lower in aggregate latency than the strict
best-C reference and 6.09% lower than its prior Rust control, using 4.5 KiB more
physical static SRAM. Two async-client small-response cells are 2.0-2.5% slower
than C, so the frozen all-six-cell gate fails. Both boot aggregate comparisons
against each C control pass.

The async cache16 integration is 55.06% slower than C and 10.94% slower than its
prior Rust control despite saving 2 KiB. It is rejected. Cache size and placement
changed together; no isolated cache-miss cause follows.

Both screens report zero client failures, repeated CoAP request sends,
unexpected API disconnects, connection refusals, Rust drops or wait errors.
Latest reported RSSI is -45 to -42 dBm. Normal firmware restoration is recorded
as verified by each producer. Raw API/identity witnesses remain private; the
portable verifier checks the exported attestations and timing records, not a
physical device. Two boots per profile do not establish RF/long-duration stability
or qualified tails.

### Capacities and memory scope

Rust uses Constrained storage: eight routes (seven populated including discovery),
four Calls, no deferred rows, two 1,152-byte datagrams in each direction, one
4,096-byte body in each direction, four dedup entries, two Observe entries and
an eight-byte token. Reserved Rust workers stay 96 KiB sync and 192 KiB async;
C reserves 16 KiB. Selected source and profile variants retain supported features.

C uses dynamic PDU/session allocation while matching this static unprotected
GET/CON-C1/Block2 workload. This is not equivalent whole-library feature,
capacity, security or memory support. Static SRAM, heap snapshots, instruction
cache reservations, stack reservations and observed lifetime stack use overlap
owners and must not be added twice. Lifetime stack samples include startup and
are not proven peaks or minimum reservations. C cleanup heap and Rust running
heap are different phases.

## Source reconstruction and export

`manifest.json` lists core/suite patches against public baseline revisions with
expected target Git tree IDs. These are retained unadopted source trees, not
changes installed by this package. To reconstruct a source tree in your own
checkout, check out its named baseline, decompress its patch, apply it with
`git apply --index`, then compare `git write-tree` with the recorded tree ID.
Do not apply it to a working tree containing unrelated changes.

All eleven patches were independently applied to their baselines using isolated
Git indexes and matched the recorded target tree IDs; `source-reconstruction.json`
records that producer check. The offline verifier checks patch bytes, not Git tree
reconstruction or source execution.

`sources/host-inputs.json.gz` identifies all 181 source inputs for each arm of
each CPU cohort. `sources/request-context-fixture.json.gz` contains 41 exact
non-core source/lock files for the last dc1/35bac fixture. One additional file's
body is omitted because its tests contain private network address literals; its
original digest remains. This snapshot does not claim to represent every earlier
fixture. All 42 originals remain privately retained.

`sources/method-provenance.json.gz` preserves frozen limits, compiler preflight,
selected host compiler/peer versions and their original method hashes. Private
commands, log paths and endpoint descriptions are omitted. Recreating measured
binaries still requires matching Windows/Xtensa toolchains, dependencies, locks,
repository fixtures and the privately retained native archive/build provenance;
this package is not a self-contained toolchain or complete firmware rebuild kit.
Native hardware reruns require your own configured device and credentials;
this package deliberately provides no enrolled state or ready-to-flash image.

`export.py` accepts explicit native/host roots and source repositories. It reads
completed reports and the captured private fixture snapshot only, uses allowlists,
checks original report hashes and refuses an existing export. Its only output is the declared destination.

```sh
python -B export.py --native-root NATIVE_ROOT --host-root HOST_ROOT --core-repo CORE_REPO --suite-repo SUITE_REPO --fixture-snapshot CAPTURED_FIXTURE_DIRECTORY --destination EMPTY_EVIDENCE_DIRECTORY
```

No MAC/IP, user paths, board/session IDs, credentials, NVS, raw API, YAML,
firmware, ELF, current private report, pending images or new measurements are
published. The entire added evidence/export area has a 64 MiB budget. Originals
and all failures remain privately retained; this package neither deletes them
nor advances the open performance goal.
