# Current Windows comparison — October 23, 2026

Open [the interactive report](report.html) for all 90 workload views. Download
[the ranking CSV](rankings.csv) or inspect [the dataset](rankings.json).

Five rotated windows verified **348,000 complete operations** in 2,610 cells,
with no failed operations, failed warmups or invalid/unaccounted cells. They
validated 1,040,547,840 response bytes. The grid covers 64/1024/65536-byte
responses, concurrency 1/4/16, CON/NON, unprotected UDP, established OSCORE,
DTLS test adapters, and separate warm/cold HTTP/3.

For native unprotected 64-byte CON at concurrency one, Coaptic reusable reaches
58,855 operations/s, bare 55,281, Mio 38,621 and async 34,170. Competitors in the
same stratum: libcoap 35,511, coap-rs 19,494, go-coap 18,202 and aiocoap 6,029.
The narrower coap-lite codec endpoint reaches 35,789.

For the common Python OSCORE client, Coaptic bare reaches 6,955/s, reusable
6,825, Mio 5,985 and async 5,678; libcoap reaches 4,081 and aiocoap 1,971.
The separate Go DTLS client reports libcoap 17,565, Coaptic test adapter
14,546, go-coap 13,642 and coap-rs test adapter 12,131. HTTP/3 warm TLS is a
separate 6,829/s reference. Compare within a client/security stratum only.

These are descriptive medians on one shared Windows host, not universal
rankings or saturation results. Bare/reusable Coaptic variants busy-poll;
Mio/async wait for readiness. At least one of four named Coaptic configurations
has the largest full-stack median in each of 54 direct-UDP views; that is a
family observation, not one configuration winning every case. The DTLS test
adapter trails the fastest competitor in 16 of 18 views.

## Sources and measurement

Core: `b9b83d8663cbdcb7a80bf143670a05019f25cf25` (clean).
Companion: `c123d8b4da0f88469a2c9692c48310cf3354163f`, with four disclosed
unrelated probe-only edits; selected server/load binaries and campaign code do
not compile or import those edits. They are now saved separately in draft
[PR #170](https://github.com/jeffglousher/coaptic-validation/pull/170).
The later core dependency update is outside this measurement.

Host: Ryzen 7 5800X3D, 8 physical/16 logical CPUs, Windows 11, approximately
32 GiB RAM. Rust 1.99.0 release, thin LTO, one codegen unit, debug off,
incremental off and two build jobs. Go 1.26.9. Pinned competitors are
libcoap 4.3.5b at `851533c3` with MbedTLS 3.6.7, go-coap 3.5.4,
coap-rs 0.28.1, coap-lite 0.13.3, aiocoap 0.4.16 and quic-go 0.63.0.
These are supplied fixtures, not a claim of latest releases or best tuning.

Each window uses 256/128/16 operations for 64/1024/65536-byte responses,
one warmup per worker, one-second operation deadlines, seed 20261023,
and at least 60 seconds between same-stratum windows. Timed activity spans
13:49:09–14:13:20 UTC. Rates are medians of five complete-window verified
operation rates; latencies pool successful samples and use linear interpolation
at `(N-1)*p`. Paired session log-ratio intervals use 2,000 bootstrap resamples.
All failures are retained; no timing cells were replaced or retried.

Independent validation performed 16,817 assertions. All 76 separate
socket-boundary capture cases passed: 36 unprotected byte/range grades,
24 independently authenticated OSCORE grades and 16 offline DTLS framing
grades. DTLS representations were authenticated online. These captures are
UDP payloads at the socket boundary, not kernel/NIC packet capture.

The [raw cell archive](cells.jsonl.gz) preserves every receipt field and latency
sample. Run `python regrade.py` here to reproduce totals and ranking medians.
Use the pinned suite's `campaign.py`, `prepare.py` and benchmark guide for a
new campaign; [sources](sources.json), [build identities](build.json), and
[publication transformations](publication.json) identify this one. The exact
private originals, plans, orchestration scripts and hashes remain retained.

## Limits and current work

CPU snapshots include driver startup/warmup/exit and have coarse Windows
resolution. RSS is the largest retained current process-tree snapshot, not
peak or whole-system memory. Shared pages may overlap. Established volatile
OSCORE excludes EDHOC setup, durable checkpoints and commissioning.
The optional idle probe failed protected readiness before measurement;
it supplies no completed protected idle qualification.

Prior Linux CPU evidence is kept separately in [cost-evidence.json](cost-evidence.json).
System CPU charge includes required socket and scheduling work; it is not a
function breakdown or blocked time. Earlier sparse profiles do not establish
stage shares. **Both 50% server CPU targets remain open under core issue #650.**

The next isolated server-App CPU probe is saved as unqualified draft PR #170.
It needs fresh combined review, native Rust checks and finite Linux ownership,
clock and cleanup qualification. No new profiler or recurring monitor is active.
