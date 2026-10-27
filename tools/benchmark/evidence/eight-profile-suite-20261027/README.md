# Eight fixed profiles: Windows development proof

The complete prepared suite passes in **14.268 and 14.231 seconds** on Windows
11 build 26200, AMD64 Family 25 Model 33, 16 logical CPUs. Preparation took
**96.661 and 98.085 seconds**, separately; build time was 95.727 and 97.336 seconds.
These are two selected source revisions, not repeated statistical trials.
The [receipt](receipt.json) records exact capacities, sources, locks, actual binary
hashes, measured arrays, phase durations, endpoint evidence and memory owners.

Tested companion: `cc6edfbd299f37be61da8bac85866b36f1c66a1c`.
Before core: `b9b83d8663cbdcb7a80bf143670a05019f25cf25`.
After core: `f4810d7adc8624d065620af476417130807d7574`.
Both copied four-binary bundles and inputs were frozen before any cells. The
before-built loopback client is identical for both runs. CPython 3.14.4,
psutil 7.0.0, locked Rust/Cargo 1.99.0, x86_64-pc-windows-msvc release;
core features std/alloc/oscore, defaults off, thin LTO, one codegen unit,
incremental off, two build jobs, no explicit Rust flags. This demonstrates
revision comparison; it does not nominate a new library optimization.

## Product coverage

All eight fixed configurations run unprotected and established volatile OSCORE:

- SmallDevice/Constrained, 32 bytes, blockwise/body pools off, C1.
- SmallDevice blockwise, 4,096 bytes, one RX/TX body, C1.
- SmallDevice blockwise/Observe, the same body bounds, one Observe entry, C1.
- Device/Default fixed, 4,096 bytes, two RX/TX bodies, C2.
- Gateway fixed, 8,192 bytes, two RX/TX bodies, C2.
- Service fixed datagram, 1,024 bytes, blockwise/body pools off, C4.
- Service fixed blockwise, 16,384 bytes, four RX/TX bodies, C4.
- Service allocated, identical Service capacities and 16,384-byte workload, C4.

The receipt preserves every route, Call, deferred, security, packet, body, dedup
and Observe dimension. These are distinct implementer choices; unequal resource
budgets are never compared as optimization gains. Automatic pool growth is off.

Each run passes nine reliability phases before timing: independent exact-body,
corruption/security refusal and fresh recovery, then profile-specific oversized
input, client refusal and recovery. **Sixteen socket cells verify 512 measured
operations plus 64 warmups, zero failures.** Device/Gateway C2 and Service C4 use
distinct actual local UDP ports, observed concurrent Calls and verified service
on every lane. One crypto sequence owner and NSTART=1 per endpoint are preserved.
This short overlap proof does not establish saturation, fairness or every server
resource boundary.

Two additional real-UDP Observe proofs each verify six complete 4,096-byte
representations: registration, a changed CON notification consumed through the
same Call, deregistration reply, fresh GET, recovery registration and final
deregistration reply. Each mode verifies 24,576 body bytes, two no-send Call
refusals, explicit remote deregistration and recovery. The local-cancellation
case deliberately reads/discards exactly one undelivered registration before
server dispatch; it does not prove reversal of a delivered remote registration
or server Observe-table overflow. The client App authenticates all protected
fragments; the packet guard checks the exact Observe-dependent outer code.
Ordinary GET timing is not notification timing.

Six separate socket-free `black_box` C1 supporting cells verify 96 measured plus
768 warmup operations per run; 24,576 separate calibrations are never subtracted.
These cover Small32 and fixed/allocated Service only. **Ten other exact core
cells are explicitly unsupported**, including SmallDevice blockwise/Observe,
Device, Gateway and Service datagram. They are not replaced by different Apps.

## Memory and limits

Mio App owners match across the selected revisions, in the profile order above:
14,032 / 27,760 / 27,112 / 57,192 / 96,312 / 174,088 / 314,872 / 34,752 bytes.
These include their 2,072-byte adapters, nested scratch and fixed pools. Requested
core pool heap is zero for fixed profiles and 282,640 bytes for allocated Service.
Representation backing is separate: 32 static bytes for SmallDevice; the selected
payload size in heap for the other socket fixtures, including Service datagram.
Poll (8 bytes), Events header (40 bytes) and capacity-eight backing are separate.
Events backing, allocator overhead, initialization, generated peak stack, runtime
and kernel owners remain unresolved. Do not add nested buffers twice or interpret
fixed pool heap zero as whole-process heap zero.

The separate Observe proof has a 26,584-byte server App and 9,784-byte client App,
each including its 1,544-byte transport. Server requested pool heap is zero;
client requested pool heap is 13,746 bytes. Two separate static representations
total 8,192 bytes; the receipt names cancellation scratch, counters and remaining
unknowns. These are different fixture owners from the timed Mio App.

Each prepared bundle contains 9,697,280 binary bytes. Preparation caps each binary
and the aggregate at 32 MiB; a revision pair is capped at 64 MiB. Builds have
900-second/16-MiB output bounds. Runtime ownership, output, timeout and cleanup
guards remain fatal. Both preparations settled compiler auxiliaries before
accepting artifacts. Canonical lock and initial resolved b9 checkout were restored.

## Validation and retained failures

Python: **257 tests run, 248 passed, 9 platform skips**. Native: **123 passes per
core**: 17 current Observe tests (including the real protected/unprotected
lifecycle), plus 106 unchanged core/client/server tests reused from prior valid
receipts. Formatting and strict release all-target Clippy pass on both cores.
Real Linux execution of this suite ownership wrapper remains unverified.

The first author check stopped on a 1.99.1 Clippy-driver / pinned 1.99.0 metadata
mismatch, before suite cells. Pinning the author check's Rustup toolchain resolved
it without changing source or dependencies. The first paired attempt then passed
all reliability phases and unprotected Observe but failed protected registration:
the new proof guard incorrectly required POST/Changed even when Observe was
present. Both cores correctly use FETCH/Content for that case. The guard was
repaired and positive/negative outer-code plus full-lifecycle regressions added.
All sixteen timing cells in that failed attempt remain NOT RUN; it is neither
erased nor pooled into the corrected proof.

See the [guide](../../development_suite.md) for prepare/run/compare commands.
Prepare both clean revisions with the same committed companion; run the after
bundle with `--client-from BEFORE_DIRECTORY`. Configuration version 2 intentionally
refuses historical four-profile version-1 comparisons. Rebuilds may produce new
hashes; freeze actual executable/input identities before measurement. Public data
omits private paths/hostname and replaces only calibration arrays with exact
count/statistics/JSON-array hashes; the original local results remain retained.

Short wall-time medians move in both directions and are descriptive regression
signals. **No qualified CPU, extreme-tail, throughput, physical-device or
whole-memory claim follows. Both 50% CPU targets remain OPEN.** Existing Linux
CPU/latency gates and all failed cohorts remain unchanged. eBPF stays an optional
separate diagnostic, and Criterion is reserved for a nominated isolated cost.
