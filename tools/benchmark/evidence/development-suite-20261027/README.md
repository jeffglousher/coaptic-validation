# Fixed development suite: Windows functional proof

Two complete prepared revision runs pass in **8.026 and 7.857 seconds** on
Windows 11 build 26200, AMD64 Family 25 Model 33, 16 logical CPUs. CPython 3.14.4,
psutil 7.0.0 and Rust/Cargo 1.99.0; native x86_64-pc-windows-msvc release,
thin LTO, one codegen unit, incremental off, two build jobs. No explicit Rust flags.
The [receipt](receipt.json) preserves fixed capacities, actual binary/input hashes,
raw measured arrays, phase durations, owners and descriptive comparisons.

Tested companion source: `a5cba800ee8345498a8d9645a7a2febc1916a6ee`.
Before core: `b9b83d8663cbdcb7a80bf143670a05019f25cf25`.
After core: `f664b09cc6c5740b606ac7f9c4dcbd3185851955`.
This demonstrates revision comparison; it does not nominate a new optimization.
The baseline-built loopback client is identical in both runs. Both selected locks,
resolved dependency sources and Cargo-reported executable paths were checked.

Each run passes five reliability phases before timing: independent full-body
corruption/security refusal/fresh recovery, then each profile's oversized-input,
client refusal and recovery checks. Eight loopback cells cover four profiles in
unprotected and volatile established OSCORE modes, C1 GET/CON: fixed SmallDevice32,
configured SmallDevice blockwise4096, Service fixed16384 and allocated Service16384.
There are **256 measured socket operations plus 32 warmups per run**, zero failures.
Six socket-free black_box cells verify **96 measured plus 768 warmup operations**
per run; 24,576 separate clock calibrations are never subtracted. Two SmallDevice
blockwise core cells are explicitly unsupported. This C1 screen does not prove
multi-client saturation, fairness or every resource-capacity boundary.

The native Mio App owners match across these revisions: 14,032 / 27,760 /
314,872 / 34,752 bytes respectively. Requested core pool heap is zero for fixed
profiles and 282,640 bytes for allocated Service. Representation backing is a
separate owner (32 static bytes for SmallDevice, and 4,096 or 16,384 heap bytes
for blockwise socket fixtures); scratch and fixed pools already nest inside App.
Core probe transports/owners differ and are recorded separately. Allocator,
Events/runtime/kernel and generated peak-stack costs remain unresolved; this is
not whole-memory acceptance. Configured capacities never change between labels.

Preparation took **1.924 seconds cached** for before and **85.714 seconds** for
after, separately from warm runs. Earlier successful Cargo builds failed strict
Job settlement; their evidence is retained. A bounded tiny Rust link identified an
owned `vctip.exe` compiler telemetry helper surviving the link. Preparation now
explicitly stops and proves exit of compiler auxiliaries after successful Cargo
exit and before accepting artifacts; this happened in the after preparation.
Benchmark/reliability workers still fail if descendants survive. Both preparations
restore the canonical lock; the dependency checkout is restored to its initial b9.

Python validation: **248 tests run, 239 passed, 9 platform skips**. Real Windows
Job assignment-before-resume, output/timeout limits, descendant termination and
cleanup refusal tests pass. Earlier preparation failures and the earlier successful
single-source warm run remain separate; none is erased or pooled into this proof.
Real Linux execution of the new suite process wrapper remains unverified.

See the [guide](../../development_suite.md) for the prepare/run/compare commands.
Prepare both selected clean core revisions from the same committed companion,
then run the after bundle with `--client-from BEFORE_DIRECTORY`. The receipt records
build-time provenance; rebuilding may produce different binary hashes, which must
be captured before running. Full local result hashes identify the retained originals;
this public receipt omits private paths/hostname and replaces calibration arrays
with their counts/statistics/hashes. Raw measured timing arrays remain included.

The socket and core medians move in both directions. These tiny samples provide
regression signals, with no gain/regression acceptance verdict. Existing Linux CPU,
eligibility and latency gates are unchanged; both 50% CPU targets and whole-memory
acceptance remain OPEN. eBPF is an optional separate diagnostic; Criterion remains
optional for a nominated isolated cost. No historic failed cohort was rerun here.
