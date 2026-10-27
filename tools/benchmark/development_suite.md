# Fixed development suite

Use this prepared-run screen during library iteration. Reliability checks run
before timing: independent exact/corrupt response checks, security refusal and
fresh recovery, then each profile's oversize/refusal/recovery checks. The native
client authenticates OSCORE and verifies complete bodies before completion.

Eight versioned configurations run GET/CON in unprotected and established volatile
OSCORE modes, with one populated route and one security association/four bindings:

- SmallDevice: fixed Constrained, 32 bytes, blockwise off, C1.
- SmallDevice blockwise: fixed Constrained, 4,096 bytes, one RX/TX body, C1.
- SmallDevice Observe: the same 4,096-byte blockwise pools, one Observe entry, C1.
- Device: fixed Default pools, 4,096 bytes, two RX/TX bodies, C2.
- Gateway: fixed Gateway pools, 8,192 bytes, two RX/TX bodies, C2.
- Service datagram: fixed Service pools, 1,024 bytes, blockwise/body pools off, C4.
- Service blockwise: fixed Service pools, 16,384 bytes, four RX/TX bodies, C4.
- Service allocated: the same Service capacities and 16,384-byte workload, C4.

`native_profiles.py` defines every route, Call, deferred, security, packet, body,
Observe and dedup capacity. C2/C4 use actual independent local UDP endpoints with
one shared client sequence owner, retaining NSTART=1 per endpoint. Reports must
prove distinct ports, actual simultaneous Calls, per-lane service and complete
body verification; a configured concurrency number alone cannot pass.

Observe has a separate real-UDP functional lifecycle proof at the exact small
blockwise/one-interest server bounds: registration, a changed complete notification,
deregistration, cancellation/release and fresh recovery. Both security modes must
pass before timing. Ordinary GET socket timing is not notification timing. Merely
reserving an Observe table is not evidence of Observe behavior.

Allocated Service requested core pools have a 282,640-byte ceiling; automatic
expansion is off. App sizes are observed separately. Six existing socket-free
`black_box` C1 core cells accompany sixteen native loopback cells. These core
probes remain separately scoped C1 supporting evidence even for Service rows
whose socket workload is C4. The ten core cells for other exact configurations
are explicitly unsupported; there is no substitution with a differently sized App.

Configuration/schema version 2 intentionally refuses comparisons with the
historical four-profile version 1. Its committed evidence remains unchanged.

## Prepare once per source/build

Use CPython3.11+ with psutil and the registered Cargo lane (Windows proof uses
CPython3.14 x64).
Sources must be committed and clean, Rust1.99 installed, and the companion's
actual `coaptic` dependency checkout selected intentionally. The expected core
must match that resolved checkout, including junctions; it is not inferred from
another editor worktree. Do not switch shared sources while a build is active.

```text
python -B tools/benchmark/development_suite.py prepare --build-lane coaptic-core-reusable --expected-core FULL_CORE_SHA --output NEW_PREPARED_DIRECTORY
python -B tools/benchmark/development_suite.py run --prepared PREPARED_DIRECTORY --output NEW_RUN.json
```

Preparation holds the existing resource lease, selects the source-specific lock
with `native_lock`, runs one locked release build of the four native binaries,
restores the canonical lock and verifies sources. It copies binaries and records
actual source trees, harness hashes, compiler/build inputs and executable hashes.
The actual pinned Cargo/rustc executables are recorded and invoked directly.
Executable paths come from Cargo's JSON artifact messages, never a guessed
`target/release` path. This initial build contract refuses ambient `CARGO_*`
overrides except Cargo home/target-directory/jobs/incremental settings, and refuses
Cargo build/target/profile/env configuration or compiler wrappers. Explicit
RUSTFLAGS/encoded Rust flags are recorded; permitted registry/network config files
are hashed and matched. This narrow contract prevents hidden configuration from
silently changing compared builds.
It refuses an existing output directory. Each binary is capped at128MiB and the
copied aggregate at256MiB; build output at16MiB and build execution at900seconds.
Use a budgeted existing disk, not a new Cargo target per revision.

Prepared receipts describe the source at build time. Later checkout changes do
not rewrite that provenance. Runs verify frozen copies and the running harness/
host; preparing another revision is explicit. These local build receipts are
auditable provenance, not cryptographic attestations against a malicious author.

## Compare revisions

Prepare both core revisions using the same committed harness, toolchain and
configuration. Keep the loopback client frozen from the first preparation:

```text
python -B tools/benchmark/development_suite.py run --prepared BEFORE_DIRECTORY --output BEFORE.json
python -B tools/benchmark/development_suite.py run --prepared AFTER_DIRECTORY --client-from BEFORE_DIRECTORY --output AFTER.json
python -B tools/benchmark/development_suite.py compare --before BEFORE.json --after AFTER.json --output NEW_COMPARISON.json
```

Comparison refuses failed/incomplete runs, differing hosts, complete companion
fixture trees, harness/build inputs,
client binaries or configurations. It reports descriptive socket/core medians and
App/requested-pool owners; no automatic baseline replacement or pass/fail speedup
claim. Keep the original #650 baseline separately from rolling development results.

## Bounds and interpretation

The prepared-run target remains about one minute for all eight configurations. A full result records actual total
duration and whether it met60seconds. Each reliability worker has a10second
deadline; later cells are explicitly NOT RUN after a failure or exhausted budget.
Output is bounded and never overwrites a prior result. A worker waits at a stdin
gate until assigned to a Windows kill-on-close Job Object or reserved Linux
process group. Timeout, output overflow, remaining descendants and unresolved
cleanup fail the run. This custody assumes the supplied cooperative workers;
Linux fixtures do not escape their inherited group/session.
After worker exit, Windows allows at most100ms for Job accounting to observe
natural exit; any benchmark/reliability member still active remains a fatal failure. Termination and
bounded exit observation still run independently. Nested helper temporary files
stay inside the owned task directory and are removed only after settlement;
unresolved custody retains that path with the primary failure.
Windows uses CPython's `_winapi` process adapter: create suspended, assign to a
Job Object capped at16active processes, then resume. Two bounded pipe-reader
threads belong to the harness, not the library. Unsupported custody is refused.

Setup/build are outside the prepared-run duration and retained in preparation.
After successful Cargo exit, preparation explicitly terminates any remaining
owned compiler auxiliaries (such as MSVC telemetry) and proves their exit before
validating or copying artifacts. The preparation receipt records this action;
cleanup failure is fatal. This policy does not apply to benchmark workers.
Socket receipts separate server startup, combined client startup/warmup, resource
window and cleanup; core process startup/warmup/calibration are not separately
instrumented. Core128warmups and4096calibrations remain visible; calibration is
never subtracted. Client/warmup and verification costs are not server savings.

Small samples are regression signals, not qualified CPU savings, reliable p99,
saturation throughput, physical-device timing or peak RAM. App inline, requested
pools, representation and harness storage remain distinct; nested scratch is not
added twice. Stack/allocator/runtime/kernel unknowns remain unknown. The full
Linux CPU/latency acceptance and optional eBPF controls keep their original gates.
Criterion belongs in optional selected hot-path comparisons; it is not needed
to replace this complete-operation fixture or production dependencies.
