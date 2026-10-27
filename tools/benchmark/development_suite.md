# Fixed development suite

Use this prepared-run screen during library iteration. Reliability checks run
before timing: independent exact/corrupt response checks, security refusal and
fresh recovery, then each profile's oversize/refusal/recovery checks. The native
client authenticates OSCORE and verifies complete bodies before completion.

Four unchanged configurations run C1 GET/CON in unprotected and established
volatile OSCORE modes: SmallDevice32, SmallDevice blockwise4096, Service fixed16KiB,
and the allocated Service equivalent. `native_profiles.py` defines every capacity.
Allocated Service requested core pools have a 282,640-byte ceiling; automatic
expansion is off. App sizes are observed separately, not hidden by pool changes.
Six existing socket-free `black_box` core cells accompany eight native loopback
cells. The two SmallDevice-blockwise core cells are explicitly unsupported.

## Prepare once per source/build

Use the existing Python environment with psutil and the registered Cargo lane.
Sources must be committed and clean, Rust1.99 installed, and the companion's
actual `coaptic` dependency checkout selected intentionally. The expected core
must match that resolved checkout, including junctions; it is not inferred from
another editor worktree. Do not switch shared sources while a build is active.

```text
python -B tools/benchmark/development_suite.py prepare --build-lane coaptic-core-reusable --expected-core FULL_CORE_SHA --output NEW_PREPARED_DIRECTORY
python -B tools/benchmark/development_suite.py run --prepared PREPARED_DIRECTORY --output NEW_RUN.json
```

Preparation holds the existing resource lease, selects the source-specific lock
with `native_lock`, runs one locked release build of the three native binaries,
restores the canonical lock and verifies sources. It copies binaries and records
actual source trees, harness hashes, compiler/build inputs and executable hashes.
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

Comparison refuses failed/incomplete runs, differing hosts, harness/build inputs,
client binaries or configurations. It reports descriptive socket/core medians and
App/requested-pool owners; no automatic baseline replacement or pass/fail speedup
claim. Keep the original #650 baseline separately from rolling development results.

## Bounds and interpretation

The prepared-run target is about one minute. A full result records actual total
duration and whether it met60seconds. Each reliability worker has a10second
deadline; later cells are explicitly NOT RUN after a failure or exhausted budget.
Output is bounded and never overwrites a prior result. A worker waits at a stdin
gate until assigned to a Windows kill-on-close Job Object or reserved Linux
process group. Timeout, output overflow, remaining descendants and unresolved
cleanup fail the run. This custody assumes the supplied cooperative workers;
Linux fixtures do not escape their inherited group/session.
Windows uses CPython's `_winapi` process adapter: create suspended, assign to a
Job Object capped at16active processes, then resume. Two bounded pipe-reader
threads belong to the harness, not the library. Unsupported custody is refused.

Setup/build are outside the prepared-run duration and retained in preparation.
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
