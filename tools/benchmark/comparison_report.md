# Understand and reproduce a comparison

Use `comparison_report.py` to turn the widened host/device receipts into one
self-contained interactive HTML report. It does not build, flash, download,
open firewall ports or rerun workloads. The report and machine-readable data go
in a **new** directory; original receipts stay unchanged.

```sh
python tools/benchmark/comparison_report.py \
  --method /evidence/RUNTIME-METHOD.json \
  --runtime /evidence/runtime.json \
  --device /evidence/device-balanced-comparison/result.json \
  --device-memory /evidence/esp-report-data.json \
  --loc /evidence/loc/summary.json \
  --builds /evidence/builds.json \
  --output /evidence/comparison
```

Only `--method`, `--runtime` and `--output` are required. Device input uses the
balanced three-server/four-client-process receipt format, with its original
JSONL files alongside it. Those files are checked against receipt hashes and
their 288 operation records are recomputed, not copied from saved summaries.
The optional device memory report must bind to that exact receipt SHA-256;
its memory values remain attributed to the original collection. No input
executes commands. The script imposes byte/sample/output bounds and refuses
duplicate host rows or unplanned workloads. Failed/missing rounds disable the
**whole cell** instead of selecting its successful rounds.

## Pick the comparison before the workload

There are three distinct questions:

1. **Cross-library behavior:** one common client, identical endpoint role,
   security, payload, concurrency and response verification. Windows loopback
   and ESP Wi-Fi are separate comparisons. The current widened physical run is
   Windows initiator to ESP server; it is not the opposite direction.
2. **Coaptic configuration:** use `native_profiles.py` and the representative
   profile runners to match routes, Calls, deferred rows, security bindings,
   datagrams and body pools. Fixed versus allocated storage and sync versus
   async are independent selections. Record unsupported cells explicitly.
3. **Core implementation change:** compare complete App operations against a
   matched revision, then use profiles/traces to explain a difference. An
   external library ranking cannot attribute a particular internal optimization.

The explorer keeps each body/concurrency/security/message-type cell separate.
Windows spin means repeated synchronous `App::poll` without sleeping. Mio means
the synchronous App with OS readiness waiting. Native Windows server async uses
a current-thread Tokio runtime; the ESP comparison's Windows async client uses
`async-io`. These are execution policies, not three implementations of CoAP.
Busy spin is hidden by default because its idle CPU tradeoff matters.

ESP sync uses a `select`-based readiness clock (up to 10 ms, returning early on
readability), with a FreeRTOS yield after a ready burst. ESP async uses a custom
single-root-future driver on the existing FreeRTOS task, with `select`, eventfd
and timers. Neither uses Tokio or Embassy. Host client timing records separate
poll and wait observations, but they are not device CPU time. In particular,
async I/O elapsed observations may include awaiting readiness; do not sum nested
timers or subtract them from end-to-end latency to invent server processing time.

## Memory is several different quantities

Keep these owners separate: App inline bytes, pool payload/metadata, requested
heap, task stack reservation, used lifetime stack watermark, executable image,
process private commit and RSS. A nested component is already counted in its
owner. Free ESP heap already reflects allocated task stacks; never add their
reservations to a computed platform heap delta a second time.

The measured ESP Rust server uses the block-enabled **Constrained profile**,
not the smaller `SmallDevice` recipe: eight route slots (six registered service
routes plus built-in discovery), four client Calls, one association/four security
bindings, two RX and two TX datagrams of 1152 bytes, dedup four, Observe two,
one 4096-byte incoming body and one 4096-byte outgoing body. The block-enabled
App also owns a 4096-byte completed-client body hold. Raw backing is 16,896 bytes
before metadata, transport and security. The libcoap device server has three GET
routes, dynamic context/session/PDU allocation and a borrowed static large body;
its behavior under multiple retained transfers is not established by this run.

The 2026-11-04 Rust reservations were 96 KiB sync / 192 KiB async, versus
libcoap's 16 KiB. Observed Rust lifetime watermarks were already about 78.5 kB
sync and 124.6 kB async before the first received request. This is evidence to
investigate construction and overlapping stack frames, not evidence that body
slots alone explain the gap or that those reservations are minimum requirements.
Do not lower them merely to make a comparison look better.

### Remove construction from the ESP async serving future

The unprotected ESP entry now constructs the existing App before pinning the
serving loop, then lends that owner to the loop. It borrows the returned `Result`
in place to avoid another large App move. Public `run_async` remains lazy until
first poll; cancellation drops the App before releasing the single-service owner.
Pools, task reservations, executor, scheduling and supported routes are unchanged.

An actual release build for `xtensa-esp32s3-none-elf`, using
`coaptic-esp-1.97` and `network,standalone,async-network`, produced:

- Serving future: 44,872 to 14,544 bytes (67.6% smaller).
- `Driver::run` frame: 63,680 to 944 bytes.
- Calling FFI frame: 45,040 to 45,056 bytes; the new preparation helper has a
  separate 32,224-byte frame and returns before the driver runs.
- The simultaneously active caller plus driver frames total 108,720 before
  and 46,000 bytes afterward (57.7% lower). This is a selected frame contribution,
  **not** the whole call graph or task peak. The future is nested in the caller;
  adding it again would double-count storage.

These are emitted unlinked archive prologues and storage constants inspected
with Xtensa `nm`/`objdump`, not a new device watermark or latency measurement.
The original archive SHA-256 is
`85744ea88815e2b42c883e99a4fd4d5edc3463d12505c7eaa928c7885e38f818`;
the changed archive is
`283c80b027c99ec275381f937a79f9c0806b75699ca81a418c4cef4964ca2383`.
The source change passed 42 synchronous and 53 asynchronous host tests, plus
strict all-target asynchronous Clippy. Device reservation reductions require a
new initialization/traffic watermark check and margin analysis; no flash or
reservation reduction is implied by this result.

An optional `--frames` inspection record adds the selected compiled frames to
the explorer, separately from historical device observations.

## LOC, startup and compilation

The source inventory separates dedicated test files and comments/rustdoc.
Dedicated tests are a subset of total code; other files still contain inline
tests and optional/unselected implementations. External dependencies are outside
these package counts. In particular, coap-rs delegates packet work to coap-lite.
Do not call package totals production-only, a compiled footprint or a comparison
of equivalent feature sets. Use symbols/link maps and explicitly named feature
sets when investigating executable size.

Startup is launch through a first verified response, including the probe process.
The existing fixtures lack a common graceful shutdown command; forced process
settlement is not graceful shutdown timing. Existing build-task durations used
shared caches and different targets/features. They are useful development costs,
but neither cold builds nor a fair language comparison. A build-cost comparison
must separately name dependency download, clean dependency compilation, clean
application compilation, unchanged incremental and changed-source incremental
work. Reuse compatible lanes and never clear a shared cache to manufacture a
clean measurement.

## Make a future result actionable

Keep one run descriptor with source/binary identities, endpoint direction,
platform, API mode, executor/wait policy, features, capacity ledger, verification
rules and operation counts. Display all failures and unsupported cells beside
results. Keep process replicates visible and use the same client/peer state
policy. For ESP diagnosis, distinguish initialization stack from steady traffic,
and socket waiting from processing. Preserve keys, NVS and normal firmware;
restoration is a separate result from performance success.
