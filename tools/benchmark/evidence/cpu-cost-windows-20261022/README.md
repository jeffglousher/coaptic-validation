# Initial CPU-cost batch — target unfinished

The first core optimization is merged in [core#651](https://github.com/jeffglousher/coaptic/pull/651).
It removes unused AES inverse-key setup, a ciphertext staging copy and option
scanning past an ordered target. No pool, App or context fields were added.
The broader50% CPU target remains open in [core#650](https://github.com/jeffglousher/coaptic/issues/650).

Three five-second Windows loopback windows per mode/variant compare the legacy
spinning server with the modified Mio readiness fixture at2,000 scheduled64-byte
GET/CON operations/sec, one outstanding operation. Every10,000-operation window
completed and verified its entire body; OSCORE responses were authenticated.
User and process-accounted kernel CPU are retained, with client CPU separate.

- Unprotected median server CPU/operation:498.44µs spinning versus26.56µs readiness.
- OSCORE median server CPU/operation:498.44µs spinning versus14.06µs readiness.
- This saves approximately95%/97% CPU in this client-limited cell, **with a latency
  tradeoff**: median window p50 rises from26.2µs to38.4µs unprotected and30.4µs
  to42.1µs OSCORE. Quantized CPU values vary substantially; every window is retained.

The variants ran in successive batches, not randomized interleaved CPU trials.
Pacing catches up after late starts, skips no operations, and records lateness.
These observations do not establish the no-material-regression target, active
request-processing CPU gains, a universal speedup or superiority at saturation.

A separate socket-free probe alternates baseline/candidate order across five
50,000-operation windows per mode. Median window **mean poll wall time** changes
from1,041.53ns to1,009.59ns unprotected and1,931.52ns to1,902.79ns OSCORE.
Per-call clocks perturb this probe; it is not process CPU accounting. Requests
are prepared and full responses verified outside the poll clock.

Baseline core is`b8f44fa` (runtime`739c277`); candidate source is`8e93916`, merged
unchanged as`21f6dea`. Baseline suite is`98b54fe`; build records retain exact
uncommitted measurement overlays, compiler and binary hashes. Bounds/validator
fixes made after these valid observations are not substituted into their source
identity. Both sides use the same frozen client binary in each CPU window.

`summary.json` contains configurations, each window, client storage figures and
limitations. `raw-observations.tar.gz` retains raw latency/calibration arrays,
CPU snapshots, build identity and check logs; `archive-index.json` binds its
members. `SHA256SUMS` binds the public files. Original binaries remain in the
owned private evidence directory for regrading, outside the public archive.

To repeat the CPU windows, build the native server/client at the identified
source or a separately identified candidate and use:

```sh
python tools/benchmark/native_diagnostic.py --server SERVER --client CLIENT --output NEW.json --bytes 64 --operations 10000 --warmup 32 --timeout-ms 1000 --policy spin --security oscore --server-kind coaptic-mio --rate 2000 --cpu-gated
```

Repeat with`--security unprotected` and`--server-kind coaptic-reusable` for the
other cells. Keep fresh output paths, credentials and source identities. The raw
archive contains the exact alternating core-probe recipe.

Core checks:1,171 all-feature and693 no-default release library tests, strict
all-target/all-feature Clippy and affected feature checks. Native focused tests
and independent corrupt-body/wrong-key refusal plus fresh protected Block2
recovery pass. No physical-device qualification was repeated.

Windows system CPU sampling was refused (`WPR0xc5585011`); process accounting does
not attribute machine-wide interrupts/DPCs. WSL remains unavailable. Linux
sampling, larger/concurrent workloads, observability overhead, EDHOC setup,
device CPU and whole-stack/runtime/initialization peaks remain unfinished work.
