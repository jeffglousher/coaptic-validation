# Initial CPU results: target unfinished

[Core #651](https://github.com/jeffglousher/coaptic/pull/651) removes unused AES
inverse-key setup, a ciphertext staging copy and option scanning beyond an ordered
target. It adds no pool, App or context fields. The broader 50% CPU target remains
open in [core #650](https://github.com/jeffglousher/coaptic/issues/650).

Three five-second Windows loopback windows per mode and variant compare the
spinning server with the modified Mio readiness fixture. Each window schedules
10,000 complete 64-byte GET/CON operations at 2,000 operations/s, with one
outstanding Call. All responses passed full-body verification; OSCORE responses
also passed authentication. Client CPU is recorded separately from server CPU.

- Unprotected median server CPU per operation: 498.44 microseconds spinning,
  26.56 microseconds with readiness.
- OSCORE median server CPU per operation: 498.44 microseconds spinning,
  14.06 microseconds with readiness.
- Readiness saves about 95% and 97% CPU in this client-limited cell, with a
  latency tradeoff: median window p50 rises from 26.2 to 38.4 microseconds
  unprotected, and from 30.4 to 42.1 microseconds with OSCORE.

CPU accounting is quantized and varies substantially between windows. The
variants ran in successive batches. Pacing catches up after late starts without
dropping operations, and every window retains that lateness. These results do not
establish the target without material regressions, active processing gains or
saturation capacity.

A separate socket-free probe alternates baseline and candidate across five
50,000-operation windows per mode. Median window mean poll wall time changes
from 1,041.53 to 1,009.59 ns unprotected, and from 1,931.52 to 1,902.79 ns with
OSCORE. Per-call clocks perturb this probe. Request preparation and complete
authenticated response verification run outside the poll clock; this measures
poll wall time, not isolated process CPU.

Baseline core is `b8f44fa` (runtime `739c277`). Candidate source is `8e93916`,
merged unchanged as `21f6dea`. Baseline suite is `98b54fe`. Build records retain
the exact measurement overlays, compiler and binary hashes. Later admission and
validator fixes do not replace those source identities. Both server variants use
the same frozen client binary.

`summary.json` contains the configuration, all windows, client storage figures and
limitations. `raw-observations.tar.gz` retains latency and calibration arrays,
CPU snapshots, build identities and check logs. `archive-index.json` binds its
members; `SHA256SUMS` binds the public files. Original binaries remain in private
evidence for regrading.

`experiments.json` records the hypotheses, results, rejected evidence and next work.

Build the native server and client at an identified source, then use fresh output
paths for each repeat:

```sh
python tools/benchmark/native_diagnostic.py --server SERVER --client CLIENT --output NEW.json --bytes 64 --operations 10000 --warmup 32 --timeout-ms 1000 --policy spin --security oscore --server-kind coaptic-mio --rate 2000 --cpu-gated
```

Repeat with `--security unprotected` and `--server-kind coaptic-reusable` for the
other cells. The raw archive also contains the alternating core-probe recipe.

Core validation passed 1,171 all-feature and 693 no-default release library tests,
strict all-target/all-feature Clippy and affected feature checks. Native focused
tests, independent corrupt-body/wrong-key refusal and fresh protected Block2
recovery pass. No physical-device qualification was repeated.

During these timing runs, Windows system sampling was refused and WSL did not
start. Process accounting does not attribute machine-wide interrupts or DPCs.
The [subsequent Linux campaign](../cpu-cost-linux-20261022/README.md) retains
matched-load process CPU and limited sampling evidence separately. Larger and
concurrent workloads, observability overhead, EDHOC setup, device CPU and
whole-system memory peaks remain unfinished.
