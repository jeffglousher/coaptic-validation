# Network performance campaigns

Independent server and load-generator processes use real sockets. The common
Rust CoAP driver has no library dependencies. It checks status, Token/MID,
Block2 ranges, representation identity and every response byte before counting
a completion. No SUT counters or in-memory exchanges determine performance.

The supplied matrix compares Coaptic, coap-rs, libcoap, plgd/go-coap and aiocoap
servers. A separately labelled coap-lite codec fixture shows a narrower codec
endpoint, not a complete competing server stack. HTTP/3 uses quic-go with a
verified fixture certificate and TLS 1.3. These are pinned candidates, not a
claim that each is its language's fastest library.

## Prepare explicitly

Setup and compilation are outside timing. Use Python 3.10+, the repository's
Rust toolchain, Go 1.26+, and CMake 3.20+ with a C compiler. Go dependencies and
the isolated Rust benchmark workspace have committed lockfiles; none enter
the production Coaptic dependency graph.

```sh
python -m venv target/benchmark-venv
target/benchmark-venv/bin/python -m pip install aiocoap==0.4.16 psutil==7.0.0
git init target/benchmark-libcoap-source
git -C target/benchmark-libcoap-source fetch --depth 1 https://github.com/obgm/libcoap.git 851533c3cf63d16984d370ce39d586ecb3694971
git -C target/benchmark-libcoap-source checkout --detach FETCH_HEAD
target/benchmark-venv/bin/python tools/benchmark/prepare.py --libcoap-source target/benchmark-libcoap-source --output target/benchmark-manifest.json
```

On Windows use `Scripts/python.exe`; pass `--go` and `--cmake` executable paths
if needed. `--peers coaptic,coap-rs` builds a smaller comparison. Preparation
fails for missing selected dependencies; it does not turn them into passes.
Unix supports an explicitly installed `uvloop==0.22.1` with `--uvloop`; Windows
results identify their asyncio event loop. Record and review the manifest's
runtime tuning before a campaign. A manifest is trusted local executable
configuration: command fields are argv arrays, never shell strings.

## Cheap check

With prepared executables, this checks four small requests per peer plus one
untimed warmup and external readiness, one CoAP blockwise representation and
one cold HTTP/3 request when those profiles are present. HTTP/3 is actually exercised. Build time
is not included and this data cannot establish a performance win.

```sh
python tools/benchmark/campaign.py plan --manifest target/benchmark-manifest.json --output target/benchmark-smoke --windows 1 --smoke
python tools/benchmark/campaign.py run --campaign target/benchmark-smoke --window 0
python tools/benchmark/campaign.py analyze --campaign target/benchmark-smoke --output target/benchmark-smoke-report.json
```

Use a new output directory after changing a binary, dependency or profile.
Retained invalid clock samples are failures, not rounded-up timings. Windows
HTTP/3 uses QueryPerformanceCounter because Go's default Windows monotonic
clock can produce zero-duration sub-millisecond requests.

## Repetitions over time

```sh
python tools/benchmark/campaign.py plan --manifest target/benchmark-manifest.json --output target/benchmark-candidate --windows 12 --seed 20261005
python tools/benchmark/campaign.py run --campaign target/benchmark-candidate --window 0
python tools/benchmark/campaign.py run --campaign target/benchmark-candidate --window 1
python tools/benchmark/campaign.py analyze --campaign target/benchmark-candidate --reference coaptic --output target/benchmark-candidate-report.json
```

Run the second command later, through the scheduler or manually. No scheduler is
installed implicitly. The manifest declares a minimum gap (60 seconds by
default); a not-yet-due session refuses immediately instead of sleeping. Use
longer intervals for independently sampled usage periods. Rotation balances
candidate positions; randomized initial order and rotated case order reduce
fixed-order bias. Each session executes its full comparison block.

Each cell is saved exclusively and synchronously. Resume reruns only missing
cells, retains failed cells and refuses to overwrite complete sessions. Plans
hash the runner, executables, scripts and Python dependency trees; aggregation checks the
plan and every retained cell. Binaries changing in place need a new campaign.
Record actual intervals, host configuration and pre/post OS resource metadata;
the suite retains noisy observations rather than selecting the fastest subset.
An OS lock refuses overlapping runs within a campaign. Resumed blocks retain
their earliest cell timestamp and are descriptive only: pairing measurements
from different invocations cannot qualify for inference. Runtime tuning variables
are recorded and enforced; changing them requires a new manifest and campaign.
Driver and server output is continuously capped. Custom commands are trusted
and must not spawn descendants; this runner is not a process sandbox.

## Interpret accurately

- Workloads are complete GET representations at 64, 1024 and 65,536 bytes,
  concurrency 1/4/16, CoAP CON/NON, and HTTP/3 reused/cold connections. Setup,
  readiness and warmup are excluded from steady-state wall time. Cold HTTP/3
  includes connection and TLS setup. Per-request latency includes byte checking.
  CoAP uses one outstanding request per endpoint without retransmission. This
  is a loss-free service workload; impairment requires a separate reliable driver.
  MID capacity rotates endpoints between complete representations and retains
  old sockets to prevent port reuse. Rotation is included in wall time, reported
  explicitly, and bounded to 1024 reserved endpoints; larger workloads refuse.
- Goodput counts completed payload bytes divided by whole measured wall time.
  Failures remain in attempt counts and consumed wall time. Per-session latency
  quantiles describe successful requests; failures and sparse tail samples are
  reported alongside them. Wire bytes are not payload bytes and are not inferred.
- Each independently scheduled session has equal statistical weight. Ratios use
  paired session rates and a seeded bootstrap, not pooled request samples. Fewer
  than five valid paired sessions produce no interval. Any invalid session or
  request/warmup failure prevents comparison eligibility. No automatic winner
  is declared. Excluded reference pairs are counted and also prevent eligibility.
  Adjacent sessions and systematic environmental bias can still
  invalidate inference; inspect timestamps and noise metadata.
- HTTP/3 TLS and plaintext CoAP remain separate strata. Their client drivers and
  security costs differ. Native client-library performance is not measured by a
  common-driver server comparison. Codec-only fixtures are explicitly narrower.
- Closed-loop concurrency measures delivered goodput and observed RTT, not
  offered-load capacity or coordinated-omission-corrected tail latency. Driver
  saturation, CPU/affinity, remote hosts and rate-controlled workloads require
  separate evidence before attributing a plateau to the server. Security,
  Observe, mutation durability, impairment and embedded cases are independent
  workload extensions, not implied by these GET results.

Focused runner checks:

```sh
python -m unittest discover -s tools/benchmark -p 'test_*.py'
cargo test --locked --manifest-path tools/benchmark/native/Cargo.toml -p bench-load
```

Architecture and further workload decisions are tracked in
[#340](https://github.com/jeffglousher/coaptic/issues/340); delivery is
[#341](https://github.com/jeffglousher/coaptic/issues/341). Existing interop,
plugtest and device qualification retain their own acceptance and reports.
