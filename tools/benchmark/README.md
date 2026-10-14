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

## Matched protected CoAP

Comparative qualification requires reviewed tuning for every selected peer,
matched security/protocol semantics and explicit CPU and memory budgets. The
supplied fixtures are preliminary configurations, not evidence that every
candidate uses its fastest configuration. Coaptic-only diagnostics and changes
to driver scheduling cannot establish a cross-library advantage. Record client
and server CPU, steady/peak memory, complete-operation latency/tails and verified
goodput; retain setup and allocator/kernel accounting limitations.

Install `tools/benchmark/protected/requirements.txt` in the benchmark environment.
Pass `--matched-oscore` to preparation to add Coaptic and aiocoap native OSCORE
servers alongside plaintext controls. This matrix uses one external Python UDP
driver for both security profiles, with independent aiocoap cryptography:

The driver validates fixture bytes with a bounded immutable periodic window
(66,013 bytes) and native byte comparison. Every received payload byte remains
checked. Driver revisions change measured client overhead: compare runs with
the same driver revision and never attribute that change to the server library.

```sh
python -m pip install -r tools/benchmark/protected/requirements.txt
python tools/benchmark/prepare.py --matched-oscore --peers coaptic,coap-rs,coap-lite-codec,aiocoap --output target/matched-oscore-manifest.json
python tools/benchmark/campaign.py plan --manifest target/matched-oscore-manifest.json --output target/matched-oscore --windows 10 --seed 20261013
python tools/benchmark/campaign.py run --campaign target/matched-oscore --window 0
python tools/benchmark/campaign.py analyze --campaign target/matched-oscore --reference coaptic --output target/matched-plaintext-report.json
python tools/benchmark/campaign.py analyze --campaign target/matched-oscore --reference coaptic-oscore --output target/matched-oscore-report.json
```

Run every scheduled window with the declared session gap. Small and blockwise
smokes cover each security stratum. OSCORE uses RFC 8613 AES-CCM-16-64-128 and
HKDF-SHA-256, fresh secret/salt per cell, and disjoint readiness and measured
sender sequence ranges. Test credentials are confined to a temporary directory
and removed after the server exits; they are not retained in reports. This is
process-lifetime benchmarking, without enrollment, durable counters or crash
recovery. The fixtures and driver accept only IPv4 loopback.

### Native complete-operation diagnostic

The bench-native-client executable uses the Coaptic client against the loopback
fixture. It times sending through complete-response assembly and exact status,
format, ETag and body verification; OSCORE authentication is included. It
reserves bounded storage before timing and enforces an aggregate requested heap
quota. Results separate core heap quota, App inline state (including UDP scratch),
verification buffers and timing storage. Allocator overhead, stack peaks and
kernel socket memory require separate accounting.

~~~sh
cargo build --release --locked --manifest-path tools/benchmark/native/Cargo.toml -p bench-rust-server
python tools/benchmark/native_diagnostic.py --server target/benchmark-native/release/bench-rust-server --client target/benchmark-native/release/bench-native-client --policy spin --security oscore --output native-cost.json
~~~

Use the existing Cargo target path selected for the build; add .exe on Windows.
The runner generates fresh pairwise credentials per process and retains CPU/RSS
samples outside operation clocks through the gated interface. CPU counters are
quantized; resource windows include control overhead and peak RSS covers process
lifetime. The spin policy consumes CPU while awaiting replies. The sleep1 policy
intentionally inserts a 1 ms per-poll delay to diagnose scheduling costs; it is
not a competing-library configuration or a recommended optimization. Neither
policy is a production runtime recommendation. This diagnostic uses Coaptic at
both ends, has one outstanding operation, and does not replace the independent
matched driver, interoperability checks, durable-recovery qualification or
comparative campaigns.

Both protected servers use a 32-entry replay window. One shared driver identity
serializes sequence reservation through UDP dispatch, preventing local sender
thread scheduling from manufacturing wider reordering before packets enter
the network. This preserves independent outstanding exchanges per worker.
Preparation requires the pinned resource sampler and hashes its dependency tree.

Completions require authenticated responses bound to their request, successful
status, Content-Format, stable ETag, valid Block2 ranges and every expected byte.
Unprotected application responses fail the protected driver. Authentication,
byte validation, Python scheduling and GIL contention are included in latency
and wall time. These results describe the matched closed-loop configuration;
they do not establish server saturation or compare directly with timings from
the native Rust driver. Keep the native driver for a separate plaintext campaign
and for matched historical regression measurements.

The manifest explicitly records selected peers without an OSCORE fixture and
the absent DTLS benchmark path. coap-rs and coap-lite have no native OSCORE path
in this harness; libcoap has native OSCORE but its benchmark fixture is currently
plaintext. HTTP/3 TLS remains a separate protocol. No unsupported combination
is treated as a successful encrypted result. Preparation records library/suite
revisions, cleanliness, lockfile, crypto versions and dependency hashes.

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

## Diagnostic stage timing

The separate `bench-profile` package enables Coaptic's `diagnostics` feature.
Its in-process mode measures each `App::poll`; socket mode additionally separates
active, idle and failed polls/receives, complete sends and failed sends. A short
or overlong send counts as failed. Existing aggregate records are retained, with
an additional `coaptic-profile-timing/1` JSON record after the run.
An active poll succeeds and receives a new datagram; an idle poll succeeds without
a new datagram and can still process timers or retained protocol work. A failed
poll returns an error regardless of whether it received a datagram.

Each distribution has a sample count, total and maximum nanoseconds, 21 fixed
bins, and an overflow count above the final bound. Reported bin upper bounds are
inclusive: the first bin includes zero, and subsequent bins exclude the previous
bound. Overflow samples retain their full value in the maximum and total. A
`counter_saturated` flag means the counters cannot represent exact accounting.
These bins bound a tail's location; they do not supply exact latency quantiles.
Recording uses fixed storage without per-sample allocation or logging.

Socket receive timing starts at the transport call, excluding earlier kernel
queue residence. A complete send means the local transport accepted every byte;
it does not establish remote receipt or delivery. Nested transport timings are
included in poll timing, so distributions must not be added together. The
in-process probe excludes kernel I/O and response validation from its poll clock.
Instrumentation, allocator accounting and histogram updates perturb this
diagnostic workload; keep it separate from diagnostics-disabled comparison runs
and from MCU or physical end-to-end latency claims.

```sh
cargo test --locked --manifest-path tools/benchmark/native/Cargo.toml -p bench-profile
```

Architecture and further workload decisions are tracked in
[#340](https://github.com/jeffglousher/coaptic/issues/340); delivery is
[#341](https://github.com/jeffglousher/coaptic/issues/341). Existing interop,
plugtest and device qualification retain their own acceptance and reports.

## Stateful entropy footprint diagnostic

The [source-bound entropy report](evidence/stateful-entropy-20261010.json) compares
pre-entropy core `9a74f23` with `05fd33d` (merged unchanged as `beef47d`). Matching
fixed and allocated App types grow by eight inline bytes on the measured
64-bit Windows target; pool allocation requests and logical work are unchanged.
Independent `std`/`alloc` modes were measured with OSCORE disabled. Inline type
sizes exclude heap pool contents, external driver state and stack peaks. The
three-operation instrumented timings do not establish throughput changes.

To repeat this narrow recipe, prepare two clean checkouts of suite
`fa0db679aae244ecf96dfe3122cdddf94ffbb1ac`, each with its clean core checkout at
`coaptic/`: baseline `9a74f2362040fde40d3b869229b4abf9c319bd35` and candidate
`05fd33d6d24888443a4130e83a6c9b5ec7e90c32`. The report retains compiler and lock
hashes. Use that compiler for an identical layout comparison; another target
or compiler produces a separately qualified observation.

```sh
python tools/benchmark/entropy_footprint.py --baseline-suite BASELINE_SUITE --candidate-suite CANDIDATE_SUITE --output NEW_EVIDENCE_DIRECTORY --build-root BUILD_DIRECTORY
```

The runner refuses dirty/wrong revisions or ambiguous compiler artifacts,
separates Cargo targets by source revision, records every command and retains
failed logs. It compiles the retained exact size probe and the explicit entropy
layout probe, then runs the unchanged profiler for only 64-byte and 64-KiB
complete bodies. It does not run a benchmark campaign or the full test suite.
