# Manual Linux CPU qualification

`performance-cpu.yml` is opt-in platform qualification for core issue #650.
It is not required hosted CI or release authorization. The workflow runs the
committed companion ref selected at dispatch. Select **full immutable core SHAs** for
baseline and candidate; branch names are refused. The initial runtime baseline is
`b8f44fa16b3e16f4c9c6cc5f1205d2aee9cb0b57`; the merged CPU candidate is
`21f6dea85fb49bd766b405b3d48f58e76976ae1d`.

The manual workflow uses Ubuntu 24.04, pinned Rust 1.99.0, two Cargo jobs and one
runner build lane. The workflow installs `RUSTUP_TOOLCHAIN=1.99.0`; the runner
sets the same value for every rustc/Cargo command, overriding ambient selection
and the root `rust-toolchain.toml`'s `stable`. Cargo uses `RUSTC=rustc` so its
compiler uses that selection too. Before either build, the runner retains full
`rustc -Vv` and `cargo -Vv` output in `build-baseline.json` or
`build-candidate.json`, requires release 1.99.0 and full commit hashes, and
checks the candidate identities against the baseline before compiling it.
Version refusals retain the request, observed versions, failure and incomplete
summary without starting that build. A successful build replaces its preflight
record with the full build record, including the same version output; this
reuses the existing metadata allowance.

The [rustup override order](https://rust-lang.github.io/rustup/overrides.html)
puts `RUSTUP_TOOLCHAIN` ahead of directory/toolchain-file defaults;
[Cargo documents `RUSTC`](https://doc.rust-lang.org/cargo/reference/environment-variables.html)
as its compiler executable selection.

It builds both revisions sequentially with `--release --locked
--target HOST`, where HOST is the validated host triple from `rustc -Vv`;
this overrides inherited Cargo target configuration and environment settings.
It copies binaries only from `lane/HOST/release` and records/compares the target
for both builds. Builds use
release debuginfo=1, no symbol stripping and forced frame pointers. The native
workspace's thin LTO and single codegen unit apply to both. It copies the baseline
binaries outside the lane before rebuilding the candidate; **the baseline client
binary drives both server revisions** to avoid silently changing client cost.
Both candidate binaries remain available for inspection. Clean source identities,
trees, compiler, flags, lock/manifest hashes, binary SHA256s and Linux hardware,
affinity, governor, load and CPU accounting tick rate are retained. A lock mismatch
fails rather than updating dependencies. No build runs during measurement.

Historical run `39779276076` predates this enforcement: the workflow selected
1.99.0, but the root `stable` override selected rustc and Cargo 1.99.1. Its
retained versions describe a valid matched 1.99.1 comparison. This fix does not
relabel that evidence or claim it used 1.99.0. Existing frame-pointer, release
debug/strip, incremental and job flags remain the same; the new recorded flags
explicitly select the toolchain and Cargo compiler. Cargo identity now includes
verbose release/commit data rather than only `cargo -V`.

On an otherwise idle Linux host with committed clean companion/core checkouts,
the pinned compiler and `psutil==7.0.0` already installed, reuse an existing lane:

```sh
python3 tools/benchmark/linux_cpu.py \
  --baseline-sha b8f44fa16b3e16f4c9c6cc5f1205d2aee9cb0b57 \
  --candidate-sha 21f6dea85fb49bd766b405b3d48f58e76976ae1d \
  --build-lane /existing/compatible/cargo-lane \
  --output /fresh/evidence/linux-cpu \
  --sizes 64,1024 --rates 100,1000 \
  --seconds 10 --repeats 4 --server-kind coaptic-reusable --perf
```

The default workload is both security modes, 64/1024-byte complete responses,
100/1000 operations/s, ten scheduled seconds and four rotated pairs, using the
reusable spin adapter: **64 clean windows**, plus **32 profile passes** with
`--perf` (the workflow enables perf by default; the CLI requires this flag).
Run 64 KiB separately at lower offered rates to stay within the native socket
budget:

```sh
python3 tools/benchmark/linux_cpu.py \
  --baseline-sha b8f44fa16b3e16f4c9c6cc5f1205d2aee9cb0b57 \
  --candidate-sha 21f6dea85fb49bd766b405b3d48f58e76976ae1d \
  --build-lane /existing/compatible/cargo-lane \
  --output /fresh/evidence/linux-cpu-64k \
  --sizes 65536 --rates 10,50 \
  --seconds 10 --repeats 4 --server-kind coaptic-reusable --perf
```

This separate invocation has 32 clean windows and 16 profile passes. Its largest
clean window needs at least `(20 + 50*10)*64 = 33280` outbound datagrams.
Validation checks **every clean and profile plan before builds**. All windows
must satisfy `(20 + operations) * ceil(bytes/1024) <= 60000`, including warmup;
the native client also enforces a live per-socket 60000-send ceiling, so retries
can still cause an explicitly retained failure. Profiles use five seconds of
offered operations regardless of the clean duration: 65536B at 200/s for two
clean seconds fits, but is refused with perf because its profiles exceed the
socket budget. No workload here establishes either CPU reduction target.

The runner changes the clean `coaptic/` checkout to each selected SHA and leaves
it at the candidate; use only an explicitly assigned checkout/lane. Output must
be fresh and outside source. It fetches only the two specified core commits.
Do not run concurrently with another lane consumer, compiler or timing campaign.

### Compare scheduling at one core revision

Use `--candidate-server-kind` to compare two explicit adapters at **identical core
SHAs**. Combining adapter and core changes, `all`, or identical adapter names is
refused before builds. Defaults and the three adapters selected by `all` stay
unchanged; `coaptic-async` and `coaptic-blocking` must be selected explicitly. The manual workflow's
`candidate_server_kind` defaults to `same` and exposes the same restriction.

For example, compare the current Tokio polling loop with native async App
wait/progress, with profiling off:

```sh
CORE_SHA=97934e67f0fde780d7f12509e1bba6b50199b2ad
python3 tools/benchmark/linux_cpu.py \
  --baseline-sha "$CORE_SHA" --candidate-sha "$CORE_SHA" \
  --build-lane /existing/compatible/cargo-lane --output /fresh/evidence/async-ab \
  --sizes 64,1024 --rates 4000 --seconds 12 --repeats 4 \
  --server-kind coaptic-ready --candidate-server-kind coaptic-async
```

This plans 32 clean windows, 384 scheduled seconds and 1,536,000 latency samples;
each fresh socket needs at least 48,020 sends including warmup. Both builds use
the same companion snapshot, compiler, locks and frozen baseline client. Window
records retain the adapter actually executed. Summary `server_kinds` names both
adapters, and `comparison_type=application_scheduling` distinguishes these ratios
from `core_revision` comparisons. Summary `server_kind` is the baseline adapter.
Wrong executed adapters or differing recorded core SHAs suppress the ratio.
Keep latency, client CPU and startup/runtime memory costs with the result; an
adapter comparison does not establish a core-processing speedup or either target.

Current native async startup records use `coaptic-native-server-resources/2`.
`loop_future_borrowing_app_bytes` describes a future borrowing a separate App;
scratch is nested inside the adapter inside App. Both App and the loop future
belong to the complete outer setup future, whose size is not reported at startup.
Nested sizes must not be summed. Outer setup, runtime, thread and polling stacks,
core/response-body heap, allocator and kernel costs remain excluded and unknown.
The current parser rejects schema 1 and its owned-App future field. Frozen runs
retain their original companion revision, schema and ledger interpretation;
the schema-1 evidence from `b9736ba` is not relabelled as schema 2.

The explicit `coaptic-blocking` control uses synchronous App polling with a
receive staged in its one 2049-byte scratch before a fresh poll timestamp. At
most one transport packet is retained there, separate from the unchanged Engine
RX pool and preserved on RX refusal. There is no second payload buffer or growing
queue. Read waits are requested for at most 5 ms; a cached timeout is reused only while it fits the next
App opportunity. Very close deadlines use a visible sleep fallback that may
delay ingress. Writes use a positive 1 ms timeout, so congestion may wait rather
than report immediate WouldBlock. OS timeouts are soft; this does not supply async
cancellation or exact absolute send deadlines. External application wake signals
need their own integration. Core processing, security and configured capacities
are unchanged; this is an application scheduling comparison.

Its `coaptic-native-blocking-resources/1` startup record reports the <=64-byte
stage/cache metadata, transport staging capacity one, 2049-byte scratch, adapter
and App sizes, requested read and write timeouts, and unknown runtime costs. The complete newline-terminated record
must pass the same bounded startup gate before CPU snapshots. Metadata and scratch
are nested inside the adapter inside App; main/polling stacks, pool/body heap,
allocator and kernel costs remain excluded. Do not sum nested owners.

For a finite same-core ready/blocking comparison with profiling off, select both
core SHAs as `120a6227ab56b31c9898870950b81ddafdb933e6`, `--sizes 64 --rates 11900
--seconds 5 --repeats 4 --server-kind coaptic-ready
--candidate-server-kind coaptic-blocking`. This schedules 16 clean windows,
80 seconds and 952,000 verified-operation attempts, each socket requiring at
least 59,520 sends with warmup. Existing live send, sample, cleanup and artifact
bounds still apply. Authentication and complete response verification remain
required; neither a successful finite proof nor adapter selection establishes a
CPU reduction target.

Each security/body/rate/adapter/concurrency/message-type cell defaults to sequential
complete CON GETs, one outstanding Call, 20 warmups, a 3s per-operation deadline
and 60s per-control-phase deadline.
Supported sizes are 64, 1024 and 65536 bytes; the last exercises complete blockwise
retrieval. Security strata are unprotected and established volatile OSCORE, each
with a new random 24-byte test credential file outside artifacts (0600, deleted
after the window). There is no device enrollment, device key, NVS or EDHOC setup.
The client verifies status, content format, ETag and every complete response byte.
Absolute dispatch deadlines pace operation starts without dropping late work.
Report achieved load, late starts and failures alongside CPU; offered rate is
never described as saturation capacity. The host fixtures use Default/AllocMemory
and fixed named pools, not the SmallDevice/Constrained fixture.

Select the same `coaptic-reusable` spin, `coaptic-mio`, or `coaptic-ready` host
adapter for both cores. `all` creates separate strata. The explicit `rotation.json`
alternates baseline/candidate order by repeat and cell. All clean passes finish
before any profiling. CPU snapshots surround `ready/run` to `measured/report`,
excluding warmup and JSON formatting. User/system CPU, client cost, RSS snapshots,
raw latency samples and full operation accounting remain separate. Each window's
`client.json` is the only retained copy of its full native report and samples;
`result.json` and `windows.jsonl` contain bounded summaries and its path.
Only eligible clean aggregation reloads raw samples; profiling arrays stay on
disk and never enter aggregate JSON. The process
window includes control/sampling overhead and server idle polling. System-wide
interrupts and unrelated kernel work are not attributed to the server. RSS and
process high-water values are not whole-system memory or isolated-window peaks.

Summary ratios require a complete campaign with resolved process cleanup,
every rotated pair to complete, achieved rates within 5%
of offered load and each other, at most 1% missed periods (minimum one), and at
least 20 server CPU ticks per window. Otherwise `comparable=false` and no ratio
is emitted. Low-rate readiness CPU often needs a longer/larger-load rerun to
resolve; a zero process CPU delta is not proof of zero cost. Costs are summed
user/system CPU divided by summed verified completions within each stratum.
Latency median/p99 is descriptive; no confidence interval, 50% acceptance,
historical regression, cross-library advantage or representative-device claim is
inferred. Poll wall time, RTT and process CPU remain distinct measurements.

Optional `--concurrency 1..4` and `--message-type con|non` select the client path;
the manual workflow exposes the same inputs. Defaults remain **C1 CON**. C2..C4
with CON are refused before credentials, sockets, warmup or builds because the
single endpoint has NSTART=1. Concurrent requests require explicit
`--message-type non`; there is no automatic fallback. For example, add
`--concurrency 2 --message-type non` to a bounded invocation above to select
**C2 NON**. C1 NON, C2 NON, C3 NON and C4 NON are separate cohorts from C1 CON
and each other. A new harness is not evidence of a CPU improvement. The runner
continues to use one frozen baseline client binary for both server revisions.
Concurrent NON is additional coverage only; it cannot qualify the primary CON
workload target. A future 2/4-endpoint CON cohort needs one in-flight CON per
endpoint, independently generated credentials and matching server associations,
with the same aggregate datagram budget. It is not implemented by these options.

Each window has one App, one OSCORE context and one monotonically advancing sender
sequence across warmup and measurement. Default Call capacity and request-binding
capacity remain four. A fixed four-slot pending array holds Call/start/deadline
metadata; its byte size is reported separately from App inline
storage. All core pools, expected bytes, one reusable completed-response output
buffer and timing storage are allocated before warmup/timing. RX body slots are
selected up front to equal concurrency (C1 retains its original one slot); all
other client and server capacities are unchanged. Concurrent blockwise transfers
can refuse at the existing server's two TX bodies or other fixed capacities;
refusals remain failures. Body-slot counts alone do not establish concurrent
blockwise success: every complete reply must pass, and a timeout invalidates the
observation. Capacities are never raised to force success. Report `rx_body_slots`, core heap allowance, App
inline size, verification/timing heap bytes, fixed pending metadata bytes and peak
pending Calls together; process/allocator/stack costs remain separate.
The existing four client RX datagram slots include one mandatory headroom slot
under `.full_responses()`, so at most three ordinary Calls can be admitted at
once. A burst C4 attempt (including unpaced warmup) refuses its fourth admission;
the three live Calls are cancelled and all four attempts count as failed. No
packet pool is enlarged for the C4 label. Paced configured-C4 traffic can fit
when its observed peak stays within those credits; it is not four-way execution.
Configured concurrency is only an admission limit. Raw native reports and each
window summary retain `peak_pending`; aggregate summaries retain each repeat's
observed peak separately for baseline and candidate. **C4 with observed peak1
does not establish concurrency qualification.** CPU comparability still describes
the observed matched load and must not be read as proof of concurrent execution
or of reaching the configured limit.

Admission follows the same absolute offered-load schedule with zero drops and
bounded catchup through the selected concurrency. One poll loop matches replies
by Call, including reordered responses, and verifies status, format, ETag and all
body bytes after authenticated response collection. Individual deadlines cover
send, polling, assembly and verification. The first detected failure stops new
admission; at most four local cancellations/collections reclaim pending state
without sending cleanup packets. `attempted = completed + failed` includes failed
send admissions and every unverified in-flight operation; `unattempted` covers the
remainder, and `cancelled_inflight` counts successful local cancellations only.
There are no synthetic success samples. The unchanged 60000 live-send ceiling
covers the whole window's warmups, blocks, retransmissions and response ACKs;
`total_sent_datagrams` exposes that total alongside measured-only traffic.

New reports must echo the requested concurrency/message type. With C outstanding
Calls, each latency must be <= elapsed and the sum must be <= C*elapsed; the
sequential sum<=elapsed rule still applies to C1. Summaries group by both new
fields as well as security/body/rate/adapter. Missing legacy metadata and mismatched
echoes cannot become eligible comparisons. The fixed-window/sample/byte/phase/
datagram budgets and clean/perf separation do not expand with concurrency.

A finite Windows correctness check at core `97934e67f0fde780d7f12509e1bba6b50199b2ad`
reproduced an unfinished **C2 NON 2048-byte response timeout**, in both security
modes: four attempted operations, three verified completions, one failure, zero
unattempted, one cancelled in-flight Call, peak two, seven sent and seven received
datagrams. Nominal RX/TX body-slot counts do not explain this failure. Its partial
reports remain failed observations; no cause or concurrent blockwise qualification
is inferred. Small-body C2/C3 success does not resolve it. Reproduce with the same
native client/server sources and existing capacities:

```sh
python tools/benchmark/native_diagnostic.py --server SERVER --client CLIENT \
  --output FRESH.json --bytes 2048 --operations 4 --warmup 0 --timeout-ms 1000 \
  --policy spin --security unprotected --server-kind coaptic-reusable \
  --concurrency 2 --message-type non --cpu-gated
```

Use `--security oscore` for the protected case. Failure output preserves the
exception and partial native report; it must not be regraded as success. Root
tracks the separate source/packet diagnosis under #650; no core or server
capacity is enlarged by this diagnostic path.

Optional **separate** five-second `sudo -n perf record` and `perf stat` passes
attach only to the selected server PID after warmup. Record samples user and
kernel execution at 997Hz using inclusive `cpu-clock`, frame-pointer call chains
and 128 mmap pages. Kernel symbols may remain unresolved under runner policy.
Clean process CPU still includes user and system time, and stat events are
unchanged. There is no eBPF, DWARF stack
dump, register dump or packet capture. Record/stat use separate socket runs; their
timings and CPU costs are excluded from comparison. The attach window is a
bounded wall interval that can include idle/control time. Record starts disabled
with `-D -1 --control fifo:CTL,ACK`; an enable acknowledgement precedes the
existing CPU snapshots and client `run` gate. After the measured gate and after
snapshots, `finish_recording()` disables and stops recording before client report
formatting/read. It is idempotent and is also attempted during context cleanup.
The old record `-- sleep 5` lifetime is removed: its clock would already be
running before acknowledgement and could clip a five-second client interval.
The post-sudo 15-second watchdog and five-second KILL grace still bound record.
Stat retains its original command, event list and sleep lifetime; clean snapshot
and timing boundaries are unchanged.
`perf.json`, `perf-command.log`, raw `perf.data` and stat output retain exact tool,
event or permission refusals. Clean CPU qualification remains separate from
profiler availability; a refused record startup leaves that profile window unrun.
No perf permissions, sysctls or shared services are changed.

Each record owns a private mode-0700 temporary directory containing two mode-0600
FIFOs, opened nonblocking. This directory uses the system temporary location,
outside the uploaded evidence paths; retained special files must never enter
artifact traversal. Paths cross sudo; inherited extra FDs are not assumed
to survive it, and no sudoers/FD-preservation setting changes. Only one control
command is outstanding, in order `enable`, `disable`, `stop`. Each ACK has at most
two seconds, clamped to the same absolute 15-second capture deadline. The whole
channel reads at most 64 bytes with an eight-byte read/parser bound. Split
`ack\n` replies and one optional trailing NUL are supported; upstream perf writes
that NUL. Wrong, extra, stale, incomplete or late ACKs, short writes and target or
recorder exits refuse the capture. A startup refusal never releases the client
run gate. Record's measured gate is clamped to the capture deadline too.

`perf_pass(..., event='cpu-clock', target=None)` yields a dict-compatible
`PerfCapture`. Its record-only `deadline` and `finish_recording()` support the
separate finite sampling probe; process handles and FDs are instance attributes,
never serialized keys. Only record accepts `cpu-clock` or `task-clock`; campaigns
continue to use inclusive `cpu-clock` without a new event CLI choice. Fixed
timestamps, ACK counts and bounded refusal fields fit the existing 16 KiB
`perf.json` allowance. Existing owned-group stop/reap precedes descriptor closure
and removal of only the owned FIFO objects; unresolved cleanup is still fatal.
An ownership mismatch is retained for review rather than recursively removed.
On unresolved cleanup, bounded `retained_control_directory` metadata identifies
the retained system-temp location in `perf.json`. A startup refusal before the
context yields carries the profiler metadata on the original exception, so the
window retains fatal cleanup status, stops later campaign windows and suppresses
all ratios. A startup refusal with resolved cleanup remains nonfatal to the
separate clean cohort comparisons. No process handles or descriptors are carried
on that exception.

An ACK fences perf command processing, not successful enabling of every kernel
event or representative sampling. See upstream
[perf control documentation](https://github.com/gregkh/linux/blob/v7.0.14/tools/perf/Documentation/perf-record.txt#L678-L728),
[control implementation](https://github.com/gregkh/linux/blob/v7.0.14/tools/perf/util/evlist.c#L1957-L2150)
and [sudo FD behavior](https://github.com/sudo-project/sudo/blob/main/docs/sudo.man.in#L250-L268).
Upstream v7.0/v7.0.14
[clock-event implementation](https://github.com/torvalds/linux/blob/v7.0/kernel/events/core.c#L12174-L12441)
shares the hrtimer between cpu-clock and task-clock, preserves its remaining
interval on stop/restart, and maps 997 Hz to a fixed 1,003,009 ns period. A full
period reset at every schedule-in or generic adaptive-frequency feedback is not
an established explanation for sparse samples. The exact Azure kernel patches,
configuration and timer delivery are not verified by those upstream sources.

The qualified [4000/s ready/blocking run 39843237773](https://github.com/jeffglousher/coaptic-validation/actions/runs/39843237773)
at companion `d4f585a` and identical core `120a622` verified 1,344,000 operations;
all 32 clean windows and four latency guards passed, with CPU reductions of
17.61–30.89%. Its eight record captures contained only 5–106 samples and establish
no remaining function/stage rank. This fence does not relabel that evidence or
prove its sparse-count cause. Both broader 50% CPU targets remain open; sampling
suitability needs a separately bounded busy/short-burst control before optimization.


For a compact ready-versus-async diagnosis, keep both core SHAs identical and use
`--sizes 64 --rates 11900 --seconds 2 --repeats 2 --server-kind coaptic-ready
--candidate-server-kind coaptic-async --perf`. This schedules eight clean and eight
profile windows: 56 seconds and 666,400 raw samples. Each five-second profile needs
at least 59,520 sends including warmup, leaving 480 below the live 60,000-send cap;
retries can exhaust that margin. Default ten-second clean windows at this rate
are refused. This higher offered load is a separate measurement stratum.

Require enough resolved samples in the CPU mode being ranked; 100 per capture
is a useful initial triage threshold, while single-digit symbol counts remain
inconclusive. Report resolved user/kernel samples and unknowns separately. Retain
lost and throttled-sample warnings and include unresolved samples in percentage
denominators. Sample percentages are not clean process CPU shares or stage times;
profile CPU/latency is excluded from the clean comparison. PID-scoped sampling
does not cover all machine-wide interrupt or worker costs, or blocked time.

After each successful record capture terminates and its raw file is readable,
nonempty and below quota, the runner reads it while the copied server/client ELF
paths still exist on the original runner. Nonprivileged `perf --version` has a
five-second deadline and appends to `perf-command.log`. The report prefix is
`sudo -n -- prlimit --fsize=QUOTA:QUOTA -- timeout --signal=TERM --kill-after=5 25
env DEBUGINFOD_URLS= perf report`: the file limit and empty debuginfod URLs apply
after sudo. The inner timeout sends TERM after 25 seconds and KILL five seconds
later; the outer owned-process wait remains 30 seconds. Combined stdout/stderr
goes to the parent-opened `perf-report.txt`, with the same file quota. Both
commands use owned sessions. Only the report opts into elevated cleanup through
`run_owned`; version and other helpers retain the default. Exact argv arrays,
return codes, byte counts, deadlines and failures remain under `report` in
`perf.json`. Missing tools or sudo refusal remain explicit unavailable reports.
No remote debuginfod downloads or symbol snapshots are added.

Upstream perf's
[kernel symbol loader](https://github.com/torvalds/linux/blob/v6.17/tools/perf/util/symbol.c#L2005-L2127)
can resolve against live `/proc/kallsyms` after matching the recorded kernel
build ID to `/sys/kernel/notes`. Keep reporting on that runner before its kernel
or module mappings change. Root does not guarantee resolution: the kernel's
[kallsyms policy](https://github.com/torvalds/linux/blob/v6.17/kernel/ksyms_common.c#L8-L40)
requires suitable `CAP_SYSLOG` in the initial user namespace under restrictive
settings, and `kptr_restrict=2` hides addresses even then. Other security policy,
missing symbols or build-ID mismatches can also prevent resolution. Retain raw
unknowns/warnings; do not change capabilities, permissions or kernel policy.

The report uses `--stdio --header --show-nr-samples --show-total-period
--sort dso,symbol --no-children --call-graph none --percent-limit 0
--stdio-color never --no-inline --demangle --force --input OWNED_PERF_DATA`.
These options are documented in the upstream
[perf report manual](https://github.com/torvalds/linux/blob/v6.8/tools/perf/Documentation/perf-report.txt).
`--force` permits reading this runner's sudo-owned capture without an ownership
check; it grants no filesystem permissions. The initial report is a flat ranked
DSO/function summary of sampled self costs, sample counts and event periods.
Callchain display and inline expansion are disabled to bound processing; the
original frame-pointer callchains remain in raw `perf.data` for later inspection.
Headers, event/sample totals, any exposed first/last sample times, lost-sample
counts and warnings remain verbatim, including stderr and unresolved symbols.
Perf versions expose different coverage details; absent warnings or zero reported
losses do not prove full measurement-window coverage. A successful report command
does not prove nonzero samples, resolved symbols or complete coverage. Sample
percentages/periods are not stage timings or clean process CPU measurements.

A nonzero report exit, quota hit or timeout with resolved cleanup leaves the
capture available and preserves its raw data and partial report. `unavailable_reports`
in `summary.json` lists successful record captures whose report was unavailable;
`unavailable_profiles` separately lists unavailable captures/stat passes. A report
refusal does not invalidate eligible clean pairs. Unresolved termination of either
the version command or report process is fatal to the campaign, as for capture
helpers. Binaries retain original build paths in debug information; copied
symbolized binaries and raw profiles remain available even if reporting fails.

Bounds: 1..3 distinct rates, 1..100000 ops/s; 2..30 scheduled seconds;
2..8 repeats; the 60000-datagram admission bound above applies to each socket
(at most 59980 measured operations for 64/1024B, 917 for 65536B);
<=96 clean windows,
<=1200 scheduled clean seconds and <=2 million retained latency samples over the
whole campaign. Raw report reads/writes have a per-window byte ceiling of
`65536 + 22*operations`: a decimal u64 needs at most 20 bytes plus comma/space;
the 64 KiB covers native fields and newline. Samples must be u64. Encoded global
JSON files are capped at 64 KiB each; per-window result, index entry and perf
metadata at 16 KiB each. Encoding is checked before opening a file, and raw
aggregation reads at most the declared report allowance plus one guard byte.
Oversized window metadata becomes a small failed result, preserving raw files
and fatal cleanup status/errors.
Server logs have a 16 KiB hard file limit; retained client stderr is also capped
at 16 KiB. The two build logs each retain at most 2 MiB through a bounded pipe
reader; overflow fails the build and stops its owned group. Compiler artifact
files are not subject to this log quota.
Source/version commands use the same bounded pipe reader with a 64 KiB output
ceiling. That ceiling does not restrict other files written by Git or its tools.
Git identity checks disable optional locks, so a clean status check cannot refresh
the source index. After output-path and workload validation, `request.json` is
retained before source inspection; preflight failures produce `failure.json` and
an incomplete summary with zero measured windows.

Before builds, the runner sums every planned raw-report, metadata and log ceiling
and rejects totals above a **96 MiB metadata reserve**. This is a checked bound,
not an estimate based on typical latency widths. At most 192 total windows and
96 profile passes (at most 48 record reports) fit the clean-window/repeat
constraints. Even the combination of those maxima with 2M samples needs at most
75391744 metadata bytes; report status fits the existing capped `perf.json`.
Each perf data/stat output has a hard `RLIMIT_FSIZE` applied **after sudo**;
its command/version log and privileged report have the same quota. Reserve
**three file quotas per profile pass**, conservatively including a report quota
for stat passes too. The per-file quota is
`min(8 MiB, floor(160 MiB / (3 * profile_passes)))` when profiling is enabled.
All perf data/log/report quotas fit the remaining 160 MiB, so runner metadata,
logs and profiles together stay within
**256 MiB**, excluding binaries and the workflow's separate setup logs. The
manifest records the exact planned metadata allowance, three-files-per-slot
reservation, per-file perf quota and total artifact ceiling. Truncation/refusal
remains an unavailable capture or report, with raw evidence retained. Each binary
copy is capped at 128 MiB (four copies <=512 MiB). Workflow timeout is 60 minutes, artifacts
retain 14 days, and the
one job has no matrix/parallel build. Raw failed windows and earlier successful
windows survive later failure and upload with `if: always()`. Credentials and
the Cargo lane are excluded from uploads. Cancellation can interrupt cleanup;
the runner starts every command in an owned session, signals only its process
group, escalates TERM to KILL and reaps with five-second waits. This targets Cargo
descendants in that group as well as server/client and perf launch groups. An
inner privileged `timeout` also bounds perf to its five-second window plus ten seconds, with KILL five
seconds later if sudo isolates its group. Reporting has its own 25+5-second
privileged watchdog as described above. These bounds and owned-group signaling
are not proof that every descendant stays in those groups or that separated
descendants have terminated. Full descendant containment has not been qualified;
it would require separate work beyond this bounded reporting change.
Client/server cleanup attempts run independently, and cleanup errors retain
`result.json` and `perf.json`.
Unresolved termination of the client, server, perf, report or any helper aborts
the remaining campaign after retaining the window and append-only index. `summary.json` records
`campaign_complete=false` and `cleanup_unresolved=true`; no stratum emits a
valid ratio, including earlier complete clean pairs. A perf permission/tool
refusal with a cleanly terminated process remains an unavailable profile and
allows later windows to run.

Portable checks (no Cargo or profiling):

```sh
python3 -m unittest discover -s tools/benchmark -p 'test_linux*.py'
python3 -c "import ast,pathlib; [ast.parse(p.read_text()) for p in pathlib.Path('tools/benchmark').glob('*linux*.py')]"
```

For qualification, dispatch a selected committed companion ref. Review failure and perf-availability artifacts,
choose rates/windows with resolved CPU counters, and investigate ranked profiles.
Concurrency, saturation, recovery, SmallDevice, representative cloud/device work
and both 50% targets remain separate work under #650.
