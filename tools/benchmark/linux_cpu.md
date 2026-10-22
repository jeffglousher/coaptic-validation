# Manual Linux CPU qualification

`performance-cpu.yml` is opt-in platform qualification for core issue #650.
It is not required hosted CI or release authorization. The workflow runs the
committed companion ref selected at dispatch. Select **full immutable core SHAs** for
baseline and candidate; branch names are refused. The initial runtime baseline is
`b8f44fa16b3e16f4c9c6cc5f1205d2aee9cb0b57`; the merged CPU candidate is
`21f6dea85fb49bd766b405b3d48f58e76976ae1d`.

The manual workflow uses Ubuntu 24.04, Rust 1.99.0, two Cargo jobs and one runner
build lane. It builds both revisions sequentially with `--release --locked
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

Each security/body/rate/adapter cell uses sequential complete GETs, one outstanding
Call, 20 warmups, a 3s per-operation deadline and 60s per-control-phase deadline.
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

Optional **separate** five-second `sudo -n perf record` and `perf stat` passes
attach only to the selected server PID after warmup. Sampling is 99Hz `cpu-clock`
with frame-pointer call chains and 128 mmap pages; there is no eBPF, DWARF stack
dump, register dump or packet capture. Record/stat use separate socket runs; their
timings and CPU costs are excluded from comparison. The attach window is a
bounded wall interval that can include idle/control time or cover only part of an
overloaded run. Perf startup overhead is not synchronized to clean CPU gates.
`perf.json`, `perf-command.log`, raw `perf.data` and stat output retain exact tool,
event or permission refusals; process CPU still runs when perf is unavailable.
No perf permissions, sysctls or shared services are changed.

After each successful record capture terminates and its raw file is readable,
nonempty and below quota, the runner reads it while the copied server/client ELF
paths still exist. Nonprivileged `perf --version` has a five-second deadline and
appends to `perf-command.log`; nonprivileged `perf report` has a 30-second deadline
and writes combined stdout/stderr to `perf-report.txt`. Both use owned sessions
and hard file limits. The exact argv arrays, return codes, byte counts, deadlines
and failures are retained under `report` in `perf.json`. A missing perf executable
is an explicit report refusal. Remote debuginfod downloads are disabled.

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
its command/version log and nonprivileged report have the same quota. Reserve
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
group, escalates TERM to KILL and reaps with five-second waits. This covers Cargo
descendants as well as server/client and perf. An inner privileged `timeout`
also bounds perf to its five-second window plus ten seconds, with KILL five
seconds later if sudo isolates its group. Client/server cleanup attempts run
independently, and cleanup errors retain `result.json` and `perf.json`.
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
