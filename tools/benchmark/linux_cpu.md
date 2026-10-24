# Manual Linux CPU qualification

## Ended level-readiness experiment

The [matched level-readiness result](evidence/level-readiness-20261024/README.md)
records run `40130199038`: all sixteen windows verify 480,000 complete operations
plus 320 warmups with no operation failures, but OSCORE repeat 2 fails the +2 us
median guard (27.431 to 29.823 us). Full-cohort CPU claims are withheld. Pooled
and p99 passes cannot rescue the pair. Stop expansion; no retry or replacement.
The experimental implementation in #202 remains unmerged; ordinary Mio remains
the reference. This comparison uses the same accepted core on both arms and
does not replace original-baseline evidence. Both 50% targets and whole-memory
acceptance remain open.

## Bounded syscall diagnostic

The [measured syscall result](evidence/ebpf-syscalls-20261024/README.md) records
run `40112478137`: 480,000 verified operations plus 320 warmups; all eight ON
captures see one successful send, one successful receive plus one EAGAIN
receive, and one epoll wait per operation. Four pair median guards fail, so
both overhead ratios remain withheld. Counts establish neither a CPU share
nor an optimization gain; both primary targets and whole memory remain open.

The first Linux proof, `40107158379`, stopped before builds: the pinned
27,995,844-byte linker archive exceeded the 16 MiB download file limit. Its
199 Python tests passed, but all sixteen benchmark windows were NOT RUN; no
syscall counts or overhead results exist. The download-only ceiling is now
32 MiB, with a 120-second transfer timeout and the same pinned checksum.
The failed run is retained.

The corrected Linux proof, `40109321826` at suite `5615ba9737e895c128b681bb7c52d118b65c8b75`,
built the BPF object, helper and native binaries and passed 199 Python tests,
three classifier tests, two loader tests and strict loader Clippy. Its first
unprotected OFF window verified 30,000 measured complete operations plus 20
warmups with no helper attached. The next ON window loaded/attached programs
94/95 on a four-possible-CPU host (2,632 map-value bytes), but timed out waiting
for the enable ACK. No ON measured report, syscall counts or overhead pair
exists; the fourteen later windows, including every OSCORE window, were NOT RUN.
Normal disable/detach ACK was not completed. This partial failure is retained.

Source inspection identified a control-reader bug: polling the OS descriptor
then reading through Rust's buffered `Stdin` can prefetch the rest of a command,
leaving later polls waiting on an empty pipe. The repair reads one byte directly
from the same borrowed descriptor it polls, retaining the nine-byte bound and
absolute 55-second helper deadline. Focused Linux pipe tests cover whole-line
writes with the writer open, queued commands, EOF, partial lines and deadlines;
they also reproduce the mixed-buffer mechanism on an owned pipe. This explains
a concrete source defect, not a dynamically traced first byte in the failed run.
Controller reply timeouts now name the expected helper ACK and retain the cause
and fatal cleanup path. Run `40112478137` now passes the Linux repair tests and
authenticated OFF/ON functional proof. Both overhead ratios remain withheld for
failed pair median guards; no CPU gain or whole-memory claim follows.

Issue 195 adds an opt-in `syscall_probe.py` path over the existing ordinary Mio
server, native client and complete response verification. The default benchmark
and core remain unchanged. The manual `ebpf-syscalls.yml` workflow builds one
native server/client pair, then runs SmallDevice32 C1 CON at 1,000 starts/s for
30 seconds, four rotated OFF/ON pairs per security mode: sixteen windows,
480,000 planned complete operations plus 320 warmups. Each window plans 30,020
minimum outbound datagrams within the unchanged 60,000 bound. Perf, admission
diagnostics, independent endpoints and network topology changes are absent.
Established OSCORE and unprotected strata remain separate.

OFF starts no tracing helper and attaches no syscall programs. ON creates the
bounded privileged helper before warmup with counters disabled, enables at the
post-warmup gate, then disables/detaches after `measured` and before client JSON
formatting. Both arms explicitly pin the single-thread server to CPU 0. Aya
opens its perf event there; that does not prove kernel callback coverage. No
comparison to earlier unpinned measurements is valid. Callback filtering can
impose system-wide work, including on non-target tasks, outside measured server
CPU. Initial target observations and anomaly checks are narrow coverage proof.

The helper requires Linux x86_64 LP64 ELF, a live PID/start-time identity, one
thread, exact `raw_syscalls` tracepoint field layouts and CPU-0 affinity. It holds
a pidfd and rechecks identity at gates. Fixed maps hold one target/gate value
and 82 per-CPU u64 counters: sixteen syscall bins times five independent entry/
exit classes, plus context-read and foreign-thread anomaly counters. EAGAIN,
EINTR and other error returns stay explicit. There are no durations, syscall
pairing, arguments, payloads, dynamic hashes, event rings or stack traces.
Entry and exit counts need not balance: gates censor in-flight syscalls and
restart behavior remains visible. vDSO calls are unobserved. Observed foreign
threads, changed thread count/identity/affinity, malformed controls, missing
hooks, read errors, saturation and unsupported layouts refuse the diagnostic.

Admission allows at most 64 possible CPUs: map value storage is at most 41,992
bytes, including the target slot. Each program's translated bytecode is capped
at 64 KiB and their reported program memlock sum at 256 KiB. Native helper limits
are 128 MiB address space (including its 1 MiB stack allowance), 30 CPU seconds,
60 wall seconds, 64 FDs and 16 KiB stderr. Program JIT/memlock and loader lifetime
CPU/RSS are retained separately. Kernel map/link allocator metadata and generated
peak stack remain unknown; a 1 MiB metadata planning allowance is not a measured
whole-kernel ceiling. Successful verifier acceptance is still needed. No pins,
global sysctls or shared network changes are used.

The existing owned-process reserved leader/group cleanup handles the privileged
helper on normal exit, EOF, timeout, context cancellation and errors. Unresolved
cleanup is fatal and blocks another helper. Controls and output have finite byte
and time bounds. Retained results are capped at 16 MiB, setup logs/identities at
6 MiB; binary build outputs are outside the upload. The runner retains raw failed
reports and separate counts/op only after complete native verification. It keeps
the existing CPU/load/latency/failure guards for diagnostic overhead eligibility;
these rows are always vetoed by primary CPU acceptance. Low CPU resolution or
failed latency guards withhold overhead ratios and do not erase valid functional
counts. Counts are not removable CPU costs or transport shares. Both 50% targets
and whole-memory acceptance remain open.

The BPF object/native helper use explicitly source-matched current BPF locks,
native Rust 1.99.0, pinned `nightly-2026-10-13` and linker 0.12.0. The native SUT
may use accepted d23 via the existing native lock selector; its exact core and
binary hashes remain separate from the BPF build core. Historical XDP proof
cannot qualify this tracer. Actual Linux compilation, attachment, authenticated
operations and measured OFF/ON overhead require the finite reviewed Linux proof.

### Bounded process memory observations (#185)

Each existing `native_diagnostic.snapshot(process)` now attempts one optional
`process_memory` object (`coaptic-proc-memory/1`) after the unchanged psutil CPU
then `memory_info` reads. Linux reads only `/proc/<owned-child-pid>/status` and
`limits`, serially at the existing before/after gates. There is no operation-loop
read, sampler, thread, worker, dependency or PID action. The caller retains sole
custody of its unreaped children; these are non-atomic observations, not an
independent PID-identity or descendant-containment mechanism. Existing identity,
cleanup, source and CPU acceptance checks still apply.

Status requires exactly one each of `VmHWM`, `VmPeak`, `VmStk` (literal `kB`,
converted with 1024 bytes per kB) and unitless positive `Threads`. Results are
`vm_hwm_bytes`, `vm_peak_bytes`, `vm_stk_bytes` and `threads`. Limits requires one
exact `Max stack size` row with `bytes`, producing `stack_soft_bytes` and
`stack_hard_bytes`: each is a nonnegative integer or the explicit string
`unlimited`. Unlimited is neither zero nor missing. Numeric input is ASCII
decimal, at most 20 digits; converted values must fit unsigned 64 bits. Finite
hard limits must be at least the soft limit. Selected rows are at most 128 bytes;
unrelated rows are ignored. This intentionally narrow format may refuse future
kernel output rather than guessing its meaning.

Each unbuffered file capture requests 8191 bytes then one EOF-check byte,
**16384 bytes total per process snapshot**. Any nonempty EOF check refuses,
including a short read ending at a newline before more data. Full-cap files
refuse even if the selected fields precede the cap; only shorter complete
newline-terminated files are parsed. Empty/incomplete input,
missing/duplicate selected rows, wrong units, invalid numbers, oversized input
and open/read failures give explicit per-source `available=false` reasons and
no values from that source. Independent successful sources can remain visible;
the outer `available` requires both. No raw proc content, exception text or
fallback zero is emitted. Non-Linux returns `unsupported_platform` without proc
access and retains the original psutil memory fields. Original CPU/memory errors
still propagate. Historical records without this member remain readable.

Parent capture costs are additional to child memory: one <=8192-byte raw buffer,
one line at a time and bounded field/token/numeric scratch (selected lines <=128
bytes, at most four stored status values), plus Python object, file/path and
exception overhead. Raw/line/partition byte payloads together stay below 32 KiB;
this is not a measured Python heap or allocator ceiling. Buffers are released
between files. Compact ASCII JSON, including the member key/comma, is checked
within 1024 bytes per snapshot: four peer/boundary snapshots add at most 4096
bytes per window inside existing metadata quotas. Existing serializers may add
whitespace within their unchanged caps. CPU counters, verified denominator,
measurement loops and gates are unchanged; serial gate capture adds boundary
work to existing resource windows and can affect their raw readings. No CPU
floor, latency failure or other acceptance failure is rescued by these fields.

Field scope follows [Linux 6.12 proc documentation](https://www.kernel.org/doc/html/v6.12/filesystems/proc.html)
and the Linux man-pages [status](https://www.man7.org/linux/man-pages/man5/proc_pid_status.5.html),
[limits](https://www.man7.org/linux/man-pages/man5/proc_pid_limits.5.html) and
[getrlimit](https://www.man7.org/linux/man-pages/man2/getrlimit.2.html) interfaces.
`VmHWM` is an approximate kernel-reported lifetime resident high-water value;
`VmPeak` is lifetime virtual high water. They include startup/warmup and are not
measurement-window deltas or proven physical peaks. `VmStk` describes stack
segments, not used/peak stack or the sum of all thread stacks. Stack limits are
configuration, not allocation or usage. These observations establish no minimum
RAM or whole-object/whole-process ceiling. Socket/kernel allocator metadata,
allocator overhead, runtime, initialization and true physical/stack peaks remain
separate OPEN accounting items.

Focused fixture/portable tests establish software behavior only. Actual Linux
proof for #185 remains pending. Run `40065560596` is pinned to companion
`430722d73818e6b23ceecc6e6edb567a20111958`, has **none of these new fields**, and
cannot be retroactively credited. Both #650 50% CPU targets and whole-memory
acceptance remain OPEN; no new campaign is authorized by this addition.

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


### Representative C1 resource profiles

`--resource-profile` defaults to `host-control`, preserving the existing host
matrix, including its separately enlarged 65536-byte body fixture. Other choices
require `--server-kind coaptic-mio`, no candidate adapter override, concurrency 1,
message type `con` and admission diagnostics off. Both labels use the same profile,
Mio driver (32-poll burst, eight events, immediate sends) and baseline-built client.
Unsupported combinations refuse before builds. Select sizes explicitly:

- `small-device`: 32 bytes; fixed Constrained, route capacity 4 (one populated),
  one Call, zero deferred, one association/four request bindings; RX/TX each
  2 x 1152, dedup 4, Observe 2, no body pools.
- `small-blockwise`: 64,1024,4096; the same dimensions with one RX and one TX
  body, each 4096 bytes. This is configured blockwise, not the body-free preset.
- `service-fixed` and `service-allocated`: 64,1024,16384; route capacity 32 (one
  populated), four Calls, eight deferred, one association/four request bindings;
  RX/TX each 32 x 1472, dedup 64, Observe 32; four RX and four TX bodies, each
  16384 bytes. Allocated storage uses an explicit required-heap request limit.

For example, use `--resource-profile small-device --server-kind coaptic-mio
--sizes 32 --rates 100,1000 --seconds 10 --repeats 4`, keeping the immutable source,
existing build lane and fresh evidence arguments above. The server binary accepts
the same `--resource-profile` option. The original `coaptic-small` spin quick
fixture is unchanged.

The startup ledger checks actual capacities, security and representation against
the selection before measurement. All profiles reserve the full 2049-byte Mio
scratch, even with 1152-byte datagrams. Scratch/adapter/fixed pools are nested in
App inline size. Allocated payloads and metadata are included in the separate
requested heap; representation backing, Poll and Events are separate owners.
SmallDevice borrows the static 32-byte representation; other representations own
exactly their declared byte count on the heap. Event heap, allocator overhead,
initialization/peak stack, runtime and kernel costs remain unknown. These ledgers
identify configurations and owners; they establish no whole-memory acceptance.

Existing campaign/output/send bounds and every rate, pacing, CPU and latency guard
remain unchanged. Low-rate windows can lack sufficient CPU resolution; retain
them as ineligible. This C1 extension establishes neither independent-endpoint CON
coverage nor either 50% CPU target. Physical and release checks remain separate.

### Explicit long representative partitions

`--long-window --security-mode unprotected|oscore` enables **31..1500 clean
seconds** only for one representative profile, one payload and one rate, ordinary
Mio on both labels (`--candidate-server-kind` absent), C1 CON, independent
endpoints off, exactly four rotated pairs, perf and admission diagnostics off.
It produces eight clean windows and at most 12,000 scheduled clean seconds.
The default remains both security modes, 2..30 seconds and the existing short
campaign bounds/options. Individual security selection without long mode refuses
before checkout/build/native preflight. The workflow adds the same two inputs;
select `perf=false` explicitly. Its default job limit remains 60 minutes; explicit
long jobs have a hard 360-minute ceiling including setup, builds and cleanup.

For a separately predeclared partition on committed clean source, use the usual
immutable baseline/candidate, existing lane and fresh output arguments, plus
`--resource-profile small-device --server-kind coaptic-mio --sizes 32 --rates 100
--seconds 599 --repeats 4 --long-window --security-mode oscore`. This is an example
plan, **not an authorized campaign or a qualified duration**. A single-security
partition is partial matrix evidence. All four pairs must stay together; every
individual window must pass the unchanged twenty-tick CPU floor, rate/pacing,
complete-operation and cleanup gates. Every pair AND pooled stratum must retain
the existing median +2 microsecond and p99 +10 microsecond latency guards.
Passing pooled values cannot erase a failed pair. No sub-floor pooling or process
clock substitution qualifies a window, and this software change establishes no
CPU reduction. Both #650 targets and #183 Linux qualification remain OPEN.

Operations remain <=60,000, with the stricter necessary pre-build minimum
`ceil(payload/1024) * (operations + 20 warmups) <= 60000`. One live global sender
counter still charges warmups, measured requests, retries and controls. Ideal
maxima are 59,980 one-block, 14,980 four-block and 3,730 sixteen-block operations;
actual extra sends can refuse earlier. Some required cells remain impossible
regardless of duration. Pools, packet/Call/body capacities, representations,
nonce/replay state, cancellation/collection and pacing are unchanged.

Only explicit native `--long-window` permits a paced dispatch span <=1500 seconds;
the default remains 120 seconds. Native long mode requires paced C1 CON, spin,
no diagnostics/independent endpoints and the same **3000 ms deadline for each
complete operation**, including its entire Block2 representation. Short functional
flag checks need not wait 31 seconds; the acceptance runner enforces that lower
bound. Request/manifest/results record the selection, partial-matrix status and
limits; native reports include selected pacing/deadline/send limits and minimum
planned sends. Historical reports/manifests remain readable without these fields.

The long measurement wait has one absolute monotonic deadline, set before
releasing the client: `ceil(D/0.95) + 3 + 10` seconds, hard capped at 1600
(1592 at D=1500). The full bounded line read shares that deadline; partial reads
do not restart it. Ready/startup guards, report 15 seconds, profiler, cleanup and
900-second build-command deadlines remain unchanged. The independent diagnostic
runner's 120-second planning guard is outside this path and remains unchanged.
Unresolved cleanup remains fatal and vetoes comparisons.

### Optional C1 admission-interval diagnostic

`--admission-diagnostics` is explicitly opt-in in the native client,
`native_diagnostic.py` and this runner; the workflow boolean defaults to false.
Use it to inspect the interval missing from an RTT-only C1 trace. It requires
an explicit rate and concurrency 1. The campaign also requires **identical full
core SHAs**, one explicit adapter for both labels (`candidate_server_kind=same`
in the workflow), and **perf=false**. Profiling with this diagnostic is refused
before setup/builds. Existing clean defaults and eligibility gates stay unchanged.

For example, with committed clean source and an assigned compatible lane:

```sh
python3 tools/benchmark/linux_cpu.py \
  --baseline-sha 7ab6949d9604133c7f8ed8904e424b8657630d50 \
  --candidate-sha 7ab6949d9604133c7f8ed8904e424b8657630d50 \
  --build-lane /existing/compatible/cargo-lane \
  --output /fresh/evidence/admission-intervals \
  --sizes 64,1024 --rates 4000 --seconds 12 --repeats 4 \
  --server-kind coaptic-mio --concurrency 1 --message-type con \
  --admission-diagnostics
```

Both labels run the same instrumentation with the frozen baseline client.
The 32 windows retain all 1,536,000 measured operations plus 640 warmups, with
48,020 minimum sends per socket. This is a diagnostic cohort. CPU aggregates
always set `comparable=false` and `server_cpu_ratio=null`, even if every original
gate passes. Any instrumented window vetoes ratios throughout a mixed campaign;
do not combine diagnostic and clean observations. Raw CPU readings, latencies,
startup refusals and operation failures remain available for inspection.

Definitions use the existing Instants, with no additional per-operation clock:

- `A`: admission `now`, before request construction/send, also the latency origin.
- `C`: previous successful fully authenticated, completely verified, in-deadline
  completion. Warmup is excluded by a fresh measured-window state.
- `D`: the absolute scheduled operation start; `P=floor(1e9/rate)` nanoseconds,
  matching the existing missed-period test.
- `E=A-max(D,C)`, using saturating durations. For admissions with C,
  `prior_forced_missed` counts `C-D>=P`. Otherwise a missed start `A-D>=P`
  increments `crossed_missed` in the selected residual bucket.
- `idle_sleep` and `no_idle_sleep` partition admissions with C by whether the
  existing idle sleep branch was traversed since C. Each retains admission count,
  positive residual count, crossed misses, total E and maximum E. Traversal counts
  even if the existing sleep clock yields a zero-duration sleep. The active-Call
  `sleep1` poll policy is not this idle branch.
- First admission has no C: `first_admissions`, `first_missed` and
  `first_lateness_ns=A-D` account for it explicitly, outside the residual buckets.
  First misses + prior-forced misses + both crossed-miss counts reconcile exactly
  with the original missed-start count. All diagnostic admissions reconcile with
  the original pre-send `attempted` count, including a subsequent send refusal.
  Early schedule checks and deadline refusals before that boundary add no counters.

C retains earlier admission debt; a short preceding RTT does not remove it.
These are local interval categories, **not causal sleep, server or VM shares**.
E includes unmeasured caller/scheduler work between those timestamps. Branch
traversal does not measure sleep duration or sleep overhead, and prior-forced
misses do not establish a root cause. No pacer defect, CPU reduction, latency
acceptance or whole-RAM claim follows. Send/poll order, pacing waits, authentication,
nonce/replay state, deadlines, cancellation and normal latency sampling are unchanged.

Storage is fixed local counters plus one previous Instant and a traversal flag;
all diagnostic arithmetic saturates. The optional JSON member is serialized only
after measurement and is bounded to 2 KiB including its key/comma, even at maximum
u64/u128 widths. `storage_bytes` and `option_storage_bytes` record actual compiled
layouts; neither is a whole-stack or whole-process memory measurement. The
disabled native report has no added member and does no detailed interval work.
The runner records the selection and limits in its request/manifest. The 2 KiB
is carved from the existing 64 KiB raw-report fixed reserve: 63,488 bytes for
ordinary fields/newline plus 2,048 bytes for the optional member. Summary base
fields are separately checked within 6 KiB, leaving 2 KiB inside their existing
8 KiB bound; result/index entries retain their existing 16 KiB caps. The
32-window metadata allowance remains 42,770,432 bytes. No reserve, artifact,
send, sample or campaign ceiling is raised.

### Optional clean-window process CPU clock

Clean windows attempt a supplementary Linux process CPU clock for both the owned
server and frozen client. The reviewed binding supports Linux x86_64 LP64 with
glibc 2.39. Other ABIs and unavailable symbols or Python readers produce explicit
unavailability. Resolve [`clock_getcpuclockid(pid)`](https://man7.org/linux/man-pages/man3/clock_getcpuclockid.3.html)
once per child outside measurement and check its positive error return directly,
without consulting `errno`. Python's `clock_getres` and `clock_gettime_ns` wrappers
handle the native `timespec` layout. No clock ID arithmetic, PID zero, self clock,
thread clock or wall clock substitution is used.

One `process-cpu-clock.json` sidecar, capped at 4 KiB within the existing 96 MiB
metadata allowance, retains setup, two raw readings per peer and CPU nanoseconds
per verified operation. For 32 clean windows this reserves an additional 131,072
bytes; the 96-window maximum adds 393,216 bytes without raising the global cap.
The index retains only a filename. Original PID, start ticks, parent, group and
session bracket every read. Helpers never poll or reap: the serial runner must
remain the sole child reaper. The new before pair precedes the original psutil
snapshots; the after pair follows the original after snapshots and resource
timestamp. These serial observations include additional boundary and idle work.
The workload, client traffic and per-operation instrumentation stay unchanged.

The clock includes all process threads, excluding descendants and unattributed
whole-machine interrupt or kernel-worker CPU. It supplies no user/system split.
CPU can exceed wall time with multiple threads. Nanoseconds are output units;
a reported 1 ns resolution does not establish 1 ns accuracy. Host variation
remains. Keep process CPU, attached-thread schedstat and wall durations separate;
their different observation windows do not support subtracting their values.

Original tick CPU, the 20-tick minimum, workload, pacing, security, failure and
cleanup gates, latency guards and aggregate ratios remain authoritative.
Unavailability or sidecar retention errors cannot rescue an ineligible cohort.
No supplementary aggregate ratio or retroactive precise value is emitted.
Both representative 50% CPU/op targets remain open.

The existing Python discovery includes one Linux-only real-binding smoke test.
It skips Windows and unsupported ABIs. On the supported ABI, binding, identity,
accounting and cleanup failures fail the test. One owned new-session Python child
performs finite gated work targeting 20 ms of CPU, bounded by 20,000 blocks and a
checked two-second work deadline. The test retains two raw clock readings in one
bounded diagnostic receipt, with errors and cleanup state. It sends no UDP or
capture traffic and establishes no workload CPU gain or clock accuracy claim.

### Compare scheduling at one core revision

Use `--candidate-server-kind` to compare two explicit adapters at **identical core
SHAs**. Combining adapter and core changes, `all`, or identical adapter names is
refused before builds. Defaults and the three adapters selected by `all` stay
unchanged; `coaptic-async`, `coaptic-blocking`, `coaptic-staged-ready` and
`coaptic-staged-mio` must be
selected explicitly. The manual workflow's
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

The explicit `coaptic-staged-ready` fixture stages an actual nonblocking receive
in ReadyUdp's existing 2049-byte scratch before App polling. Empty transport
probes do not run App maintenance. One staged datagram adds capacity beyond the
unchanged Engine RX pool; it survives RX refusal and pins. N+1 truncation checks
use the configured receive capacity, and only WouldBlock means empty. Sends
delegate to the original immediate `try_send_to`, without writable waits, retries
or socket timeouts. Fresh time and due/local work are checked before receiving
and after readiness wakes. Every 32 work turns yields, including empty probes
and immediate readiness returns. External application signals, pin releases and
policy changes still need an independent wake source; this fixture uses static
handlers.

Its flushed `coaptic-native-server-resources/2` startup line declares staging
capacity one, Stage metadata bytes, the immediate send policy, adapter/App sizes,
and separate Driver and borrowing-loop-future sizes. Scratch and Stage belong
to the adapter, which belongs to App. The loop future borrows App and Driver;
the complete outer setup future is not measured. Test counters compile out of
ordinary builds, whose layouts are reported directly at startup. Do not add
nested sizes or infer whole-system RAM: core/body heap, runtime allocations,
allocator, outer future, thread/polling stacks and kernel costs remain unknown.
The bounded startup parser rejects blocking timeout-policy fields for this mode.

For one clean same-core scheduling comparison, leave profiling off:

```sh
CORE_SHA=b428572774ae4e57259f562b38e268f40fcadd7b
python3 tools/benchmark/linux_cpu.py \
  --baseline-sha "$CORE_SHA" --candidate-sha "$CORE_SHA" \
  --build-lane /existing/compatible/cargo-lane --output /fresh/evidence/staged-ready-ab \
  --sizes 64,1024 --rates 4000 --seconds 5 --repeats 4 \
  --server-kind coaptic-ready --candidate-server-kind coaptic-staged-ready
```

This plans four security/body cells, 32 clean windows, 160 scheduled seconds and
640,000 measured operations, plus 640 warmups. Each fresh socket needs at least
20,020 outbound datagrams, with retries subject to the live 60,000-send ceiling.
The same companion/core/compiler/locks and frozen baseline client drive both
adapters with existing AB/BA rotation. Eligibility and latency guards remain
unchanged; keep failures and withhold ineligible cohort ratios. Selection and
finite correctness checks establish no CPU gain or representative 50% target.

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

The raw reader accepts the earlier single-clock layout or the observed
clock-plus-dummy layout with `IDENTIFIER`. Every sample must bind to the requested
clock's IDs and target PID; tracking metadata and loss stay separate. Other
layouts are retained and refused.

[Run 39855681794](https://github.com/jeffglousher/coaptic-validation/actions/runs/39855681794)
passed all 57 selected Linux tests, then refused enable ACK before releasing work.
No measured CPU receipt exists. Its partial samples and eventual log messages do
not establish startup latency, the failure cause or sampling density.

Upstream 6.17.13 accepts newline or NUL commands, opens both FIFOs read/write and
nonblocking, and sends ACK after handling enable/disable. The current framing is
supported by its [control implementation](https://github.com/gregkh/linux/blob/v6.17.13/tools/perf/util/evlist.c#L1890-L2229).
Its [startup loop](https://github.com/gregkh/linux/blob/v6.17.13/tools/perf/builtin-record.c#L2560-L2801)
initializes control before synthesis. These facts do not prove the runner binary's
patches or failure mechanism.

Metadata retains spawn, command, deadline, refusal and ACK observations. Legacy
`deadline_exceeded` covers either timeout; `control_timeout_boundary` identifies
`ACK` or `capture`, while `capture_deadline_exceeded` records absolute expiry.
An independent regular-log reader uses 4096-byte chunks, a 64-byte tail and the
existing file quota. Fixed marker timestamps are first observations, not emission
times or ACKs. Log text cannot release work or move perf's write offset.

After refused control and confirmed reap, a nonblocking drain retains late bytes
as hex and observation timestamps within the same 64-byte channel allowance.
It preserves the refusal and successful ACK count and never reopens the gate.
These changes repair missing failure evidence; timely enable/run/measured/
disable/stop and a verified worker receipt are still required for comparison.

Record passes also retain separate `/proc/PID/schedstat` observations around the
existing workload gates. Each snapshot brackets its reads with monotonic times,
checks PID/start-time identity before and after, and bounds reads to 4096 bytes
for `stat` and 128 bytes for the three scheduler counters. The counters report
attached-thread CPU runtime, runqueue wait and timeslices; see the
[kernel contract](https://docs.kernel.org/scheduler/sched-stats.html#proc-pid-schedstat).
These are additional observations, not replacements for process user/system CPU.
Clean/stat passes and all existing eligibility gates are unchanged.

Unavailable, malformed, changed-identity, multi-thread or regressed observations
cannot supply a runtime delta. Zero runtime and deltas beyond the observation
envelope are refused. Original observations and bounded reasons remain visible.
Single-thread counts at the gates do not prove no transient thread existed;
these values never cover descendants or machine-wide interrupt/worker costs.
The read envelopes are not exact workload timestamps. New Linux execution must
qualify this accounting before any density or CPU-per-operation conclusion uses
it. This diagnostic removes no application work and establishes no CPU gain.

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
Callchain display and inline expansion are disabled in this flat view; the
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

Socket record windows explicitly request two additional readouts after the
capture and flat report succeed, on that runner while the copied ELF paths exist.
`perf-callers.txt` uses `perf report --sort pid,dso,symbol --children --call-graph
graph,0,caller --inline --percent-limit 0 --percentage absolute`, retaining the
header, sample and period totals. `perf-samples.txt` uses `perf script --ns
--demangle --inline --show-task-events --show-lost-events -F
comm,pid,tid,time,event,period,ip,sym,dso`. Both explicitly filter `--pid` to the
capture's positive server PID and use `--force --input OWNED_PERF_DATA`.
The sampling controls and other default `perf_pass` callers keep their flat-only
behavior; clean and stat windows do not run these additional helpers.

Each readout runs sequentially through the existing elevated owned-process path,
with the current per-file quota reapplied by `prlimit` after `sudo -n`, empty
`DEBUGINFOD_URLS`, and `timeout --foreground --signal=TERM --kill-after=5 25`
inside the 30-second owned wait. Exact argv, PID, output size, limits, exit and
error/deadline status are retained under `attribution` in `perf.json`. A failed
capture, failed window or unavailable flat report explicitly skips attribution.
An unavailable first readout skips the second without retry; partial output and
warnings remain. Unresolved process or output-close cleanup prevents another
readout and aborts the campaign through the existing fatal flag. Readout
availability establishes no inline completeness, App ancestry, eligible sample
count, exposure, removable cost or CPU share. Source-guided review must still
establish at least 200 eligible App-rooted samples per cohort/source, with
user/kernel/client costs and unknowns kept separate. Strict raw/report count
integrity, including refusal of rounded sample headers, remains unchanged.
This source integration has no native Linux readout qualification by itself.

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
75,784,960 metadata bytes including 96 process-clock sidecars; the optional
admission member uses the existing fixed report/summary reserves and adds no
allowance. Report status fits the existing capped `perf.json`.
Each perf data/stat output has a hard `RLIMIT_FSIZE` applied **after sudo**;
its command/version log, flat report and two inline readouts have the same quota.
Reserve **five file quotas per profile pass**, conservatively including the
three report/readout quotas for stat passes too. The per-file quota is
`min(8 MiB, floor(160 MiB / (5 * profile_passes)))` when profiling is enabled.
The original metadata/profile allowance of **256 MiB excluded copied binaries
and setup logs**; historical manifests retain that narrower meaning. It was not
a whole-upload bound. Now a named **WHOLE_UPLOAD_BUDGET = 256 MiB** includes all
uploaded owners: planned metadata (including build/window logs), actual copied
binaries, a combined **16 MiB setup-log reserve** when supplied, and all five
quotas per profile slot. Each binary still has its existing 128 MiB copy limit;
four such maxima cannot fit and will refuse before measurement. After copying,
the runner reduces only capture quotas as needed within their existing per-file
maxima, or refuses if the whole plan cannot fit. Clean work/latency/output caps
and profiling defaults remain unchanged.

The workflow bounds shell setup-log files to 2 MiB during production, uses the
existing 2 MiB bounded command helper for native setup, and checks their combined
reserve before each native check. `--setup-logs` names the disjoint upload owner.
The runner checks actual setup bytes and actual copied binaries with planned
metadata/captures before measurement, and verifies actual final upload bytes.
The workflow independently verifies both upload roots before upload, including
failure paths; excess refuses upload without deleting evidence. Nested owners
are never added twice. Credentials and the build lane stay outside uploads.
This is a retained-file bound, not a transient disk, RSS, allocator, runtime or
peak-memory measurement. Default timeout is 60 minutes, explicit long timeout
360 minutes, artifacts retain 14 days, and the
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

Exit observations use Linux `waitid(WNOWAIT)`: the sole owner retains the
unreaped direct leader through the final group signal, then reaps it. Already
reaped/non-waitable leaders and non-default SIGCHLD handling refuse numeric group
signaling. Elevated cleanup always invokes the privileged TERM and KILL helper;
unprivileged group-signal success alone does not prove privileged members were
reached. Helper refusal remains fatal even when other cleanup actions succeed.
After KILL, bounded process pidfds observe complete thread-group exit before the
reserved leader is reaped or capture handoff is permitted. A zombie thread-group
leader alone is insufficient. Two `/proc` censuses allow at most 4,096 entries
each, 4 KiB per stat, 64 retained pidfds and one five-second observation deadline;
mount visibility input is limited to 64 KiB. These are external runner cleanup
resources, with at most one directory and one stat handle in addition to pidfds;
they add no server transport owner or per-operation worker. Proc visibility,
namespace, membership, acquisition or exit uncertainty refuses settlement. The
deadline is checked between bounded syscalls and is not a hard real-time promise.
The original core probe keeps its worker in that reserved wrapper group with
`timeout --foreground`; worker/builder markers no longer authorize signals.
The build watchdog requests cancellation from the sole process owner. The
separate batch probe retains its pidfd/control-EOF custody protocol.

The manual workflow opts into bounded Linux mixed-UID and production launcher
success/timeout tests with `COAPTIC_PRIVILEGED_CLEANUP_TESTS=1`. Missing privileged
test prerequisites fail this opt-in rather than count as passing skips. These
tests and the direct transport tests must execute before the comparison; portable
mock tests alone do not establish production cleanup or descendant containment.

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

### Explicit staged Mio control

Select coaptic-staged-mio explicitly to combine direct Mio readiness (no Tokio
runtime) with one staged receive before synchronous App polling. It uses one
socket and the existing 2049-byte scratch, with a <=64-byte Stage and capacity
one beyond the unchanged four Engine RX slots. N+1 guarding occurs at ingress;
occupied stages survive short destinations, RX refusal, stop and errors. Empty
actual WouldBlock probes skip App maintenance; zero-length packets and every
other receive error pass through ordinary App polling. Sends use immediate
send_to refusal and short-send handling without writable waits or retries.

Fresh App::next_poll_at eligibility precedes probes and follows poll wakes.
Successful reads and advisory edge-triggered events never prove emptiness:
actual reads continue to WouldBlock. Every 32 total turns, including spurious
immediate wakes, yields the OS thread as a synchronous control checkpoint.
Production has no artificial lifetime or turn limit. External signals, pin
release or policy changes require independent wakes; no async cancellation or
absolute send deadline is promised.

Its single flushed schema-2 startup ledger passes the existing <=4096-byte
newline/deadline/exit gate before measurements. Scratch and Stage nest in adapter
in App; Driver separately owns Poll/Events. The ledger reports compiled inline
sizes with no future field. Core pools/body heap, Events/poller allocations,
stacks, allocator/kernel costs and whole RAM remain unknown. Existing selectors,
defaults, all, capacities, authentication and guards are unchanged. This
unmeasured fixture supports a same-core explicit adapter comparison; it claims no
CPU gain, causal stage/kernel result or completion of either 50% target.

### Bounded Linux direct receive control

Explicit `coaptic-mio-direct` uses Linux `recvfrom(MSG_TRUNC | MSG_DONTWAIT)`
through pinned safe Rustix bindings. It receives into the borrowed Engine RX
slot and refuses a returned original datagram length larger than that slot.
There is no adapter packet scratch, submitted completion, retained pointer,
worker thread, ring or future. Kernel access ends before the synchronous call
returns; cancellation and forgotten-future safety do not rely on Drop. Sends
use the same immediate Mio send_to path and Engine exact-length checks.

Both Mio kinds share one 32-pass drain/deadline loop. Consumed oversize input
continues draining until actual WouldBlock or the existing 32-pass checkpoint;
an oversize prefix is never parsed. Previously, this fixture exited on oversize
receive errors. The shared loop now preserves service and RX-slot recovery for
this specific input failure. Other transport failures remain explicit.

The experiment retains the same App capacities and adds no packet, selector or
runtime owner. Each startup ledger records enclosing App and adapter layouts,
separate Poll/Events owners and eight-event capacity. Scratch is nested in the
adapter, itself nested in App: never add those sizes again. Events heap, existing
App heap and representation storage, allocator overhead, peak stack and kernel
socket/epoll memory require separate accounting; null fields mean unknown.
There is one server OS thread and no offloaded worker CPU. This is not a complete
memory requirement or a demonstrated CPU gain.

The bounded comparison uses identical core
`b9b83d8663cbdcb7a80bf143670a05019f25cf25` for both labels, keeping the retained
syn-2 native lock compatible with the original runtime baseline and both existing
core-probe modes. Core main's later syn-3 manifest uses the separate source-specific
input described below; do not silently update a locked measurement. Use the committed companion revision containing this
control, a frozen baseline client, both security modes, 64/1024 B, 4,000/s, C1 CON,
twelve seconds and two rotated pairs, with perf and detailed diagnostics off:

```sh
python3 tools/benchmark/linux_cpu.py \
  --baseline-sha b9b83d8663cbdcb7a80bf143670a05019f25cf25 \
  --candidate-sha b9b83d8663cbdcb7a80bf143670a05019f25cf25 \
  --build-lane /existing/compatible/cargo-lane --output /fresh/evidence/direct-rx \
  --server-kind coaptic-mio --candidate-server-kind coaptic-mio-direct \
  --sizes 64,1024 --rates 4000 --seconds 12 --repeats 2 \
  --concurrency 1 --message-type con
```

The manual workflow runs Linux direct receive, authenticated operation,
saturation/error-recovery tests and strict Clippy before measurement. An
ineligible or latency-failing cell remains failed; no replacement cohort or
transport percentage follows from it. Two-pair host evidence cannot complete
both representative #650 targets. Keep Mio as the reference and existing defaults.

### Source-specific native lock inputs

The accepted original core and `b9b83d8` require syn 2 in `coaptic-io`; current
core requires syn 3. Keep `native/Cargo.lock` as the original input and
`native/Cargo.syn3.lock` as a separate committed input. They differ only in the
`coaptic-io` dependency edge, from syn 2.0.119 to 3.0.9; both package records
already exist. Both inputs retain LF bytes across normal Git checkouts.

After verifying the selected immutable core checkout, the build reads that core's
`crates/coaptic-io/Cargo.toml`. Only exact syn requirements `2` and `3` are
supported. It validates the input relationship, temporarily installs the selected
bytes, and runs the same Cargo command with `--locked`. No resolution/update
fallback exists. Success, Cargo failure and ordinary interruption all verify and
restore the original input before clean-source identity or binary acceptance.
Unexpected concurrent canonical edits remain untouched and refuse acceptance.
Failed restoration remains fatal; abrupt process death may leave a dirty lock,
which the next invocation must refuse rather than repair automatically.

Each build records `native_lock_input`: selected path and actual selected SHA256,
both committed input digests and the selected core manifest digest. The existing
`native_lock_sha256` is the digest Cargo actually consumed, not the original lock
after restoration. Paired builds must select from the same validated input pair;
compiler, target, release flags and native manifest matching stay unchanged. The
baseline-built client remains frozen for both labels. Direct transport preflight
uses the same selector and restores source before measurement.

Source and lane exclusivity are caller requirements: this is not a concurrent
writer or crash-recovery protocol. Fixture tests do not substitute for actual
locked builds. The fixed old-source `core_cost_probe.py` modes keep their original
lock and source pins. Other preparation helpers do not acquire syn-3 support from
this change.

### Independent local endpoints (explicit CON mode)

Select `--independent-endpoints --concurrency 2` (or 3/4) with CON and Mio.
One client App owns K connected loopback UDP sockets to the one actual server,
one OSCORE context/global sender sequence and globally unique Tokens. Private
namespace-zero Endpoint keys encode each full stable local/remote pair. Each
pair retains NSTART=1. Default C1 and shared-endpoint NON keep their existing
client configuration; NON is a separate cohort.

The new client uses five RX and five TX slots of 1472 bytes, K RX body slots,
four Calls/request bindings, one 1473-byte scratch and at most K receive attempts
per adapter receive. Pending rows reserve their sockets until terminal collection
or cancellation cleanup. There are no packet queues or workers. Adapter/sockets
and scratch are nested in App inline; requested core heap, verification and timing
heap remain separate. Kernel socket buffers, allocator overhead and peak stack
are unknown; no whole-memory or CPU improvement follows from this selector.
The 60000 outbound budget is global, including warmup, retries and controls.

The runner explicitly refuses SmallDevice concurrency, whose unchanged body
capacity cannot establish four overlapping bodies. Host-control multiblock
supports at most two endpoints; Service fixed/allocated support C2..4 with their
unchanged four TX bodies. Reports retain actual source ports, per-lane send/receive
lifetime counts, measured-window datagram deltas, per-lane fully verified
completion counts and completions while another Call was live. Raw datagram
counts include protocol/control/invalid traffic and are not verified operations.
The report names the bounded counter snapshot and Window metadata; neither
size is a measured peak stack. CPU acceptance additionally
requires actual observed overlap and service on every lane. A low-paced C4
parameter alone cannot establish C4 overlap. No concurrency campaign is implied.

Delaying one initial protected request while other endpoints advance the shared
sequence beyond the server's replay window can legitimately cause replay refusal,
even with only four live Calls. The fixture preserves this limitation and never
widens the replay window, clones contexts or promises recovery from arbitrary loss.

### Ended higher-rate sampling screen (#180)

[PR #181](https://github.com/jeffglousher/coaptic-validation/pull/181) added an
optional 9970 Hz diagnostic. Its single finite
[control run 40060666280](https://github.com/jeffglousher/coaptic-validation/actions/runs/40060666280)
stopped at the first cpu-clock continuous control: perf reported a rounded
`Samples: 4K`, so the existing exact raw/report count check refused it. The raw
reader independently verifies 4,990 samples (2,828 user and 2,162 kernel), but this does
not rescue the failed control. The other three controls did not run; burst and
pattern suitability are unproven. No retry or communication capture followed.

The report already requested `--show-nr-samples`; Linux 6.17's
[header formatter](https://github.com/torvalds/linux/blob/v6.17/tools/perf/builtin-report.c#L482)
scales its total unconditionally. The higher-rate experiment is withdrawn,
restoring the qualified 997 Hz code, workflows and tests from `8dc65fd`.
The parser, resource bounds, complete-operation checks and acceptance gates
remain unchanged. Raw failure evidence is retained; no diagnostic parser or
sampling infrastructure is added to extend this approach. Both 50% server CPU
targets remain open, and sample counts establish no CPU gain or transport share.

### Opt-in SmallDevice core wall probe (#187)

The existing socket-free native `bench-core` accepts one appended
`--small-device` flag after an explicit security mode:

```sh
bench-core 16 unprotected --small-device
bench-core 16 oscore --small-device
```

This selects the unchanged `SmallDevice::new()` fixed Constrained preset:
four route capacity/one populated GET, one Call, zero deferred rows, one
association/four request bindings, RX/TX each two by 1,152 bytes, dedup four,
Observe two, blockwise off and no body pools; the complete response is 32 bytes.
It constructs only that App, with startup storage reused and no automatic growth.
The existing `bench-core OPERATIONS [unprotected|oscore]` Default/Alloc 64-byte
CLI and JSON shape stay supported. The fixed 50,000-operation `--batch-cpu`
mode remains separate; mixed flags, unknown options and extra arguments refuse.
Existing `core_cost_probe.py` source pins and workflows are unchanged.

Wall mode permits 1..60,000 measured operations plus 128 distinct-MID warmups.
Each poll retains optimizer barriers around the App, monotonic input and result;
fixture receive/send copies, dispatch, maintenance and server crypto remain
inside that same timed `App::poll`. Request preparation/protection and complete
ACK MID, Token, code, content-format, single ETag, payload and absence-of-Block2
verification run outside. OSCORE responses must authenticate. The 4,096 clock
calibrations are separate and never subtracted.

Only the opt-in JSON adds profile/payload/capacity and memory fields. App inline
includes fixed pools, security and CoreIo; its transport size and two 1,472-byte
fixture buffers are nested owners, not additional App bytes. These fixture
buffers are distinct from the preset's two 1,152-byte RX and TX slots and do not
establish native Mio memory equivalence. Timing vector payloads/headers,
the 1,472-byte verification buffer, optional client context and 32 static
representation bytes are named separately. Requested vector capacity excludes
allocator overhead; initialization, generated peak stack and runtime costs
remain unknown. This is no whole-memory ceiling.

Build the same probe source against both immutable cores with Rust 1.99.0,
the existing native release profile (`std,alloc,oscore`, defaults disabled,
thin LTO/one codegen unit), `--locked` and the source-specific lock selector
above. Freeze physical source/patch, compiler/flags, selected lock and both
actual executable hashes before finite matched functional checks; restore the
canonical lock and junction afterward. Preserve failures. Windows functional
proof and per-poll wall arrays are supporting evidence only: they do not qualify
future Linux/profile probes, socket latency, server CPU, transport share, peak
stack or whole RAM. Both 50% targets and the remaining matrix obligations stay open.

For the remaining Linux #187 functional proof, the existing **Manual fixed
socket-free core cost diagnosis** workflow has one explicit `small-device-proof`
choice. Select a reviewed immutable companion commit containing the unchanged
PR #188 probe; the parent authorizes any dispatch. This fixed mode builds original
`b8f44fa16b3e16f4c9c6cc5f1205d2aee9cb0b57` and accepted
`d23f93c0699b75ec17e692999d62ff89bb71463d` serially with source-specific locks,
Rust 1.99.0 and the existing Linux release flags. Ten unfiltered release tests
must actually pass per core. Both copied executable/source/lock/compiler records
are frozen before eight fresh serial processes: each core, both security modes,
SmallDevice32 and the old Default64 control, sixteen operations plus 128 warmups
per cell. All 1,152 exchanges must fully verify; 32,768 separate calibrations
remain unadjusted. Each process has a 30-second deadline, 512 MiB address-space
limit and separate 512 KiB raw output limits through the existing owned-process
group/thread settlement path. Native source barriers and verification are unchanged.

The opt-in phase restores the initial hosted b8 checkout and exact canonical lock
before cells and on ordinary exit, refusing unexpected edits; abrupt job death
cannot guarantee restoration, so the next clean gate refuses leftovers. It reserves
16 MiB for non-ELF records, including final receipts, and at most 111 MiB for the
two copied ELFs within a 127 MiB proof owner; the entire upload including the
existing test log must pass 128 MiB. Failed/refused cells remain raw and later
cells stay NOT RUN, with no retry or replacement. Actual Linux inline sizes and
nested fixture owners are captured without assuming Windows sizes. Legacy
`original` and `server-app-batch-cpu` choices keep their pins/plans and batch-only
custody checks. The new mode does not invoke their profiling/CPU phases.
Linux execution and independent receipt review remain pending until a separately
authorized run completes. Issue #187, both 50% targets, remaining representative
probes and whole-memory acceptance stay open; this workflow adds no CPU or
statistical wall-time claim.

### Opt-in complete Service core wall probe (#190)

The existing socket-free executable also accepts explicit C1 Service modes:

```sh
bench-core 16 unprotected --service-fixed 16384
bench-core 16 oscore --service-allocated 16384
```

Only payloads 64, 1024 and 16384 are supported. Both storage choices preserve
Service's 32 routes/one GET, four Calls/eight deferred rows, one association/four
bindings, RX/TX 32 by 1472, dedup 64/Observe 32, and RX/TX four bodies of 16384.
The separate allocated full-response client has one route/no handler, four Calls,
zero deferred rows, one association/four bindings, RX/TX four by 1472, dedup
eight/Observe four, one 16384 RX body and one 1024 TX body. Startup pools are reused
without growth. One client Call owns each complete operation; no C4 claim follows.

For 16KiB the initial CON requests 1024-byte Block2 fragments. Two real Apps
exchange through two counted single-packet ports, each with nested 1472-byte input
and output buffers. No extra bridge buffer or queue is added. Every wire response's
ACK/MID/Token is checked against its request. Client App authenticates OSCORE and
assembles the complete varied body; terminal collection verifies code, format,
single ETag, peer, first-fragment MID/Token and all bytes. Completed Block2 metadata
retains the first fragment header (possibly NUM0/M=1); it is not compared to the
last continuation MID or rejected merely for containing Block2.

Each reported `server_poll_wall_sum_ns` is the sum of **every server App::poll wall
interval** for one fully verified operation; `server_poll_counts` records clock
multiplicity. Server receive/send fixture copies, maintenance, dispatch, body
snapshot and crypto stay inside those intervals. Bridge copies and client request
preparation, polls, protection, authentication, assembly and verification are
outside. Optimizer barriers retain observable inputs, App results and full bodies.
The 4096 clock calibrations remain separate and are never subtracted.

Absolute three-second deadlines cover initial send through verification, with at
most 32 rounds. Each port permits at most 30000 accepted sends: the combined
60000 bound includes 128 warmups, continuations, retransmissions and controls.
Admission requires `(operations+128)*ceil(payload/1024)<=30000`: measured ceilings
are 1747 for 16KiB and 29872 for 64/1024; runtime refusal can occur sooner. Missing
packets, unexpected extra work, occupied ports or failed verification stop the run.
Old modes retain their existing limits, layouts and output contracts.

The new JSON names actual inline Apps (including security, scratch and transports),
requested allocated pools, nested pool payloads, all four nested packet buffers,
and separate static 16384-byte representation, reusable verification buffer,
timing/poll-count/calibration payload capacities, vector headers and pending metadata.
Fixed server pools request zero heap. Nested owners must not be added twice.
Allocator overhead, initialization temporaries, generated peak stack and runtime
remain unknown; these are not Mio sizes or a whole-memory ceiling. Fixed Service
construction uses a separate safe entry point, without boxing or another thread;
stack fit must be validated for each executable's recorded process stack budget.

Build the same source against immutable b8/d23 using source-specific locks and the
pinned Rust release configuration. Freeze both actual executable/input identities
before eight finite 16KiB cells (two cores, both securities, both storage choices).
Sixteen measured plus 128 warmups per cell means 1152 verified operations and
32768 separate calibrations. Preserve failures and restore the canonical lock and
junction. Windows functionality is not Linux qualification. Existing Small32
workflow source pins and legacy helper plans remain unchanged; any future Service
Linux integration requires a separate reviewed change. This wall supporting
evidence cannot rescue failed socket guards, establish CPU/transport shares or
either 50% target. #190 Linux proof and whole-memory acceptance remain open;
delivered #187 is not reopened.

For the separate #190 Linux functional proof, select the explicit `service-proof`
mode in that same existing manual workflow only after parent review/dispatch
authorization. It uses the PR #191 Service probe Git blob
`dbffc02293898336087a640cd4b61cca5eb70d5e` (Linux LF SHA256
`5ff878db5d1f0eadc0e85da789cb12fe1e5508146874d5440f07d60f147051c6`),
with immutable original b8 and accepted d23. The earlier `small-device-proof`
choice keeps its PR #188 source pins and Default64/Small32 plan; it does not
qualify the newer Service source. Legacy original/batch modes are unchanged.

Service mode requests the pinned Rust 1.99.0 Clippy component and requires all
16 unfiltered release tests plus strict binary-target release Clippy per core,
inside the selected native-lock context. The existing paired build, identity,
4 GiB lane/900-second build/log watchdog, restoration, copy and input-freeze
paths are reused. Both actual copied ELFs, selected locks/manifests, compiler,
native target, features, flags and probe/helper identities freeze before any
native cell. The 25-minute job remains a hard bound.

Exactly eight serial fresh processes cover the two cores, unprotected/OSCORE,
and fixed/allocated Service at 16KiB. Each has 16 measured operations plus 128
verified warmups and 4096 separate calibrations: totals are 1152 verified
operations, 32768 calibrations, 18432 server polls and 36864 accepted sends.
The exact 21-key raw schema, type/u128/count bounds, capacities, wall/authentication
scope and nested/separate owner ledger must validate. Every operation requires
16 server polls; each process reports 2304 sends per port, including warmup.
Immutable native code retains the three-second operation deadline, 32-round
ceiling and 30000 accepted sends per port/60000 combined global limit.

Actual GNU owner figures are bounded and recorded, then frozen as references
for matching source/compiler/configuration cells. Fixed heap is zero; allocated
requested layouts include pool metadata/alignment. Server/client payloads
225280/29184 bytes nest in fixed App or requested heap; four 1472-byte fixture
buffers nest in their transports inside Apps. Static representation, verification,
timing/poll counts, calibration, vector headers, pending metadata and clock are
separate. Security and profile scratch nest in Apps. Allocator overhead,
initialization, peak stack and runtime remain unknown. No Windows or Mio App size,
portable minimum, or whole-memory equivalence is assumed.

Each process retains the existing 30-second owned-process deadline, 512 MiB
address-space limit and separate 512 KiB raw-file bounds. No CPU/perf or socket
phase runs. First failure keeps subsequent cells NOT RUN, with no retry; cleanup,
source/lock restoration and independent final identity failures remain fatal.
The existing 111 MiB paired-ELF, 16 MiB non-ELF, 127 MiB proof/<100-file bounds and
final-receipt reserve remain, with the whole 128 MiB upload gate including setup,
test and Clippy logs. Overbudget evidence refuses upload rather than trimming.

Local actionlint/AST/pure checks do not establish Linux execution. #190 stays open
until the separately authorized finite Linux run and independent receipt review
complete. #187 stays closed. Both 50% targets, whole memory and physical/release
gaps remain open; these wall arrays cannot replace failed socket cohorts or
establish CPU gains or transport shares.
