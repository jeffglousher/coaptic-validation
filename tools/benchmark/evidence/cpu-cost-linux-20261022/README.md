# Linux CPU results: target unfinished

[Run 39779276076](https://github.com/jeffglousher/coaptic-validation/actions/runs/39779276076)
completed 24 clean windows, 12 sampling passes and 12 counter passes. All
1,872,000 measured operations passed complete response verification, including
OSCORE authentication in protected cells. There were no failed operations,
incomplete windows or unresolved process cleanup. All 52 runner tests passed
on Linux, including the real process and Git-index checks.

The first core optimization batch does **not** establish a 50% CPU reduction.
At matched load, candidate/baseline server CPU changes range from a 4.7%
reduction to an 8.8% increase across these cells. Two rotated pairs on hosted
hardware do not establish small regressions or improvements reliably.
[Core #650](https://github.com/jeffglousher/coaptic/issues/650) remains open.

Each clean window runs 48,000 complete 64-byte GET/CON operations at 6,000/s,
with one outstanding Call. Both revisions use the same frozen baseline client.
The fixture uses Default/AllocMemory, four RX and four TX datagrams, eight
dedup rows, four Observe rows, one RX body and two TX bodies. This is a host
configuration, separate from SmallDevice/Constrained qualification.

Aggregate server process CPU per verified operation, baseline to candidate:

- Spinning reusable socket: 166.67 to 166.88 microseconds unprotected;
  166.67 to 166.56 microseconds OSCORE.
- Mio readiness: 17.81 to 19.38 microseconds unprotected;
  22.40 to 21.35 microseconds OSCORE.
- Tokio readiness: 21.35 to 22.71 microseconds unprotected;
  23.65 to 24.79 microseconds OSCORE.

Readiness avoids much of the CPU consumed between requests. It also changes
latency: candidate median RTT is 17.79/21.11 microseconds spinning,
31.72/35.02 with Mio and 36.73/37.84 with Tokio, respectively unprotected/OSCORE.
These are separate scheduling strata; that saving is not a core speedup or
evidence that the complete performance target is achieved. Client CPU and all
raw latency samples are retained separately.

Each per-revision result pools the 96,000 clean latency samples from its two
windows. The median averages the middle two sorted values; p99 uses nearest
rank `ceil(0.99 * N)`. CPU cost divides summed process user/system time by the
96,000 verified operations, rather than averaging rounded window costs.

Clean achieved rates are 5,999.998 to 6,000.097/s. Missed whole pacing periods
remain below 0.613% in every clean window; late starts catch up without drops.
The process CPU clock has 10 ms ticks, with at least 81 server ticks per window.
Accounting includes server user/kernel time, idle work and control boundaries.
It does not attribute unrelated interrupt or whole-machine kernel work.

Sampling supports investigating repeated receive and poll maintenance work.
The reusable candidate resolves `recvfrom` at 8.50% unprotected and 10.12%
OSCORE, and `poll_engine` at 7.09% in both modes. Treat these as exploratory
self-sample costs: 1,476 of 1,479 kernel samples are unresolved addresses;
three resolve an existing host BPF probe that this runner did not configure.
Readiness captures have only 27 to 53 samples each. All reports retain perf
header warnings and zero first/last/duration fields, so zero reported lost
samples does not establish full-window coverage. Hardware cycles/instructions
are unsupported; task-clock and scheduling counters are retained.

Server RSS snapshots span 4,395,008 to 4,960,256 bytes. They are not a server
storage ledger, peak measurement or minimum RAM requirement. The client ledger
includes its App, requested heap, verification and timing arrays; its UDP scratch
is already inside the App figure. Whole-system memory remains unfinished.

The exact companion source is `4be0a2e189b0d768f5f16539cb1edf5102e91884`
(same tree as merge `165fa5c`). Core baseline is
`b8f44fa16b3e16f4c9c6cc5f1205d2aee9cb0b57`, candidate
`21f6dea85fb49bd766b405b3d48f58e76976ae1d`. Both builds actually used
Rust/Cargo **1.99.1**, LLVM 23.1.1, x86_64-unknown-linux-gnu, release,
debuginfo 1 and forced frame pointers on an AMD EPYC 7763 hosted runner with
four available logical CPUs. The workflow selected 1.99.0, but the repository's
stable toolchain overrode that default. Preserve these as matched 1.99.1 results;
later enforcement of the selected compiler does not relabel this run.

At that exact companion source, with a clean `coaptic` checkout and psutil 7.0.0,
reproduce the plan on Linux using fresh output and one compatible Cargo lane:

```sh
RUSTUP_TOOLCHAIN=1.99.1 python3 tools/benchmark/linux_cpu.py \
  --baseline-sha b8f44fa16b3e16f4c9c6cc5f1205d2aee9cb0b57 \
  --candidate-sha 21f6dea85fb49bd766b405b3d48f58e76976ae1d \
  --build-lane /absolute/reused-cpu-lane --output /absolute/new-cpu-evidence \
  --sizes 64 --rates 6000 --seconds 8 --repeats 2 --server-kind all --perf
```

`raw-observations.tar.gz` retains all 48 client latency arrays, window results,
CPU/memory snapshots, source/build identities, logs and readable perf reports.
`archive-index.json` binds every member; `SHA256SUMS` binds public files.
`summary.json` and `qualification-report.txt` retain the analysis and limitations;
the public report omits the private ownership/path/retention paragraph.
Independent regrading recomputed counts, CPU ratios, medians
and p99 from the raw observations before publication. Original ELF binaries and
raw perf captures remain in the private original ZIP, SHA-256
`d03a7f1b20eef624ad7c7b9b7fce0cb669e52a2d432ac1b183ea3be5fcc4147b`.

Next work is reducing demonstrated poll maintenance and idle receive waste.
Larger bodies, concurrency, saturation/recovery, representative embedded/cloud
configurations, instrumentation overhead and whole-system memory still need
evidence. EDHOC setup is a separate workload. Further Windows elevation and
physical qualification remain deferred by the operator.
