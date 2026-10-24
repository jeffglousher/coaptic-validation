# eBPF syscall benchmark ? October 24, 2026

[Run 40112478137, attempt 1](https://github.com/jeffglousher/coaptic-validation/actions/runs/40112478137)
passes functional measurement: **16 windows, 480,000 verified operations and 320
warmups**, with zero operation failures. All eight tracing-on captures agree.
**Both security-stratum overhead ratios are withheld** because four pair median
latency guards fail. This is measurement functionality, not an optimization gain
or primary CPU acceptance. Both 50% targets and whole-memory acceptance remain open.

## What eBPF observed

For each of 30,000 verified complete operations in every ON window, both
unprotected and established OSCORE:

- `sendto`: one entry and one successful exit.
- `recvfrom`: two entries, one successful exit and one EAGAIN exit.
- `epoll_wait`: one entry and one successful exit.

All other fixed syscall bins and both anomaly counters (read failure and foreign
thread) are zero. EAGAIN denotes an empty nonblocking receive, not a failed CoAP
operation. The [receipt](receipt.json) retains all eight counter snapshots, raw
per-window statistics and every pair/pooled guard. Entry/exit observations are
independently gate-censored; no balance invariant is assumed. They provide no
syscall duration, vDSO-clock coverage or removable CPU percentage.

This confirms the successful-receive / empty-receive / selector-wait mechanism.
Avoiding that empty receive is a source hypothesis to assess, not a demonstrated
CPU saving: queued packets, readiness semantics, fairness, deadlines and refusal
must remain correct. No new transport, buffer, batching or kernel-bypass gain is
established. The older [XDP component benchmark](../ebpf-ingress-20261024/README.md)
is a separate always-PASS classifier cost experiment and is not accelerated
application communication.

## Matched setup and failed overhead gates

Native core is `d23f93c0699b75ec17e692999d62ff89bb71463d`; BPF compilation core is
`1b93171035fa4b9506ec5e798ccef5d0773e1109`. Companion source is
`35a86de963503cd93cd0a579f0fcfbec85ce0b00`, tree
`3265cb3a972aef3258826c8eda56d217bf61b63e`. Identical frozen native server/client
binaries serve both arms. OFF has no tracing helper or attached syscall programs.
ON attaches disabled before warmup, enables before CPU/run boundaries, and
disables/detaches after measured snapshots before client report formatting.

SmallDevice fixed/Constrained, ordinary Mio, 32-byte complete GET, C1 CON,
1,000 starts/s, thirty seconds, four rotated OFF/ON pairs per security mode;
both single-thread servers are pinned to CPU0. Routes four/one populated GET,
Calls one, deferred zero, associations one, request bindings four, RX/TX each
two ? 1,152 bytes, dedup four, Observe two, no body pools. Each client window
uses 30,020 total sends under its unchanged 60,000 ceiling.

AMD EPYC 7763, four assigned logical CPUs, Ubuntu 24.04/Linux
6.17.0-1022-azure, glibc 2.39, 100 Hz process CPU accounting; governor unavailable.
Native Rust/Cargo 1.99.0 GNU release: locked, default features off,
`std,alloc,oscore`, thin LTO, one codegen unit, frame pointers, debug=1,
strip=none, incremental=0 and two build jobs. Helper Rust 1.99.0; BPF
nightly-2026-10-13, linker 0.12.0 with the unchanged pinned archive checksum.
Exact compiler/lock/binary identities remain in hosted build receipts; selected
native syn3 input is `cb9a96e1?`, restored canonical input `3ed89aed?`.

All operation, rate, matched-rate, pacing, twenty-tick and cleanup gates pass.
The required ON-minus-OFF median limit is +2 microseconds for **every pair**:

- Unprotected repeat 3: **+2.084 ?s**, fail.
- OSCORE repeats 0/1/2: **+2.875 / +16.642 / +2.514 ?s**, fail.

All pair p99 guards (+10 ?s limit) and both pooled guards pass. Those pooled
passes cannot erase pair failures. Both overhead ratios remain withheld; no
favorable pairs are selected as a replacement cohort. Every diagnostic row is
permanently ineligible for primary #650 acceptance. CPU/user/system observations
are retained separately in the receipt, without qualifying an overhead ratio.

## Tests, resources and limits

Actual Linux checks pass: 201 Python tests, three classifier tests, all nine
loader tests (including seven new command-reader regressions), strict loader
Clippy and locked helper/BPF/native builds. This workflow does not run native
Rust tests or native Clippy. The repaired enable/disable protocol, validated
counter snapshots and normal detach are observed; cleanup results have no
unresolved flags. There is no standalone system-wide post-run link census.

Actual map values total **2,632 bytes** across four possible CPUs. Both programs
together report **8,192 bytes memlock**; translated/JIT lengths are nested and
must not be added again. Map/link allocator metadata is unknown. Helper limits
are 128 MiB address space (including the 1 MiB stack limit), CPU 30 seconds,
64 FDs and wall 60 seconds. Its separate lifetime CPU snapshot is
53,721?56,762 ?s; maximum RSS 49,220?51,852 KiB. These include setup, warmup,
waiting and controls, exclude final formatting/drop, and cannot be subtracted
from or added to differently scoped native CPU windows to manufacture a share.
System-wide prefilter callback and machine/kernel worker CPU remain unassigned.

Server App is **14,016 bytes**, including the 2,056-byte adapter, its 2,049-byte
scratch and fixed pools; requested pool heap is zero. Separate owners are the
32-byte representation, 4-byte Poll and 24-byte Events header (capacity eight).
Events heap, allocator, initialization, peak stack/runtime and kernel costs
remain unresolved. Non-atomic lifetime RSS/HWM/stack mappings are not minimum
RAM or whole-memory acceptance. Client timing/verification/pool costs remain
separate in raw receipts. Tracing is an optional host diagnostic, not an
embedded App memory requirement.

## Reproduce and inspect

```sh
gh workflow run ebpf-syscalls.yml --repo jeffglousher/coaptic-validation \
  --ref SOURCE_BRANCH \
  -f library_revision=d23f93c0699b75ec17e692999d62ff89bb71463d \
  -f bpf_library_revision=1b93171035fa4b9506ec5e798ccef5d0773e1109
```

GitHub workflow dispatch requires a branch/tag on this host: the actual run used
`main` immediately verified at the exact SHA above, and the resulting run's
head SHA was checked. For future reproduction use a branch already pointing to
that source and verify the resulting head; do not create a release tag. The
native driver invocation and immutable workflow provide the exact commands.
No rerun or replacement cohort is planned for the failed overhead guards.

Artifact `12566918509` contains 141 text members, 3,667,819 expanded bytes,
SHA-256 `997f2065b5ac53545ebeffa814946105fb8978edeb4bb18bdc9b22e617aff9c1`.
All member CRC/SHA, artifact digest and 25 immutable source records were checked.
Binaries are excluded from upload: binary hashes and pre-window freezes are
captured build/control-flow evidence, not fresh collector ELF rehashes. Raw
records and both earlier failures remain retained beyond this report.

The hosted API's late embedded step fields remained inconsistent despite the
completed-success job, finished log, finalized artifact and full raw campaign.
Original API responses and two initial collector analysis refusals are retained;
individual terminal step API states are unavailable, not invented. This does
not change benchmark guards or supply overhead acceptance.

Earlier run `40107158379` stopped at an undersized linker-download guard with
zero windows. Run `40109321826` verified one OFF window (30,000 plus 20 warmups),
then failed ON enable acknowledgement with fourteen later windows NOT RUN.
Both failures are preserved; the reviewed download and unbuffered same-descriptor
command repairs changed source before this proof. No failed measurement is
silently replaced. Companion #197/#198/#199 deliver the implementation and fixes;
#195's measurement disposition does not complete either #650 CPU target.
