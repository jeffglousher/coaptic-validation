# Ended level-readiness comparison - October 24, 2026

[Run 40130199038, attempt 1](https://github.com/jeffglousher/coaptic-validation/actions/runs/40130199038)
**fails the comparison**, although the workflow completed successfully. All
sixteen windows verify 480,000 measured complete operations plus 320 warmups,
with zero operation failures. OSCORE zero-based repeat 2 fails the existing
median-latency guard: ordinary Mio is 27.431 us and level readiness 29.823 us,
a +2.392 us delta against the +2 us limit. Every p99 and both pooled latency
guards pass; those passes cannot rescue the failed pair.

**Full-cohort CPU comparisons are withheld.** OSCORE pair CPU tick changes also
have mixed directions. The predeclared stop rule applies: no retry, replacement
cohort or expansion. The experimental implementation in
[PR #202](https://github.com/jeffglousher/coaptic-validation/pull/202) remains
unmerged. Ordinary Mio stays the supported reference. Both 50% CPU targets and
whole-memory acceptance remain open.

## Hypothesis and matched scope

The earlier [eBPF syscall measurement](../ebpf-syscalls-20261024/README.md)
observed one successful send, one successful receive plus one EAGAIN receive,
and one epoll wait per verified SmallDevice operation. It supplied no syscall
duration or removable CPU share. The new experiment tested a Linux `ppoll`
receive-credit control intended to avoid the empty receive while retaining
queued-packet progress, fresh deadlines and the same nonblocking I/O/send policy.
No tracing or profiling was enabled in this comparison, so a four-to-three
syscall prediction was not independently measured here.

Both labels use core `d23f93c0699b75ec17e692999d62ff89bb71463d` and companion
`4f7869be939292b0fce340c58dc6729c0a2faf4c`, tree
`b8cde021a7ca162a9fc74bd2ca8105af10f886e7`. The same server binary selects ordinary
Mio or the level control at startup; both labels use the same frozen baseline
client. This is an adapter comparison, not acceptance against original core
baseline `b8f44fa`.

SmallDevice fixed/Constrained, 32-byte complete GET, C1 CON, 1,000 starts/s,
thirty-second windows and four rotated pairs per security mode. Capacities are
routes four/one populated GET, Call one, deferred zero, association one, request
bindings four, RX/TX each two x 1,152 bytes, dedup four, Observe two and no body
pools. Every window uses 30,020 total client sends under the unchanged 60,000
ceiling, including warmup. Complete established OSCORE responses are authenticated
and verified by the native client.

The host is AMD EPYC 9V74, four assigned logical CPUs, Ubuntu 24.04/Linux
6.17.0-1022-azure, glibc 2.39 and 100 Hz process CPU accounting; governor
unavailable. Rust/Cargo 1.99.0 GNU release uses `--locked`, defaults disabled,
`std,alloc,oscore`, thin LTO, one codegen unit, frame pointers, debug=1,
strip=none, incremental=0 and two build jobs. Source-specific syn3 lock input
is `cb9a96e1...`; canonical `3ed89aed...` is restored. Full compiler, binary,
lock and artifact identities are in the [receipt](receipt.json).

## What passed and what remains withheld

All operation, offered-rate, matched-rate, pacing, CPU tick-floor and cleanup
gates pass. Server windows contain 39 to 47 ticks; missed starts range from zero
to two, and achieved rates from 1,000.0302 to 1,000.0306 operations/s. These are
paced results, not saturation throughput. Every pair and pooled latency statistic
is retained in the receipt, including the failed OSCORE pair. Raw user/system
ticks are diagnostic observations; no qualified CPU ratio or improvement is
reported for either mode. No precise-clock rescue, App/socket subtraction or
transport-cost percentage is used.

Actual Linux preflight passes ten endpoint, 37 staged and thirteen level tests,
strict release all-target Clippy and 332 Python tests with two skips. Separate
functional proofs pass: Linux `40127468237` has 104 native tests and six cells
(12 measured operations plus six warmups); Windows `40129245779` has 96 native
tests and four cells (eight plus four). Formatting, strict Clippy and release
builds pass on both. Windows covers ordinary-Mio SmallDevice and fixed-Service
16 KiB startup/authenticated responses; it does not run the Linux control.
Earlier Linux compile/Clippy failures and the first Windows sampler failure
remain retained. Functional success supplies no CPU or peak-stack acceptance.

Both Linux SmallDevice Apps are 14,016 bytes. Scratch 2,049 bytes nests inside
the ordinary 2,056-byte or level 2,060-byte adapter, itself inside App; the level
one-byte credit is already included. Ordinary Mio separately owns a four-byte
Poll and 24-byte Events header with capacity eight and unmeasured allocator
cost. The level control instead uses one separate temporary eight-byte borrowed
pollfd; no selector, worker or pending kernel operation is added. The 32-byte
representation is separate borrowed storage. Requested fixed App heap is zero,
which does not mean whole-process heap or RAM is zero. Allocator, initialization,
peak stack, runtime and kernel costs remain unresolved. Machine kernel work is
not assigned a CPU share.

## Reproduction and provenance

Inspect the immutable experimental commit before reconstructing this historical
configuration; the level option is not delivered on main. No repeat is planned.
On the same pinned Linux lane, with the existing benchmark prerequisites:

```sh
python3 -B tools/benchmark/linux_cpu.py \
  --baseline-sha d23f93c0699b75ec17e692999d62ff89bb71463d \
  --candidate-sha d23f93c0699b75ec17e692999d62ff89bb71463d \
  --resource-profile small-device --sizes 32 --rates 1000 --seconds 30 \
  --repeats 4 --server-kind coaptic-mio \
  --candidate-server-kind coaptic-mio-level --concurrency 1 --message-type con \
  --build-lane /absolute/existing/exclusive/build-lane \
  --output /absolute/exclusive/evidence
```

The artifact has 101 members, 84,108,995 expanded bytes including four copied
ELFs, and 22,334,608 compressed bytes; it passes the existing 256 MiB whole-upload
bound. Collector path/type/CRC/SHA checks and streamed ELF hashes are retained;
no retained binary was executed. Parent verification independently rehashed 168
local indexed files and reproduced all 480,000 latency samples and pair/pooled
statistics. Remote archive/ELF and source identity receipts were explicitly
reused. The public receipt references original member hashes; full raw arrays
remain with the retained run evidence.

A collector source-export destination error was corrected: 31 prior source
exports and four metadata exports were restored against their original index.
Raw benchmark data and repositories were unaffected. This provenance correction
does not alter the failed comparison or qualify any CPU claim.
