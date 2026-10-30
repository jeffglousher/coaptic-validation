# Windows live C1 profiling screen

This is a new capability workload, separate from the frozen batch screen. It is
not a replacement cohort or a performance comparison. The core stays unchanged.
Implementation and source review precede any recording.

## Fixed workload and capture plan

Each fresh process completes 128 warmup exchanges and exactly 1,000,000 work
exchanges. Work has a 90-second cooperative deadline; an incomplete prefix is a
failure, never a smaller successful cohort. The collector has a 120-second
deadline. One context pair and fresh startup key material are used throughout
each protected process, without resetting sequences, replay state or bindings.

The main thread owns the unchanged Default allocated server App. Exactly one
client helper prepares and verifies requests through a capacity-one fixed
1,472-byte handoff slot. The main thread performs every complete App poll. Both
threads remain alive until the collector has stopped. Waiting uses condition
predicates and an absolute deadline, without empty polling or a growing queue.

The body is 64 bytes. Capacities are routes=1, Calls=4, deferred=0,
security_bindings=4, associations=1, RX/TX datagrams=4x1472, dedup=8,
Observe=4, RX body=1x1024, TX body=2x1024, blockwise enabled.

Global operation indices include warmup. Tokens are all eight big-endian bytes
of the index; MIDs are its low 16 bits. The App receives checked virtual time
`index * 8` milliseconds, from 0 through 8,001,016 inclusive. This is new fixture
semantics: the old batch uses real monotonic elapsed time. A MID cycle advances
524,288 ms, exceeding EXCHANGE_LIFETIME=247,000 ms. This is socket-free protocol
progress, not a real traffic rate, RTT, or device workload.

Serial cohorts, each a fresh process:

1. unprotected control 0
2. unprotected capture 0
3. OSCORE control 0
4. OSCORE capture 0
5. OSCORE capture 1
6. unprotected capture 1

No pooling across processes, threads, modes or runs. Keep every selected-server
sample, including handoff, driver, wait and unresolved paths. App ancestry is a
separate count. The existing 200 App-sample floor and all quality gates remain
unchanged; unknown unwind/inline completeness and unknown CPU mode prevent a
qualified CPU-share claim. The partial recorded attempt is described below;
replicated sampling and stack qualification remain unproven.

## Native JSONL protocol

Invocation: `bench-core 1000000 MODE --live-c1`, MODE is `unprotected` or `oscore`.
Every row has `event`, `mode="server-app-live-c1/1"`, and `security=MODE`.
Only the new flag admits this operation count; old admission stays unchanged.

The parent sends `start`, receives `fixture`, `warmup`, `ready`, sends `run`,
receives `measured`, stops and flushes ETW, sends `verify`, receives `verified`
and `complete`, then sends `exit`. Commands include a terminating newline.

`fixture` additionally contains `operations=1000000`, `warmup=128`, positive
distinct Windows `workload_thread_id` and `client_thread_id`, `deadline_seconds=90`,
`virtual_tick_ms=8`, `virtual_first_ms=0`, `virtual_last_ms=8001016`, and
`capacities` with the following exact keys/values:

```
routes:1, calls:4, deferred:0, security_bindings:4, associations:1,
rx_datagram_slots:4, rx_datagram_bytes:1472,
tx_datagram_slots:4, tx_datagram_bytes:1472, dedup_entries:8,
observe_entries:4, rx_body_slots:1, rx_body_bytes:1024,
tx_body_slots:2, tx_body_bytes:1024, blockwise:true
```

It also contains `layout` with nonnegative integer byte counts:
`shared_slot`, `client_context`, `client_request_ref`, `client_decrypt_scratch`,
`server_app_inline`, `server_requested_heap`, `helper_stack_requested`.
The decrypt scratch is 1472 bytes; helper stack request is 2097152 bytes.
Shared slot includes synchronization and metadata/padding. App inline includes
CoreIo. These are separate storage categories, not a sum of whole-process memory,
emitted frame sizes or allocator/startup overhead. No new App plaintext backing.

`warmup` contains `warmup_verified=128`. `ready` contains `kind="work"`.
`measured`, `verified`, and `complete` contain the exact common counters:
`prepared=1000000`, `polled=1000000`, `responded=1000000`, `verified=1000000`,
`warmup_verified=128`, `total_verified=1000128`, `internal_datagrams=2000256`,
`udp_datagrams=0`, `max_outstanding=1`, `slot_empty=true`,
`pending_binding=false`, `io_pending=false`.
`measured` is emitted only AFTER final client authentication/verification.
`verified` and `complete` additionally contain `helper_settled=true`.
The helper remains alive awaiting finalization until `verify`, outside capture.

Failures must wake the peer and preserve bounded actual counters and a terminal
reason. Panic, poison, EOF, timeout, cancellation and partial completion cannot
be successful protocol rows. Cooperative deadlines cannot preempt a stuck poll
or OS call: parent containment and ETW-stop-before-process-kill remain required.
Failure rows use `event="failed"`, the same mode/security identity,
`terminal=true`, and a nonempty static ASCII `reason` of at most 64 characters.
They retain actual values under the success-counter key names; expected totals
must never replace actual partial progress. `helper_settled` is true only after
observed settlement. The adapter retains and rejects every failed row.

Each helper waiting phase has one absolute 120-second deadline, recomputed after
spurious wakes. Active work still has one 90-second deadline for the entire
cohort, not a fresh deadline per exchange. Main-thread stdin remains blocking
and externally contained; these cooperative waits do not establish preemption.

## Validation and resource ownership

Before recording, focused native tests cover both security modes through the
first MID wrap and PIV-width transitions, response/token/binding corruption,
replay refusal, slot ownership, spurious wakeups, panic/cancel/timeout settlement,
and zero steady-operation allocations on both threads. Reuse the existing
test-only thread-local allocator observer. Python tests enforce the exact
protocol, count/type/TID/capacity gates, stop-before-finalize and unchanged batch.

All hosted output belongs to Coaptic/root in a fresh RUNNER_TEMP child. Existing
8 GiB owned build and 256 MiB evidence limits remain. Live capture worker inner
deadline is 830 seconds and outer containment is 900 seconds, with cleanup
grace inside that gap; the hosted job is capped at 40 minutes. Old batch bounds
remain unchanged. RSS checks remain sampled guards, not hard whole-job quotas.
No local native build or capture is part of this implementation phase.

## Setup amendment before any recording

[Attempt 41035344492](https://github.com/jeffglousher/coaptic-validation/actions/runs/41035344492)
passed both builds, all 12 focused native tests and 98 portable checks. Capture
orchestration then refused the requested 1,060-second timeout: the shared process
owner has a 900-second ceiling and refused before creating a worker. All six
native cohorts, four ETW captures, two controls and C# model self-tests were not
run. Preserve that failure; no sample or operation cohort is replaced.

The corrected setup keeps the shared ceiling at 900 seconds and uses an inner
830-second live capture deadline, leaving 70 seconds for owned cleanup before
outer containment. Six 90-second work bounds total 540 seconds, leaving 290
seconds for capture setup/export and other work inside the inner deadline. This
is a refusal budget, not a guarantee of completion. One corrected fixed attempt
is permitted after source review; operations, cohort order, capacities, protocol,
per-cohort deadlines, sample selection and all quality gates remain unchanged.

## Recorded attempt and offline projection

[Corrected attempt 41038109816](https://github.com/jeffglousher/coaptic-validation/actions/runs/41038109816)
passed 99 portable checks, all 12 focused native tests, 113 C# model assertions
and both builds. The first four native cohorts completed all one million work
exchanges plus 128 warmups. Both selected ETW sessions explicitly stopped.
Unprotected capture 0 exported 3,164 samples, including 1,633 with App ancestry.
It remains diagnostic: unresolved system frames, unwind/inline completeness,
CPU mode and circular overwrite prevent a qualified CPU-share claim.

OSCORE capture 0 then refused export with `Frame text budget exceeded.` No
protected profile or failed partial count is inferred. The final OSCORE and
unprotected capture 1 cohorts did not run. The recording campaign is stopped;
there are no replacement cohorts, new recordings or relaxed qualification gates.

A separate offline projection uses only those same two hash-bound ETLs, original
capture receipts and owned EXE/PDB bytes. `aggregate_exact_paths` is explicit and
default off. It groups identical full root-to-leaf symbol sequences within one
original scope/window, preserving counts, self/inclusive weights and flame
prefixes. Raw event/frame/depth limits and all output byte caps remain unchanged.
The projection omits per-event timestamps, addresses, modules, comm and order;
the retained original ETL remains authoritative for those metadata. Aggregate
JSON alone cannot independently establish timestamp membership or timeline queries.

The unprotected projection must reproduce every exact path multiplicity, symbol
self/inclusive count, flame prefix, App count and quality counter from its
original per-event profile. The protected projection has no prior profile to
compare. Each scope remains separate; no pooling or new sampling follows. One
reviewed offline attempt may export both traces in that order. Any JSON, HTML,
conversion, identity or resource refusal is retained without a larger cap or
fallback recording. Successful projection alone does not qualify the stacks.

## Retained offline outcome

[Offline attempt 41044460748](https://github.com/jeffglousher/coaptic-validation/actions/runs/41044460748)
passed all 126 portable checks, 209 C# pure model assertions and the SDK 8.0.427
exporter build. No native workload or ETW session ran. The unprotected exact-path
projection preserves all 3,164 original samples, 332 paths, 341 symbols, 531
recursive prefixes, 42,573 weighted frame occurrences and 11,260 unresolved
occurrences. Independent full control equivalence passes. Its 1,633 App samples
meet the count floor but do not resolve the other qualification limits.

OSCORE then refused `Stack/frame count budget exceeded.` Which predicate fired
and partial sample/frame counts are unknown; no protected profile is inferred.
This ends the offline attempt. Preserve both refusals and the final two original
NOTRUN captures; do not raise limits, segment the trace, retry or record replacement
cohorts. The [retained proof](evidence/windows-live-c1-capability-20261030/README.md)
delivers diagnostic unprotected capture-to-flame capability and its exact projection
check, without a qualified cost ranking, production optimization or device claim.
