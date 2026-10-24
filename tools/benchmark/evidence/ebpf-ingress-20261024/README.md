# eBPF ingress cost in the benchmark report

Report date: October 24, 2026. This report incorporates valid retained eBPF
measurements into the benchmark evidence; it does not rerun them or relabel them
as current-source socket results.

The Rust/Aya ingress pilot is implemented and kernel-qualified for its named
sources. It shares Coaptic's checked decoder, observes bounded syntax, increments
five per-CPU counters and always returns `XDP_PASS` without modifying bytes.
It does not authenticate OSCORE, execute an App, replace the UDP transport,
remove userspace parsing or bypass the kernel stack. It is not an accelerator.

## Measured component costs

[Run 39359240571](https://github.com/jeffglousher/coaptic-validation/actions/runs/39359240571)
uses core `cdabea60b43db0a9ec110276b9122d45c85eab73` and companion
`f09f168eb4897f483cbd3345d41b070bf75f6d6c`. Its
[committed raw arrays and review receipt](../../../qualification/evidence/bpf-ingress/run-39359240571-cost-review.json)
retain both programs' five integer-average nanosecond samples for every frame.
The following medians are medians of those five batch averages, not packet
percentiles:

- Unrelated IPv4 UDP port, 79-byte frame: classifier **158 ns**, minimal PASS
  **28 ns**. Raw classifier samples: 157, 158, 158, 158, 158.
- IPv4 CoAP with 32-byte unprotected body, 79-byte frame: classifier **160 ns**,
  minimal PASS **28 ns**. Raw classifier: 161, 160, 160, 164, 160.
- IPv6 opaque OSCORE syntax, 97-byte frame: classifier **170 ns**, minimal PASS
  **28 ns**. Raw classifier: 170, 170, 170, 170, 169.
- IPv6 CoAP with 126 options, 318-byte frame: classifier **429 ns**, minimal
  PASS **28 ns**. Raw classifier: 429, 429, 429, 428, 429.

Each measured batch executes 10,000 kernel `BPF_PROG_TEST_RUN` invocations;
each program/frame has 100 warmups and five measured batches with alternating
program order. The native loader pins one available CPU and restores affinity.
Both programs are loaded with unmodified Aya; neither is attached and there is
no network delivery. Each invocation checks PASS and unchanged returned bytes.
Counter deltas match all 200,400 classifier invocations; the control also
executes 200,400 times without changing counters. Linux already divides the
reported duration by repetitions; do not divide it again.

The observed host is AMD EPYC 9V74, four logical CPUs with sample CPU 0 pinned,
Ubuntu 24.04.5/Linux 6.17.0-1022-azure, runner image `20261012.334.1`.
Build inputs are nightly `2026-10-13`, LLVM 23.1.3, bpf-linker 0.12.0,
Aya 0.14.0 and aya-ebpf 0.2.1 with committed locks. ELF SHA-256:
`d99395001e422ea4dca5ad82554890f65bee94d579b353ee07f2e1091cfbef69`.
Original artifact SHA-256:
`08656eeb33c9125603f69d2794f0996cea73c60719ce8eb210de02a96b3de879`.

## Functional and resource proof

The separate full qualification
[run 39254465762](https://github.com/jeffglousher/coaptic-validation/actions/runs/39254465762)
uses core `244809ebcd852cfeaf912bd2f5ba5956b6495bfc` and companion
`7d34275be771ee1b689c9005c2eb2745b74586e7`. It validates two instrumented
cycles and one ordinary unmodified-Aya cycle; each executes 4,556 BPF inputs
plus 1,456 kernel-rejected short frames. Counter, exact byte-preservation,
ownership/lifecycle/process recovery and capability-refusal checks pass. These
are separate sources and proof obligations from the cost sample.

For that qualified object/kernel, emitted stack is 352 bytes, translated code
344 instructions/2,752 bytes, JIT code 1,816 bytes and program memlock 4,096
bytes. Its map has five u64 values per possible CPU: 40 bytes of value payload
per possible CPU, plus kernel allocation/metadata. Reported map memlock is 464
bytes on that runner, not a portable whole-memory formula. The invocation-local
338-byte copy buffer is nested in emitted stack and must not be added twice.
The maximum inspected CoAP datagram is 256 bytes; unsupported/oversized traffic
passes uninspected. This cannot substitute for configured App capacities.

## Relation to complete-operation results

The accepted Coaptic socket work uses a real App and full response verification.
Its separately qualified SmallDevice 32-byte/C1 CON/1,000/s measurements report
4.65% less server CPU unprotected and 3.14% less OSCORE CPU. Fixed-Service
16 KiB/C1 CON/50/s OSCORE reports 8.08% less CPU. Those results use other
sources/hosts and do not include this XDP hook. Do not add, subtract, pool or
multiply their numbers with these detached kernel times. See
[core #650](https://github.com/jeffglousher/coaptic/issues/650) for exact strata,
retained failures and the still-open independent 50% targets.

An actual end-to-end eBPF benchmark is **not yet qualified**. It must compare
no hook, minimal PASS and observation on the same owned ingress, with frozen
server/client binaries, identical topology, complete authenticated responses,
unchanged capacities and explicit kernel/loader CPU and memory accounting.
Loopback benchmark traffic does not traverse the pilot's owned veth merely
because a program was loaded. Attaching an observation program cannot establish
that userspace work was removed. Diagnostic eBPF syscall/scheduler tracing would
be a distinct instrument, with measured overhead; it is not this XDP pilot.

Remaining costs are not yet causally apportioned. Existing process user/system
accounting includes substantial system time, while sparse App-rooted samples
do not establish removable syscall, scheduler, crypto or copy percentages.
Potential work includes bounded receive/send batching at actual concurrency,
reuse of completed parsing and prepared crypto state within explicit memory
ceilings. AF_XDP/kernel bypass would require a new bounded transport and
ownership/cancellation proof. These are hypotheses, not demonstrated solutions.
OSCORE authentication, replay/nonce ownership and durable effects remain in App.

## Reproduction and boundaries

From the recorded companion/core sources and pinned toolchain, the existing
manual `bpf-pilot.yml` workflow accepts `cost_probe=true` and
`full_qualification=false`; or invoke the built ordinary loader as:

```sh
coaptic-ingress-loader ingress.elf cost 1
```

The workflow bounds the cost process to 120 seconds. Reproduction is a new
source/host observation, not an update to the retained result. The detailed
[pilot contract](../../../bpf-ingress/README.md) records compiler/linker commands,
ownership, capabilities and unsupported cases. Native NIC/XDP driver throughput,
production packet rates, authenticated App delivery and whole-system peak RAM
are not established by the detached sample. Both 50% CPU targets remain open.
