# Observation-only ingress pilot

This is a Rust/Aya kernel portability and syntax-observation pilot. It is not a
Coaptic transport, endpoint, security boundary or demonstrated accelerator.
It always returns XDP_PASS and does not write packet bytes. CoAP syntax,
including an OSCORE option, does not establish authentication or valid checksums.

## Compilation and execution

The kernel crate uses `aya-ebpf = 0.2.1`, `no_std` and no allocator. Pinned
`nightly-2026-10-13` compiles it and the reachable shared decoder to LLVM bitcode;
official `bpf-linker 0.12.0` links and emits an ELF containing little-endian eBPF
instructions for `bpfel-unknown-none`. There is no Rust-to-C translation, libbpf
or separate CoAP parser. LLVM is a compiler/linker dependency.

The separate native Linux loader uses `aya = 0.14.0` to relocate the ELF, create
maps, request kernel verification and attach the loaded program to XDP. The
qualified x86_64 kernel JIT compiles the accepted instructions to native code.
Aya does not replace the kernel verifier or make arbitrary Rust verifier-safe.
Only syntax classification executes in BPF; the App, UDP endpoint, OSCORE,
EDHOC, retransmissions and persistent ownership do not execute there.

Three manifests keep portable classifier tests independent of the Linux loader
and BPF toolchain. Reviewed lockfiles retain all resolved dependency versions.
All paths assume the existing `coaptic` source link under this repository.

## Current proof

Actual kernel qualification is complete for the named sources in
[run39254465762](https://github.com/jeffglousher/coaptic-validation/actions/runs/39254465762):
core `244809ebcd852cfeaf912bd2f5ba5956b6495bfc` and companion
`7d34275be771ee1b689c9005c2eb2745b74586e7`. The
[retained receipt](../qualification/evidence/bpf-ingress/README.md) records two
instrumented cycles and one ordinary unmodified-Aya cycle, each with 4,556
executed BPF inputs plus 1,456 kernel-rejected short frames. Byte preservation,
counters, lifecycle/process recovery and capability refusal pass. Original
failures remain retained. This is exact-source proof, not a latest-source rerun.

The named Linux 6.17.0-1022-azure kernel reports 352+0 bytes stack, 344 translated
instructions (2,752 bytes), 1,816 JIT bytes and 4,096 bytes program memlock.
These are verifier/object measurements, not per-packet execution costs.
No native NIC, throughput or production-load benefit has been measured.

## Finite execution cost sample

`coaptic-ingress-loader OBJECT cost 1` loads the existing classifier and a minimal
`XDP_PASS` control from the same ELF, then runs both through Aya's ordinary
`BPF_PROG_TEST_RUN` API without attachment or network delivery. It creates no
veth, needs no network-administration operation, and uses unmodified Aya. The
control never touches maps and is never attached by the loader. The classifier's
packet path, stack buffer and counters are unchanged.

The loader pins its thread to one available CPU and restores its affinity on
exit. Four fixed frames cover an unrelated IPv4 UDP port, a 32-byte unprotected
IPv4 body, an opaque OSCORE IPv6 request and 126 Uri-Path options in a 256-byte
IPv6 CoAP message. Each program/frame gets 100 warmup invocations and five batches
of 10,000 measured invocations, with alternating program order. Every call checks
`XDP_PASS` and exact returned bytes; counter deltas must include all warmup and
measured classifier invocations, and the control must leave them unchanged.

The JSON output preserves all five raw integer-average nanosecond values per
program/frame. Linux already divides its accumulated test-run time by repetitions;
do not divide the returned Aya duration again. These are averages of repeated
kernel test execution, including its execution-loop overhead, rather than
individual-packet latency distributions. The control provides context for that
overhead; it does not make this a NIC, throughput, CPU saturation or end-to-end
cloud benefit measurement. No result threshold or acceleration claim is implied.

Set `cost_probe=true` on the manual workflow for this sample instead of normal
load/attach smoke; it is mutually exclusive with `full_qualification=true`.
The workflow retains exact source, object/toolchain hashes, observed kernel and
CPU identity and the raw sample, and bounds the loader process to 120 seconds.
This mode is optional and does not add qualification work to routine edits.

## Quick deployed batch and full qualification

The manual **Advisory BPF kernel pilot** workflow requires an exact core SHA and
records the companion SHA, compiler/linker, object hash and observed kernel/image/
BTF identity. It is not a PR gate. The hosted kernel is observed, not pinned.

The default dispatch builds the portable classifier, native loader and BPF ELF,
then runs `coaptic-ingress-loader OBJECT quick 1` with unmodified Aya. The default
core pin is `15388140d24867285e89fbc2ecfecb1dc55aac48`; the existing checkout/
preparation step verifies the requested source. This documents the intended run,
not a completed current-source kernel receipt.

Quick creates and identity-checks one owned veth pair, proves four unchanged live
IPv4/IPv6 plain/opaque OSCORE frames before attachment, then loads and attaches
the real program in SKB mode and verifies its actual program ID. Eight attached
frames must arrive byte-for-byte: those four, malformed TKL9, a 257-byte CoAP
message, unrelated IPv6 UDP with both ports different from 5683, and a valid
recovery frame. IPv4 header and IPv4/IPv6 UDP checksums are computed after packet
construction and recomputed after port mutation. Inline loader tests cover the
finite classes, sizes, checksums and mutation repair.

Attached counter deltas require exactly five syntax, one malformed and one
oversized, with total at least eight and uninspected at least one; ambient traffic
can increase the latter two. Quick explicitly detaches, checks attachment absence,
delivers the four live recovery frames with unchanged counters, then verifies pair
identity, deletes it and checks both names absent. Uncertain cleanup is fatal and
retains the ownership record for reconciliation. The workflow also compares the
before/after interface inventory and retains failures. Loader phase milliseconds
and workflow setup/build/execution seconds are recorded separately. There is no
cold-build one-minute promise or CPU-gain claim.

No Aya source patch, bpftool or full feature probe is needed by quick. It does not
establish the full corpus, resource budgets, interruption or capability refusal.
Opaque OSCORE bytes establish syntax/byte preservation only; the App remains the
sole cryptographic authentication/decryption boundary.

Set `full_qualification=true` to additionally run the retained finite corpus,
verifier metrics, multi-CPU counters, exact live bytes, process/lifecycle recovery
and capability refusal. Full qualification still exercises the ordinary loader.
Its inspection tools, temporary Aya instrumentation and repeated cycles are
explicit opt-in work, not the normal edit loop.

Aya 0.14.0 exposes verifier log-level selection but discards successful load logs.
The full qualification copy applies a two-line patch to the checksum-verified
crate: allocate its existing log buffer before the first load and print success
logs. Original/patched sources and locks are retained; the global Cargo cache
is unchanged. This instrumentation is needed for the recorded verifier resource
report, not for ordinary loading or deployment.

## Inspection and memory contract

The pilot uses generic XDP on an exclusively created veth. Ports 5683 source or
destination qualify for inspection. IPv4 options are bounded by IHL. Fragments,
IPv6 extension headers/jumbograms, VLAN, non-UDP, other ports and incomplete
linear packets remain uninspected and pass; there is no reassembly.

The complete linear frame must fit 338 bytes, with at most 256 bytes of CoAP.
This is an inspection profile, not a network packet-size limit. One 338-byte
invocation-local stack buffer and `bpf_xdp_load_bytes` copy the bounded frame so
the shared `coaptic::message::extended::decode` can read ordinary memory. Helper
failure counts as uninspected and still passes. The total emitted BPF stack must
fit 512 bytes; the 338-byte buffer is included in the measured stack, not added
to it. Copy cost and any benefit from direct packet access remain unmeasured.

One PerCpuArray has five saturating u64 counters: uninspected, oversized CoAP,
malformed CoAP, CoAP syntax and total. Value storage is 40 bytes per possible
CPU, plus kernel map metadata/allocation. Missing lookup skips the metric and
passes. There are no flow keys, insertion, eviction or event-ring losses.
No token or payload contents are exported. Snapshots are observations, not an
accounting authority or application admission decision.

The parser has data-dependent bounded option traversal. Compile success and
host tests alone cannot establish verifier acceptance. Any surviving panic edge
must fail loading. Keep the shared checked parser; do not add a BPF parser fork.
A production acceleration proposal needs a measured workload and benefit before
adding kernel protocol state, changing packet actions or optimizing the copy.

## Local commands and ownership

Use the registered compatible build lane after coordination, with jobs=2 and
incremental disabled. Do not create a per-branch target or silently install tools.

1. Host: `cargo test --locked --manifest-path tools/bpf-ingress/classifier/Cargo.toml`.
2. Pinned nightly/rust-src and official bpf-linker:
   `cargo +nightly-2026-10-13 build --locked --release -Z build-std=core --target bpfel-unknown-none --manifest-path tools/bpf-ingress/ebpf/Cargo.toml`.
3. Native Linux: `cargo build --locked --release --manifest-path tools/bpf-ingress/loader/Cargo.toml`.
4. Quick deployed batch: `coaptic-ingress-loader OBJECT quick 1`.
   The existing timed attach command `OBJECT SECONDS CYCLES` remains available.
5. Full finite proof: `coaptic-ingress-loader OBJECT qualify CYCLES` (1..3 cycles),
   plus the workflow's instrumentation and capability controls.
6. Detached finite cost sample: `coaptic-ingress-loader OBJECT cost 1`.

Attachment modes need Linux BPF/XDP/veth support, sufficient BPF/network
privileges and iproute2. Detached cost mode needs BPF/test-run support and BPF
privileges; it skips installation of attachment and qualification tools.
The Windows loader explicitly refuses execution with exit code 2. Installing
WSL alone does not establish kernel features or a passing verifier result.

The loader creates `cpb<PID>a` and `cpb<PID>b`; existing names cause refusal. It
checks both names/ifindices and reciprocal links before attaching or deleting,
attaches only its own disposable ingress in SKB mode, and detaches its returned
link. It changes no routes, sysctls, firewall or persisted BPF pins. Missing or
replaced identity refuses cleanup and requires reconciliation; there is no
protection against a competing privileged namespace mutator. Ordinary errors
attempt owned cleanup. SIGKILL/abort recovery needs the recorded identities and
confirmed child termination before deletion, as exercised by full qualification.

Full live AF_PACKET receipts prove unchanged bytes, not UDP checksum acceptance
or authenticated delivery. The program does not request XDP_HAS_FRAGS; native
multi-buffer hooks and production NIC driver modes are not qualified.

Official references:
- https://github.com/aya-rs/aya
- https://doc.rust-lang.org/nightly/rustc/platform-support/bpf-unknown-none.html
- https://github.com/aya-rs/bpf-linker
- https://docs.rs/aya/0.14.0/aya/programs/xdp/struct.Xdp.html
- https://docs.rs/aya-ebpf/0.2.1/aya_ebpf/maps/per_cpu_array/struct.PerCpuArray.html

## Separate bounded syscall observer (issue 195)

The opt-in `syscall-trace` feature declares separate `coaptic-syscall-ebpf` and
`coaptic-syscall-loader` binaries. Existing ingress ELF maps, commands and default
builds do not acquire tracing behavior. The three current BPF locks explicitly
bind `coaptic-io` to syn3; Aya's own syn2 edges stay pinned. Historical receipts
remain evidence for their old commits. Do not use current locks with an old syn2
core or implicitly update them after `--locked` refusal. Native benchmark locks
retain their existing source-selection mechanism.

The observer counts independent syscall entries and return classes for one
PID/TID. It reads no arguments or payloads, keeps no dynamic flow keys, timestamps,
events or stack samples, and makes no packet/admission decisions. The trace ELF
has no reachable Coaptic code. Its explicitly recorded build core may therefore
differ from the same-binary native OFF/ON core.
See [the socket integration](../benchmark/linux_cpu.md#bounded-syscall-diagnostic).
