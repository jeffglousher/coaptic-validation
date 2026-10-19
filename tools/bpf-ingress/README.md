# Observation-only ingress pilot

The manual **Advisory BPF kernel pilot** workflow builds a named object with
`nightly-2026-10-13` and the checksum-pinned official bpf-linker 0.12.0. It is not
a PR gate. Dispatch requires an exact core SHA; the companion workflow SHA and
the hosted runner's observed kernel/image/BTF identity are retained. The hosted
kernel is recorded, not version-controlled by this project. No kernel execution
result is implied merely by adding this workflow.

`OBJECT qualify CYCLES` runs the same finite corpus through Aya's kernel
test-run API, checks PASS/unchanged bytes/counter deltas and exercises an owned
veth before/during/after attachment. Two available CPUs execute concurrent finite
batches with exact per-CPU accounting; saturation and array-bound refusal are
checked separately. A child loader is killed and reaped before its recorded
names, both ifindices and reciprocal links authorize cleanup. Frames rejected before XDP execution remain
explicitly separate from executed cases. Checksummed IPv4/IPv6 live samples
include RFC 8613 C.4 ciphertext, treated only as opaque syntax. Packet-socket
receipt proves byte preservation, not UDP checksum validation or authentication.

Aya discards successful verifier logs. The workflow builds a separate temporary
qualification copy using a two-line patch to the checksum-verified Aya crate (allocate its existing
10 KiB verifier buffer before the first load, then print successful logs);
original/patched source and lock identities are retained. Ordinary loader sources
are copied unchanged and the normal unpatched binary is also exercised. No
global crate cache is edited, no BPF pins are created, and bpftool inspects only
the live owned program/map IDs. First-failure artifacts are retained. No native
NIC, throughput or production-load claim is made by this finite pilot.

Portable classifier tests, Linux loader cross-target checking and BPF target
type-checking pass; linked object, verifier and loaded-hook results remain
unexecuted. Core CoAP parsing is
`coaptic::message::extended::decode`, with no separate CoAP parser. The BPF
program always returns XDP_PASS and never writes packet bytes. Parsed syntax,
including an OSCORE option, says nothing about authentication or valid checksums.

The pilot uses generic XDP on an exclusively created veth. IPv4 options are
bounded by IHL; IPv4 fragments, IPv6 extension headers/jumbograms, VLAN frames,
non-UDP traffic, other ports and incomplete linear packets remain uninspected.
Ports 5683 source or destination qualify for syntax inspection. No reassembly.
The complete linear frame must fit 338 bytes; UDP CoAP payload at most 256 bytes.
This is a named inspection profile, not a network packet size limit. Everything
outside the profile still passes. The BPF adapter uses one 338-byte invocation-local
stack buffer and helper 189 (`bpf_xdp_load_bytes`) to copy exactly the bounded
linear frame into memory the unchanged shared decoder can read. Helper failure
counts as uninspected and still passes. No persistent buffer or map is added.
The total emitted stack must remain within 512 bytes; copy cost is unmeasured.

One PerCpuArray contains five u64 counters: uninspected, oversized CoAP,
malformed CoAP, CoAP syntax, total. Value storage is 40 bytes per possible CPU,
plus kernel map metadata/allocation; record actual map accounting. There are no
flow keys, insertion failures, eviction or event-ring loss. Missing map lookup
skips the metric and still passes. Counters saturate. Counters are observations,
not an accounting authority; concurrent snapshots and per-CPU update behavior
must be qualified. No payload or token contents are exported.

## Build and prerequisites

Use the registered shared build lane after coordination, with jobs=2 and
incremental disabled. Do not create a per-branch target or silently install tools.
Three independent manifests prevent portable classifier tests from requiring
the Linux loader or BPF toolchain. All paths assume this directory is applied at
`coaptic-validation/tools/bpf-ingress`, with the existing `coaptic` source link.

1. Host proof: `cargo test --manifest-path tools/bpf-ingress/classifier/Cargo.toml`.
2. Pinned nightly + rust-src, matching official prebuilt bpf-linker:
   `cargo +NIGHTLY build --release -Z build-std=core --target bpfel-unknown-none --manifest-path tools/bpf-ingress/ebpf/Cargo.toml`.
3. Linux loader: `cargo build --release --manifest-path tools/bpf-ingress/loader/Cargo.toml`.

Reviewed lockfiles pin Aya 0.14.0 and aya-ebpf 0.2.1 and their resolved dependencies.
Windows classifier tests and strict Clippy pass; the Windows loader explicitly
refuses execution with exit code 2. Linux loader check and strict Clippy pass
with installed Rust 1.99.0 and x86_64-unknown-linux-gnu. BPF target cargo check
passes with installed nightly-2026-10-01, rust-src and build-std=core. The latter
reports two core no-OSCORE unreachable-expression warnings, not classifier/BPF
errors. These checks do not generate a linked BPF object or prove verifier
acceptance, kernel support, packet handling or cleanup on Linux.
Linux needs BPF syscall/XDP/veth support, sufficient BPF/network privileges,
and `ip` from iproute2. Check the actual WSL kernel configuration and capabilities;
installation alone does not prove these. Retain uname, kernel config/probes,
compiler, linker, source pins, object hash, disassembly and complete verifier log.
Kernel must support bounded loops. No libbpf, C wire parser or kernel headers
are introduced by this code; the LLVM-backed compiler/linker remain build tools.

The shared parser has data-dependent option traversal and checked slice access.
At most 252 option bytes can be traversed for this payload limit, but verifier
acceptance/instruction count and stack usage are unmeasured. Any surviving panic
edge deliberately fails acceptance. If compilation or verification rejects the
shared implementation, fix its shared bounded access/ABI path; do not fork it.
Acceptance requires measured stack <=512 bytes and a recorded finite instruction
budget supported by the selected kernel, not a source-size inference.

## Owned lifecycle and finite execution proof

The loader takes `OBJECT SECONDS CYCLES` (1..60 seconds, 1..3 cycles). It creates
`cpb<PID>a` and `cpb<PID>b`; existing names cause refusal. It attaches only its
own new ingress in SKB mode, detaches its returned link, reads counters, then
reloads a fresh unpinned object for the next cycle. It deletes only the veth it
successfully created. It retains both ifindices and checks both names still map
to those indices and reciprocal iflink values before attachment and deletion.
Missing or replaced identities refuse cleanup and require reconciliation; they
never authorize deleting a same-name replacement. Attachment addresses the
verified ifindex. The disposable pair must remain exclusively owned during this
run, including the short identity-check/delete interval; this is not protection
against a competing privileged namespace mutator. Ordinary errors drop owned
links and attempt cleanup.
SIGKILL/process abort may leave the veth; retain printed names/ifindices and
verify ownership before manual deletion. It never detaches an arbitrary existing
interface program or changes routes, sysctls, firewall or persisted BPF pins.

The disposable-veth pilot is within the authorized task. Check shared runtime
and resource coordination before execution, and attach only to the exclusively
owned disposable pair. There is no automatic attach on build/test. Windows
loader exits with an explicit unsupported-platform error.

Portable tests compare shared-decoder outcomes for each truncated input of seven
valid/invalid/extended-token/opaque-OSCORE seeds in IPv4 and IPv6 envelopes,
check all frame truncations, 256/257-byte boundaries, ports and fragments.
Three portable suites and Linux-target all-target strict Clippy pass with
installed Rust 1.99.0 for the qualification implementation. Actual Linux results
still require executing the manual workflow. Its finite acceptance covers:

- Replay the same finite vectors through BPF_PROG_TEST_RUN and compare return
  PASS, unchanged bytes and per-class counters against the host classifier.
- Inject valid checksummed frames through the peer veth; compare original bytes
  at userspace receiver before/during/after attach, including protected samples.
- Exercise missing network/BPF capability refusal. This program does not request
  XDP_HAS_FRAGS: native multi-buffer hooks are explicitly unsupported, not tested
  PASS cases. Only the named generic linear veth hook is qualified.
- Send known finite batches on multiple CPUs; record counter/loss behavior,
  saturating values and out-of-range array API refusal. Arrays have no full-map insertion
  case; all keys exist from creation. Test this contract rather than invent flow
  exhaustion.
- Run two reload cycles, explicit detach, ordinary loader error and terminated
  process recovery; verify no unrelated links changed and owned cleanup complete.

Official API references:
- https://docs.rs/aya/0.14.0/aya/programs/xdp/struct.Xdp.html
- https://aya-rs.dev/book/start/parsing-packets
- https://docs.rs/aya-ebpf/0.2.1/aya_ebpf/maps/per_cpu_array/struct.PerCpuArray.html
- https://doc.rust-lang.org/nightly/rustc/platform-support/bpf-unknown-none.html
- https://github.com/aya-rs/bpf-linker
