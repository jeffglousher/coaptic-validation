Audit source: main 72c0083. Existing CI checks host Rust stable/MSRV, feature combinations, tests/docs/package and Linux process interop. The initial audit identified the following missing qualification evidence. Subsequent resolved portions are recorded below; remaining work stays open:

- Fuzz/property/state-machine campaigns for datagram and option codecs, nested CBOR/problem details, block reassembly and OSCORE parsing/replay.

- Line/branch coverage reports mapping product requirements to exercised/refusal paths. Test counts and TD inventories are not coverage percentages.

- Embedded no_std cross-target checks/runtime qualification (32-bit MCU, different alignment/endianness as applicable); host no-default-features check alone does not establish embedded support.

- Windows/macOS adapter/platform breadth and IPv6 networking coverage; continuous library execution is covered by #271 below. Windows C-peer DTLS remains unavailable in the local build.

- Multi-peer saturation, cancellation/restart cleanup, body/slot/Observe lifecycle soak, deterministic compound fault schedules and finite-resource invariants across feature combinations.

- Memory/stack footprint qualification on target. Existing footprint tests establish useful host layout assertions but do not measure target stack high-water or runtime allocation of adapters.

Acceptance: pin reproducible seeds/corpora/toolchain/target and archive evidence. Define supported target matrix and explicit unavailable checks. Add useful fault/property oracles rather than tests that mirror implementation. Coordinate the independent peer matrix and legacy TD correction work; keep performance ranking out of this coverage milestone.

Sources: https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/.github/workflows/ci.yml ; https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/tests/footprint.rs ; https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/tests/block_sweep.rs.

Implemented in #231 (main 6465441): pinned Rust 1.97.1 release code generation for a concrete bounded App probe on thumbv6m-none-eabi, thumbv7em-none-eabi, riscv32imac-unknown-none-elf and wasm32-unknown-unknown, each with core/alloc/oscore/alloc+oscore. All 16 local and Linux CI combinations passed; per-target source/compiler/command JSON artifacts are archived. This closes the initial cross-build absence only. Firmware linking, runtime/device behavior, stack high-water, allocators/entropy/adapters and big-endian execution remain unqualified.

Implemented in #232 (main ff4db0d): pinned finite campaigns for 50,000 datagram mutations, 50,000 CBOR mutations, 100,000 replay-window model steps and 512 authenticated corruption/original/replay sequences. Local and Linux CI evidence includes seeds/corpus source, exact commands, compiler identity and nonempty test accounting. This adds reproducible invariant checks, not coverage-guided fuzzing, full requirements or branch coverage, compound network/lifecycle soak, or device execution. Those remain open.

Implemented in #234 (main 250a9c8): five IPv6 UDP loopback pairings verify GET, 4.04, exact 2000-byte Block2 and subsequent service, with an independent AF_INET6 socket probe and actual ::1 bytes. All 36 full Linux cases and all 31 enabled Windows cases passed; Windows still explicitly excludes five C-peer DTLS cases. Scoped/link-local IPv6, IPv6 DTLS and compound fault schedules remain unqualified.

Implemented in #271 (main baa0913): pinned Rust 1.97.1 continuous Windows x86_64 and macOS host library execution in six feature configurations. Source-bound artifacts retain commands, platform/compiler, executed/ignored counts, stdout/stderr and failures; zero-test results and timeouts fail. All six modes passed on both hosted platforms; all 17 local checks, Linux process 51/51 and hosted checks passed before merge. This does not qualify host adapter/DTLS matrices, host MSRV, MCU runtime, target stack or full branch/RFC coverage.

#275: reproducible Rust 1.97.1 LLVM execution coverage now archives source/compiler/platform/commands, executable hashes, per-file counters and complete export. Hosted Linux source d4edf1009ddbbd2e2bf694105c4cae2b45a33de1 clean executed 674 tests; src-tree line hits 33081/35477. This denominator includes src unit-test modules and only all-feature compiled code. Integration execution contributes hits; dependency/external test source, rustdoc, other configurations, branch/condition and RFC requirement completeness are not represented by these percentages. All local/hosted checks passed before merge. Requirement mapping, branch evidence and target runtime remain open.

#276 (main c8320b8): the seeded qualification artifact now requires the 6,000-operation fixed/allocated body parity test. Twenty operation categories execute 300 times each, plus periodic draining. Exact result/state/byte comparisons and successful outgoing bounds are checked. All local and hosted checks passed; alloc modes execute the test. It does not establish arbitrary allocator exhaustion, branch completeness, wire binding or compound network/restart soak.


#283 (main a1755e5): native i686 Windows and Linux execute all six library feature configurations. Both hosted runs passed 578/706/607/674/703/610 tests (core/all/alloc/oscore/alloc+oscore/std), one ignored manual benchmark per mode, with six verified 32-bit test images per mode. Clean hosted source a20d8598b8e5be66876ba41005916653859044f2; all local and hosted checks passed. Reports retain image hashes/PE-or-ELF identity and actual executed counts. This closes native 32-bit x86 host execution only; MCU runtime, physical stack, big-endian and hardware qualification remain separate.
