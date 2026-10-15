# Contributing

Humans and agents follow [AGENTS.md](AGENTS.md). Architecture planning lives in
[GitHub project 2](https://github.com/users/jeffglousher/projects/2); protocol source
copies live in `knowledge/rfcs/`. Public API documentation belongs in rustdoc.

Use the stable toolchain in `rust-toolchain.toml`. The library uses edition 2024
and supports Rust 1.85; test peers have independent dependency requirements.
Merges to `main` are squash-only and must pass the repository CI checks.

## Local validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy -p coaptic-plugtest --all-targets --features dtls,oscore -- -D warnings
cargo test --no-default-features
cargo test --all-features
cargo test --no-default-features --features alloc
cargo test --no-default-features --features oscore
cargo test --no-default-features --features alloc,oscore
cargo test --no-default-features --features std
cargo test -p coaptic-plugtest --features dtls,oscore
cargo doc --no-deps --all-features
cargo package -p coaptic --locked
cargo +1.85.0 check --locked -p coaptic --no-default-features
cargo +1.85.0 check --locked -p coaptic --all-features
```

Run the [dogfood baseline checks](crates/coaptic-plugtest/README.md) and
[independent process suite](tools/interop/README.md) for transport/harness changes.
The [CI workflow](.github/workflows/ci.yml) is authoritative for job flags and
platforms. It runs on pull requests and manual dispatch; process timing JSON is
retained as the `process-interop` artifact. CI smoke timings are not a performance SLA.

## Cross-target build evidence

CI pins Rust 1.97.1 for Cortex-M0 (`thumbv6m-none-eabi`), Cortex-M4
(`thumbv7em-none-eabi`), RV32 (`riscv32imac-unknown-none-elf`) and WebAssembly
(`wasm32-unknown-unknown`). `tools/qualification/cross_build.py` builds a concrete
bounded App probe with core, alloc, OSCORE and alloc+OSCORE configurations and
archives source identity, compiler, commands and results. Install that toolchain
and target, then run it with `--target TARGET --output PATH` to reproduce.

This establishes release code generation, including the library dependency.
It does not link a firmware image, execute on a device, measure stack high-water,
or qualify platform allocators, entropy or networking. Those remain tracked in #202.
The library MSRV remains 1.85; ordinary host CI also checks current stable.

## Seeded qualification

`python tools/qualification/seeded.py --output PATH` uses Rust 1.97.1 and the
committed lockfile to retain source-bound outcomes for five finite campaigns:
6,000 fixed/allocated body operations, 50,000 datagram mutations, 50,000 CBOR mutations, 100,000 replay-window model
steps and 512 authenticated corruption/original/replay sequences. Seeds and
hand-written corpus bytes live beside their oracles in the tests. Body parity
compares typed results, every retained byte/sidecar and periodic reclamation,
with independent exact-byte/range bounds for successful outgoing operations.
The two backends share protocol-state logic; parity is not an independent RFC
oracle or complete multi-peer/network/restart soak. CI archives
the commands, compiler identity, counters and results and refuses missing tests.
These campaigns establish their named invariants; coverage-guided fuzzing,
line/branch coverage and compound network/lifecycle soak remain open in #202.

## Windows and macOS host execution

PR CI runs the library unit, integration and rustdoc tests on Windows and macOS
with pinned Rust 1.97.1 in core, all, alloc, oscore, alloc+oscore and std modes.
`python tools/qualification/host.py --output PATH` reproduces these checks and
retains source/compiler/platform identity, commands, output, executed/ignored
counts and failures. Empty test runs cannot pass. Failure or timeout in one mode
does not suppress evidence from the remaining modes.

These jobs qualify their library test surface on the recorded host architecture.
They do not run the independent process/DTLS adapter matrix, establish host MSRV,
or replace MCU execution, target stack or complete requirements coverage in #202.

## Native 32-bit library execution

The same six-feature host runner accepts `--target i686-pc-windows-msvc` or
`--target i686-unknown-linux-gnu`. Install that target for Rust 1.97.1 and a
matching native linker/runtime (MSVC x86 tools or Linux gcc-multilib). CI runs
both targets. Reports retain executed/ignored test counts and failures, Cargo
artifact paths, SHA-256 hashes and verified PE/ELF 32-bit x86 image headers.
Missing test artifacts, a 64-bit image, zero executed tests or a failed command
cannot pass qualification.

This executes the library's tests with 32-bit pointers on x86 hosts. It does
not qualify ARM/RISC-V MCU execution, big-endian targets, device stack high-water,
entropy, networking or platform allocators. Compiler target selection and image
headers complement actual test execution; none replaces the other.

## Source coverage evidence

Install `llvm-tools` for Rust 1.97.1, then run
`python tools/qualification/coverage.py --work-root BUILD_PARENT --output REPORT.json`.
Each run uses a fresh instrumented build/profile directory and archives source,
compiler, commands, test counts, executable hashes, per-file counters and full
LLVM export. Linux CI retains the report and export. Local build/profile work
is retained at the recorded directory for inspection.

The denominator is compiled `src/` code in the all-feature configuration,
including inline and dedicated unit-test modules. Integration test execution
contributes hits; dependency and external integration-test files do not contribute
to these totals. Rustdoc and other feature configurations are outside this run.
Line, region and function percentages are not branch/condition or RFC requirement
coverage. No minimum percentage is claimed as acceptance; missing tests, profiles,
source files or invalid counters fail the evidence job. Requirement mapping and
branch qualification remain #202.

## Packaging and release

Only `coaptic` is published; harnesses and peers are test-only. Packaging checks
exclude vendored knowledge, tools and workspace test crates from the tarball.
Publishing remains parked ([#132](https://github.com/jeffglousher/coaptic/issues/132)).
Version tags can trigger rustdoc and crates.io release workflows; do not create
release tags as part of ordinary development.
