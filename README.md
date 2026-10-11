# Coaptic validation

Independent sanity checks for [Coaptic](https://github.com/jeffglousher/coaptic):
CoAP interoperability, protected messages, constrained-target builds, and
preliminary performance measurements. The library and its Rust tests stay in
Coaptic. Test peers and Python, Go, and C tooling live here.

## Run

Clone the library into the ignored `coaptic/` directory and check out the full
commit SHA in [library.json](library.json), or a candidate commit you want to check:

```sh
git clone https://github.com/jeffglousher/coaptic.git coaptic
git -C coaptic checkout --detach LIBRARY_COMMIT_SHA
python tools/prepare.py --expected-revision LIBRARY_COMMIT_SHA --output target/validation-source.json
cargo test --locked -p coaptic-plugtest --features dtls,oscore
```

Preparation rejects modified source and mismatched plugtest fixtures. It aligns
only Coaptic's path-package version in the seven lockfiles; dependency pins stay
fixed. Keep the preparation report with results. Reports identify the library
and suite revisions, dirty state, prepared lock hashes, and fixture hashes.

- [App plugtests and dogfood](crates/coaptic-plugtest/README.md)
- [Independent process interoperability](tools/interop/README.md)
- [Benchmark method and limitations](tools/benchmark/README.md)
- [Qualification commands](#qualification)
- [Durable host effect/receipt reference](tools/durable-host/README.md)

Coaptic CI calls [validation.yml](.github/workflows/validation.yml) at an exact
suite commit. This repository's CI checks the public baseline in `library.json`;
manual runs accept another full library commit SHA. Updating that baseline is an
explicit change. Moving the tooling does not establish production readiness.

## Qualification

Run from this repository after preparation; Python 3.10+ and Rust 1.97.1 are
required for these runners. Cross targets must be installed with rustup.

```sh
python tools/qualification/host.py --output target/host.json
python tools/qualification/seeded.py --output target/seeded.json
python tools/qualification/cross_build.py --target thumbv7em-none-eabi --output target/cross-build.json
python tools/qualification/coverage.py --work-root BUILD_PARENT --output target/coverage.json
python tools/qualification/coverage.py --branches --work-root BUILD_PARENT --output target/branches.json
python tools/qualification/fuzz.py --seconds 60 --output target/fuzz.json
```

Host checks cover six feature modes; explicit i686 targets verify 32-bit test
images, and s390x uses QEMU with ELF endianness checks. Cross builds establish
code generation only. Seeded campaigns are finite sanity checks. LLVM coverage
covers compiled source, including test modules; it has no acceptance percentage.
Branch coverage and address-sanitized libFuzzer campaigns require
`nightly-2026-10-01` with `llvm-tools` and `rust-src`, plus cargo-fuzz 0.13.1.
Fuzzing uses fresh seeded corpora, bounded time/inputs/memory, three semantic
oracles and nonzero execution/feedback requirements. Reports retain both source
revisions and the fuzz lock hash. The coverage report also requires execution
of 18 named RFC requirement proofs; this inventory is selected, not exhaustive.
On Windows, supply `--asan-runtime-directory` for the installed MSVC ASan DLL;
the runner adds it only to the campaign environment and records its hash.
Device execution, stack limits, physical power-loss recovery, and full
RFC conformance remain separate qualification work. Performance results are
preliminary and must retain commands, environment, source revisions, and setup
limitations; see the benchmark method before interpreting them.

### Protected Linux container

With Docker available on an isolated Linux host, prepare the selected library
revision as above, then run:

```sh
python3 tools/qualification/container_host.py --output target/protected-container
```

Use a new output directory for each run. The runner uses the pinned official
Rust 1.97.1 image digest in its source and mounts the library read-only. It builds
separate `std` fixed-storage and `std,alloc` heap-storage examples, records their
hashes, then disconnects external container networking before execution. Both
peers use loopback and fresh in-process OSCORE credentials.

Seven cases check complete 200-byte responses, unknown-argument refusal,
`--alloc` refusal when allocator support was not compiled, and valid recovery.
The report retains commands, raw stdout/stderr, exit codes, library/suite/lock
identities, the image digest and toolchain. Only the runner's uniquely named
container is removed; image caches are retained.

The [initial hosted run](https://github.com/jeffglousher/coaptic-validation/actions/runs/38078017939)
passed all seven cases against core `47058bb169e855694b267b7fb658d6010f8d93f2`
and clean synthetic suite `d6350482860acb6319b60f0589b842fc5e8dc2cc`.
The `protected-linux-container` artifact contains the full evidence. This
qualifies those localhost examples in a container, not physical devices,
enrollment, persistence, routed networks or sustained service capacity.

### Custom ESPHome qualification

The local [package](tools/esphome/coaptic-network-package.yaml) preserves the
consuming configuration's device, Wi-Fi and API/OTA settings. It requires ESP-IDF
and an explicit qualification-only opt-in. No upstream ESPHome contribution is
planned. The sample package explicitly selects `allow_plaintext: true` for
unprotected qualification. Protected mode instead requires an `oscore` profile
with unique private `master_secret` (32 bytes), `master_salt` (16 bytes),
`context_id` (16 bytes), and mirrored Sender/Recipient IDs. Use ESPHome secret
references; never commit credential values. The two modes cannot be combined.

For first-time setup, an operator stages fresh credentials and selects
`oscore.provision_only: true`: that image writes the authenticated 100-byte NVS
record and exposes no UDP service. A later image with `provision_only: false`
recovers that record before protected traffic. Missing, corrupt, wrong-context
and uncertain storage refuse; no record is silently reset. Sender ranges of
256 are durably reserved and skipped after restart; inbound replay checkpoints
commit before dispatch. A failed or ambiguous commit stops the service.
The qualification task also stops after 32 consecutive poll failures, including
invalid protected packets; sustained hostile-traffic availability is unqualified.

Both network modes guard the caller's millisecond clock. Equal ticks are valid;
a backward tick stops before another receive, sender reservation, checkpoint or
notification, with FFI result `-7`. `None` remains an explicit clean stop. A new
run performs ordinary ownership and durable-security recovery; do not reset the
clock epoch while an App is live. Extend wrapping counters in the platform
adapter. The guard does not detect stopped clocks or incorrect forward jumps,
and host tests do not qualify the physical timer or update installed firmware.

The task exclusively owns its context and NVS record. Authentication/readback
protect against corruption and accidental substitution, not restoration of a
valid old flash snapshot. NVS and compiled credentials do not establish hostile
rollback resistance or production key custody. After uncertain freshness or
state loss, provision fresh credentials through an explicit operator step.
This service supplies no actuators or durable application-effect receipts.

The finite Rust `waveshare-peer` host driver uses fixed Coaptic storage with
`std` and without `alloc`. Its private credential file has 66 bytes; its locked
100-byte state file requires explicit offline `provision` before `check`.
Each process recovery skips the previous 256-value sender reservation.
`replay` locally authenticates the saved identity request, sends it first, then
requires a fresh protected response matching the firmware run ID. To attribute
that result to durable device recovery, independently observe the restart and
allow no intervening protected traffic. Silence alone is not a passing result.
This finite driver is a qualification tool, not an unbounded host service.

The optional Rust `telemetry` feature provides
[`pending_telemetry`](tools/esphome/rust/src/pending_telemetry.rs): one
authenticated 1,214-byte caller-owned record for a complete pending operation
and its matching receipt. It requires separate storage from OSCORE counters,
refuses uncertain writes until recovery, and compiles without `std` or `alloc`.
It is an adapter building block; the live ESPHome service does not yet send
durable application telemetry through it. Physical restart/power-loss evidence
and the deployed device-to-host flow remain in the project issues.

Build tooling requires clean library and suite checkouts after preparation:

```sh
python tools/qualification/esp32.py --chip esp32c3 --expected-library-revision LIBRARY_COMMIT_SHA --output target/c3/build.json
python tools/qualification/esphome_probe.py --chip esp32s3 --compile --expected-library-revision LIBRARY_COMMIT_SHA --output target/s3/build.json
python tools/esphome/build_archive.py --expected-library-revision LIBRARY_COMMIT_SHA --oscore
```

ESPHome tooling pins version 2026.9.1 and ESP-IDF 5.5.5. S3 compilation requires
the `coaptic-esp-1.97` Espressif Rust toolchain. Generated archives stay out of
git; bundled mode requires both expected source revisions and checks the archive
checksum, target, features and prepared lock hashes. External mode lets a
consuming Rust subsystem own the enclosing static library and panic handler.
Configuration-only tests use opaque archive bytes and do not establish linking.

Capture recording requires both `--expected-library-revision` and
`--expected-suite-revision`, unchanged firmware hashes and fresh run IDs. Build
reports are not device results or authenticated attestation. These commands do
not deploy firmware. Protected networking, platform entropy and durable flash
recovery remain unqualified.

## License

MIT OR Apache-2.0. Independent peers retain their own licenses, including the
[libedhoc fixture notice](tools/interop/libedhoc/LICENSE.libedhoc).
