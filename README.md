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
suite commit. This repository's CI checks the full library revision pinned in
[ci.yml](.github/workflows/ci.yml); manual runs accept another full library commit
SHA. `library.json` supplies the checkout baseline for local setup. Changing either
reference is an explicit source selection. Moving the tooling does not establish
production readiness.

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
of every named proof in [the requirement manifest](tools/qualification/contracts.json);
this inventory is selected, not exhaustive.
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

`raw-udp ADDRESS CREDENTIALS STATE REPORT RUN_ID` uses the same exclusive
private state, with a new report path instead of a saved request. In protected
service mode it checks identity, complete 2000-byte delivery, 128-byte echo and
an authenticated timer before and after four finite 64-packet UDP groups
(1153, 2047, 2048 and 4096 bytes, all `0xa5`, 50 ms pacing). It never provisions
or switches firmware. A completed host report explicitly leaves device
qualification false: [the offline grader](tools/qualification/raw_udp.py)
requires independent encrypted-API counter capture and verified build/install
records. [Synthetic fixtures](tools/qualification/test_raw_udp.py) exercise
refusal grading and do not qualify hardware or sustained availability.

Pacing targets observable delivery through the device socket boundary, not
throughput. The [source-bound physical record](tools/qualification/evidence/waveshare-raw-udp-20261011.json)
and [qualification report](https://github.com/jeffglousher/coaptic/issues/462#issuecomment-6107306240)
retain three actual trials: 56 recorded drops at 2 ms pacing, 64 at 50 ms,
and all 256 after enabling IPv4 reassembly in the qualification image. The
unchanged strict grader rejected both incomplete trials and accepted the third,
including all 20 protected controls and timer progress. Those failures do not
conclusively locate packet loss. Firmware and host source identities are separate.

The successful ESP-IDF v5.5.5 qualification image adds these platform settings
to the existing ESPHome `esp32.framework` configuration:

```yaml
sdkconfig_options:
  CONFIG_LWIP_IP4_REASSEMBLY: "y"
  CONFIG_LWIP_IP_REASS_MAX_PBUFS: "10"
```

These settings let fragmented IPv4 UDP datagrams reach the socket boundary.
The generated SDK configuration changed only the reassembly enable flag; the
waiting-pbuf limit remained 10. Its three-second reassembly lifetime and ten-pbuf
count describe platform resources outside Coaptic's storage budget, not a byte
or whole-device memory ceiling. This qualification configuration does not change
core defaults or establish sustained availability or throughput.

The grader's `--help` lists the required retained artifacts. Its manifest binds
40-character core/suite revisions, host binary and OTA hashes, protected mode
1, run ID, installation time/receipt hash, capture-tool hash and SHA-256 hashes
of `host_build`, `firmware_preparation`, `component_archive` and `installation`.
The firmware preparation retains `images` with build success, run ID and OTA
hash; the upload receipt records `exit_code: 0`, `mode: "protected"`, run ID,
OTA hash and host `observed_at_ms`. Existing static-archive build metadata is
checked inside the component archive without filesystem extraction. Compressed
input is limited to 16 MB, expansion to 32 MiB and physical/logical TAR headers
to 64; duplicate members and links refuse. This is build/install attribution, not
cryptographic firmware attestation.

Capture input is JSONL: `capture_begin` records `at_ms`,
`clock: "host_utc_receipt"`, `transport: "encrypted_esphome_api"` and
`device_ipv4`; each `log` records host receipt `at_ms` and `message`;
`capture_end` records `at_ms`. Use the same host UTC clock as the campaign,
start after the verified service is ready, and retain counter samples within
10 seconds before and after the campaign. Device timestamps are not substituted.
All 256 actual socket drops must be accounted for; unrelated oversize traffic,
missing counters, counter resets, stopped tasks or partial bodies refuse the
result. The task may yield zero times under paced traffic; this campaign does
not establish scheduling fairness. Telemetry mode 3 requires a separately
reviewed service-mode transition before this demonstration.

The optional Rust `telemetry` feature provides
[`pending_telemetry`](tools/esphome/rust/src/pending_telemetry.rs): one
authenticated 1,214-byte caller-owned record for a complete pending operation
and its matching receipt. It requires separate storage from OSCORE counters,
refuses uncertain writes until recovery, and compiles without `std` or `alloc`.
The optional `coaptic_network.telemetry` configuration runs one retained
operation through the protected network adapter. It requires existing OSCORE
state and an explicitly installed `principal_public_key`, `principal_kid`,
32-byte hexadecimal `resource`, unicast IPv4 `peer_address`, and optional
`peer_port` (5683) and `timeout_ms` (30000, at most 300000).
This is a caller-installed pairwise qualification binding, not enrollment.

First add `telemetry.provision_pending` with a unique hexadecimal `operation_id`
(16 bytes), `payload_hex` (at most 1024 bytes), and optional `content_format`.
This selects an offline task: it verifies existing security state and commits
the complete pending operation before any socket opens. An existing pending
record refuses replacement. Then remove `provision_pending` to transmit that
saved operation. Normal operation never initializes missing records. Both modes
use the same telemetry archive; `oscore.provision_only` cannot be combined with
telemetry. The NVS keys `state_v1` and `pending_v1` are separate records in the
owned `coaptic_sec` namespace. No key is erased by these modes.

The task stops after one bounded attempt. A restart recovers the same operation
and skips previously reserved sender sequences; an authenticated receipt must
be durably saved before `COAPTIC_TELEMETRY_COMPLETE` is logged. A previously
completed record returns its saved result without transmitting.

A [source-verified ESP32-S3/Windows qualification](tools/esphome/evidence/retained-telemetry-20261011.json)
retained a 1024-byte operation across a device software restart after the host
withheld its receipt. A fresh host process returned the original receipt with
one journaled effect and a byte-identical journal; the device then logged durable completion.
The report records separate firmware and host source revisions, hashes, methods,
setup failures and limits. ESP32-S3 is a qualification platform for the portable
constrained adapter. Flash power-loss recovery, hostile snapshot rollback,
production key custody and enrollment remain unqualified in #333/#365.

Build tooling requires clean library and suite checkouts after preparation:

```sh
python tools/qualification/esp32.py --chip esp32c3 --expected-library-revision LIBRARY_COMMIT_SHA --output target/c3/build.json
python tools/qualification/esphome_probe.py --chip esp32s3 --compile --expected-library-revision LIBRARY_COMMIT_SHA --output target/s3/build.json
python tools/esphome/build_archive.py --expected-library-revision LIBRARY_COMMIT_SHA --oscore
# For the pending-telemetry modes, add --telemetry to the protected archive build.
# Add --async-network for a native async archive, matching async_network: true below.
```

Set `coaptic_network.async_network: true` to run the same App, protected service,
pairing or retained telemetry mode on socket readiness and absolute timers in
the existing ESPHome worker task. Bundled archives must include `async-network`;
source mode selects it automatically. Pairing also waits on the existing USB
console, so local management remains available when its network session stops.
The default synchronous integration remains available. The async driver adds
no packet queue or payload staging buffer; ESP-IDF owns native select/eventfd
bookkeeping. Its metadata and retained future have independent compile-time
ceilings, and startup logs their actual sizes for the built configuration.

The reserved ESPHome integration keeps its existing ESP-IDF/lwIP socket and
FreeRTOS task. [Embassy's executor](https://github.com/embassy-rs/embassy/tree/main/embassy-executor)
can support a custom RTOS platform, but that still needs a platform wake callback
and sleep loop. This single-service adapter uses those existing task facilities
directly. [Embassy-net](https://github.com/embassy-rs/embassy/tree/main/embassy-net)
provides its own network stack; replacing the firmware's Wi-Fi/network ownership
is unnecessary for this integration. Coaptic's portable async transport and timer
traits remain executor-neutral. This ESPHome component permits one runtime;
that platform choice does not restrict multiple Apps in other integrations.

ESPHome tooling pins version 2026.9.1 and ESP-IDF 5.5.5. S3 compilation requires
the `coaptic-esp-1.97` Espressif Rust toolchain. Generated archives stay out of
git; bundled mode requires both expected source revisions and checks the archive
checksum, target, features and prepared lock hashes. External mode lets a
consuming Rust subsystem own the enclosing static library and panic handler.
Configuration-only tests use opaque archive bytes and do not establish linking.

Capture recording requires both `--expected-library-revision` and
`--expected-suite-revision`, unchanged firmware hashes and fresh run IDs. Build
reports are not device results or authenticated attestation. These commands do
not deploy firmware. Build success alone does not establish protected networking,
platform entropy or durable flash recovery on a physical device.

## License

MIT OR Apache-2.0. Independent peers retain their own licenses, including the
[libedhoc fixture notice](tools/interop/libedhoc/LICENSE.libedhoc).
