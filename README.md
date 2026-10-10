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
only Coaptic's path-package version in the six lockfiles; dependency pins stay
fixed. Keep the preparation report with results. Reports identify the library
and suite revisions, dirty state, prepared lock hashes, and fixture hashes.

- [App plugtests and dogfood](crates/coaptic-plugtest/README.md)
- [Independent process interoperability](tools/interop/README.md)
- [Benchmark method and limitations](tools/benchmark/README.md)
- [Qualification commands](#qualification)

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
```

Host checks cover six feature modes; explicit i686 targets verify 32-bit test
images, and s390x uses QEMU with ELF endianness checks. Cross builds establish
code generation only. Seeded campaigns are finite sanity checks. LLVM coverage
covers compiled source, including test modules; it has no acceptance percentage.
Device execution, stack limits, power-loss recovery, branch coverage, and full
RFC conformance remain separate qualification work. Performance results are
preliminary and must retain commands, environment, source revisions, and setup
limitations; see the benchmark method before interpreting them.

### Custom ESPHome qualification

The local [package](tools/esphome/coaptic-network-package.yaml) preserves the
consuming configuration's device, Wi-Fi and API/OTA settings. It requires ESP-IDF
and an explicit qualification-only opt-in. No upstream ESPHome contribution is
planned. Its IPv4 UDP service is a plaintext test fixture without actuators,
identity credentials or durable security state.

Build tooling requires clean library and suite checkouts after preparation:

```sh
python tools/qualification/esp32.py --chip esp32c3 --expected-library-revision LIBRARY_COMMIT_SHA --output target/c3/build.json
python tools/qualification/esphome_probe.py --chip esp32s3 --compile --expected-library-revision LIBRARY_COMMIT_SHA --output target/s3/build.json
python tools/esphome/build_archive.py --expected-library-revision LIBRARY_COMMIT_SHA
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
