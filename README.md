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
only Coaptic's path-package version in the four lockfiles; dependency pins stay
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

## License

MIT OR Apache-2.0. Independent peers retain their own licenses, including the
[libedhoc fixture notice](tools/interop/libedhoc/LICENSE.libedhoc).
