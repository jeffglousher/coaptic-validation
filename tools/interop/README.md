# Independent process interoperability

Three executables talk over loopback UDP or DTLS:

- `peer-coaptic`: Coaptic App, webrtc-dtls 0.12 / util 0.11.
- `peer-coap-rs`: coap 0.28.1, same DTLS crates, no Coaptic types.
- `peer-libcoap`: libcoap 4.3.5b at `851533c3cf63d16984d370ce39d586ecb3694971`. CMake checks that revision. CI builds OpenSSL DTLS and OSCORE.

libcoap is BSD-2-Clause and is not linked into the library. OpenSSL is a test-machine dependency. The PSK `sesame` is a fixture.

## Build and run

Requires stable Rust, Python 3.10+, CMake 3.20+, a C compiler, and OpenSSL headers.

```sh
cargo build --locked --release -p peer-coaptic -p peer-coap-rs
git init /tmp/libcoap
git -C /tmp/libcoap fetch --depth 1 https://github.com/obgm/libcoap.git 851533c3cf63d16984d370ce39d586ecb3694971
git -C /tmp/libcoap checkout --detach FETCH_HEAD
cmake -S tools/interop/libcoap -B target/libcoap-peer -DLIBCOAP_SOURCE=/tmp/libcoap -DCMAKE_BUILD_TYPE=Release -DENABLE_DTLS=ON -DDTLS_BACKEND=openssl -DENABLE_OSCORE=ON
cmake --build target/libcoap-peer --parallel 2
python3 -m unittest discover -s tools/interop -p 'test_*.py'
python3 tools/interop/run.py --coaptic target/release/peer-coaptic --coap-rs target/release/peer-coap-rs --libcoap target/libcoap-peer/peer-libcoap --iterations 100 --output target/process-interop.json
```

Windows: MSVC (`-G "Visual Studio 17 2022" -A x64`, `--config Release`) and `.exe` paths. Without OpenSSL, configure `-DENABLE_DTLS=OFF -DENABLE_OSCORE=OFF` and pass `--libcoap-udp-only`. CI does not use that flag.

## Result

[`capabilities.json`](capabilities.json) is the case list. A report passes when every enabled case appears once, passes, and keeps evidence. Gaps in that file are open. Linux and Windows are the declared platforms.

`--libcoap-udp-only` and `--libcoap-oscore-unavailable` mark the matching C cases build-excluded. An empty run fails. Wrong-key and blackhole cases need the peer's error exit. A timeout is not a DTLS alert.

Upload readback is `accepted:calls`. `sesame` selects the public RFC 8613 C.1 secret. Any other key label mismatches on purpose.

The Coaptic OSCORE client retries one authenticated 4.01 that carries Echo, once, with the same request. The libcoap direction uses its B.1.2 challenge.

coap-rs answers a skipped Block1 number with 2.31. coap-rs and libcoap apply a duplicated counter POST twice.
