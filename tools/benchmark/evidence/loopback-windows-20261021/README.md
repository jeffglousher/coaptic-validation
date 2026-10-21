# Windows loopback comparison — 2026-10-21

Core **9a1922ba38f2b34aabfa86156d22dc985203f135**, companion **3612a9ee708898b2f86a7d4a3173b06f770f1433**, both clean at preparation and SmallDevice execution. Cleanup is merged as core#643 / companion#141. This bundle reports current named configurations; it makes no historical speedup or whole-library ranking claim.

Open [loopback-report.html](loopback-report.html) locally for all72 workload views, or inspect [comparison-data.json](comparison-data.json). [raw-sessions.tar.gz](raw-sessions.tar.gz) retains every plan, cell, complete session, source/driver/binary/dependency hash, report, lockfile and executed benchmark command. SHA256SUMS binds these public files; extract the archive into a new owned evidence directory, never over a runtime/source tree. No credentials are included.

## Coverage and result

**1,260 full-matrix cells / 168,000 measured operations, 0 failed, 0 invalid cells and 0 failed warmups.** All 502,333,440 completed payload bytes are checked. A separate six-cell SmallDevice baseline completes1,200/1,200 operations with zero failures.

Five complete rotated windows per stratum, seed20261021, ≥60s gaps;64/1,024/65,536B × concurrency1/4/16 × CON/NON. Operations/cell are256/128/16 by body size, one warmup/worker,1s deadline, fresh server/cell. HTTP3 substitutes warm/cold connections. Measured interval: 2026-10-21T21:00:51.776448+00:00 through 2026-10-21T21:12:47.709472+00:00 UTC. All raw observations are retained; no measured cells were retried or filtered.

- Native independent Rust-driver unprotected CoAP: Coaptic bare and reusable adapters, coap-rs0.28.1, libcoap4.3.5b @851533c3, plgd/go-coap3.5.4, aiocoap0.4.16 and coap-lite0.13.3 codec fixture.126cells/window.
- Matched independent Python driver: Coaptic bare/reusable and aiocoap, each unprotected and volatile OSCORE.108cells/window. OSCORE uses AES-CCM-16-64-128 / HKDF-SHA256, replay32, one shared context with sequence+dispatch serialization. Protected reference analysis uses coaptic-oscore separately.
- quic-go0.63.0 HTTP3/TLS1.3:18cells/window, separate protocol/driver; no direct CoAP-equivalence claim.
- libcoap/coap-rs/go-coap/codec OSCORE fixtures are absent. libcoap's fixture build explicitly disables OSCORE; this is not a claim that the library lacks it. DTLS is unmeasured.

## One reference workload

Unprotected, native driver, complete64B GET/CON, concurrency1. Rates are median per-window verified completions/s; p50 is median per-window; p99 pools successful requests across five windows. The interactive report covers all other cells. These few numbers do not establish an overall winner.

| Fixture | verified ops/s | p50µs | pooled p99µs |
| --- | ---: | ---: | ---: |
| coaptic | 56,497 | 17.1 | 23.1 |
| coaptic-reusable | 56,191 | 17.3 | 34.4 |
| coap-lite-codec | 44,187 | 21.8 | 32.7 |
| libcoap | 40,102 | 23.9 | 51.7 |
| coap-rs | 22,855 | 42.8 | 64.2 |
| go-coap | 18,602 | 52.9 | 98.2 |
| aiocoap | 5,983 | 163.8 | 242.4 |

## Configurations and resource boundary

The broad Coaptic fixture uses custom startup-sized AllocMemory with profiles::Default, blockwise enabled, route1/Calls4/deferred0/association1/bindings4/Observe4/dedup8, RX4/TX4 ×1,472B, RXbody1/TXbodies2 rounded up to1,024B. Growth is off. Bare UdpSocket transient receive scratch is1,473B; reusable UdpSocketIo scratch is2,049B allocated once. These are not total-RAM claims.

The separate SmallDevice/Constrained baseline has fixed RX2/TX2 ×1,152B, routes4/one installed, Call1/deferred0, association1/bindings4/dedup4/Observe2 and blockwise off. Whole App including nested adapter/scratch is13,128B in both modes. Adapter1,168B includes scratch1,153B; static32B response is separate. Do not add nested views again. Core pools are fixed; the process/runtime and setup can allocate. Each of its six cells uses32B GET/CON, concurrency1,20warmups/200measured, common Python client.

Host: Ryzen7 5800X3D,8cores/16logical,34,266,349,568 OS-reported RAM bytes, Windows11 x86_64. Rust1.99.0 release thinLTO/codegen-units1/debug0, incremental off, jobs1; Go1.26.0; Python3.14.4/aiocoap0.4.16/cryptography50.0.2/cbor2 6.1.5/psutil7.0.0. Existing compatible build output was reused; no Coaptic builds overlapped measured sessions. Shared-host noise is retained, not claimed absent.

## Interpretation limits

Closed-loop verified static GET goodput/RTT is not offered-load saturation, native-client library speed or corrected tail latency. CoAP has one outstanding request/endpoint and no retransmission; endpoint rotation and byte checking are timed. Successful latency excludes failures (reported separately); large-body cells have only80successful samples per peer/case across five windows. Paired session bootstrap intervals do not remove shared-host/systematic bias or prove session independence.

Coaptic spins one thread; coap-rs has twoTokio workers; aiocoap uses asyncio. Main native and matched aiocoap also change server transport/ETag, so cross-campaign deltas are not driver-only overhead. coap-lite is a narrower codec endpoint. OSCORE/control differences include client and server crypto, GIL and locking; they do not isolate AES cost. Enrollment, EDHOC setup, persistence, durable effects and restart recovery are outside timing.

Full matrix records server-process CPU and host noise, with quantized counters over driver startup/warmup/requests/exit. Precise per-requestCPU, full-matrixRSS/heap, startup/ISR/kernel/stack peaks and minimum deployment RAM are unmeasured. SmallDevice retains complete process-treeRSS/clientCPU/memory records; these views include runtime and overlap component storage. This is local loopback only. Remaining MCU reverse-LAN and physical persistence/touch qualifications stay open under core#341/#333/#365.
