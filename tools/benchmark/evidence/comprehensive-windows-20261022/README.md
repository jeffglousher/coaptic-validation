# Protected and unprotected loopback sitrep — 2026-10-22 UTC

Redundant OSCORE receive reconstruction, RX reserialization and fresh-TX staging are removed in [core#648](https://github.com/jeffglousher/coaptic/pull/648). The before/after64B core-poll probe shows unchanged median p50 at1µs unprotected /2µs OSCORE. This batch removes real duplicate work; it does not establish a large speedup or a historical regression.

Open [comprehensive-report.html](comprehensive-report.html) for all90 workload views, CPU/memory snapshots, exact configurations, copy/lifetime findings, packet grades and remaining work. [comparison-data.json](comparison-data.json) contains the full analysis. [raw-sessions.tar.gz](raw-sessions.tar.gz) retains every plan, cell, window, raw latency, failure, lock/source/tool identity, diagnostic and execution recipe. [archive-index.json](archive-index.json) hashes every archive member; SHA256SUMS binds the public files. Extract into a new evidence directory, never over a source/runtime tree.

## What the current core achieved

Coaptic completed **84,000/84,000** main-matrix operations across its named configurations, with no failed requests, warmups or invalid cells. In the reference64B complete GET/CON, concurrency1, median window rates were:

- Native Rust unprotected: Coaptic57,325ops/s, reusable54,019; libcoap36,341, coap-rs23,349, go-coap16,881, aiocoap5,647. The narrower coap-lite codec fixture delivered39,441.
- Matched Python unprotected: Coaptic19,027ops/s, reusable17,936.
- Matched Python OSCORE: Coaptic6,530ops/s, reusable6,609; libcoap4,016 and aiocoap1,959.
- Common Go DTLS: Coaptic14,041ops/s, coap-rs11,934, go-coap12,964, libcoap16,925. Coaptic/coap-rs use explicitly test-only adapters; DTLS is not added to the core endpoint scope.
- HTTP/3 TLS1.3 warm:6,489ops/s, a separate protocol/client baseline.

These are named shared-host observations for one reference workload, not universal rankings. Native Rust UDP, Python UDP/OSCORE, Go DTLS and HTTP/3 are separate measurement strata. Do not subtract their times to isolate cryptography. The interactive report includes the other89 views, all tails, goodput, failure counts and eligible paired intervals.

## Complete accounting, including problems

The main matrix recorded **2,070cells**, **275,952 accounted measured attempts**, **275,945 verified completions**, **7 failed requests**, **3 invalid cells**, and **821,657,600 verified payload bytes**. Failed warmups are0 in valid records. Of276,000 planned operations,48 have no valid accounting; activity before the DTLS crash is unknown. Main collection ran 2026-10-22T01:53:02.215896+00:00 through 2026-10-22T02:13:41.585907+00:00 UTC. No measured cell was overwritten, retried or filtered.

Five complete rotated windows per stratum, seed20261022, ≥60s same-stratum gaps;64/1024/65536B × concurrency1/4/16 × CON/NON (HTTP/3 warm/cold). Operations/cell256/128/16, one warmup/worker,1s complete-operation deadline. Python also performs a verified bootstrap GET/worker before warmup/timing; libcoap's authenticated Echo replay initialization occurs there. Setup and compilation precede timing.

All final-source failures involved Go-related cells. [Comparator issue#146](https://github.com/jeffglousher/coaptic-validation/issues/146) tracks a proven NON response-cache MID collision: distinct client MIDs and new token2 receive stale token1. The [five-frame diagnostic receipt](go-mid-collision-r2.json) verifies two1024B blocks, not complete64KiB operations. The initial diagnostic's parser-direction assertion and corrected r2 are both retained.

[Runtime issue#147](https://github.com/jeffglousher/coaptic-validation/issues/147) records the Go1.26.0 Windows UDP driver/runtime crash. It is consistent with a [known upstream regression](https://github.com/golang/go/issues/77975), [backported in1.26.2](https://github.com/golang/go/issues/78041); the truncated stack does not prove that cause. [Follow-up#148](https://github.com/jeffglousher/coaptic-validation/pull/148) requires Go1.26.2+. A separate Go1.26.9 control completes14cells/224operations without failure. Those samples do not replace the original Go1.26.0 matrix or establish absence of intermittent crashes.

## Sources and tools

Main core **739c277642219ae235b0ab0926b5c95d81f51b59**; main harness **eb1645f18ede454a85f28677a4a97698137c9a9b**, both clean when prepared. Follow-up capture/toolchain guard is **5b414b0938dd6bcb0c6dd1ebafa4c1f688b49caa**. It changes capture shutdown handling and the Go minimum, without rewriting main samples or Go wire-driver logic. Before-copy baseline is fae3fa444076779197f5f1a6918546d7aed87814, tested with the identical black-box probe/lock/compiler. Raw4096-sample clock calibrations/window are separate and never subtracted.

Windows11 Pro26200 x86_64; Ryzen7 5800X3D,8cores/16logical,34,266,349,568 OS-reported RAM bytes. Rust1.99.0 release thin-LTO/codegen-units1/debug0;Go1.26.0 for main matrix,1.26.9 for separate control;Python3.14.4;aiocoap0.4.16;cryptography50.0.2;cbor2 6.1.5;psutil7.0.0. libcoap4.3.5b@851533c3;portable MbedTLS3.6.7 asset SHA256 a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6;go-coap3.5.4;coap-rs0.28.1;coap-lite0.13.3. Manifests hash executables, scripts, crypto extensions, dependency trees and locks. Existing build lanes were reused; builds and packet capture never overlapped main timing.

Real sockets and complete observed outputs prevent trivial network-test elimination. Socket-free polls additionally use [std::hint::black_box](https://doc.rust-lang.org/std/hint/fn.black_box.html), a best-effort optimization barrier rather than a security/constant-time guarantee. Criterion was not added to the manual process/network harness. The static representation excludes business logic; closed-loop goodput/RTT is not offered-load saturation or corrected tail latency.

## Resource and security boundaries

SmallDevice/Constrained fixed App is **13,128B**, including its1,168B adapter/1,153B scratch; packet payload arrays total4,608B and the static32B body is external. Six descriptive cells complete1,200/1,200 operations. It is a fixed-core fixture inside a std/alloc host executable, not a wholly allocator-free process.

The broad Default/blockwise fixture requests **23,462B pool heap** for64/1024B bodies and **216,998B** for64KiB, including slot/table/pin metadata. Whole bare-UDP App inline is13,960B; reusable App16,016B includes2,049B scratch. The original representation is additional. Pools are allocated at App initialization and never automatically grow. DTLS admits one App/session, bounded128, rather than preallocating all128 at process startup. Its aggregate pools multiply; runtime/crypto/queues are additional.

The separate diagnostics-enabled, OSCORE-disabled profiler records32 setup allocations and zero poll allocations/reallocations for64B×1000 and64KiB×32 operations. Its heap totals differ from the OSCORE-enabled ABI; they are not substituted for the broad comparison budget. Source arrays, inline ownership, requested heap and process RSS overlap and must not be blindly added. Whole-stack/initialization/allocator/kernel/runtime peaks and minimum deployment RAM remain unmeasured. Server-tree CPU/current-memory/thread snapshots are retained; shared pages overlap, CPU is quantized, and individual lifetime peaks are never summed into a false simultaneous peak.

No wipe policy was added. [Core#647](https://github.com/jeffglousher/coaptic/issues/647) tracks plaintext/key lifetime and compiler-resistant zeroization as future study. Fewer logical copies do not guarantee physical erasure. Transactional retained-TX staging and necessary crypto/ownership copies remain. No device keys, firmware, NVS, pairing or unresolved effects changed.

## Packet proof and remaining work

**60/60 final validation cases pass**:28unprotected complete-body/exchange cases,16OSCORE independently authenticated complete-body cases,16DTLS record-framing cases with separate online authenticated body verification. **19,831** actual received UDP payload frames are in the final validation set. Initial16DTLS capture failures and all76capture attempts remain in private evidence/receipts. Windows closed-client ICMP handling was fixed on the relay's front socket; no payloads or actual forward errors are ignored. The public bundle retains capture/grade receipts and hashes; synthetic credentials and full capture directories remain private for regrading. Go MID diagnostic PCAP contains public synthetic unprotected data and is included.

PCAP DLT_USER0 is socket-boundary evidence with direction/time/hash sidecars, no invented IP/Ethernet headers. Kernel capture was unavailable: no installed Npcap/Wireshark and pktmon driver access denied. DTLS offline framing is not decrypted-body or authentication proof. Capture never contributes timing data.

Focused local validation:1,169 core tests; strict core Clippy all-feature/no-default;73Python benchmark tests;24native tests;Go tests;formatting;independent general correctness/security reviews;all90report views exercised without NaN/undefined. Physical persistence#333, installed backup recovery#365 and two reverse ESP32 LAN cells under#341 remain deferred. Release publication remains separate under#132. The open Go comparator defect#146 is explicit; it does not reopen accepted Coaptic protocol implementation.
