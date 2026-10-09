# coaptic-plugtest

Workspace test crate. Not published. The `coaptic` library stays `no_std`; OSCORE is enabled by default. This harness disables default features and explicitly selects plaintext unless its OSCORE mode is requested.

```bash
cargo test -p coaptic-plugtest
cargo test -p coaptic-plugtest --features dtls
cargo run -p coaptic-plugtest --bin dogfood
cargo run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore
cargo run -p coaptic-plugtest --bin dogfood -- --iterations 2 --compare crates/coaptic-plugtest/baselines/dogfood.json
cargo run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore --iterations 2 --compare crates/coaptic-plugtest/baselines/dogfood-oscore.json
```

Timed mixed-stack dogfood (coap-rs client → coaptic server and the swap): GET/PUT/POST, Observe register/deregister, Block2/Block1. The run fails if mixed-stack `observe_register` / `observe_cancel` or Block assemble stay cold — not only `--compare`. A third leg is coaptic↔coaptic Observe **notify collect** (`App::notify` → client `take_response`) so `observe_notify` is not left cold — coap-rs is a register/deregister stub. `--oscore` (feature `oscore`) adds a coaptic↔coaptic OSCORE GET/PUT/POST loop plus Observe register/notify collect and Inner Block-wise (Block2 GET /large, Block1 PUT /large-update) with mirrored caller-owned `SecurityContext`s; the run fails if protect/unprotect, protected notify, or protected Block stays cold, or a token-matching plain 2.xx / plaintext notify completes a Call. The `coap` 0.28 peer has no OSCORE API. Default is 50 iterations; short CI smoke: `--iterations 2` and `--oscore --iterations 2`. Prints wall min/mean/p50/p99/max, Engine occupancy, `app.metrics()`, and a **coverage** section (mixed vs still coaptic-only).

**Covered (coap-rs, both directions):** GET/PUT/POST `/test`, Observe register/deregister `/obs`, Block2 GET `/large`, Block1 PUT `/large-update`.

**Still coaptic-only:** Observe notify collect; OSCORE (`--oscore`). **Not covered by dogfood:** DTLS, coap-rs OSCORE, full ETSI plugtest matrix. Separate [process tests](../../tools/interop/README.md) exercise PSK DTLS with independent Rust and C stacks.

`--json PATH` writes schema `coaptic-dogfood/1` (Metrics + series timings). `--compare PATH` diffs this run against that file: **fail** if path-proving counters drop (`observe_notify`, `block1_assemble`, `block2_assemble`, mixed-pair `sum(block1_assemble)` / `sum(block2_assemble)`, …) or error counters rise; **print** wall-timing deltas (host/load specific, not a fail). Pair-local Block assemble of 0 on one mixed direction is expected (server Block1 vs client Block2); the cross-pair sums are the name-independent floor so a silent swap cannot hide a cold assemble type. `progress` stays informational. CI compares the `--iterations 2` smokes to [`baselines/dogfood.json`](baselines/dogfood.json) and [`baselines/dogfood-oscore.json`](baselines/dogfood-oscore.json) (a lock, not a perf SLA). Refresh those files with the same flags after an intentional Metrics change:

```bash
cargo run -p coaptic-plugtest --bin dogfood -- --iterations 2 --json crates/coaptic-plugtest/baselines/dogfood.json
cargo run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore --iterations 2 --json crates/coaptic-plugtest/baselines/dogfood-oscore.json
```

This crate is the **App SUT**. The in-crate `cargo test --test plugtest` harness is Engine↔Engine only (no sockets).

- [`Peer`](src/peer.rs) — start/stop server, client request, local UDP addr. Backends: `coaptic`, `coap-rs`. Add a library by implementing the trait.
- Pcap writer + golden JSON grader (`expectations/catalog.json`). CORE goldens assert type, token echo, and CON↔ACK MID, and omit `allow_extra`. OBS / BLOCK / LINK / DTLS keep `allow_extra` (notifications, block trains, mixed-peer extras). Ports / time are wildcards.
- DTLS: feature `dtls` uses webrtc-dtls 0.12 via explicit transport adapters as a **harness** `DatagramIo` adapter. The library has no DTLS dependency. Mixed pairs (`coap-rs→coaptic`, `coaptic→coap-rs`, `coaptic→coaptic`) run handshake + GET `/secure` with coaptic as SUT.
- `TD_6LoWPAN_*` stay skipped (`future/backlog` — contributor opportunity).

### Qualification boundary

The App TD runner reports known incomplete scenarios as `SKIP: coverage gap #199`.
Still unfinished, not conformance passes: OBS_01 (notifications stay NON until the
24-hour confirm point); the rest of OBS except a coaptic↔coaptic OBS_02 NON
notification (coap-rs does not collect notifications); DTLS_02 (no plaintext
`decrypt_error` alert); DTLS_03 (each handshake flight is not dropped); and
DTLS_04–07 (no RFC 7250 raw public key). An X.509 run is a different test.
CORE separate responses, loss and retransmission, BLOCK trains, and DTLS_01
cipher offer, selection, and Finished are graded from the capture. The Engine
tests, dogfood and process tests retain their separate, narrower coverage. See
[#199](https://github.com/jeffglousher/coaptic/issues/199).
The DTLS grader requires captured decrypted responses for success and visible
plaintext fatal alerts for its alert expectation. It does not interpret encrypted
alerts or reassemble fragmented handshakes; unavailable evidence fails grading.

All nine LINK TDs now compare complete assembled discovery results
against explicit expected membership, including exclusion of nonmatching links,
and require Content-Format 40. They run in both mixed peer directions and the
Coaptic self-pair. Refusal tests cover missing, extra, duplicate and truncated
links and missing/incorrect Content-Format. This fixture comparison is not a
general-purpose RFC 6690 parser qualification. LINK_04 includes the specified
empty `rt` group and proves its exclusion from Type2 results. LINK_03 includes
that group in `rt=*` results while excluding absent attributes. LINK_09 checks
both child links, content format, selection from received links, and the exact
final sub-resource response; malformed/partial/extra/duplicate child sets fail.

The legacy coap-rs DTLS feature is disabled. Test-only bridges use its public
transport traits with webrtc-dtls 0.12, keeping CoAP behavior independent while
retiring the old ring/webpki chain. Dedicated tests qualify mutual X.509 GET in
the two mixed directions and Coaptic self-pair, and require a certificate-verifier
error for unrelated trust roots on either endpoint. They do not upgrade skipped
RPK TDs to passes; independent DTLS-backend coverage remains libcoap/OpenSSL.
