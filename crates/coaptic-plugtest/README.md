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
OBS_01 and OBS_02 pass for Coaptic and coap-rs clients against the Coaptic
server; their coap-rs-server directions remain SKIP. Still unfinished, not
conformance passes: the remaining Observe scenarios; DTLS_02 (no plaintext
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

### Literal confirmable Observe qualification

`cargo test --locked -p coaptic-plugtest --test interop confirmable_observe_notifications_reach_each_client_backend`
runs the original TD_COAP_OBS_01: CON registration for `/obs`, initial ACK
representation, then two complete CON notifications with matching empty ACKs.
The fixture requests CON explicitly through `App::notify_confirmable`; caller
time is not accelerated and ordinary adaptive `notify` remains unchanged.
Both clients collect the full expected bodies. The grader checks endpoint
roles, token/MID ownership, content format and increasing Observe values;
12 mutation cases per client reject incomplete or corrupted evidence.
Set `COAPTIC_OBSERVE_CAPTURE_DIR` to retain `obs-01-coaptic.pcap` and
`obs-01-coap-rs.pcap`. Duplicate client/server capture taps are deduplicated;
only the six prescribed unique datagrams are accepted.

This plaintext socket proof is separate from protected interoperability and
sustained-loss qualification. The coap-rs server wrapper has no controlled CON
notification source and stays SKIP. OBS_06 and all other incomplete literal
Observe scenarios remain SKIP; see [#410](https://github.com/jeffglousher/coaptic/issues/410).

### Observe reset socket qualification

`cargo test --locked -p coaptic-plugtest --test observe_reset` checks RFC 7641
section 4.5 against the Coaptic App server and a scripted UDP client on loopback.
Wrong message-ID and wrong-endpoint resets must leave notifications working.
A matching reset must stop notifications for a 3.5-second observation window
(longer than the 3-second NON hold), while an ordinary GET and fresh registration
must still succeed. The exact server-side packet trace rejects missing resets,
wrong reset ownership, late notifications, and corrupted recovered payloads.
Registration and health exchanges must use the expected endpoint directions,
resource paths and complete fixture bodies; 23 trace mutations exercise refusal.
Set `COAPTIC_OBSERVE_CAPTURE_DIR` to retain `rfc7641-non-reset.pcap`.

This plaintext fixture qualifies message/endpoint matching, not authenticated
peer identity or protected interoperability. It is not TD_COAP_OBS_06: that TD
requires CON notifications, while this fixture exercises NON notifications.
The literal TD remains skipped; finite silence is not sustained availability
qualification. Tracking: [#402](https://github.com/jeffglousher/coaptic/issues/402),
[#199](https://github.com/jeffglousher/coaptic/issues/199), and
[#202](https://github.com/jeffglousher/coaptic/issues/202).
