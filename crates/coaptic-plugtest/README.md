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
- `TD_6LoWPAN_*` remain skipped; 6LoWPAN transport qualification is not implemented.

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
notification source and stays SKIP. Other incomplete literal Observe scenarios
remain SKIP; see [#410](https://github.com/jeffglousher/coaptic/issues/410).

### Literal Observe client restart qualification

`cargo test --locked -p coaptic-plugtest --test interop observe_client_restart_resets_on_same_endpoint_and_recovers`
executes TD_COAP_OBS_06 with a Coaptic client and server. After two acknowledged
CON notifications, the client consumes its App and binds fresh protocol state
around the same UDP transport. The next CON is discarded and receives matching
RST. Three attempted updates during three one-second quiet intervals produce no
traffic or application delivery. Fresh registration on that same endpoint then
receives two complete CON notifications and acknowledges them.

Strict grading requires the fourteen-datagram registration/reset/recovery trace;
twelve altered traces are refused. A separate live socket test sends wrong-peer
and wrong-MID resets and verifies the legitimate observation still delivers.
`COAPTIC_OBSERVE_CAPTURE_DIR` retains `obs-06-coaptic.pcap`. Quiet duration and
application non-delivery are runner assertions; the packet grader validates the
wire sequence. This is protocol-state restart on loopback, not physical reboot,
protected peer authentication, or sustained availability. Both coap-rs directions
remain SKIP. See [#416](https://github.com/jeffglousher/coaptic/issues/416).

### Same-owner Observe GET and cancellation

`cargo test --locked -p coaptic-plugtest --test interop same_owner_get_preserves_observation_and_explicit_cancel_stops_it`
executes literal TD_COAP_OBS_10 and TD_COAP_OBS_12 with Coaptic on both ends.
The client reuses its App, socket and clock origin. An unrelated GET uses a fresh
token without Observe and leaves the original subscription delivering complete
CON notifications. Explicit cancellation uses `deregister_call` to retain the
original token and exact request identity; its complete ACK has no Observe.
Three attempted updates across three one-second quiet intervals then produce no
traffic or application delivery, followed by fresh same-endpoint registration.

The strict twelve-/fourteen-datagram oracles bind paths, endpoints, tokens, MIDs,
Observe values, content format and complete bodies. Sixteen trace mutations per
scenario must fail. Separate live checks refuse wrong-path/wrong-peer cancellation
before I/O, preserve the original observation, then cancel and recover. Other
backends refuse the new hook by default; both coap-rs directions remain SKIP.
`COAPTIC_OBSERVE_CAPTURE_DIR` retains each scenario's PCAP. These plaintext
loopback tests do not qualify authenticated ownership or sustained availability.
Tracking: [#419](https://github.com/jeffglousher/coaptic/issues/419).

### Observed resource mutation and read-back

`cargo test --locked -p coaptic-plugtest --test interop observed_resource_updates_are_delivered_and_read_back`
executes literal TD_COAP_OBS_09 with Coaptic on both ends. Two accepted local
updates select one of two fixed representations before sending the corresponding
CON notification. The GET handler and retransmission snapshot read that same
state; same-owner GETs confirm both changed representations while notifications
retain their original token, content format and increasing Observe sequence.

The fixture uses a bounded atomic selector under the existing serialized harness
lock and resets it for each server. The strict fourteen-datagram oracle checks
complete notification/read-back bodies and ownership; sixteen mutated traces
must fail. Live tests refuse invalid paths/payloads without traffic or state
changes, recover with valid updates, and verify the next fixture starts clean.
Unsupported backends refuse updates by default; both coap-rs directions remain
SKIP. `COAPTIC_OBSERVE_CAPTURE_DIR` retains `obs-09-coaptic.pcap`. This is volatile
in-memory resource state and plaintext loopback evidence, not durable effects,
authenticated ownership or hardware qualification.
Tracking: [#423](https://github.com/jeffglousher/coaptic/issues/423).

### Observed resource deletion and format change

`observed_resource_terminal_errors_and_recovery` executes literal TD_COAP_OBS_07
and TD_COAP_OBS_08 with Coaptic peers. The server persists local resource deletion
or a changed content format before terminating the observation. A separate GET
reads back 4.04 or the complete changed representation with format 42. The
original relation receives CON 4.04 or 4.06 with its original token and no Observe
option; the client acknowledges it. Three one-second attempted-update intervals
remain quiet, then restoring the fixture and fresh registration recover complete
CON delivery on the same client endpoint.

The strict sixteen-datagram grader binds request paths, endpoints, tokens, MIDs,
terminal options, complete read-back bodies, and recovery. Eighteen trace
mutations per scenario must fail. A focused adapter test checks invalid path/state,
occupied command refusal without replacement, valid recovery, fixture reset, and
unsupported-backend refusal. Both coap-rs directions remain SKIP. Set
`COAPTIC_OBSERVE_CAPTURE_DIR` to retain each scenario's PCAP. This is volatile,
plaintext loopback protocol qualification, not durable deletion or authenticated
access control. Tracked in [#425](https://github.com/jeffglousher/coaptic/issues/425).

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
The separate literal restart scenario above supplies the CON evidence; finite
silence is not sustained availability qualification. Tracking: [#402](https://github.com/jeffglousher/coaptic/issues/402),
[#199](https://github.com/jeffglousher/coaptic/issues/199), and
[#202](https://github.com/jeffglousher/coaptic/issues/202).

### Cloud admission and protected progress

`cargo test --locked -p coaptic-plugtest --features edhoc --test cloud_admission_progress -- --nocapture`
qualifies a finite caller-scheduled workload using public admission and OSCORE
APIs. `CloudAdmission<3,1,3,4>` holds two authenticated owners while one abandoned
reachable handshake fills its sole pending slot. Thirty-two repeated admission
datagrams produce six cached replies and 26 budget refusals without fresh
entropy or deadline renewal. Both existing owners complete a protected exchange
per round, each with the entire 192-byte request and 256-byte response checked.

The test refuses new admission before the original expiry and restores it at
expiry. A full active pool refuses a fourth owner; explicit release denies the
old route and permits replacement while surviving owners continue. Seventy
protected exchanges complete across the full scenario with exact bodies, tokens,
codes and options. One separate cross-owner packet must fail both endpoint routing
and authentication under the other owner's context; later valid traffic succeeds.
`COAPTIC_CLOUD_PROGRESS_REPORT` optionally writes the result;
CI retains it alongside the exact source/preparation identity.

The host fixture allocates and uses deterministic test entropy, synthetic
monotonic timestamps and installed trust. The library admission structure and
cryptographic buffers remain bounded.
This uses low-level OSCORE owners and an explicit round-robin caller schedule,
not expanded App capacity or scheduler-independent fairness. It does not qualify
sockets, physical devices, sustained availability or throughput. Tracking:
[#409](https://github.com/jeffglousher/coaptic/issues/409),
[#340](https://github.com/jeffglousher/coaptic/issues/340), and
[#202](https://github.com/jeffglousher/coaptic/issues/202).

### Literal lossy CON Observe qualification

`observe_con_and_ack_loss_preserve_nstart_and_recover` executes TD_COAP_OBS_11
with Coaptic peers. One transport discards one received CON notification; the
other discards one exact empty ACK. Each control is owned by its transport,
bound to the registered endpoint/token, and consumed once. ACK loss additionally
binds the MID of that owner's outgoing notification. Real UDP and real retry
timers produce recovery; no clock acceleration is used.

A competing notification attempt while each CON is outstanding is refused by
NSTART; it does not commit a new resource representation. The client receives
complete values, suppresses duplicate delivery after ACK loss,
and receives two fresh updates after recovery. The seventeen-datagram grader
uses the server tap only, preserving retransmissions without duplicate capture
taps. It checks identical retransmitted bytes, ACK ownership, distinct new MIDs,
sequence progression, and complete bodies. The live runner separately verifies
both intended loss counters. The PCAP alone does not encode a receive-drop flag.

Sixteen trace mutations and three focused control/adapter tests cover refusal,
wrong peer/token/MID, occupied rules, one-shot consumption and recovery.
Unsupported directions remain SKIP. `COAPTIC_OBSERVE_CAPTURE_DIR` retains
`obs-11-coaptic.pcap`. This plaintext loopback qualification does not claim
OBS05's separate updated-Observe retransmission requirement, sustained hostile
traffic availability, or protected interoperability. See
[#429](https://github.com/jeffglousher/coaptic/issues/429).

### Complete large Observe representations

`observe_large_complete_block2_snapshots` executes literal TD_COAP_OBS_13 with
Coaptic peers. The bounded `/obs-large` fixture selects three static 2000-byte
representations with distinct ETags. Initial registration and two subsequent CON
notifications each deliver block zero, request the final block, and expose the
complete expected body. GET and notification snapshots select the same version.

The twelve-datagram grader binds endpoint/path/token/MID ownership, Observe
progression, block number/size/M flag, content format, Max-Age, ETag and both body
slices. Twenty trace mutations must fail. Two adapter tests check invalid path or
version, occupied command preservation, unchanged fixture state, full-delivery
recovery and reset. Both coap-rs directions remain SKIP; set
`COAPTIC_OBSERVE_CAPTURE_DIR` to retain `obs-13-coaptic.pcap`.

This is one-observer plaintext qualification with two subsequent notifications.
Additional rapid Block2 rounds or response owners can exhaust retained TX
datagram slots before duplicate-cache expiry; an exploratory extra round returned
`Saturated`. It does not establish sustained update cadence, multi-client
capacity, protected interoperability, or OBS14 variable-size behavior. Tracked in
[#432](https://github.com/jeffglousher/coaptic/issues/432).

### Variable-size Observe representations

`observe_pumping_covers_both_initial_sizes_and_complete_notifications` executes
literal TD_COAP_OBS_14 with Coaptic peers. The bounded `/obs-pumping` fixture uses
static 32-, 2000- and 64-byte representations with distinct ETags and one content
format. One run starts small and delivers large then small CON notifications;
a fresh server and registration start large and deliver small then large. Both
runs obtain and check every byte before scheduling the next update. A bounded
command completion confirms the selected initial state before registration.

The eighteen-datagram grader checks both initial forms, complete small and Block2
bodies, ETag consistency, Observe progression, endpoint/path/token/MID ownership
and exact empty ACKs. Thirty trace mutations must fail, including malformed Block2 on small bodies. Two adapter tests
cover invalid path/version, missing server, occupied command preservation,
unchanged state/no traffic on refusal, valid delivery recovery and server reset.
Unsupported directions remain SKIP. `COAPTIC_OBSERVE_CAPTURE_DIR` retains
`obs-14-coaptic.pcap`.

This is plaintext loopback qualification of one observer and two subsequent
notifications per fresh run. It does not establish sustained cadence, resource
capacity across additional owners, or protected interoperability. The original
TD requirements and RFC7959 section 2.6 are tracked in
[#435](https://github.com/jeffglousher/coaptic/issues/435).

### Observe recovery after server state loss

Literal TD_COAP_OBS_04 uses a bounded control that rebuilds the server App while
retaining the UDP socket, then confirms completion. After two acknowledged CON
notifications, the server loses its observation state and cannot deliver another
update. The consuming client fixture polls through 160 real seconds before using
`reregister_call` with the same token and request identity. This is the existing
notification's default Max-Age (60 seconds) plus MAX_LATENCY (100 seconds), without
clock acceleration. It also exceeds RFC7641's 128-second ordering window so the
reset server sequence can be accepted. The core does not schedule refresh itself.

The twelve-datagram grader requires unchanged endpoints/token/request options,
a distinct refresh MID, the elapsed capture interval, reset sequence zero, and
two complete acknowledged CON notifications both before and after reset. Fifteen
trace mutations refuse altered ownership, bodies, missing packets or early refresh.
Short adapter tests cover identity mismatch without traffic, occupied/missing
reset control, same-endpoint silence after reset and valid registration recovery.
`COAPTIC_OBSERVE_CAPTURE_DIR` retains `obs-04-coaptic.pcap`. This is one plaintext
loopback observer, not protected or cross-implementation qualification. Tracked in
[#436](https://github.com/jeffglousher/coaptic/issues/436).
