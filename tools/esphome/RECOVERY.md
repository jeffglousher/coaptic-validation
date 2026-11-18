# Finite installed-device recovery fixture

The ordinary `coaptic_network` qualification service exposes `GET effects` in
both sync/async and unprotected/OSCORE modes. Its four-byte big-endian counter
counts echo handler entries, including oversized echo refusals. Compare before
and after an exact-wire duplicate campaign using wrapping subtraction. Counter
reads do not increment it. This volatile instrumentation is not an actuator or
durable application-effect receipt. The original eight-route table is now full;
pool, Call, body, security and worker capacities are unchanged.

An opt-in platform schedule interrupts only the device's Wi-Fi:

```yaml
coaptic_network:
  # Existing run identity, runtime and security selection remain required.
  wifi_interruption:
    start_delay_ms: 30000
    duration_ms: 1000
```

The delay begins after worker creation and Wi-Fi connection. One interruption
disables Wi-Fi for a requested 250–5,000 ms, then calls enable from the main loop
even if the protocol worker stopped. No App, credential or NVS state is reset.
Shutdown during the disabled phase also re-enables Wi-Fi. The recovery log names
the run, requested duration, measured call-to-call disabled interval and Wi-Fi
connection observation, or a failed connection observation after 60 seconds.
These times include main-loop scheduling; they are not measured RF outage times.
Automatic re-enablement cannot guarantee association with an unavailable AP.

The schedule accepts ordinary unprotected or existing durable OSCORE service;
it rejects pairing, provisioning, telemetry and reverse read campaigns. Wi-Fi
and API reboot timeouts must be zero, with no fallback AP. The shared external
AP is never controlled. The campaign owner must retain partial failures and
restore and verify the authorized normal image after any OTA attempt.

`tools/qualification/recovery_peer.py` selects `duplicate-effects` or
`observe-capacity` explicitly for an unprotected device. It verifies the supplied
run identity, retains a partial failure receipt, bounds every exchange by five
seconds and 128 datagrams, and cancels owned Observe relations after the capacity
case. That case fills both Observe slots, verifies the third registration is
refused by the absence of Observe, cancels one and verifies slot reuse. It does
not prove exhaustion of other pools. Never relabel this client as protected.

Host tests and generated configuration checks do not establish installed-device
execution. `waveshare-peer qblock-suffix-unprotected ADDRESS - - REPORT RUN_ID`
selects a current-source host App receiving a known-size 2,000-byte NON Q-Block2
body. The fixture's stable `large-v1` ETag permits Q-Block2 response identity.
The host drops exactly the first final 976-byte block after receiving block zero
with Size2=2000, then requires complete byte recovery and a fresh small read.
Its scope is device response reissue after host receive loss; it does not prove
MCU client suffix recovery. A real UDP regression exercises the ordinary fixture.

`waveshare-peer recovery ADDRESS CREDENTIALS STATE REPORT RUN_ID` selects the
protected duplicate-count and Observe-capacity campaign. It recovers and owns the
existing exclusive durable host security record; it never provisions or copies
that state. After authenticating the first echo response, it resends the retained
protected request bytes and requires the matching cached ciphertext response.
A fresh authenticated counter read must show one handler entry. Three distinct elective
cache-key values (private option 2048) prevent client subscription coalescing;
they fill two device Observe slots, refuse the third registration, then verify
cancellation and reuse. All remaining relations receive bounded authenticated
cancellation attempts, with cleanup failures and an unresolved-relation bitmask
retained separately. A checkpoint gate refuses cancellation traffic on a poisoned
session; cleanup never overrides a failed/ambiguous durable commit.

This small-control client uses the existing 128-byte inline response hold. Full
datagram retention reserves RX credits and admits only one persistent Call with
two RX datagrams, which cannot fill the device's two Observe slots. Pool sizes,
Calls and security capacities are unchanged; timing/Q-Block2 clients retain full
response assembly. Ordinary handler Observe queries are not supported, so the
campaign uses elective options rather than Uri-Query to distinguish Calls.

Other pool campaigns,
four-cell device execution and CPU measurement remain work
for the current recovery qualification assignment.
