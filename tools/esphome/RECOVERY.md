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
MCU client suffix recovery. Real UDP regressions exercise the ordinary fixture and both protected service
implementations. `qblock-suffix ADDRESS CREDENTIALS STATE REPORT RUN_ID` selects
the durable OSCORE version. Read-only request/response graders authenticate the
inner Q-Block2 options before selecting the loss and recording suffix repair.
They originate no traffic and do not own replay admission; only the App recovered
from the exclusively held durable record owns live security state. Setup failures
also produce a structured failure receipt.

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
Registration controls first drain/ACK a complete notification cadence, separating
temporary ordinary-TX/NSTART refusal from Observe pool refusal. Cancellation
honors bounded existing backoff instead of discarding the live relation.

This small-control client uses the existing 128-byte inline response hold. Full
datagram retention reserves RX credits and admits only one persistent Call with
two RX datagrams, which cannot fill the device's two Observe slots. Pool sizes,
Calls and security capacities are unchanged; timing/Q-Block2 clients retain full
response assembly. Ordinary handler Observe queries are not supported, so the
campaign uses elective options rather than Uri-Query to distinguish Calls.

`reconnect` and `reconnect-unprotected` use the same ADDRESS/credentials/state/
report/run arguments (literal `- -` placeholders for unprotected). They retain
one App and its security owner while sending at most 128 finite identity Calls
over a 70-second campaign, with a 15-second bound per Call and 300 ms between
completed Calls. CLI runs observe at least 35 seconds for the 30-second device
schedule. A delayed Call (at least 500 ms) must complete and a subsequent
fresh identity must complete. The runner must also grade the source-bound Wi-Fi
interruption/recovery receipt: a slow Call alone does not prove radio recovery.
Reports retain monotonic operation spans with a host UTC anchor for correlation.
The device retains one fixed first-receive timestamp/MID/token mark under a
spinlock, never overwritten. Reconnect traffic must precede other eight-byte-token
CoAP I/O so the initial mark matches its authenticated first Call. Last/sample
marks cannot calibrate clocks because they may describe late duplicate packets.
Repeated recovery/clock receipts fit separate bounded log records and include logical member bytes and aligned component
size. The grader brackets
the device/host clock offset using a matched fast round trip (authenticated in
protected mode; run-ID-matched in unprotected mode), adds
10 ms of clock uncertainty, then requires a delayed Call to overlap the controlled
interruption and complete after the connection observation for the entire offset
bracket, followed by fresh recovery.
This traffic exercises same-App Call retry/reconnect, beyond the prior
idle reconnection proof. A Call initiated during the outage does not establish
a Call already pending before disable; it is not a CPU/latency benchmark or cold-power recovery.

The four sync/async and unprotected/durable OSCORE device cells passed the finite
controls, with source-matched images and verified normal restoration. The
[core qualification record](https://github.com/jeffglousher/coaptic/blob/main/architecture/requirements/ESP-DEVICE-RECOVERY-20261118.md)
names exact source, hashes, cases and retained failures. Only Observe pool
exhaustion was selected; this is not exhaustion proof for every App pool.

`device_cpu_patch.py` prepares exact-SHA copies of IDF5.5.5 `tasks.c` and this
component for one finite diagnostic. It never writes the installed SDK. A
separate generated CMake input replaces exactly one kernel source and preserves
its internal compile definition. The kernel refuses other configurations: it
requires the IDF non-SMP two-core kernel, ESP_TIMER and U64 runtime statistics.
Under the existing kernel lock it observes current-core runtime including the
unswitched slice, blocked-to-Ready transitions and context switches. It does not
change scheduling or protocol state. Its single selected worker must not be
externally suspended, replaced or deleted during the capture.

The diagnostic stores at most 512 metadata rows (28,672 bytes), without payloads
or keys. Rows distinguish select, receive, send and durable-state boundaries;
published rows become immutable. CPU includes attributed ISR time and flash
stalls. Ready-but-unscheduled time includes preemption and yields. Readiness
means worker-observed select return; it excludes earlier socket enqueue delay.
Queued receives without a fresh select get an explicit receive-return boundary.
Heap/stack samples include diagnostic overhead, and global minima include startup.

`device_cpu_grading.py` binds all 32 device exchanges to exactly eight
identity/small/large iteration groups in an authenticated 24-read host campaign.
It rejects overflow, missing/foreign rows, unmatched input, wrong operation
inventory and inconsistent CPU+blocked+ready wall accounting. It requires a
resource snapshot beginning inside the measured traffic interval. Defined
readiness-to-final-send-return spans exclude post-send cleanup; available
readiness-to-next-select-entry spans retain that tail and are reported separately.
Neither is silently described as whole-App CPU. The accepted async OSCORE
capture is one diagnostic, not an optimization or a cross-runtime speed result.

`export_device_recovery.py` accepts explicit evidence/core roots and exports
only checked numeric receipts. Credential-bearing configs, OTA binaries and raw
private evidence remain outside these public repositories.
