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

Host tests and generated configuration checks do not establish installed-device
execution. Missing Q-Block2 suffix-loss and pool-exhaustion selectors, protected
duplicate campaigns, four-cell device execution and CPU measurement remain work
for the current recovery qualification assignment.
