# Complete-operation timing diagnostics

`waveshare-peer timing ADDRESS CREDENTIALS STATE REPORT RUN_ID` performs 24
protected reads: eight each of identity, the small test body, and the complete
2000-byte Block2 body. Use the `network,oscore,host` features. It reuses the
exclusively locked authenticated host security state; do not copy, reset or
provision that state for a timing run. Identity must match the expected firmware
run before other bodies are accepted.

The core uses fixed storage and `std` without `alloc`. The host diagnostic
reserves a bounded 128-entry trace vector before timing. Output is created
exclusively; a refused campaign retains partial observations. The JSONL report
includes request preparation, poll, durable replay checkpoint, response assembly,
complete-byte verification and actual requested-1-ms sleep durations. UDP
receive/send and state read/commit intervals are nested within those stages:
do not add the nested totals to their parent totals. Poll includes protocol
parsing, authentication, blockwise processing and transport calls.
The first UDP send can occur during request preparation; subtracting all UDP
time from poll time alone is invalid. Use the recorded event boundaries.
Initialization/recovery and sender-range refills are reported separately.
Datagram events contain timestamps, lengths and Message IDs, never payloads or
credentials. An event overflow refuses the result.

For device-side diagnostics only, compile the ESPHome C++ adapter with
`COAPTIC_TIMING_TRACE`. This retains at most 512 events in caller-owned adapter
memory and dumps them through the encrypted ESPHome API after two seconds of
quiet following traffic. It records receive (1), send (2), security-state read
(3), durable NVS commit (4), readiness/scheduler wait (5), and the ready-poll
interval (6). Read/commit/transport intervals are nested in the ready-poll
interval. An overflowing, prematurely frozen or missing trace is incomplete;
never grade it as a successful decomposition. Logging happens after the quiet
interval; additional incoming traffic after freeze is not captured. This macro
adds no trace storage or timer calls to ordinary firmware.

Retain exact core, Rust archive and C++ adapter revisions/hashes, configuration,
firmware, host executable, runtime run identity and raw observations. The Rust
archive and host can have different revisions; do not attribute firmware to the
host checkout. Measure instrumented and ordinary runs separately. Host and
device monotonic clocks are independent: correlate Message IDs and order, but
do not subtract their timestamps to claim one-way latency. Device receive-to-
send service time can be compared with the corresponding host round trip;
the residual combines network delivery, queueing, scheduling and unobserved
boundaries. It is not a measurement of radio airtime or either one-way hop.

`waveshare-peer timing-server 127.0.0.1:PORT CREDENTIALS STATE REPORT RUN_ID`
runs the same protected constrained service on the PC with a durable host file.
Provision a fresh, isolated pair of host/server credentials and state explicitly
for loopback; never reuse the device's keys or state there. The server traces
receive/send, state read/commit and ready-poll intervals, reserves at most 512
events before startup, and stops after 32 received packets followed by two seconds
of quiet or a 30-second deadline. Fewer than 32 packets or trace overflow refuses
the server result. Only the combined verified client/server trace establishes a
complete campaign. Spin polling is an instrumented diagnostic policy, not a
lower-CPU performance recommendation. PC file commits and device NVS commits are
different storage surfaces; their costs must remain visible and separately named.

Correlate one complete session with:

```sh
python tools/benchmark/hop_analysis.py --client HOST.jsonl --server DEVICE.json --output ANALYSIS.json
python -m unittest discover -s tools/benchmark -p test_hop_analysis.py -v
```

`DEVICE.json` contains the complete `COAPTIC_TIMING_END` record as `end` and
ordered timing records as `events`. A loopback server report is accepted directly.
The analyzer requires all 24 operations and 32 uniquely correlated request/response
exchanges (64 UDP datagrams),
matching wire lengths, one durable commit with two reads per request, and matching
host/device run identities. It rejects missing, failed, overflowed, ambiguous,
out-of-order or partially verified data. Successful reports retain every hop and
summarize observed means, medians and ranges; small samples are not tail
qualification. Client phase totals, corresponding server service spans and
transport/wait residuals are separate nested views of the same elapsed time.
