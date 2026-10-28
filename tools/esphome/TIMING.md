# Complete-operation timing diagnostics

`waveshare-peer timing ADDRESS CREDENTIALS STATE REPORT RUN_ID` performs 24
protected reads: eight each of identity, the small test body, and the complete
2000-byte Block2 body. Use the `network,oscore,host` features. It reuses the
exclusively locked authenticated host security state; do not copy, reset or
provision that state for a timing run. Identity must match the expected firmware
run before other bodies are accepted.

For the matched unprotected host-initiated workload, select:

```text
waveshare-peer timing-unprotected ADDRESS - - REPORT RUN_ID
```

This performs the same 24 reads, complete-byte checks, deadlines and requested
1 ms wait, using the same Constrained pools and blockwise/full-response options.
The two `-` arguments are required: this selection never opens credentials or
security state. Its run identity is verified for attribution, without peer
authentication. The existing `timing` command remains durable OSCORE and never
falls back. Reports identify `unprotected` or `durable-oscore` explicitly;
unprotected preparation has zero security-recovery time and no reservations.
The host executable still uses the `network,oscore,host` feature set for both
selections; enabling compiled OSCORE support does not enable protection for an
unprotected App. Firmware mode 0 and mode 1 are separate named service images,
not a runtime fallback. Host-initiated timing needs no host service or inbound
listener; it does not install or modify firewall rules.

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

The initiator algorithm is `rust/src/read_campaign.rs`, shared independently of
the host adapter. It uses fixed storage without `std` or allocation, accepts
caller-owned I/O/storage, entropy, a monotonic nanosecond clock and a bounded
wait callback, and verifies every complete body. The host `timing` command calls
this algorithm with a requested 1 ms wait. A five-second deadline and a 100,000
poll bound independently prevent an unanswered operation or a frozen clock from
running forever. Clock regression/stop, transport/storage/report failures and
wrong identities or bodies refuse the campaign; partial observations remain.
Instrumentation and extra clock reads affect results, so retain the executable
identity and measure observer overhead before comparing revisions.

The comparison matrix has four role configurations:

- PC loopback, host initiator and constrained service.
- PC loopback, constrained initiator algorithm and host service.
- LAN, PC initiator and ESP32-S3 service.
- LAN, ESP32-S3 initiator and PC service.

Each uses the same identity, small and complete 2000-byte GET workload. The LAN
matrix has two directions and two explicit security selections: unprotected and
durable OSCORE. The two loopback configurations are separate role controls.
Protected runs require authenticated durable security state. Host execution of
the constrained algorithm is a role control, not ESP32 emulation. The ESP32-S3
is the qualification platform; it does not restrict the library to that MCU.
Do not label the last configuration measured until the initiator is integrated
into verified firmware and every operation and terminal record is retained.
The retained reverse telemetry POST/receipt test has additional application
journaling semantics and is a separate workload, not a matched GET result.

Keep unprotected/protected and volatile/durable profiles separate. Request and
response packets within one operation do not establish both initiator roles.
For LAN role reversal, use an explicitly scoped host service and
temporary inbound firewall access restricted to the reserved device and exact
host executable. `timing-server` remains loopback-only. For the LAN role use:

```text
waveshare-peer timing-server-lan LOCAL_IPV4:PORT CREDENTIALS STATE REPORT RUN_ID REMOTE_IPV4
```

Both addresses must be explicit private IPv4 addresses and differ; wildcard,
public, IPv6 and port-zero binds refuse. Only packets from the configured remote
address reach Coaptic, and sends to any other address refuse. OSCORE authentication
is still required. Source-address filtering is not peer authentication. The
finite 30-second lifetime, trace bound and exclusively owned authenticated
durable state also apply to this mode. Do not copy device credentials/state into
a loopback control, or replace the configured firewall executable with an
unverified build. No firewall rule is installed by the driver.

For the unprotected service, select one of these commands explicitly:

```text
waveshare-peer timing-server-unprotected 127.0.0.1:PORT - - REPORT RUN_ID
waveshare-peer timing-server-lan-unprotected LOCAL_IPV4:PORT - - REPORT RUN_ID REMOTE_IPV4
```

Both literal `-` arguments are required, and dispatch occurs before credential
loading. These selections open no credentials or security-state file and report
`security: unprotected`; they provide no peer authentication. They reuse the
same constrained service, transport scratch, bounded trace, lifetime and source
filter as the protected selections. Scope validation is identical: the loopback
command cannot bind a LAN address, and the LAN command requires explicit private,
distinct local and remote IPv4 addresses. No protection fallback is performed.

## Selected ESP32 initiator

`rust/src/read_campaign_device.rs` binds the shared workload to the synchronous
ESPHome socket. The protected mode uses existing authenticated NVS state; the
explicit unprotected selection uses no credentials or security-state store and
does not require compiled OSCORE support. Both require an explicit private IPv4
host and port and the same 32-byte hexadecimal run ID as the selected host
service. They refuse
`async_network`, provisioning, pairing and telemetry combinations. This mode
does not provision, reset or copy durable state. A protected host needs matching
counterpart credentials and its own exclusively locked state.

Select `coaptic_network.read_campaign.peer_address` and `peer_port` (default
5683). `start_delay_ms` defaults to 30000 and accepts 0 through 120000, allowing
the host and recorder to be ready before this single boot campaign starts.

This is `profiles::Constrained` with blockwise transfers: eight route slots
(none installed on the initiator), four Calls, no deferred slots, one security
association and four request bindings when protected, RX2/TX2 datagrams of 1152 bytes, one
4096-byte body per direction, four dedup entries and two Observe entries. One
Call runs at a time. It is a distinct configuration from the SmallDevice
32-byte comparison and the Service cloud fixture.

The adapter requests a bounded 1 ms scheduler wait and reads a nonblocking
monotonic clock; component shutdown stops the campaign. It streams one reused
128-byte metadata record after each complete operation, plus preparation,
sender-range reservations if needed, and a terminal row. The bound is 50 rows;
all 24 verified operation rows, successful terminal counts and worker completion
are required. Missing or failed output leaves the campaign incomplete. These
records contain lengths, phases and counters, never payloads or credentials.
Logging happens outside operation intervals and can affect later operations.

Preparation reports the actual whole App and security-owner layouts, existing
4096-byte collection output, record size, and independent 48 KiB App / 1 KiB
security-owner ceilings. These overlapping object categories are not an
additive stack peak: retain the worker stack watermark and system heap readings,
including initialization, transport, Wi-Fi, runtime and logging costs. There is
no retained device trace, task, packet pool or sample array added by this
binding. Whole-operation timing does not require the optional hop trace below.

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

## Isolated checkpoint cost

```sh
cargo run --locked --release --manifest-path tools/esphome/rust/Cargo.toml --features network,oscore,host --bin checkpoint-cost
```

This finite diagnostic runs seven batches of 20,000 advancing checkpoints using
a fixed volatile record store and public fixture keys, without sockets or files.
It reports the complete adapter checkpoint span and independently times context
derivation. The latter is a control, not an additive stage or proof of CPU-cycle
attribution. Setup/recovery is outside the measured loop. Every checkpoint still
performs the read-current/commit/readback sequence, with counts checked after
each batch. The comparison guard is shared with core replay restoration; it needs
no key derivation, second security context, allocation or extra durable-storage bytes.
The live state retains one fixed 100-byte copy of the last authenticated record.
Its context identity and old-record tag are reused; each new record still gets a
fresh HMAC. The cache advances only after successful durable commit and exact
readback. External changes still refuse before writing and poison the session;
failed or ambiguous writes require authenticated recovery. Report the complete
`state_bytes` cost on the measured target because layout and padding vary.

Retain compiler, both source revisions, lockfiles, source/binary hashes, process
order, all batches and original failures. Use balanced before/after process order
and unchanged fixtures. These host elapsed-time measurements do not qualify
durable I/O, network latency, MCU execution, application effects or flash recovery.

Correlate one complete session with:

```sh
python tools/benchmark/hop_analysis.py --client HOST.jsonl --server DEVICE.json --output ANALYSIS.json
python -m unittest discover -s tools/benchmark -p test_hop_analysis.py -v
```

`DEVICE.json` contains the complete `COAPTIC_TIMING_END` record as `end` and
ordered timing records as `events`. A loopback server report is accepted directly.
The analyzer currently grades protected traces. It requires all 24 operations
and 32 uniquely correlated request/response
exchanges (64 UDP datagrams),
matching wire lengths, one durable commit with two reads per request, and matching
host/device run identities. It rejects missing, failed, overflowed, ambiguous,
out-of-order or partially verified data. Successful reports retain every hop and
summarize observed means, medians and ranges; small samples are not tail
qualification. Client phase totals, corresponding server service spans and
transport/wait residuals are separate nested views of the same elapsed time.

## Hosted public pairing archive

Dispatch `Public Xtensa archive` with lowercase hex40 `suite_revision` selected
after companion merge. Core is fixed at `28d9f1a61d15121d75d5dd426ad8d6b5cc891005`.
The unchanged helper uses `--locked --pairing --async-network`.

Ubuntu 24.04 verifies exact lengths and SHA256 pins for four official Linux x64
payloads before any extraction or execution: Rust/rust-src 1.97.0.0, LLVM libraries
21.1.3 and Xtensa GCC 16.1.0. The receipt retains each URL, expected and actual
size/hash, verification result and phase duration. Downloads are streamed with
per-payload time/length limits and whole-job cancellation/deadline checks.
Rust commit `8ea53bcd7257011cbf96f6398551bdc650b04334` and LLVM 21.1.3 remain gates;
ancillary equivalence to the local custom SDK remains unproven.

Both official Rust installers use the owned absolute named-toolchain `--prefix`
with `--disable-ldconfig`; Rust excludes documentation. Without `--destdir`, the
[exact compiler's installer template](https://github.com/esp-rs/rust/blob/8ea53bcd7257011cbf96f6398551bdc650b04334/src/tools/rust-installer/install-template.sh)
uses that prefix directly. SDK extraction and installation use bounded owned
process groups; LIBCLANG_PATH and the GCC PATH are set explicitly. No espup,
home-directory reassignment or system installation is involved.

Refusal limits: 45-minute job/40-minute processing, sampled 10 GiB owned output,
1 GiB free floor, logs 128 KiB, archive 16 MiB, artifact 32 MiB. No sufficiency,
retry, cap increase or cache is implied. One-day evidence retains phase durations,
sampled storage, compiler and failures; archive/build.json require inspection.

Verify clean source SHAs, seven locks, source hashes, compiler, target/features
and archive SHA256 before use. The runner owns SDK/registry/target disposal.
Private YAML/keys stay local. Preserve prior images/evidence; preserving app-only
OTA and paired device qualification remain separate from archive compilation.
