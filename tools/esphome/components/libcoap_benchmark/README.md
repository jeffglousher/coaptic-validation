# Finite ESP32-S3 libcoap benchmark

This source fixture uses `espressif/coap ==4.3.5~8` in the existing native
ESPHome 2026.9.1 / ESP-IDF 5.5.5 shell. Compilation and physical execution are
separate checks; adding this directory does not qualify either. Retain the
commissioned WiFi, encrypted API, OTA, partition table, credentials and NVS.
Do not erase, provision or migrate state for this fixture.

Replace the `coaptic_network` benchmark component selection with this component
in a separately reviewed application image; keep the shell configuration.
The components conflict to avoid a second CoAP implementation consuming CPU
and memory during the comparison. The default client role opens only an outbound UDP session. The optional
server role accepts the explicitly configured Windows peer for a finite window.
Neither role writes security state.

```yaml
external_components:
  - source:
      type: local
      path: /absolute/path/to/tools/esphome/components
    components: [libcoap_benchmark]

libcoap_benchmark:
  qualification_only: true
  allow_unprotected: true
  run_id: 0123456789abcdef0123456789abcdef
  server_run_id: 0123456789abcdef0123456789abcdef
  peer_address: 192.168.1.134
  peer_port: 5683
  start_delay_ms: 30000
```

Start the existing `waveshare-peer timing-server-lan-unprotected` on Windows,
with both literal `-` state arguments, the same `server_run_id`, its explicit
private local address and the device's explicit private remote address. The
host service may use the separately compiled synchronous or native async
selection; retain its actual `io_mode` with the result. Scope any host firewall
rule to that exact executable, port and device. No firewall change is made by
this component.

One owning FreeRTOS task creates one libcoap context/session, then sends eight
rounds of CON GET `/identity`, `/test`, `/large`: 24 complete operations at
concurrency one. Expected bodies are the 32 ASCII server identity bytes,
`coaptic` (7 bytes), and 2000 `0x5a` bytes. Each response must be 2.05 Content,
have the exact token and complete assembled body, and omit Content-Format and
Observe as the existing service does. ETag, if present, must have valid length;
libcoap owns native Block2 assembly and cross-block consistency. There is no
fixed ETag value in this service contract. Identity is attribution without
authentication. The Coaptic read campaign validates status and every complete
body; this fixture additionally checks the service's absent Content-Format.

`COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY` retains libcoap's complete
response assembly. No extra C-owned payload copy or fragment-discard shortcut
is used. Libcoap/IDF allocation is dynamic; this is not fixed-memory parity or
a whole-memory measurement. The 1152-byte session MTU is a send limit, not a
claimed receive or assembly ceiling. Use only the explicitly scoped fixture
host; this client does not impose a libcoap incoming body allocation ceiling.

Each operation includes PDU construction, real send/retry/Block2 processing and
whole-response verification, with a 5-second deadline and 100000-turn bound.
`coap_io_process(..., 1)` uses libcoap's socket event loop; every 32 incomplete
turns yields one RTOS tick. It is not Rust futures execution. Keep scheduling
and timer-resolution differences with the result rather than claiming equal
transport CPU cost. No warmups are removed: all 24 operations are reported.
The task starts once after the delay and network availability, or refuses after
an additional 30 seconds. A failed operation ends the campaign; no retries of
the campaign, replacements or auto-restarts occur.

Structured log records use `LIBCOAP_BENCH_STARTUP`, `PREPARATION`, `MEMORY`,
`OPERATION` and `TERMINAL` prefixes. Every operation captures monotonic `esp_timer` clocks
before logging; timestamps are nanoseconds converted from microsecond ticks.
Initialization/task creation are separate from complete-operation elapsed time.
No trace queue or payload logging is retained. Heap samples cover the whole
running platform, and global minimum heap is since boot, not a libcoap-only
peak. Free task stack high-water is sampled before the terminal log; the log
itself can consume additional stack. Reserved task stack is 16384 bytes.

The consumed local IDF manifest pins the registry component, and public CMake
`REQUIRES` exposes its headers to ESPHome without replacing other components.
Keep the generated dependency lock, component source identity, image hash,
host source/binary identity, all 24 operation rows and terminal result together.
This is an initial unprotected shared workload, not an OSCORE/DTLS, firmware
attestation, commissioning, maximum-throughput or certification result.

## Optional server role for Windows-initiated reads

The default `role: client` retains the 24-read client and its complete
`SINGLE_BODY` assembly/verification. To have Windows initiate outbound requests
and receive stateful UDP replies, select the optional server in the same shell:

```yaml
libcoap_benchmark:
  qualification_only: true
  allow_unprotected: true
  role: server
  run_id: 0123456789abcdef0123456789abcdef
  peer_address: 192.168.1.134
  listen_port: 5683
  start_delay_ms: 30000
```

`server_run_id` is required only for the client role. The server's `/identity`
returns its own 32-byte `run_id`, matching readiness/terminal records and the
source-bound image marker. `/test` returns `coaptic`; `/large` returns 2000
`0x5a` bytes. The Windows complete-operation client must verify that image
identity, 2.05 status, complete bytes and representation metadata for every
operation. Peer filtering checks the requesting IPv4 address against
`peer_address`; a different peer receives 4.01 without representation data.
Peer source ports may be ephemeral. `peer_port` applies only to the client;
`listen_port` applies only to the server.

The server uses public `coap_get_block_b`, `coap_write_block_b_opt` and
`coap_add_block_b_data` helpers for Block2 negotiation, encoding and payload
selection. It borrows static read-only representation data, with no retained
whole-body copy and a handler invocation for each block GET. This matches the
ordinary borrowed Coaptic GET fixture; Windows owns full-response assembly.
Content-Format is absent and no ETag is emitted. The high-level
`coap_add_data_large_response` helper always inserts Content-Format in this
version, so it is not used. No internal option mutation or custom wire encoder
is used.

`LIBCOAP_BENCH_SERVER_READY` is logged before any request dispatch. The same
16384-byte task owns the context and three resources for a finite 30-second
window, then releases the context. `SERVER_MEMORY` and `SERVER_TERMINAL` record
whole-platform heap samples and task stack high-water. The terminal `passed`
means the service window ended without an internal failure and at least one
allowed handler invocation; it does not certify 24 completed operations.
Handler calls include block GETs and are not logical completion counts. Use
the separate Windows client's exact completion/verification report for the
comparison. There is no timed handler instrumentation or automatic restart.

Primary API/build references:

- [ESP component and supported targets](https://components.espressif.com/components/espressif/coap/versions/4.3.5~8/readme)
- [Espressif native client example](https://github.com/espressif/idf-extra-components/tree/master/coap/examples/coap_client)
- [ESPHome 2026.9.1 native component registration](https://github.com/esphome/esphome/blob/2026.9.1/esphome/components/esp32/__init__.py)
