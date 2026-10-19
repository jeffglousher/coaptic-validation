# Current Windows SmallDevice sample

The retained [receipt](receipt.json) contains all six cells, raw latencies,
process-tree resource snapshots, exact source and dependency identities. Every
cell completed 200/200 measured operations and 20/20 warmups with no failures,
verifying 6,400 measured payload bytes. This is one short sample, not a statistical
ranking or a saturation result.

Source: core `0bec951735a2c72b5d950d0636c68441250cf262`, fixture/runner
`6ca492b410c5bba101be097025694de0f1c1885a`. The server was compiled from the
identical Rust fixture at parent `9aabc10`; the later commit changed only Python
process-tree measurement. SHA256:
`836c27cbf3608915f8a53aa8083a60861438659bb4a1f45055066be377b359af`.
The subsequent cleanup-only change explicitly terminates owned launcher/worker
processes; its two-process smoke passed without repeating the timing sample.

AMD Ryzen 7 5800X3D, 8 physical/16 logical CPUs, 34,266,349,568 OS-reported RAM
bytes; Windows x86_64, Rust 1.99.0, thin LTO/codegen-units 1. The receipt names the
full compiler, OS, native lock hash and Python dependencies. Every cell uses the
same independent Python driver: 32-byte complete GET/CON, concurrency 1,
20 warmups then 200 measured operations. aiocoap is 0.4.16, coap-rs 0.28.1,
coap-lite 0.13.3. OSCORE is volatile AES-CCM-16-64-128, without enrollment or
durable security state.

Measured p 50 / p 95 latency and verified operation rate:

- Coaptic SmallDevice unprotected:50.3 /67.8 microseconds;18,498 operations/s.
- Coaptic SmallDevice volatile OSCORE:141.3 /186.9 microseconds;6,456 operations/s.
- aiocoap unprotected:238.8 /313.9 microseconds;3,993 operations/s.
- aiocoap volatile OSCORE:510.6 /640.5 microseconds;1,906 operations/s.
- coap-rs unprotected:81.6 /103.5 microseconds;11,427 operations/s.
- coap-lite codec endpoint unprotected:58.0 /76.9 microseconds;15,982 operations/s.

SmallDevice stays fixed Constrained: four route slots (one populated), one Call,
zero deferred, one association/four request bindings, no blockwise storage,
two 1152-byte RX slots and two 1152-byte TX slots, four dedup/two Observe entries.
Whole App including its UDP adapter is 13,128 bytes in both modes. The nested
adapter is 1,168 bytes including 1,153 bytes of scratch; the static body is 32 bytes.
The 14KiB test ceiling is an independent owner-size limit, not observed stack or
process peak. Process setup/runtime still allocates; App pools do not.

Scheduling differs: Coaptic spins one thread, coap-rs uses two Tokio workers,
aiocoap uses asyncio. Coaptic server CPU was 0.359375s in each approximately
0.36–0.37s resource window, including idle spin during driver startup. These are
not CPU-per-operation measurements. CPU resolution is 15.625ms here, including
some zero deltas for short sleeping-server windows. Process RSS includes runtime
and dependency pages: Coaptic 5,054,464/5,152,768 bytes unprotected/protected;
aiocoap launcher+worker sum 43,372,544/44,552,192 bytes. The sum double-counts shared
pages and is not physical memory uniquely owned by the library. Client resource
windows include context/socket setup and warmup; latency includes Python/GIL,
authentication and byte checks. No kernel-buffer or initialization-stack ceiling
is inferred from these measurements. No device/grant/history was touched.
