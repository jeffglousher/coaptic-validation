# ESP compatibility and rejected optimization evidence

The selected production fix binds `LoopbackConstrained::ResidentRxScratch` to
the current core Constrained profile. Accepted core code and its one-shot timer
API remain unchanged. Core `3b62f05` and companion `12fdc73` build the exact
async ESP image that completes 48 verified reads across sync and async Windows
clients. Normal firmware is restored and its encrypted API identity verified.
All 91 companion network, pairing and security-state checks pass. This is
functional proof, not a new peer-speed or long-term Wi-Fi qualification.

The serving App keeps eight route slots, six installed routes plus built-in
discovery, four Calls, zero deferred slots, two RX and two TX datagrams of
1,152 bytes, one 4,096-byte body per direction, four dedup and two Observe
entries. Selected firmware is unprotected; hardware authentication is not
claimed. The original 192 KiB Rust worker, 240 MHz CPU, 16 KiB instruction
cache, disabled power management and disabled PSRAM remain. C controls use
16 KiB workers and implement the matched GET workload. There is no full-feature
or minimum-RAM parity claim.

## Rejected runtime candidates

- Combined quiet dispatch (`0d31cbc`): four-pair CPU points 0.97545 sync /
  0.97608 async, but seven of 28 cell guards fail.
- Scheduled timer (`ec9221f`): fixed 64-pair points 1.00037 sync / 1.01014 async;
  four fixed-Service async upper95 guards fail. All 14,680,064 measured
  operations retain their cycle vectors.
- Blocked-only guard (`496e216`): four-pair points 1.00081 sync / 0.99435 async;
  one fixed-Service sync point, 1.02809, fails. The formerly failing async cells
  improve; that does not qualify adoption.
- Separate ESP Wi-Fi screens each close 192 reads over four boots. Rust/C
  latency ratios 1.40604 initial, 1.04366 timer-corrected cache16 and 1.24687
  cache32 all fail. No repeated sends or unexpected API disconnects occur.
  RSSI and per-boot vectors remain. Do not pool cohorts or infer isolated RTT
  gains. The extra 16 KiB cache reservation is rejected.

## Fresh host comparisons

Five independent windows close 84,000 measured reads without request or warmup
failures. The 18-cell unprotected loopback grid is 64/1,024/65,536 bytes,
concurrency 1/4/16, CON/NON. Completion-rate/C geometric means are:

- Coaptic sync/spin: 1.55635; Mio: 1.30014; async: 1.20454.
- coap-lite codec fixture: 1.34698; coap-rs: 0.81251; aiocoap: 0.09741.
- The libcoap C reference is 1.0.

These measure rejected core `0d31cbc`, fixture `130683f` and Rust 1.99.0.
CPU cohorts use pinned Rust 1.99.1. The C `851533c` clean source and matching
fixture Release build were checked before timing. Codec behavior is narrower.
Go and HTTP/3 were not rerun. Closed-loop rates are not throughput ceilings.
RSS snapshots include code, runtime and allocator, may overlap shared pages,
and are not peak or embedded App RAM.

## Reproduce the numerical results

Run `python -B verify.py` using only the Python standard library. It verifies
file and ZIP hashes, recomputes process means from complete cycle vectors,
reproduces failed CPU guards, rebuilds the six-cell ESP latency ratios and
recomputes seven host rate points. It does not run hardware or recover private
configuration.

CPU vector ZIPs and aggregate JSON are separate for each immutable cohort.
Wi-Fi JSON retains every complete-operation timing record from both clients;
diagnostic peer addresses are removed. Source/image/compiler commitments are
in `source-identities.json`. Original stream hashes identify private originals.
Firmware, Wi-Fi credentials, API captures, persistent identity and network
addresses remain private. Earlier failed sources are also retained on archive
branches. No RFC certification, peak-memory or faster-than-libcoap
goal-completion claim is made.
