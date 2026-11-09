# Fresh TargetCPU Wi-Fi speed screen

The fresh screen is complete and **both candidates remain rejected**. This package
retains all **1,152 complete-read latency vectors, 48 fresh client processes and
12 device boots**: six profiles in fixed opposite boot orders, both Windows client
modes, three read bodies and two boots per profile. No success-only filtering,
sample replacement, trimming, previous-vector pooling or new host measurement occurs.

Run with Python 3.10+ and its standard library from this directory:

```text
python -B verify.py
python -B test_export.py
```

The verifier checks file/gzip/raw hashes, strict field allowlists, all original
operation counts/order, stages, repeated-send accounting, configured capacities,
source commitments, memory ledgers and qualification limits. It independently
reconstructs every cell median/P95/P99, both boot medians, all ten declared
pairwise comparisons and the **actual original promising decisions**. The tiny
tests include a genuinely promising synthetic case, a failed cell despite a good
aggregate, a failed boot despite a good pool, missing records, privacy leaks and
invented task/startup qualification. The prior 39 controller checks and producer
proofs are reused as attestations and are not rerun here.

The original gate requires every pooled cell median below the faster
contemporaneous C median, geometric latency ratio <=0.97, every boot aggregate
below each C control, and operation/stability/resource guards. The strict reference
combines per-cell C winners. All ratios in this package measure **complete-read
Wi-Fi latency**, never task CPU.

- **Sync/C aggregate: 0.8537528379**, but the three sync-client cell ratios are
  **1.0438958 / 1.0126164 / 1.0159530**. The original gate fails. Sync/own Rust is
  **0.9840702781**; individual cells remain mixed.
- **Async/C aggregate: 1.4833688982** and async/own OsFat control **1.1425300466**.
  All six pooled cells fail; both boot aggregates exceed each C control.

## Wi-Fi variation and observation limits

The ESP32-S3 is on **Wi-Fi** behind an access point; the Windows client is on
Ethernet. The complete path is inside timing. Reported RSSI spans **-54 to -34 dBm**,
a **20 dB observed range**. The final pinned-C boot reports -54 dBm; all other boots
report -34 to -41 dBm. All reports remain mapped to their actual boot. Operational
stability/completion guards pass, but this is an uneven observed RF setting, not a
controlled radio comparison or a causal explanation. Two boot clusters are
descriptive; pooled tails do not establish long-duration/RF or tail qualification.

At least 30 s after OTA and 500 ms after readiness are outside timing. Reads are
sequential C1, without an imposed inter-operation gap. The two boot rounds use
opposite profile orders and reversed sync/async/async/sync client order. Every
client process verifies 24 reads: identity32 B, test7 B and large2000 B (Block2),
eight repetitions of each. Latency is retained in nanoseconds with all recorded
stage times. Actual protocol MIDs/tokens are omitted; verified numeric send,
distinct-send and repeat counts preserve the original repeat guard.

Actual Rust task-policy observations are absent, including all four new Rust
boots. The new images compile a core1/priority1 request; **compiled placement is
not observed execution**. C has four startup task records showing actual core1;
floating C is still compiled core-1. A startup record is not continuous affinity
proof. Exact pre-task contiguous-allocation observations are absent in these
uninstrumented images. Declared worker+4,096 B requirements and running resource
checks do not qualify that missing startup margin. Startup qualification remains
open, regardless of the completed speed collection.

## Memory and integration tradeoffs

Async's physical net static addition falls **9,984 -> 8,960 B (-1,024 B)** and its
observed lifetime stack watermark falls **112,056 -> 88,564 B (-23,492 B)**, while its
image grows **1,183,104 -> 1,439,088 B (+255,984 B)**. Its original **196,608 B worker
reservation is unchanged**. Sync keeps net static **60,928 B** and its original
**98,304 B worker**; image size grows **304 B**. These gains do not override the
failed latency gates.

Observed stack use is not a released physical reservation, safe minimum or
whole-system peak. Static placement, IRAM aliases, runtime/future owners and heap
snapshots overlap; do not sum them twice. C workers remain16,384 B. C heap figures
are **terminal cleanup only**: unavailable C running-heap arrays stay empty/null,
not zero. Rust running floors remain8 KiB free /8 KiB largest block /12 KiB regional
low-water. New candidate I/D caches are attested per image at32 KiB /8 ways /32-byte
lines, CPU240 MHz, tick1,000 Hz and dual-core SDK. Older controls retain only their
recorded instruction-cache facts; absent per-image data-cache/tick settings remain
unqualified and are not reconstructed into attestations.

Both new modes use O3/thin LTO with target code-generation/IRAM placement and a
compiled worker-affinity request. The integration changes these together: no
isolated CPU, cache-miss, affinity or async cause is established. Rust Constrained
capacities remain8 routes (7 populated),4 Calls,0 deferred,RX/TX2 x1152 B,
RX/TX body1 x4096 B,dedup4,Observe2,token8 B. C matches the static unprotected
GET/CON-C1/Block2 service using dynamic PDU/session allocation; complete library,
security and capacity parity is not asserted.

## Sources, private attestations and reproduction

Candidate core `c0151713fc187a4a2b8ed3cba1eb0b12df597d00` is the accepted a85 behavior
with target code-generation annotations, not the rejected H logic. The baseline is
`a85c51e689607051e36e450567fe051f8f85dc2b`; runtime is
`32f8fcac22fc16b1957c35f4f145df6be3a72532`. The exact task-core and annotation source
patches, compiler profile, source byte joins, image/archive/config/ELF hash
commitments, frozen method and all raw report commitments are retained. These are
source/measurement commitments, **not an independent firmware rebuild kit**.
Full identity, binary, source/role/security, body/packet and API producer joins
remain private attestations. No firmware, raw API, configuration, credentials,
NVS, private addresses, run/session/process identities, tokens, MIDs or user paths
are published. Selected class/runtime/future sizes remain scoped owner facts,
not minimum RAM or peak stack guarantees.

The [earlier exact-H host/Wi-Fi package](https://github.com/jeffglousher/coaptic-validation/tree/021b691ed34167e488bde6915561613c98ae9455/tools/benchmark/evidence/esp-idle-observe-20261109)
and [merged MCU diagnostic](https://github.com/jeffglousher/coaptic-validation/tree/a50f202ed2ed289e391ec2cc358498954b55f6db/tools/benchmark/evidence/mcu-processing-span-20261109)
remain separate and unchanged. This screen adds no host sample and does not
rewrite those failures or instrumented spans. Runtime-adapter work is complete;
the timer prototype remains untimed and on hold. No profile adoption or completed
host/device speed goal follows from these results.

`export.py` requires both explicit parent clock-release and verified-normal-restoration
flags, also checks the terminal private result, and refuses an existing `package/`.
It performs no timing, hardware action, network call, build or cleanup. Its private
preparation and emitted package together have a1 MiB budget. To reproduce extraction
with retained private inputs, copy these tools to a fresh private preparation
folder and run:

```text
python -B export.py --native-root PRIVATE_EVIDENCE_ROOT --parent-clocks-released --normal-restored-verified
```

Public verification needs only this package. Original failures and private raw
records remain retained outside it; offline arithmetic PASS does not supply the
missing startup/task-policy or independent firmware/identity proof.
