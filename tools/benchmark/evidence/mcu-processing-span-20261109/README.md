# Common MCU receive-to-send diagnostic, V2

This is the completed, instrumented ESP32-S3 development diagnostic: **192 verified
reads and 256 fully matched datagrams**, four profiles, **one boot per profile**.
It retains every whitelisted numeric packet span and all 192 operation records,
including the two associated Block2 packet spans for each large read. No trimming,
sample replacement, successful-profile selection or fake boot replication is used.

This package establishes **no task CPU, clean RTT, speed gain, H adoption or completed
goal claim**. Its offline PASS means the exported arithmetic, structural guards,
hash commitments and declared scope agree. Full packet/body, identity, OTA, API and
producer/source joins remain **retained private attestations**. This is not an
independent firmware or packet rebuild kit.

Run with Python 3.10+ from this directory; only the standard library is required:

```text
python -B verify.py
python -B test_export.py
```

`verify.py` checks every file and expanded gzip digest, exact field allowlists,
finite method, source pins, one-boot structure, original reservations and all three
running heap floors. It independently reconstructs **64 packets -> 48 operations**
per profile, **16 operations per path**, and reproduces the saved summaries. A large
operation sums its two associated packet spans *before* taking an operation median.
The packet/block, client and operation summaries remain descriptive finite samples.
Native outer-call wall and residual must reconcile; nested call counts are separate.
The verifier refuses false CPU/speed/adoption claims, missing/reordered rows,
wrong Block2 sums, lost nonzero delays and extra identity fields. The small export
counterexamples do not rerun the prior target, codec, C++ or controller checks.

The operation medians in microseconds, ordered identity / test / large, are:

- Hsync: **570 / 405 / 1232.5**.
- Hasync: **1335 / 1255 / 2984**.
- Cpin: **481 / 497.5 / 1419**.
- Cfloat: **498 / 487.5 / 1353**.

All 256 spans contain **zero native select calls**. Hasync alone has **two delay
calls totaling 1,139 microseconds**; every other delay total is zero. All original
native lifecycle and refusal counters are retained. Would-block counts cover the
observation window; they are not a CPU or elapsed-time accounting method.

The boundary starts at a successful socket receive return and ends at send entry.
Receive-call and send-call wall are retained separately and lie outside that
processing span. The span includes preemption and RX observer work. Post-send
logging is paced by 50 ms but may perturb the cache and later work. Residual wall
is not task CPU, and instrumented RTT does not enter promotion. The timer-probe
prototype remains untimed and on hold for this GET fixture.

The integrated Rust profiles differ: **Hsync uses O3/thin LTO; Hasync uses Os/fat
LTO**. Their frozen core is `de9230aa22dab0c67604ea4b040a1c1daa59a41e` and runtime
is `32f8fcac22fc16b1957c35f4f145df6be3a72532`. Their libraries and service sources
are identified by original hashes. The H core patches and runtime source are
already public in the [prior exact-H source package](https://github.com/jeffglousher/coaptic-validation/tree/021b691ed34167e488bde6915561613c98ae9455/tools/benchmark/evidence/esp-idle-observe-20261109/sources).
They are referenced, not duplicated or adopted here. The subsequent c015-based
candidate is **not measured by this package**. C retains libcoap `4.3.5~8`, with its exact component, source, placed archive and
component-receipt hashes in provenance. This is not an isolated comparison
of async, language, codegen or task placement.

The separate, uninstrumented H Wi-Fi speed screen remains failed: strict-best-C
latency ratios **1.06576 sync / 1.47413 async**. That host/Wi-Fi package retains its
own samples, boot variation, methods and gates. Do not combine these diagnostic
spans with it or infer Wi-Fi/transport cost by subtracting unrelated medians.
The ESP32 uses Wi-Fi; its radio/AP and Windows path are outside this MCU processing
boundary but inside the separately reported complete-read latency.

## Capacities, memory and startup

Rust Constrained keeps 8 routes (7 populated), 4 Calls, 0 deferred, RX/TX 2 x 1,152 B,
RX/TX body 1 x 4,096 B, dedup4, Observe2 and token8 B. C matches the static
unprotected GET/CON-C1/Block2 fixture using its original dynamic session/PDU
allocation. Complete library/security/capacity parity is not asserted.

Original worker reservations remain **98,304 B sync / 196,608 B async / 16,384 B C**.
Before-task largest contiguous internal allocation must be worker + 4,096 B.
Hasync's 200,704 B witness meets that inclusive floor exactly. All three running
heap floors are preserved: **8,192 B free, 8,192 B largest block, 12,288 B summed
regional low-water**. Pre-client and post-capture witnesses are separate values.

Observed lifetime stack watermarks are not safe minimum stacks or whole-system
peaks. The 2,512 B observer context is inside the worker stack; 28 global bytes are
inside static RAM. Their 2,540 B storage sum differs from aligned main-SRAM static
deltas (24 B sync/C; 32 B async). The encoder's 256 B source stack bound is separate
nested work. Heap snapshots, regional lows, original worker allocations and static
owners overlap; do not add them twice or infer minimum RAM from these samples.

Every new diagnostic image attests actual I/D caches of **32 KiB / 8 ways / 32-byte
lines**, CPU **240 MHz**, tick **1,000 Hz**, dual-core SDK and the remaining declared
SDK choices. VFS select support is enabled only in Hasync; the observed native
select-call count inside consumed-RX processing remains zero. Earlier speed-run data-cache defaults remain reconstructed rather
than per-image attestations. Rust actual task policy is unavailable in API output:
only compiled floating core -1/priority1 is known. Cpin observed core1/compiled1;
Cfloat observed startup core1/compiled-1. A startup observation is not continuous
affinity proof.

## Sources, private proofs and retained failures

Generic observer CPP/header/CMake bytes are included unchanged with exact hashes.
The optional standalone matcher is included for inspection. **Only its EXPECTED_IP
constant changes**, preserving its network-order integer representation and using
the documentation-only TEST-NET default `192.0.2.1`.
The exporter proves the original/public ASTs match after normalizing that one
constant; the verifier checks the normalized AST commitment and published source
hash. The original private matcher hash remains committed. The actual private
address is not published. The public matcher is not invoked on absent raw packets
by the numeric verifier.

Previously completed **14 codec counterexamples, actual-source C++ host mock,
28 controller preparation checks and four-image target guards** are retained as
producer attestations and are not rerun here. The actual SDK/source/OTA/image,
full-packet/body and API joins cannot be independently reconstructed from this
whitelist. Private raw captures, firmware/configuration, ELF, credentials, identity
and NVS remain outside the public package. Numeric rows omit addresses, ports,
protocol tokens/MIDs, run/session/process identities and user paths. Original
raw/result/method/source/API/client digests preserve commitments to withheld data.

Both original failures stay failed:

- **V1 capture:** 48 client reads passed, but full 64-packet publication was
  incomplete within the frozen bound. The original result remains incomplete,
  with normal restoration verified.
- **V2 original Cpin SDK/component pipeline:** immutable libcoap archive regeneration
  was refused. Its original inventory remains failed, with source assertions and
  staging/fixture preservation retained. A **separate guarded controls inventory**
  supplied the completed diagnostic images. Its success does not replace that
  failed pipeline record.

The exporter requires **both** `--parent-clocks-released` and
`--normal-restored-verified`, and also requires the terminal private result's
verified restoration. It reads only explicit private inputs, emits a new `package/`
beside itself, refuses existing output, and performs no build, hardware action,
network call, performance repeat or cleanup. The combined private prep plus package
budget is 2 MiB within the unchanged source phase/root cap. To repeat extraction
with the retained private root, copy these tools to a fresh private preparation
directory and run:

```text
python -B export.py --native-root PRIVATE_EVIDENCE_ROOT --parent-clocks-released --normal-restored-verified
```

The flags attest parent custody; they do not probe or modify the device. Hashes
provide commitments, not a replacement for the explicitly withheld producer proof.
