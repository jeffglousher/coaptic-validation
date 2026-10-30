# Admission headroom: retained Stage A evidence

Conditional socket-free Windows full-App::poll wall evidence, run [41086130074/1](https://github.com/jeffglousher/coaptic-validation/actions/runs/41086130074/attempts/1), success. Candidate unmerged at collection. Stage B pressure and continuation: **NOT RUN; REQUIRED before promotion**. No Stage A rerun, gate/cap change, release or marketing claim.

Frozen sources: A `623c82db1a6606ec86cd56bb52009988b9f0d87e`, tree `4f349c19039de513487dff283289658402593991`; B `8782a6a0b0aef2facf51bec884cfe37f2a80f28d`, tree `ebc37d15f4d37aa2dfd322db16aff4d448c3d321`; harness `c58e47e36ebc5d90d3301fb62fa244d5e4803aae`, tree `19cfd5d02b988c42a724919f6b23e21b4a435891`. All source reads for this bundle used Git objects, never working native code.

Four cells: SmallDevice/fixed/Constrained/32 B and Default/allocated/64 B, each unprotected and OSCORE. AB then BA for each cell: 16 fresh processes, each 60,000 measured + 128 warmup operations and 4,096 separate timer calibrations. All 960,000 latency values, 65,536 calibration values and original producer texts are retained byte-exact, without outlier removal or calibration subtraction. The 2,048 total warmups are source/producer-derived, not a retained warmup latency array.

Eight conditional bootstrap gates PASS, separately per round; never pool rounds. Each uses 60 consecutive 1,000-operation block means, 10,000 resamples, seed 20261030 reset for each comparison, A draws then B draws, equal-tail linear .025/.975 quantiles. Unprotected: mean B/A <= .99 and upper95 < 1; OSCORE: upper95 <= 1.02. All ratios/CIs remain in the exact collector and original comparisons. Both arms' exact four native wall tests passed (see retained tests stdout/list and collector).

SmallDevice emits its full ledger. Default emits exactly seven fields: operations, warmup, security, black_box, measurement, latencies_ns, clock_calibration_ns. Default capacities and 60,128 verified completions are source-derived, not emitted: routes 1/populated 1, Calls 4, deferred 0, associations 1, security requests 4, blockwise enabled, RX/TX slots 4/4, datagrams 1472/1472 B, dedup 8, Observe 4, RX/TX body slots 1/2 at 1024 B each, concurrency 1/CON. Frozen validation constants in verify.py and collector preserve the complete capacity contracts.

Compiler execution, process affinity and cleanup/restoration are producer-attested despite independently consistent source and binary hashes. CPU, sockets, device, generated peak stack and whole memory are unsupported claims. Native test success is software evidence, not hardware qualification.

`collector.json.gz` and `prior-failure.json.gz` decompress to the unchanged sealed 38,093 B and 7,668 B collectors. The initial run 41084281643 used `tests::` instead of `batch_tests::`, stopped before measurements, and is preserved. The current collector's `artifact.manifest` is the original full 113-member ZIP manifest, including the four EXE/PDB hashes.

Artifact 12992721409: ZIP 3,928,831 B, SHA256 `202e47e98b9b51284d922c8841f45179581f7eeb5cc3b35d975c204246308967`; 113 safe unique regular members, 15,683,637 B expanded. Raw ZIP and binaries remain remote, are not included, and may expire (API expiry at collection: 2026-11-13T16:09:16Z). This bundle offers no future executable replay guarantee.

`data.json.gz` maps all 109 nonbinary members to offsets, byte counts and SHA256 in a concatenated UTF-8 payload, encoded with stdlib XZ then base64 inside JSON. Empty files are retained. This reversible packing preserves every original byte including line endings. `index.json` hashes exact stored files and decompressed gzip payloads; its own hash is reported at handoff, not recursively embedded. Gzip mtime is zero. The scoped -text Git rule prevents checkout newline conversion.

From this directory, verify using only Python's standard library (no writes, workload or producer imports):

```powershell
& D:/CoapticCurrent/matched-benchmark-20261013-venv/Scripts/python.exe -X utf8 -B verify.py
```

On another host: `python -X utf8 -B verify.py`. The verifier checks index/gzip hashes, UTF-8 roundtrip, every retained member against the original manifest, exact member/count conservation, all 16 schemas/commands, both test censuses and all eight comparisons using pure functions/constants extracted from the frozen harness. To access an original member in Python after loading data and decoding payload: `payload[spec['offset']:spec['offset'] + spec['bytes']]`; do not normalize line endings.

Independent source/evidence review NONE is attributed to parent handoff, core-board notice ef6f27ee-1ca2-4179-87c7-92298859801f, source urn:uuid:7d4d54df-5cb0-4ef8-a339-97bb08056485, parent acknowledged. That notice was unavailable in this implementation mailbox. Publication review is not complete; parent owns review, integration, commit and delivery. Startup mailbox traversal completed with an initial retention gap; this is not complete historical-mail coverage.

Owner root / Coaptic; public evidence retained through delivery, total bundle ceiling 524,288 B. No private generated output, native execution or builds. Credential/embedded-binary scanning is heuristic, not proof of absence; checks.json records its patterns and scope. No scan finding was redacted. Remote binaries were hashed/CRC-checked in RAM and excluded by explicit name/type. All implementation read/write holds release at handoff; retained files remain evidence under parent custody.
