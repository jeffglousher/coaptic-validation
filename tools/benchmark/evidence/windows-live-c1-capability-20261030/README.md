# Windows live server-thread profiling capability

Diagnostic capability proof; no qualified hotspot ranking or optimization result.
The library remains at core `8af71fe4aa73b3bb76a921a836a1a9647d75f361`.

## What ran

[Recording run 41038109816](https://github.com/jeffglousher/coaptic-validation/actions/runs/41038109816)
used companion `1897220f57b9379b4e1332a0f17bb977b8f01900`. Both controls and
unprotected/OSCORE capture 0 completed 1,000,000 fresh work exchanges plus 128
warmups. Both ETW sessions explicitly stopped. Unprotected export succeeded;
OSCORE export refused `Frame text budget exceeded.` The final two captures did
not run. The recording campaign stopped without replacement cohorts.

[Offline run 41044460748](https://github.com/jeffglousher/coaptic-validation/actions/runs/41044460748)
used companion `625728bd9aba0afc80c84fd6c78e046ca5b4efa8`, tree
`f64cc7616307ff0a13304b708ac20531068046f0`. It replayed those same two ETLs,
with no Rust provisioning, native workload or new ETW session. All 126 portable
checks and 209 pure C# model assertions passed. SDK 8.0.427 built the exporter in
26.62 seconds with zero warnings/errors. The original native fixture's 12 tests
passed in the recording run; those tests were not rerun offline.

## Retained unprotected profile

The exact-path projection contains 3,164 observed samples/weight, 332 distinct
full-symbol paths, 341 symbols, 531 nonempty recursive prefixes and 42,573
weighted frame occurrences. Of those samples, 1,633 contain App ancestry and
1,531 do not. There are 11,260 unresolved frame occurrences. Reported lost and
refused event counts are zero; unknown is not zero.

Independent collection compared every exact path multiplicity, full-symbol
self/inclusive/occurrence count, recursive flame prefix, weighted depth and
quality counter against the original per-event profile. All agree. The counted
profile JSON is 523,735 bytes, SHA256
`f5a699f58dd877143bc60c233a1ca683b392e0313cbfe3a87a51c48046b53f47`.
The path-counter SHA256 is
`66997201a5009a90a6bdfdae93ceda034dc13536cadf4682d596b313330c84b4`.

`profile.json.gz` and the standalone interactive `profile.html.gz` decompress to
exact producer output bytes. `equivalence.json.gz` and `export-receipt.json.gz`
retain producer checks; `offline-collector.json.gz` records the independent
comparison and archive/input checks. `original-live-collector.json.gz` preserves
the recording census. The index hashes exact stored bytes, including gzip files.
Browser DOM, frame geometry, zoom, filter and reset checks passed on the actual
projected HTML. Full-page screenshot snapshots timed out, so no fresh visual
inspection of that full artifact is claimed. A separate compact presentation of
the original data was visually checked earlier.

## Workload and interpretation

This is a 64-byte, socket-free, C1 workload using the Default allocated App,
not SmallDevice/32-byte traffic. Capacities: route 1, Calls 4, deferred 0,
security bindings 4, association 1, RX/TX 4x1472, dedup 8, Observe 4,
RX body 1x1024, TX body 2x1024; blockwise enabled. The main thread performs App
polls; one client helper prepares and authenticates through a bounded handoff.
The profile selects server PID 2688/TID 6728; helper TID 2384 is excluded, while
its scheduling effects remain. Keep server handoff, wait, driver and unresolved
system paths alongside library paths. Virtual protocol time is `index * 8 ms`,
not real RTT, throughput or a device clock.

The profile preserves original capture identity. Current exporter source/build
identity is recorded separately. Exact-path grouping is explicit and default
off; it preserves counts but omits per-event timestamps/QPC, addresses, modules,
comm and event order. Aggregate JSON cannot independently prove window membership
or answer timeline/address queries. The original hash-bound ETL remains
authoritative; selection checks in the export receipt are producer-attested.
No pooling across processes, threads, modes or runs occurred.

The 200 App-sample floor is met, but unwind/inline completeness and CPU mode
remain unknown. Circular overwrite is not fully measurable. Conversion/depth
truncation is reported false/zero by the producer, while qualification retains
unknown truncation. Live-owned file hashes/mapping and local PDB GUID/age bind
symbols; recorded-zero image ID and absent DebugID are unavailable corroboration,
not matches or proof of exact in-memory bytes. Only owned EXE/PDB symbols resolve.
Compiler/tool identity, descendant cleanup and raw ETL selection are not all
independently reproduced. Hosted VM retirement and prior global sampling-interval
restoration are unproven. Windows sampling enables the machine-global 1 ms
interval on the dedicated VM. No qualified CPU share, emitted frame/peak-stack,
whole-memory, device benefit or performance improvement follows.

## Preserved refusal and custody

OSCORE offline export refused `InvalidDataException: Stack/frame count budget exceeded.`
No protected canonical profile or partial totals were retained. Which raw-count
predicate fired remains unknown. The 100,000-event, 200,000-frame, depth-128 and
16 MiB text/JSON/HTML limits remain unchanged. No cap increase, segmentation,
fallback, retry or replacement recording follows. Earlier timeout/source-pin
failures and both OSCORE refusals remain in `retained-failures.json`.

Original artifact 12969046956 is 6,179,117 bytes, SHA256
`bfc9b19766836cb5f3a7c59971bfc062068ff5ecb071433b0c74ced7c803a3bf`.
Offline artifact 12971628053 is 6,018,623 bytes, SHA256
`779ad633370b78bfee8cc8e8abc21c6b943be2a3ef30e14ed2a9994c2122ced0`.
All 33 current artifact members passed independent CRC/size/SHA checks, and all
ten selected original inputs match their pins. Raw ETL, EXE and PDB bytes are
excluded from this committed bundle and remain private retained evidence.
This stored bundle has a 128 KiB ceiling. See the
[live plan](../../windows_live_c1_plan.md) and
[profiling guide](../../stack_profiling.md) for contracts and limits.
