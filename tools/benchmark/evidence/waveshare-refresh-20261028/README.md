# Current-source Waveshare refresh, October 28

Functional PASS on the commissioned Waveshare ESP32-S3. The hosted archive from
[run 40694497672](https://github.com/jeffglousher/coaptic-validation/actions/runs/40694497672)
was linked locally into the normal pairing/async application and deployed once
through app-only network OTA. Exact source, image, client and operation receipts
are in [receipt.json](receipt.json). Private configuration and images stay private.

Core: `28d9f1a61d15121d75d5dd426ad8d6b5cc891005`; Rust archive companion:
`a4c11efd73e4dcb72d4799f19ffe52600af05e1b`; C++ assembly companion:
`828bb4572a2a99fa933ca1c5f116a4576cb60731`. The frozen retained host client has
historical source provenance; its actual binary hash is recorded.

The 2,326,656-byte image passes explicit ESP32-S3 chip, application descriptor,
checksum, appended SHA256, fresh marker and 8,126,464-byte OTA partition gates.
Encrypted API witnesses before and after the probes identify fresh run
`5092e00212e5465f8903bcf1eb1e4d7b`. Existing pairing and grant support protected
echo and four warmup plus 24 measured authenticated 32-byte identity reads.
No erase, recommission, partition update or serial flashing was performed.

Deployment took 24.039 s. Protected echo took 1.601 s; the prepared timing CLI
took 0.941 s, including a 0.350 s connection setup nested within that command.
The 24 measured logical operations observe min/mean/median/p95/max of
10.569/13.86042/14.1674/16.5784/17.0915 ms. Raw sample rows remain in the receipt.
These short host-observed latencies include authentication, polling and transport;
they establish no matched improvement or extreme-tail qualification.

Preparation remains separate: hosted archive job 127 s; local failed assembly
wrappers 67.524/418.460 s; corrected final compile command 50.348 s using retained
objects. The first local failure exposed marker loss during ESPHome clean;
[controller PR32](https://github.com/jeffglousher/agent-message-board/pull/32)
provides original-owner recovery, checked against 566 unchanged payload files.
The second failed in the nested bootloader build with a Windows process quota
error. `CMAKE_BUILD_PARALLEL_LEVEL=1` bounds its `cmake --build .` job count;
the 16-process Job cap and storage/time limits stayed unchanged. This successful
continuation does not independently establish the original quota's sole cause.

One initial API capture finished after connection without observing logs; another
complete-resource attempt overflowed its cap. Both remain failed receipts. The
accepted identity check retains one bounded encrypted resource record per witness;
it makes no complete resource/task census claim. Original logs are retained
losslessly compressed with hash-verified decompression.

Device recipe: fixed EnrolledDevice RX3/TX2 packets at 1152 bytes, routes8, Calls4,
deferred0, one association, four security request bindings, recovery caches2,
dedup4, Observe2, body pools/blockwise disabled. Reserved Coaptic task stack remains
196,608 bytes. This device run covers one recipe. The eight host rows, deployed
eBPF fixtures and physical hardware are distinct validation surfaces.

Both 50% CPU goals, peak stack, whole-memory, minimum-RAM, concurrency/throughput
and remaining qualification stay open. No hardware performance improvement or
SDK equivalence follows from this functional delivery.
