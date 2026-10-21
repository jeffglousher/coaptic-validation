# Matched host-to-ESP32 reads, 21 October 2026

Core 3ca0be6fe8b13e23d0f834d7340f8e06ee9547a1 and companion
97517ea3cf71a201c2f33778544a2fbcf92ec465 are clean build inputs. Both
source-bound images ran on the reserved ESP32-S3. Each completed 24 verified
reads: eight ordered identity (32 B), test (7 B), large (2,000 B) cycles.
The large response uses blockwise assembly. No warmup is removed.

Median complete-operation milliseconds, unprotected / durable OSCORE:
identity 8.8774 / 18.10895; test 7.6426 / 17.6536; large 20.42265 / 44.66395.
The first protected identity read took 139.0548 ms. Keep it when reading the
mean (33.874775 ms); eight samples do not support a useful tail estimate.

The synchronous service uses body-enabled Constrained: RX2/TX2 × 1,152 B,
one 4,096 B body per direction, dedup4, Observe2, eight route slots/six
application routes plus separate discovery, four Calls and no deferred slots.
OSCORE adds one association/four request bindings. Both host initiators are
compiled with OSCORE available; the unprotected device image omits it.
Host full-response collection is enabled; server full-response mode is disabled.
This existing full-service workload is separate from the body-disabled
SmallDevice host comparison and the installed paired Managed image.

Existing authenticated security records were verified without provisioning or
snapshot restoration. The durable device performs the required checkpoint
boundary; device flash timing/counts were not instrumented. Client recovery
and sender reservation precede the 24 operations. Per-operation host state
reads/commits are zero. The unprotected state file remains byte-identical.
The requested 1 ms host wait, actual scheduling, network and security work
contribute to elapsed time. These measurements do not isolate encryption cost.

Observed worker touched-stack maxima are 65,212 / 87,964 B within the existing
98,304 B reservation. Running all-8-bit heap nonfree maxima are
193,928 / 194,248 B; smallest observed largest block is 124,928 B in both.
Capability views overlap; task reservations and nested App/scratch already
contribute. Four complete 12-task snapshots per mode are retained.
These are running observations, not absolute stack/ISR/kernel peaks or minimum
deployment RAM. Target server App size and initialization peaks are unmeasured.

The exact normal OTA (a5c6fa3b...) was restored. Encrypted API run 31e69a...,
original identity/owner/revision24/echo grant/completed custody, fresh protected
echo, and byte-identical pairing plus four retained effects all pass.
No credentials, firmware, private configuration or NVS bytes are published.
The reverse MCU-to-host cells still require scoped Windows inbound permission.
Cold power/interrupted storage checks remain open; touch revalidation is deferred.

result.json contains image/archive/compiler/lock/input digests, raw-sample
summaries, finite resource projections, restoration receipts and limits.
The JSONL files preserve exact numeric client and authenticated API captures.
manifest.json hashes this bundle; it does not relabel the older completion
baseline or qualify a later source merely because documentation changes.
