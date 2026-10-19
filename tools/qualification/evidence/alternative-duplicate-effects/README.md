# Alternative-server duplicate effects

This finite Q4 characterization uses the retained independent coap-rs/libcoap
process fixtures. It does not claim either upstream library as a whole violates
a protocol requirement, and it does not count missing duplicate suppression as
successful deduplication.

Both named fixtures produced the same captured sequence:

1. Fresh GET `/counter`: `0`.
2. One CON POST `/counter`, forwarded twice byte-for-byte by the existing relay;
   two matching ACK responses, then a fresh GET observes `2`.
3. A distinct fresh POST succeeds; GET `/counter` observes `3`.
4. Fresh GET `/test` returns the exact expected application bytes.

The oracle binds every reply to MID/full token, all four endpoint owners, unchanged
relay bytes and the same server instance. It rejects missing duplicate replies,
changed wire data/owners/MIDs, a single effect, and missing fresh recovery. The
relay's duplicate action uses two `sendto` calls with the same bytes; this is
application-level socket evidence, not an independent packet-sniffer trace.

`characterization.json` records runner source `6ed91f9`, core snapshot `1ba5ebb`,
original binary/build source identities, executable hashes and unchanged peer
fixture contracts. Existing executables came from the retained PR91 build record;
no rebuild against today's core is implied. The original libcoap source is
`851533c3cf63d16984d370ce39d586ecb3694971`; DTLS/OSCORE are disabled for that native
binary. Only unprotected IPv4 loopback is exercised here.

Both characterizations succeeded. Three mutation-oracle tests and all12 capability
inventory tests passed. All181 manifest cases and build exclusions remain intact;
this independent characterization is separate from that runner's PASS inventory.

Run `tools/interop/duplicate_effects.py` with explicit `--coap-rs`, `--libcoap`,
`--build-record` and `--output` arguments. Changed binary hashes or fixture source
contracts require a matching rebuild record. Different observed effects fail this
characterization expectation and remain evidence for review rather than being
silently relabeled.
