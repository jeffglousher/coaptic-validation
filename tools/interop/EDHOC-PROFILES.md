# Selected independent EDHOC profiles

`edhoc_profiles.py` runs method 3 with suites 2 and 3, both Coaptic roles,
mandatory message 4, and fixed mutual CCS/kid pins. Eight successful configurations
cover no EAD and three ordered EAD items in every message: a handled critical
item, an unhandled elective item with absent value, and one with an empty value.
Eight unknown-critical refusals each have a fresh successful handshake afterward.
Five exporter requests compare labels 32768/65535 and context lengths 0/23/24/255/256.

`edhoc_wire_errors.py` reuses the existing UDP bridge and native public error codec
for errors 1/2/3 in both directions. Each refusal is followed by a fresh UDP
handshake and protected App exchange. `--direction` and `--code` select a focused
rerun. Error receipts remain unauthenticated advisory data.

The pinned native library has built-in suite 2. `libedhoc/profiles.h` supplies suite
3 through its public descriptor/backend API: upstream P-256/SHA-256 operations and
PSA AES-CCM with a 16-byte tag. It copies no cryptographic primitive. The native
CBOR backend accepts at most three EAD items; its advertised-suite list has room
for both selected suites. These are host fixture capacities, not Coaptic App RAM.

Current retained evidence in `../qualification/evidence/independent-edhoc/index.json`
records 24 successful raw sessions, 11/12 initial UDP cases, and the corrected
outbound error-2 case plus fresh protected recovery (2/2). The initial native
four-item EAD build failure and one-suite-list decoding failure remain retained.
Core source is `0c14097`; companion captures identify `46077df` and the targeted
fixture correction `7ae11e5`. Captures include clean-source guards and binary
hashes; native manifests retain pinned dependencies, compiler commands and flags.

The native exporter only permits its selected private-label range, so these runs
make no independent full-u64-label claim. Padding, arbitrary EAD capacities,
additional authentication methods, device integration and transparent one-sided
restart are outside this finite host batch. Suite 3 is explicitly a custom native
backend profile. No timing benchmark or stability claim is made.

Run the existing pinned `libedhoc/build.py`, then invoke either runner with
`--coaptic EXE --libedhoc EXE --core CORE_CHECKOUT --companion SUITE_CHECKOUT --output REPORT`.
The raw runner uses `edhoc_peer`; the UDP runner uses `edhoc_udp_peer`. Both require
clean committed source. Native build provenance must match the current fixture.

Native EAD callbacks in pinned libedhoc can run before its MAC check. They only
validate fixture input and record counters. `ead_after_success` is emitted after
the entire native handshake succeeds; it does not establish authentication before
the callback. Only Coaptic's `ead_authenticated` checks the verified Principal at
callback time. Original native captures named that post-success field
`ead_authenticated`; retain them with this corrected interpretation.
