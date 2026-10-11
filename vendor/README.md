# Test-only DTLS dependency

`webrtc-dtls/` is the complete 0.12.0 crate archive, excluding Cargo's generated
`.cargo-ok` marker, with a bounded final-flight recovery patch. The core Coaptic
crate does not depend on this code. Both upstream MIT and Apache-2.0 licenses,
author metadata, examples, tests and original manifests are retained.

Original package: `webrtc-dtls 0.12.0` from crates.io, archive SHA-256
`5ccbe4d9049390ab52695c3646c1395c877e16c15fb05d3bda8eee0c7351711c`.
The archive records upstream revision `632dccdbf8e9638b5770ad4bd556c99d9905fd83`
and repository subdirectory `dtls`. `webrtc-dtls-original.json` lists every
original file's size and SHA-256 before local edits. It is provenance, not a
claim that patched files still match their original hash.

The companion workspace patches only this package to the owned path. Its
production dependency versions remain unchanged in the workspace lockfile.
The retained upstream crate lockfile separately fixes the backend's private
unit-test dependencies; it is not used by the companion production build.

The ordinary server transfers its already generated final CCS/Finished packets
into a private response owner before exposing handshake completion. A finite private responder task
retains a fixed four-minute deadline (RFC6347 section4.2.4 and RFC793's two-minute
MSL), coalesces intact authenticated peer retries, and rate-limits responses from
one second with exponential backoff capped at sixty seconds. It submits through
the existing connection writer, preserving fresh record sequence ownership.
It never cancels a generic connection receive. Expiry and close also cancel a
blocked queue reservation and release the pending packet clone. The deadline
bounds queue handoff, not socket-write scheduling after admission by the writer.
It does not alter handshake contents, encryption, verification or key derivation.

Expiry clears retained packets, the expected Finished copy and coverage state.
A small epoch/message-sequence filter remains to discard well-formed records
consisting entirely of that old Finished's fragments. Malformed or mixed-message
records retain upstream behavior; this patch does not qualify general fragment
buffer availability. Different epochs/messages and separate connections do not
share the response owner. Explicit close and reader exit clear it.

The original RFC6347 text is retained in `knowledge/rfcs/rfc6347.txt` at the
repository root, retrieved from `https://www.rfc-editor.org/rfc/rfc6347.txt`,
SHA-256 `16c851f2ee94586e653566cc3276c6c58256f0b54f3331a68784a6d55357104b`.

Focused private tests:
`cargo test --locked --manifest-path vendor/webrtc-dtls/Cargo.toml --lib final_flight`.
Real intact-loss qualification:
`cargo test --locked -p coaptic-plugtest --features dtls --lib dtls03_`.
No altered-Finished experiment, DTLS02 prescribed-alert claim, RPK support,
independent DTLS stack or hardware qualification is included.
