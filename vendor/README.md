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
into a private response owner before exposing handshake completion. A finite
private task accepts intact authenticated retries for four minutes (RFC6347
section 4.2.4 and RFC793's two-minute MSL). It coalesces requests and rate-limits
responses from one second with exponential backoff capped at sixty seconds.
A fixed additional sixty-second drain allowance lets a retry accepted just
before the acceptance cutoff reach its rate deadline. Neither deadline extends:
new retries cannot add work at or after 240 seconds, and retained packets and blocked
queue reservations are released by the hard 300-second deadline or close.

The task submits through the existing connection writer, preserving fresh record
sequence ownership, and never cancels a generic connection receive. Deadlines
bound queue handoff, not socket-write scheduling after admission by the writer.
Handshake contents, encryption, verification and key derivation are unchanged.

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

Diagnostic minimization after vendoring: CodeQL reported eleven cleartext-logging
paths in unchanged upstream statements. Two production traces printed only the
peer-certificate count; eight codec assertions printed public, hardcoded fixture
values; one local cookie assertion received certificate-enum taint despite its
ClientHello match. These paths did not demonstrate private-key or master-secret
disclosure. Static diagnostics now retain the same equality checks without
certificate or cookie value dumps. No query is suppressed and no alert dismissed.

Local edits retain their original file hashes in `webrtc-dtls-original.json`.
The connection implementation/tests, handshake cache, handshaker, flight4,
selected codec tests and CCM/GCM record codecs differ from that baseline;
the final-flight and record-policy modules are local additions. The GCM policy
increment records its changed-file hashes in `webrtc-dtls-gcm-policy.json`.

Record-error policy (#485/#486): CCM, CCM8 and GCM reject records shorter than
their explicit nonce and authentication tag before subtracting tag length.
Authentication failures retain typed `ErrInvalidMac`; supported PSK AEAD suites
use the existing fatal-close path with `bad_record_mac(20)` (RFC6347 section
4.1.2.1 and RFC5246 section6.2.3.3). Structural decrypt errors are silently
discarded without asserting that a PSK identity is unknown. Non-PSK discard
policy remains unchanged. This does not alter key derivation, Finished
verification, identity lookup or the literal DTLS02 alert51 requirement.

Offline targeted checks:
`cargo test --locked --manifest-path vendor/webrtc-dtls/Cargo.toml --lib record_policy`.
Finite loopback controls, known-identity wrong-key refusal and fresh recovery:
`cargo test --locked -p coaptic-plugtest --features dtls --lib dtls_record_policy`.
The two profile tests retain separate captures and exact source identities;
GCM is not reported as the literal CCM8 TD_COAP_DTLS_01.
