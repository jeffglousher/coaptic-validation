App clients can now explicitly echo a received challenge via Outgoing::echo. Retain the typed 1..40-byte value on initial requests, every Block1/Q-Block1 upload fragment and Block2/Q-Block2 download continuation.

RFC 9175 section 2.3 requires the source endpoint/security association and Inner/Outer class to be preserved. The API documents this caller obligation. Retry is explicit so callers decide whether an unsafe operation remains fresh; no automatic replay, endpoint authentication, or server challenge-generation security claim is added.

Tests prove a 4.01 challenge is surfaced without automatic retry, an explicit retry preserves path/query/payload and uses a new Token, every upload/download fragment retains the Echo, and an actual OSCORE client/server challenge and retry keep Echo entirely Inner in the same context. Existing primitive length/refusal tests remain active.

All eleven CONTRIBUTING.md checks passed at f5e367a3f369050c75d3e9c29d34bc8d52449982 (512 all-feature library tests), including DTLS+OSCORE harness, no-default, Clippy, rustdoc, package and Rust 1.85 builds. No dependency or heap changes. Linux CI required before merge. Progress on #201; independent Echo peers and full protected Q-Block recovery remain unqualified.
