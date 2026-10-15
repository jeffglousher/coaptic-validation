Q-Block wire assembly now requires Size1/Size2 on every incoming payload and refuses changes before modifying an existing body, following RFC 9177 section 4.6. Missing sizes produce a typed MissingSize error. Classic Block estimates remain unaffected.

Positive/refusal tests cover both receive directions, absent initial size, absent/changed continuation sizes, unchanged body and completion state after refusal, corrected retries, and an App upload handler invoked exactly once with the exact complete body. Range-only APIs remain available for caller-managed metadata; their size indication must remain stable for Q-Block. Updated a wire-success fixture that previously omitted mandatory Size1.

All eleven CONTRIBUTING.md local checks passed at 97c14dc (496 all-feature library tests), including no-default, DTLS+OSCORE harness, Clippy, rustdoc, packaging and both Rust 1.85 builds. The rebase adds only the merged workflow pin update. Linux CI required before merge.

Progress on #201/#200. Remaining Q-Block body identities, full recovery, independent qualification and complete ETSI sequences are not claimed by this slice.
