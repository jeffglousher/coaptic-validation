Classic Block1/Block2 rejected valid bodies whenever Size1/Size2 estimates differed from the final byte count. Follow RFC 7959 section 4: M determines completion; actual body-slot capacity still bounds bytes. Apply the same rule to BERT. Preserve Q-Block exact-length enforcement under RFC 9177 section 4.6.

Regression coverage: both directions, classic and BERT, absent/zero/under/over/u32::MAX estimates, exact capacity and one-byte overflow with state preservation; real encoded two-fragment requests/responses with changed or omitted estimates; Q-Block incorrect-size refusal and exact-size acceptance. Rustdoc and errors describe the distinction.

Validation at 18a419b: all eleven CONTRIBUTING.md local checks passed, including 494 all-feature unit tests, plugtests with DTLS+OSCORE, packaging and Rust 1.85 feature/no-default checks. No storage growth or new dependency. Linux CI remains required before merge. This does not qualify Q-Block mandatory metadata, recovery, full ETSI block sequences, or embedded runtime behavior; audit issues remain open.

Progress on #201 and #200.
