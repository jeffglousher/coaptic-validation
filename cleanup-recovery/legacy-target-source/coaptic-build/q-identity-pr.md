Q-Block wire helpers previously accepted and emitted missing body identities. Require Request-Tag for Q-Block1 (present-empty remains valid) and nonempty ETag for Q-Block2. Refuse outgoing identity errors before advancing a window or writing TX; keep range-only APIs available for caller-managed encoding.

App Q-Block2 now requires the handler ETag, including small explicitly requested transfers, retains it with the body, and refuses active continuations whose ETag or bytes change. Callers own representation identity across operations and restarts. Update success fixtures to send required identities instead of treating malformed wire output as success.

Tests cover missing/empty/present identities in both directions, no slot allocation on receive refusal, unchanged transfer/TX on outgoing refusal and reissue, small/large App response refusal, ETag on every fragment, and changed-identity/body refusal followed by successful continuation. 500 all-feature unit tests pass.

All eleven CONTRIBUTING.md checks plus ordinary and OSCORE dogfood comparisons passed at 81a1d87; rebased source has the same tree. CI required before merge. No new dependencies or persistent sidecar fields. This is not full RFC 9177 qualification: missing-block recovery, complete Observe/protected flows, independent Q-Block peer coverage and retained-body lifetime remain tracked in #200/#201.
