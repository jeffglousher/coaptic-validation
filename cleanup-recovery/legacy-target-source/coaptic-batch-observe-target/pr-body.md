Qualify RFC 7641 section 4.5 NON notification reset removal using a real UDP Coaptic App server and a scripted loopback client. Wrong MID and wrong endpoint resets must preserve notifications; a matching reset must stop them, then ordinary GET and fresh registration must recover successfully.

The test waits past the 3-second NON hold before each notification attempt, including after removal, so throttling cannot impersonate observer removal. It grades an exact 13-datagram server trace and rejects 23 mutations: missing reset, wrong MID, wrong endpoint, late notification, corrupted recovery payload, plus endpoint-direction, resource-path and complete-body mutations for registration and health exchanges.

Validation against core `d67f94a5040f526d06b875e0f6ba27b25fb09a4e`:
- `cargo test --locked -p coaptic-plugtest --test observe_reset -- --nocapture`: passed in 18.65 s, including 23 mutation refusals.
- `cargo clippy --locked -p coaptic-plugtest --test observe_reset -- -D warnings`: passed.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
- Retained local PCAP: `D:\coaptic-batch-observe-target\evidence-reviewed\rfc7641-non-reset.pcap`; SHA-256 `b445c58dbc98b4e8fca166705961fe68dd4803a3402a5952087aa04972e7ceda`.

This plaintext fixture checks endpoint/message matching, not authenticated identity. The finite quiet window is not sustained availability qualification. TD_COAP_OBS_06 remains SKIP because its CON notification prerequisite is not available in this fixture. No literal TD is relabeled PASS.

Closes jeffglousher/coaptic#402. Advances jeffglousher/coaptic#199 and jeffglousher/coaptic#202; the umbrella issues remain open.
