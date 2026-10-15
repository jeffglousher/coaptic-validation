App previously used deterministic Tokens, minimum retransmission delays and unchecked MID wraparound. Require an explicit caller-owned cryptographic random source, with a clearly named deterministic test mode. Use bounded unbiased RTO jitter, collision checks for active Tokens and a shared local MID allocator for requests, NON responses and Q windows. Refuse MID reuse until the quiet interval and pending-transmission checks pass. Entropy failures are typed and reclaim partial upload state.

This changes the prepublication App builder API: add `.randomness(...)` before binding. Executable peers use getrandom 0.3.4; the default no_std library retains zero runtime dependencies. Callers own entropy quality and endpoint restart persistence/quiet time; random initialization alone is not a restart guarantee.

Validation on 7dfb5b8, rebased without tree changes to 1fa01db2d2daadcb3a69de564a908d849e0e1084: all 11 CONTRIBUTING checks, plaintext and OSCORE dogfood comparisons, and peer-coaptic Clippy passed. 537 library unit tests pass. Specific proofs cover all 1001 initial delay values, bounded rejection sampling, source failures before I/O and during fragment allocation, exact retransmission boundaries, active Token collisions, all 65536 MIDs, clock rollback, pending transmission wrap refusal, and shared response/Q-window allocation.

Clean Windows native process run at 1fa01db: 26/26 scenarios, eight pairings with 100 request samples each. C peer is UDP-only on Windows. CI supplies Linux independent C DTLS evidence. This does not qualify full Observe, OSCORE or Q-Block interoperability, embedded runtime behavior, entropy-source quality or persistent identity across restart.

Advances #201 and #202; neither umbrella is closed by this slice.
