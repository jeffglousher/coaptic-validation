Q-Block2 responses mixed a piggybacked ACK payload with later NON payloads. RFC 9177 section 7 requires one message type for the body; RFC 7252 sections 5.2.2/5.2.3 permit an empty ACK followed by NON responses to a CON request.

Successful Q-Block2 bodies now use all-NON payloads. CON requests receive a separate empty ACK first, retained before sending for duplicate/protected retransmission handling. The same policy applies to response handlers requesting separate delivery. Range, identity and body admission checks still precede the ACK; repeated selection preflight still rejects an invalid later range without output.

Tests explicitly verify ACK MID/type before examining the subsequent NON body transcript, covering single/tail/repeated selections, shared local MID allocation, ordinary and separate handlers, CON/NON requests and duplicate handler-effect suppression. Protected assembly tests consume the actual ACK before testing response reordering/corruption/replay. Injected ACK-send failure preserves duplicate handling without re-entering the handler or leaking body storage; sequence-exhaustion tests distinguish the empty ACK from protected body output.

Validation: all 15 CONTRIBUTING commands and both two-iteration dogfood comparisons passed at d86fe08 before a clean rebase to cec43741ca09135c1f92d4cabaa01226524d341f. All-features inventory: 602 passing unit tests. Windows MSVC stable Rust 1.97.1 plus Rust 1.85 checks. CI retains Linux/process/seeded/cross-build evidence; independent process cases do not qualify Q-Block.

Related: #201. This resolves the server body message-type policy, not endpoint-wide congestion control, NON pacing, complete-body retention, client missing-block reissue, timed protected recovery or Q Observe.
