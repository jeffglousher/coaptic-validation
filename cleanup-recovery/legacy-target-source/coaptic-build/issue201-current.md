Owner acceptance: each App limitation is resolved with executable positive/refusal proofs, or has a precise documented supported boundary and advanced API route. Preserve no_std, bounded resources and accurate claims. Performance/API polish follows coverage. Initial audit source: main 72c0083.

Resolved on main:

- #204: IPv6 scope identity and strict datagram send counts. #207: oversized UDP receive refusal and empty query retention. Scoped/link-local network qualification remains #200/#202.

- #205: Uri-Query/Accept retained on all upload fragments. Conditional fragmented uploads are explicitly refused before I/O; advanced Engine use remains required.

- #206: explicit Request-Tag retention, active same-peer reuse refusal and exact received operation binding. Callers own uniqueness across operations/restarts.

- #211: cancellation, deadlines and typed local outcomes distinguish received remote responses from timeout/reset/assembly failure, with cleanup proofs.

- #212: classic/BERT Size estimates are not exact-length requirements. #213/#214: Q payloads require stable exact Size and wire identities; App Q-Block2 retains a stable nonempty ETag and representation. These do not qualify full Q recovery.

- #215: server response Location/ETag bounds are explicit typed refusals; empty Location segments survive.

- #216: bounded client response headers retain Location, Echo, Max-Age and raw options. Bounds are 24 options, 512 encoded header bytes, at most eight values per Location kind; overflow is a typed terminal failure. First-fragment metadata survives assembly.

- #217: explicit Echo retry and fragment retention, including protected Inner Echo. Caller owns endpoint/security association and safe retry policy; this is not automatic server freshness authentication.

- #218: explicit No-Response policy survives sending/download follow-ups and OSCORE protection. Silence is never success. Fragmented uploads and suppressing Observe registration have typed App refusals; advanced Engine use remains required.

- #219: failed initial sending retires request bindings, pending datagrams and upload state, including partial Q windows, without resetting OSCORE sequence state or damaging another active call.

- #220: plaintext Observe serial ordering, wrap/half-range/128-second boundaries and protected PIV ordering; unauthenticated Outer Observe cannot replace Inner Observe.

- #221: Max-Age means stale data, not subscription expiry. Terminal responses, unknown CON reset, retransmission give-up and late protected notifications have lifecycle proofs.

- #222: successful notifications retain the initial Content-Format; format mismatch produces terminal 4.06. Error notifications and deregistration responses omit Observe.

- #223: explicit caller-owned Echo issuer/verifier replaces implicit timestamp policy. Exact policy decision, refusal and protected retry paths are tested; callers own cryptographic issuance, identity binding and reboot policy.

- #224: required injected randomness, bounded Token collision sampling, unbiased RTO jitter and shared local MID allocation/reuse guard. Entropy failures are typed; runtime peers use getrandom. Caller retains endpoint restart/quiet-time responsibility.

- #227: client/server Observe roles and exact App route identities are isolated; protected same-Token bidirectional notifications and cancellation are tested.

- #228: successful DELETE queues terminal 4.04 CON notifications, preserving pacing and failed-send retries; ACK/exhaustion releases delivery state. Protected deletion is tested.

- #229: notification RST removes only the server relation, preserving an opposite-direction protected client binding with the same Token. Both CON and NON and wrong-endpoint refusal are tested.

- #230: failed classic Block1/Block2 and Q-Block2 window continuation sends retire the Call with a typed failure and reclaim client transfer state. Repeated CON/NON errors/short sends, protected classic cleanup and unrelated-call survival are tested. Full Q recovery remains open.

- #233: separate-response rustdoc explicitly describes synchronous handler completion and same-poll ACK/CON sends. Truly deferred work belongs to the advanced Engine lifecycle; no deferred App handle is advertised.

- #235: validated replay checkpoints and monotonic restore reject rollback in a live context; authenticated replay after context recreation is tested. The caller still owns checkpoint authenticity, freshness, durable commit ordering, sender reservation and restart identity. App has no pre-handler durable checkpoint barrier.

- #236: unknown definite-CBOR extension scanning uses constant auxiliary memory; deep nesting, impossible lengths, UTF-8 and malformed simple-value refusals are tested. CI now exercises core, alloc, OSCORE, alloc+OSCORE and std separately.

- #237: extension-only problem-details maps, full-width integer/URI keys and lossless unknown-field forwarding/edit retention are covered by literal and seeded proofs.

- #238: RFC 9290 tag-38 title/detail, explicit direction versus inherited context, instance/base URI/language/direction access and malformed-value refusals are covered. Definite CBOR only; URI semantics, registry language validation and arbitrary extension schemas are not claimed.

- #239: single Q-Block2 selections honor NUM/M; non-aligned M=1 selects only the current set tail; cached selection preserves window state and temporary snapshots are reclaimed. The whole-body client sets M=1. Full recovery is not claimed.

- #240: ordinary protected Q-Block2 response batches have fresh response Partial IVs, binding retention through assembly and bounded replay checks. Both delivery orders, corrupt/replayed packets, one no-PIV response compatibility, capacity reuse and sequence exhaustion are tested. Timed protected recovery and Q Observe remain open.

- #241: repeated Q-Block2 selections send an ordered union once, retain window state and validate every option/range before output. Plaintext and protected selection tests are covered; full recovery remains open.

- #242: missing Q-Block1 Request-Tag or Size1 produces 4.00 before handler/body admission, including protected requests. Empty Request-Tag and Size1 zero are valid when present.

- #243: incomplete Q-Block1 CON payloads receive empty ACKs; NON Continue is emitted for complete payload sets with the acknowledged NUM. Duplicate payloads preserve assembly; protected retransmissions and ACK-send failure recovery are tested, as are exact body bytes and one final handler effect.

- #244: recovery opportunities are invalidated when same-poll ingress completes or changes a Q body. Exact-deadline upload/download completion and partial-hole deadline reset are tested.

- #245: pending Observe signals are claimed after ingress. Full-table same/different-resource registration replacement cannot inherit the prior row's notification, and unrelated response-send failure preserves the signal and sequence.

- #246: Q recovery and expiry now run after ingress. Final-deadline completion wins over body reclamation; exhausted client downloads complete as TimedOut and clear partial inbox/exchange/body/binding state. Other-call and protected late-response isolation are tested.

- #247: confirmable Q-Block1 uploads remain all-CON and advance one payload per matching ACK, including crossing a complete set. Wrong/duplicate ACKs, lost protected ACKs, repeated error/short-send continuations and unrelated-call survival are tested. This is a per-upload policy, not endpoint-wide NSTART qualification.

- #248: successful Q-Block2 replies use an empty ACK for a CON request followed by all-NON body payloads. Ordinary/separate handlers, duplicate request ACK replay and protected ACK-send failures are tested.

- #249: NON Q-Block1 missing-block reports reissue only validated, previously issued ranges and retain the live Call. Ordered unique bounded reports, malformed reports, repeated send failures and protected corruption/replay are tested. Older OSCORE request bindings and duplicate-report scheduling remain unqualified.

- #250: timed live-client GET Q-Block2 recovery preserves path/query/Accept/Echo, selects only holes, omits Observe and uses fresh OSCORE protection. Reordered completion, exhaustion, deadline arrival and repeated send-failure cleanup are tested. Latest request binding only.

- #251: FETCH retains the original selection body/format/conditions through classic and Q download follow-ups within the existing 512-byte encoded identity bound. Larger selections are refused before I/O and require advanced Engine use; protected timed completion, timeout and failure paths are covered.

- #252: download follow-ups retain If-Match, If-None-Match and Content-Format; classic Block2 also retains request ETag while Q-Block2 omits cache-validation ETag. GET/FETCH/POST across all three continuation modes, protected conditions and oversized-tag pre-send refusal are tested. Four-call metadata adds 96 host bytes, covered by explicit footprint accounting.

- #253: FETCH requires exactly one valid Content-Format. Missing format receives 4.00; malformed/repeated format receives 4.02 before body admission or handler execution, including protected requests. Local requests without format are refused before I/O/protection; empty selections with explicit format remain valid.

- #255: protected Outer response routing matches endpoint and piggybacked ACK MID before request/notification state is consumed. Established notifications require CON/NON; ordinary and Observe mismatch-then-valid delivery, including plaintext ACK-shaped notification refusal, are covered.

- #256: ordinary protected response bindings survive rejection and ACK-send failure, then retire on collection/cancellation. Sixteen rounds of four concurrent Calls prove fifth-call refusal before protection, reverse-order exact reply collection and full capacity reuse.

- #257: protected Observe/Q response freshness is checked before response admission, with replay state committed only after critical-option validation and successful CON ACK. Eight PIV/no-PIV rejection/failure cases preserve retryability. This establishes in-memory ordering, not durable checkpoint storage.

- #258: accepted CON responses retain bounded empty-ACK replay before/after reply collection. Protected ordinary/Observe/Q duplicate handling, wrong-peer isolation, failed replay sends, expiry and default-table eviction are tested. Eight rows are not arbitrary-pressure retention.

- #260: larger custom Engine profiles cannot return a silently truncated assembled App response; completed bodies above the App hold return ResponseBodyBounds. Classic/Q 4,095/4,096/4,097-byte boundaries, exact bytes, repeated refusal/reuse, unrelated-call preservation and protected cleanup are tested. Protected inline 127/128/129-byte snapshots retain explicit truncation metadata.

- #261: retained Q-Block2 block-zero and repeated aligned Continue requests reselect the requested set without acknowledging/advancing it again. Plaintext CON/NON and protected cases preserve state on reselection/refusal, reject future-window jumps without output and complete/reclaim normally. Representation changes and final-set retention remain open.

- #262: timed protected server Q-Block1 missing-range reports retain the newest authenticated request reference and emit fresh response Partial IVs. Same/different Tokens, reordered arrivals, corrupted input, retry-send failure, sequence exhaustion, completion and expiry are tested. Manually seeded advanced bodies without an authenticated reference still refuse protected recovery. Hosted Linux: 51/51 process cases; source 4d6d5a07ab0af37167e56865db39e9075c4072bd, clean.

- #263: allocated storage now enforces the same stable Q-Block length as fixed storage before writing continuations. Both backends exercise upload/download, same/changed Token, invalid hints, refusal preservation and corrected completion; classic changing size estimates remain supported. All local and hosted checks passed. This is size parity, not complete differential backend qualification.

- #264: incoming fixed/allocated body lookup and outgoing client upload continuation/cleanup now distinguish request/response transfer roles sharing the same peer, Token and tag. Both arrival orders, classic/Q combinations, malformed refusal without mutation, independent release and client completion/cancel/send failure are covered. Hosted Linux process cases passed 51/51, source f1b9fcb7c8c74e19aa7a65b39ba8ea2c0a0bdbff; all checks green before merge.

- #265: server re-registration advances the retained 24-bit sequence for the same peer/Token/route, including wraparound, while replacing scheduling/protection state. Duplicate requests do not advance twice. Protected failed-send and corrupted-request paths are covered.

- #266: explicit client reregister_call reuses the exact live request identity and Call, permits changed ETags, preserves ordering/deadlines and reports terminal refresh send failure. GET/FETCH mismatch refusal, stale ACK versus CON/NON handling and protected binding replacement/reuse are covered. Refresh scheduling remains caller-owned.

- #267: fresh Observe format changes/malformed/repeated options are typed terminal failures, before replay/body admission; CON sends RST and cannot acquire an ACK replay entry. Plaintext format/2.03 cases and protected inline/classic/Q refusal, failed RST, unrelated-call preservation and cleanup are covered.

- #268: body follow-ups omit Observe and retain the original OSCORE registration independently from the latest download request. Notification freshness survives retrieval; bounded two-candidate authentication, corrupt/superseded references, classic/Q binding updates, capacity and exact classic assembly followed by notification are tested. SecurityContext is 360 host bytes; older concurrent body request references remain unretained.

- #269: protected oversized server notifications now start classic Block2 with fresh response Partial IVs. CON/NON, 2,000/4,096/4,097-byte bounds, first-send failures, exact assembly, retry cleanup and sequence exhaustion are covered. Snapshot consistency still requires a stable handler representation; cached snapshot metadata/final-block recovery remains open.

- #270: duplicate same-peer Observe targets share the existing Call before Token allocation, sending or deadline mutation. GET/FETCH, cache-key differences, FETCH selection, capacity, cancellation/reuse, protected binding/sequence preservation and unsupported-method refusal are tested. Notification fanout and refresh scheduling remain caller-owned.

- #274: retained classic Block2 compares exact handler payload and ETag before body output or advancement, using the existing identity storage. Changed bytes/length/tag/removed-tag refusals preserve the transfer; a corrected response completes and releases it. The protected large-notification fixture now serves the exact notified length on follow-up. All 17 local and hosted checks passed; full cached metadata/final-block recovery remains open.

- #276: fixed/allocated body parity now has a pinned 6,000-operation campaign comparing typed results, every retained byte/sidecar and periodic reclamation, with exact outgoing-byte/range checks. All local/hosted validation passed. This covers direct body APIs and finite schedules; shared state logic means it is not independent RFC proof or full network/Observe/restart soak.

Remaining work:

- Finish independent Observe re-registration evidence, query-specific representation selection, sequence continuity across removed/restarted relations and large-notification lifecycle. Role/resource isolation and deletion delivery are covered above; independent peer evidence remains #200.

- Protected recovery for manually seeded advanced receive bodies without authenticated request references remains unsupported. Live-client GET download recovery and server Q-Block1 recovery are covered above. Full App Q recovery/retained-body/continuation behavior remains unqualified.

- Extend lifecycle qualification to compound concurrency/cancellation/restart soak and caller-owned persistent sequence/replay recovery. Four-Call capacity and inline/assembled boundaries are covered above; large Observe remains separate work.

- Complete RFC 9290 problem-details compatibility: extension-only maps, full-width integer/URI keys, unknown-field retention, language-tagged text and precise CBOR/schema boundaries. Extension retention and language-tagged text are covered above; indefinite CBOR and full schema/independent-peer qualification remain open.

- Q-Block transport conformance still requires endpoint-wide congestion/NSTART qualification, duplicate-report scheduling and complete-body duplicate/retention lifecycle. Per-upload CON progression, all-NON response bodies and bounded missing-range upload reissue are covered above. Older concurrent OSCORE request bindings remain unqualified.

Related: #199 literal TD qualification, #200 independent feature matrix, #202 systematic fault/platform/coverage evidence. Their remaining work is not closed by App unit-test counts. Publishing remains parked in #132; unrelated future protocols remain #46.



#280 (main ce83ec4): retained large-notification snapshots now survive every incomplete same-Token follow-up and send failure. Completion and server observer lifecycle exits reclaim the body while preserving opposite-role client uploads/subscriptions. New exact 4096-byte block proof plus five lifecycle cases; 645 unit tests and all 17 local checks passed. Hosted CI and CodeQL passed, including 75/75 independent Linux cases on clean 28d2418de16a51e01d2678a6e0f27abd75b6fa8d. Full cached metadata/request-key binding and final-block recovery remain open.


#281 (main 3818833): classic Block2 ACKs now retain exact wire replies in the bounded dedup cache, fixing protected first-reply loss without accepting replayed requests again. Twelve GET/POST fragment cases prove one handler effect, identical duplicate bytes, initial-send failure recovery and cache expiry; notification final-send failure also reclaims completed body state. Independent OSCORE Block2 normal/lost-first-reply/duplicate-request schedules and wrong-key recovery pass in all three pairings. Linux 78/78 on clean 9b223c667247c0dee0dac60061baf8775b33aa13; Windows 61/61 enabled, 17 native-crypto exclusions. All 17 local and every hosted check passed, with 646 all-feature unit tests. Cache pressure can evict replies; full history, Block1/Observe/Q independent coverage and durable contexts remain unqualified.


#282 (main d558db2): RFC 9290 key -8 now has allocation-free typed scalar/list access and bounded builders, full u64 values, duplicate/shape refusal and lossless unrelated-entry editing. Generated unknown-critical-option 4.02 names the actual option number. All 17 local checks passed with 650 unit tests; every hosted check and 78/78 Linux process cases passed. Indefinite CBOR, URI/schema/full-map validity boundaries remain explicit; this does not claim complete CBOR validation.
