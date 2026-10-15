Audit source: main 72c0083. Owner prioritizes completeness/coverage before performance tuning. Related #197; legacy advisory retirement #193.







#226 adds the checked-in capability manifest and source-bound coverage accounting. After #259 the suite has 51 full-build cases (44 enabled plus seven explicit C-DTLS exclusions in the local Windows build). Every enabled case must execute exactly once with passing evidence. This is not whole-library qualification.







The inventory/accounting part of acceptance is implemented. Extend independent libcoap coverage with positive and negative evidence:



- Extend the bounded seven-method UDP/DTLS/IPv6 workflows from #254/#259 to conditional transitions, standardized patch formats, IPv6 DTLS and full option negotiation. Add exact upload/download bodies, Block1/Block2 negotiation and changed tokens, malformed/missing/duplicate blocks, body limits and rejection cleanup.



- Observe actual notification collection, ordering/stale suppression, CON/NON, cancel/RST, Max-Age/re-registration and block-wise notifications.



- Pairwise OSCORE independent interop (including wrong key, replay, corrupted ciphertext, protected Observe and inner blocks). Current vectors/self-pairs remain valuable but cannot establish independent compatibility.



- Q-Block, Echo, Request-Tag, No-Response, problem details and complete option/critical-option policy. The process peers now expose all seven methods for a bounded fixture; the separate ETSI wrapper and advanced feature support remain distinct evidence. Choose capable peers per feature.



- Real separate responses; exact discovery filtering and conditional request transitions.



- PSK and certificate auth across independent DTLS implementations; actual RPK only with a supporting backend. Add DTLS loss/duplication/timeout/reconnect and retained evidence of auth refusal.



- Scoped IPv6 and IPv6 DTLS, alternate server fault directions, mixed concurrent exchanges, saturation/recovery, long-lived Observe/session churn, reordering/delay/MTU boundaries and seeded combined faults.







Acceptance: checked-in capability manifest maps feature, role, transport/security, peer, failure proof and platform to executable case; unsupported combinations explicitly recorded. Do not treat libcoap build features as tested features. Full-library qualification does not require implementing unrelated future protocols from #46.







Sources: https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/tools/interop/run.py ; https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/crates/coaptic-plugtest/src/dogfood.rs ; https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/crates/coaptic-plugtest/src/coap_rs.rs.







Implemented in #234 (main 250a9c8): five IPv6 UDP loopback pairings verify GET, 4.04, exact 2000-byte Block2 and subsequent service, with an independent AF_INET6 socket probe and actual ::1 bytes. All 36 full Linux cases and all 31 enabled Windows cases passed; Windows still explicitly excludes five C-peer DTLS cases. Scoped/link-local IPv6, IPv6 DTLS and compound fault schedules remain unqualified.











Implemented in #254 (main 1a5d1da): five independent IPv4 UDP method workflows, 29 exact status/body/state steps per pairing, including repeated iPATCH, malformed selection/patch and overflow refusal without state changes. All 41 Linux cases and 36 enabled Windows cases passed; source-bound reports retained. PATCH uses a documented private octet-stream fixture contract, not JSON Patch. No full RFC or option-negotiation claim.















#259 extends the method workflows to IPv4 PSK DTLS and IPv6 UDP in all five pairings: 15 workflows total, 29 ordered method/state checks each. DTLS additionally refuses a wrong-key replacement PUT and preserves prior state; IPv6 requires an independent AF_INET6 socket probe. The full Linux/OpenSSL inventory is now 51 passing cases; Windows passes 44 with seven explicit native C-DTLS exclusions. Literal bounded octet-stream fixture behavior is qualified, not standardized patch formats, conditional options or IPv6 DTLS. Source-bound evidence retained in CI run 35499443076 and local method-transports-process.json.









#272 (main ce50934): IPv6 PSK DTLS GET/4.04/exact 2,000-byte Block2/wrong-key refusal/service-after-refusal in five pairings. AF_INET6/IPV6_V6ONLY relays retain datagrams; corrected the Coaptic test peer client binding that previously forced IPv4. Linux source ae5e4946f57f233a457ac7f020462520a88bfd6f clean: 56/56; Windows 47 enabled cases passed with nine explicit native C-DTLS exclusions. All 17 local and hosted checks green before merge. IPv6 method workflows, scoped addresses, loss/reorder/MTU and literal DTLS handshake evidence remain unqualified.






#273 (main 36d5860): eight IPv4 UDP client fault/restart scenarios against independent Rust/C servers. Lost replies require byte-identical retransmission; idempotent PUT/readback establishes exact final state, blackholes require protocol refusal, and restart expects a fresh in-memory fixture. Linux source f0bdbcff5688f641ad5e3af77d56dbcba89a342b clean: 64/64; Windows 55 enabled cases passed with nine native C-DTLS exclusions. All local and hosted checks passed before merge. Exploratory counter POST loss/duplication produced two handler effects in both alternative fixtures; this remains an explicit capability gap. Passing PUT evidence does not qualify their non-idempotent duplicate suppression, and no fixture cache was added to conceal that behavior.



#277 (main 2af8bc3): five 29-step method workflows now run over IPv6 PSK DTLS, through IPv6-only relays with retained datagrams, wrong-key PUT refusal and exact state readback. Full process inventory: 69/69 Linux cases on clean source e4e4982c53f5fc86f27044e0f82e8e2373ae29b2; Windows 58/58 enabled, 11 native C-DTLS exclusions. All checks passed before merge. Twenty method workflows now cover IPv4/IPv6 UDP and PSK DTLS; standardized patch formats, complete options/conditions, scoped addresses and DTLS loss remain unqualified.

#278 (main 1267650): three OSCORE state workflows now cover Coaptic and both libcoap directions using public C.1 vectors, authenticated Echo retry, exact GET/PUT state, wrong-key and plaintext refusal. Linux passed 72/72 cases on clean source ecc7bacfec7855eff9d2dd51fd2bb19d6cc33a3e; all local and hosted checks passed. Replay/corruption is under review in #279; protected Observe/block/Q, concurrent contexts and persistent security state remain unqualified.

#279 (main 079c5d9): three sequential OSCORE replay/corruption workflows pass for Coaptic self-test and both libcoap directions. Upgraded the independent peer to tagged v4.3.5b, exact clean source 851533c3cf63d16984d370ce39d586ecb3694971, retaining the original failed qualification and unchanged oracles. Linux 75/75 at clean b262d7efd1fc995c519efe3765beb705a3ecb336; Windows 60/60 enabled with 15 native-crypto exclusions. All required checks passed. Protected Observe/block/Q, concurrent contexts and durable security state remain outside this proof.


#281 (main 3818833): classic Block2 ACKs now retain exact wire replies in the bounded dedup cache, fixing protected first-reply loss without accepting replayed requests again. Twelve GET/POST fragment cases prove one handler effect, identical duplicate bytes, initial-send failure recovery and cache expiry; notification final-send failure also reclaims completed body state. Independent OSCORE Block2 normal/lost-first-reply/duplicate-request schedules and wrong-key recovery pass in all three pairings. Linux 78/78 on clean 9b223c667247c0dee0dac60061baf8775b33aa13; Windows 61/61 enabled, 17 native-crypto exclusions. All 17 local and every hosted check passed, with 646 all-feature unit tests. Cache pressure can evict replies; full history, Block1/Observe/Q independent coverage and durable contexts remain unqualified.
