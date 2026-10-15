Owner acceptance: each vendored TD step maps to executable assertions and real captures. Unsupported or incomplete scenarios stay SKIP, never literal conformance PASS. Keep genuine Engine/App/process proofs separate. Initial audit: main 72c0083.

Resolved evidence/claim defects on main:
- #204: DTLS grading rejects missing decrypted response/fatal-alert evidence and malformed handshake records. Generic I/O failure is not authenticated alert evidence.
- #210: all nine LINK scenarios now check exact discovery/filter results and follow the discovered hierarchy across three role pairs, with missing/extra/duplicate/truncated-result refusal tests.
- #226: remove certificate-as-RPK dispatch and manufactured DTLS capture packets; retain real PSK and mutual-X.509 qualification tests. DTLS_01 is explicitly unfinished because required cipher/Finished capture is absent. Its golden now requires cipher offer/selection, and decrypted GET alone cannot pass it.

Current App TD inventory: 28 runnable / 60 skipped. Of the skips, 29 are future 6LoWPAN; 31 are unfinished non-6LoWPAN coverage. This is an inventory, not a conformance percentage.

Remaining literal scenarios:
- CORE_09/11/17: full separate-response empty-ACK/response sequence on each peer. CORE_15/16: required actual loss injection and retransmission proof.
- BLOCK: complete trains, exact assembled bodies, negotiations and exactly one application effect. Dogfood/process evidence does not replace literal TD assertions.
- OBS: actual notifications, ordering, CON/NON, cancellation/RST, Max-Age/re-registration, client/server restart, loss and large notifications. The coap-rs wrapper currently does not collect notifications.
- DTLS_01: cipher offer/selection and Finished evidence. DTLS_02: prescribed authenticated failure evidence. DTLS_03/07: complete handshake-loss schedule. DTLS_04..07: actual raw public keys using a supporting backend; X.509 is not a substitute.

Source of scenarios: tests/plugtest/td-coap4/*.yml. Implementations/grade contract: crates/coaptic-plugtest/src/{catalog,runner,grade,dtls}.rs and expectations/catalog.json. Independent capability scope: tools/interop/capabilities.json (#200); systematic qualification: #202. Future protocols remain #46.
