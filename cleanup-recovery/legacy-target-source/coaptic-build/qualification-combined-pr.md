The process benchmark exposed stale DTLS sessions on reused UDP endpoints and a client exit race that skipped shutdown. Both Rust fixture listeners now use bounded, generation-aware routing and preserve an authenticated association until replacement authentication succeeds (RFC 6347 section 4.2.8). Explicit shutdown stops backend reader tasks, survives delayed peer ICMP errors, and completes before the Coaptic client exits. The executables retain independent dependency graphs; shared routing is fixture code, not a library transport dependency.

Timing uses monotonic nanoseconds, raw samples, clock metadata and failure retention. Response time ends at assembly; host time includes process startup and orderly shutdown. No retries or replacement samples hide failures. Nanosecond precision is not an accuracy or engine-only performance claim.

Qualification and library changes:
- Incomplete App TDs are explicit skips. The grader refuses missing/contradictory DTLS and payload evidence. PCAP framing is corrected and unsupported captures are refused.
- Block2 retains bounded query/Accept metadata; discovery checks exact assembled results. Incomplete datagram sends are errors with the packet retained for retry.
- IPv6 identity retains scope. OSCORE context cloning and sender-sequence rollback are refused, Debug output is redacted, and future Echo timestamps are rejected.

Validation at head 23072b0:
- Required local matrix passes: feature configurations, Clippy, harness DTLS/OSCORE tests, rustdoc, package, Rust 1.85 checks and both dogfood baselines. All-feature library unit count: 471; harness: 33 unit tests and 12 integration entry points with explicit TD skips.
- Thirteen Rust peer tests cover malformed hello routing, unverified replacement, bounded handshakes and timeout reclamation, generation-safe cleanup, shutdown, departed-peer ICMP, and shutdown completion/error propagation. Removing the ICMP repair makes its Windows regression fail with error 10054. Eight Python supervisor/timing tests pass.
- Windows Release: 26/26 available scenarios, N=100 per timed pairing; C peer is UDP-only. Report: D:/coaptic-build/dtls-close-windows.json.
- Linux CI and CodeQL pass: https://github.com/jeffglousher/coaptic/actions/runs/35472156787 and https://github.com/jeffglousher/coaptic/actions/runs/35472155411 . All 31 process cases pass; ten pairings retain 100 successful samples each. Artifact source is clean merge commit 5e894a3b42286e27bc3b88f6cb4dea0e4dd45732. Report retained at D:/coaptic-build/combined-linux-23072b0/process-interop.json.
- Deterministic reconnect cases retain one server-visible endpoint, including wrong-key recovery and abrupt legacy-client exit against both Rust servers. Churn proves 140 distinct POST effects. The libcoap orderly-close case completes 141 sessions and records 141 client alert records; it does not qualify abrupt replacement at the C server.

Limits: App inventory is 27 runnable TDs and 61 skips, including 29 future 6LoWPAN cases. The PSK listener bounds 128 endpoints, 16 pending handshakes, 32 packets per route and 4096-byte datagrams, with 2s handshake and 30s idle deadlines; fragmented initial ClientHello is unsupported. This is not complete RFC/ETSI qualification, IPv6 network qualification, authenticated Echo, crash-safe OSCORE persistence, or a performance SLA. Wider coverage remains #199/#200/#201/#202 and legacy crypto debt #193. No release tags or publication.

Includes the timing implementation from superseded #198.

Closes: #197
Closes: #203
