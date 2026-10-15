Large App uploads lost Uri-Query and Accept when converted into Block1/Q-Block1, including the first fragment. Every upload packet now retains those options in order using the existing bounded live-call storage. Wire tests check every fragment and the exact 2,000-byte reconstructed body for both paths.

ETag/If-Match/If-None-Match were also silently dropped. The App now returns the typed ConditionalUploadUnsupported error before any send when such a request requires fragmentation. Ordinary single-datagram conditional uploads retain their options. Rustdoc describes the boundary and the Engine route for callers managing conditional transfers. This deliberately does not claim implementation of fragmented conditional writes; RFC 7959 section 2.10 requires special If-None-Match handling after NUM 0.

Positive/refusal proof: query order, Accept/Content-Format on every packet, exact body, complete response and released slots; excessive query count/bytes rejected before I/O with subsequent transfer recovery; all three conditional options rejected on fragmented classic/Q uploads without I/O; all three preserved for single-datagram uploads. The original wire regression failed because the first query was absent.

Sources: RFC 7252 sections 5.10.1/5.10.4, RFC 7959 sections 2.5/2.10, RFC 9177 section 4.3 (local knowledge/rfcs copies). Q-Block1 still lacks the mandatory Request-Tag contract; this remains explicitly tracked in #201 and these tests are not RFC 9177 conformance proof. No new persistent allocation or larger transfer buffers.

Partial resolution of #201; broader audit remains open. 

Local validation passes: fmt; all-feature/no-default Clippy; harness DTLS/OSCORE Clippy and tests; both library test configurations (475 all-feature unit tests plus integration/doctests); rustdoc; package; both Rust 1.85 checks. Logs retained as D:/coaptic-build/upload-guard-final-*.log.

Linux CI 35472412229 passes all jobs, both dogfood baselines and all 31 process cases, with 100 successful samples in each of ten timed pairings. Clean artifact source: 7f7afb209d21a618d95a69248fe691a5bcf214b8. Report retained at D:/coaptic-build/upload-linux-14a9d93/process-interop.json. Run: https://github.com/jeffglousher/coaptic/actions/runs/35472412229 .

CodeQL passed for Rust, C/C++, Python and Actions: https://github.com/jeffglousher/coaptic/actions/runs/35472411161 . Squash merge 72639f8 has an identical tree to tested head 14a9d93; local main and origin/main are synchronized and clean.
