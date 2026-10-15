FETCH download continuation previously lost the original selection payload, Content-Format and conditional options. Retain the encoded selection in the existing per-call 512-byte identity buffer and reconstruct classic Block2, Q-Block2 window and timed missing-range requests from it. Oversized FETCH selections return FetchRequestTooLarge before I/O; advanced Engine users own larger selection transfers.

Tests cover all three continuation paths with If-Match and If-None-Match, exact payload/format/path/query/Accept retention, repeated pre-send bounds refusal with later successful admission, and protected GET/FETCH timed retries through completion, timeout and send failure. Observe cancellation identity tests continue to pass. Protocol sources: RFC 8132 sections 2 and 2.5; RFC 7959 section 2.4; RFC 9177 section 4.4.

Validation at b7f9e10: all 15 CONTRIBUTING checks and both two-iteration dogfood baselines passed on Windows MSVC; 610 all-feature library tests. Logs: D:\coaptic-build\fetch-retention-validation-*.log. Hosted qualification checked before merge. Hardware runtime and independent FETCH peer coverage are not established by these local tests.

Limits: 512 encoded bytes excludes Token, Observe and ETag; no new buffer/allocation. Larger FETCH selections require advanced Engine use. This does not qualify all conditional GET/POST follow-ups, Q Observe, earlier concurrent OSCORE request references or full RFC conformance.

Refs #201. Depends on #250.
