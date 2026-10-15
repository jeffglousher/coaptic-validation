Fresh Observe representations with a changed, malformed or repeated Content-Format now terminate the Call with ObserveFormatMismatch instead of delivering incompatible bytes. CON refusal sends RST; failed RST sends still retire local state. The format check precedes replay commit and body admission, and refused responses cannot acquire an empty-ACK replay entry. Stale notification ordering is preserved; 2.03 validation can omit its format without changing the retained value.

The regression failed before the fix. Plaintext tests cover initial format presence/absence, CON/NON, changed/removed/malformed/repeated options and 2.03 validation. Protected tests cover inline/classic/Q first blocks, successful/failed RST, unchanged replay checkpoint, no body admission, unrelated Call preservation and duplicate refusal. Re-registration retains the format. Retention uses a bounded three-state field (at most four bytes per Call; alignment budget explicit).

Validation at 8e3e2cb: all 15 CONTRIBUTING checks plus both two-iteration dogfood baselines pass on Windows MSVC; 635 all-feature library tests and eight footprint tests. Logs D:\coaptic-build\observe-format-validation-*.log. Hosted checks required before merge. RFC source: RFC 7641 sections 3.2 and 4.2. This does not qualify every representation/cache option or independent Observe peers.

Refs #201. Depends on #266.
