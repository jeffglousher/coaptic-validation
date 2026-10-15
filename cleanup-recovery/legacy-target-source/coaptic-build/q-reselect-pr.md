Retained Q-Block2 bodies now distinguish reselection from a new Continue. NUM=0 requests the body; an aligned NUM at or before the issued window reselects that set without acknowledging/advancing it twice. Future Continues still must follow the issued window.

A regression failed with Block(Gap) before the fix. Plaintext CON/NON and protected CON sequences cover 0, 10, repeated 10, old 0, invalid future 30, then final 20. Tests assert exact NUM/body/Size2/ETag, empty ACK then all-NON payloads, unchanged retained state on reselection/refusal, fresh protected response PIVs, no output for invalid Continue and cleanup after final completion.

Validation at aa47807: all 15 CONTRIBUTING checks and both two-iteration dogfood baselines pass on Windows MSVC; 625 all-feature library tests. Logs D:\coaptic-build\q-reselect-validation-*.log. Hosted checks required before merge. This does not qualify representation changes, final-set retention, independent Q peers or endpoint-wide congestion control.

Refs #201. Depends on #260.
