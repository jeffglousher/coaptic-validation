Server Observe re-registration for the same peer, Token and route now advances the retained 24-bit sequence instead of restarting at zero. The replacement still clears prior scheduling/notification state and adopts the newly authenticated OSCORE request reference.

Regression evidence covers five sequence boundaries including wraparound, same/different resource replacement, full-table slot reuse, duplicate request replay without double advancement, opposite client-role preservation and the next notification. Protected tests exercise three successive registrations, corrupted refresh refusal and a failed registration-response send followed by an authenticated notification using the new binding.

All 15 CONTRIBUTING checks and both two-iteration dogfood baselines pass on Windows MSVC at the recorded branch head; 631 all-feature library tests. Logs D:\coaptic-build\observe-refresh-validation-*.log. Hosted checks required before merge. RFC source: knowledge/rfcs/rfc7641.txt section 4.4. Sequence continuity after removal/restart, client re-registration API and query-specific selection remain open; this is not complete Observe qualification.

Refs #201. Depends on #264.
