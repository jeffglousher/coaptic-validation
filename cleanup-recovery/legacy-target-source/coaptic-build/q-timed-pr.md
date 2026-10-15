Timed Q-Block2 recovery previously constructed a bare GET, losing the live request path and queries. Route live-call recovery through the retained client request, issue only the missing ranges as repeated Q-Block2 options, and protect the new request when OSCORE is attached. Missing-range requests omit Observe (RFC 9177 section 4.5).

Evidence: local RFC 9177 sections 4.4/4.5 and 7.2; the request-identity regression failed before the fix. Tests cover original CON/NON GETs, exact path/query/Accept/Echo retention, two disjoint holes, reordered completion, 12 repeated errors and short sends with unrelated-call survival, protected retries through exhaustion or deadline completion, and protected send-failure binding/body cleanup. Advanced receive bodies without live Calls and server Q-Block1 recovery retain explicit protected Unsupported refusal.

Validation at 64aa1c5: all 15 CONTRIBUTING checks and both two-iteration dogfood baselines passed on Windows MSVC; all-feature library suite has 608 tests. Logs retained at D:\coaptic-build\q-timed-validation-*.log. Hosted source-bound qualification/interop/cross-codegen evidence will be checked before merge. Cross builds do not establish device runtime behavior.

Limits: latest OSCORE request binding only; earlier-request late replies, FETCH payload retention, Q Observe, endpoint-wide congestion and full recovery qualification remain open. No full RFC conformance claim.

Refs #201. This closes the timed live-GET recovery slice, not the umbrella issue.
