Audit source: main 72c0083. Review concrete App limitations before declaring library completion; some may be intentional bounded contracts rather than bugs.

Confirmed work to qualify/resolve:
- Resolved identity portion in #204: Endpoint::V6 retains scope_id; conversion/identity proof passes. Scoped/link-local IPv6 network qualification remains #200/#202.
- Client ReplyMeta retains code/type/token/MID/peer/payload/content-format/Observe/ETag, but not Location-Path/Query, Max-Age, Echo or generic response options. Decide and test a bounded representation so callers can use server metadata; server-side Response setters already exist.
- Outgoing still needs Echo retry/explicit Echo and No-Response flows or precise advanced-API boundaries. Request-Tag is implemented and qualified in #206 (including presence, active same-peer reuse refusal and fragment retention); callers own cross-operation/restart uniqueness.
- App send uses zero retransmission jitter and deterministic counters; introduce caller-injected randomness/ID policy with deterministic tests and RFC-bound timing evidence.
- Timed Q-Block gap recovery with an attached OSCORE context explicitly returns Unsupported; complete the protected recovery path or explicitly exclude this combination with refusal proof (src/app/mod.rs send_q_recover).
- Resolved in #211: explicit cancellation/deadlines and typed local outcomes distinguish retry exhaustion, reset and assembly failures from received remote responses. Positive/refusal/cleanup tests include Observe and OSCORE bindings; completed outcomes remain bounded until taken.
- Bounds: four live Calls/context bindings, 128-byte non-block reply copy, 4 KiB assembled bodies. #204 refuses query overflow (eight values, each <=255 bytes, <=256 total); empty query values retained with count/byte bounds in #207. Location overflow and remaining truncation/boundary contracts still need proof.
- Transport qualification: #204 now refuses short/oversized successful send counts and retains the packet for retry. Resolved receive portion in #207: oversized datagrams are refused before exposing a prefix. IPv4/IPv6 loopback proves exact-fit, oversize, recovery and bounded scratch behavior.
- Handler functions return immediate response intent; Response::separate exists, but qualify a truly deferred application completion workflow before advertising asynchronous separate work.

Acceptance: each item is resolved with App-level positive/refusal proofs or has a precise documented supported boundary/advanced API route. Preserve no_std and bounded resources; this is protocol/contract work, not naming/style churn.

Sources: https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/src/storage/endpoint.rs ; https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/src/app/client.rs ; https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/src/app/response.rs ; https://github.com/jeffglousher/coaptic/blob/72c0083e8dd9cb2332e6cb91d1d4bfecffe2aa49/src/app/routing.rs.


Further source-confirmed upload gaps (2026-09-19):
- Block1/Q-Block1 lose Uri-Query and Accept, including the first fragment. Merged #205 retains these on every fragment, with exact-body/wire proof (main 72639f8).
- Conditional upload options (If-Match, If-None-Match, ETag) were lost during fragmentation. Merged #205 explicitly refuses the unsupported operation before any I/O, with a typed error and positive/refusal/recovery tests. Implementing fragmented conditional writes remains advanced Engine work; RFC 7959 section 2.10 forbids If-None-Match on NUM != 0.
- RFC 9177 section 4.3 requires Request-Tag on every Q-Block1 request, stable for the body and unique across distinct bodies. Sender tag contract and exact receive operation binding resolved in #206. Recovery qualification remains open. Current Q-Block tests do not establish RFC 9177 conformance.

Further RFC 9177 gaps confirmed during size-contract review: wire receive must require stable Size1/Size2 on every payload (fix in progress), Q-Block2 must retain a stable nonempty ETag for the body, and low-level wire Q-Block1 must require Request-Tag. Full App recovery/continuation semantics still need separate qualification; current Q-Block unit coverage is not a conformance claim.
