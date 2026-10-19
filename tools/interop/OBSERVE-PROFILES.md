# Independent selected Observe and token profiles

This finite addition to `profiles.py` owns seven selected directions in core
issue200. The manual `observe-profiles.yml` workflow runs these identifiers only:

- `observe-selected-query:coaptic->libcoap` and the reverse direction.
- `observe-selected-fetch:coaptic->libcoap` and the reverse direction.
- `observe-con-q:coaptic->libcoap` and the reverse direction.
- `protected-token-boundary:libcoap->coaptic`.

These are original fixtures, not literal TD identifiers. Both peers must emit
actual Observe registration and notifications; an ordinary response is never a
successful fallback. A failed row retains raw traces and process output. A real
backend capability refusal requires an explicit reviewed disposition and fresh
control; it is not relabeled as passing Observe support.

## Selected representations

The GET selector is exactly one `pick=left` or `pick=right` Uri-Query. FETCH
uses Content-Format42 and the complete selection body `left` or `right`, without
Uri-Query. Each observed representation has96 bytes, a selection-specific ETag,
and three distinguishable epochs. Native clients exchange complete bodies
through both servers. Additional independent Python wire controls retain one
endpoint with two distinct observer tokens, exercise invalid-selector refusal,
re-register, verify both selected notifications, cancel one selection, verify
the surviving relation, and register fresh. Those controls are identified as
Python clients, not native CLI cancellation support.

RFC7641 sections3–4 and RFC8132 sections2.3–2.5 govern the selection/lifecycle
boundary. Classic Block2 identity follows RFC7959 section2.6. Every fragment,
full token, request/ACK MID, ETag, Observe serial and complete body is checked.

## Confirmable Q notifications

The host-only `obs-q` representation has704 bytes:22 blocks at SZX1 (32 bytes).
Coaptic's current `BlockTransfer::MAX_PAYLOADS` is10. The native server records
its actual `coap_session_get_max_payloads()` value. This profile requires10,
crosses two set boundaries, and preserves CON type, exact ACK progression,
ETag, Size2 and Observe epoch across each full notification. A separate same-
endpoint Python control requests the retained final set's blocks20 and21 with
no Observe, checks exact recovery bytes without unintended continuation, then
checks a new epoch, cancellation and fresh ordinary work. This is explicit
missing-block selection, not an adaptive packet-loss timer claim.

The contracts are RFC9177 sections4.4–4.6 and7. No Core or device capacity grows.
The existing desktop fixture still uses4096-byte receive/transmit body pools,
four client Calls, zero deferred replies, a4096-byte response copy and an8MiB
worker stack. Its route count becomes14. Added static representations and native
output space are host fixture costs, not embedded App RAM measurements.

## Protected extended tokens

The selected native libcoap backend must actually send32/64-byte tokens under
OSCORE. A32-byte authenticated POST succeeds. The64-byte capability probe must
receive authenticated4.00 echoing the complete token and prevent application
POST. A32-byte POST with only its authentication tag altered must fail without
an effect; a fresh protected POST succeeds. Protected counter readbacks after
every stage distinguish refusal from hidden application dispatch.

The offline oracle uses aiocoap's independent OSCORE implementation with public
RFC8613 fixture keys. Its compact-only UDP decoder is bypassed by populating a
Message from the existing strict RFC8974 token reader and unchanged options/
ciphertext. The full token is retained; crypto and peer packets are unchanged.
Offline mutation tests reject altered tags, changed final token bytes and wrong
MIDs. This adapter is part of the evidence tooling, not a claim that aiocoap's
UDP client implements RFC8974.

## Execution boundary

The workflow uses loopback only, pinned libcoap851533c3 with its native OpenSSL
OSCORE backend and separately built Rust peers. Both source trees must be clean;
build receipts retain complete hashes/configuration/tool identities, and source
identity is checked again after the selected cases. The native source/build live
in runner temporary storage outside the tracked checkout. This manual advisory
workflow neither changes network configuration nor adds a release gate. No
physical, performance or broader protected-profile claim follows from it.
