Parent: #199; related #202. Prerequisite: #416 / companion PR24.

Qualify literal TD_COAP_OBS_10 and TD_COAP_OBS_12 over captured loopback UDP using a Coaptic client and server, sharing one bounded same-owner request hook. Reuse the existing App, socket and monotonic origin; do not silently destroy/recreate the observation to issue another request.

Acceptance:
- OBS_10: registration and acknowledged CON delivery; unrelated CON GET /obs without Observe using a different token, full matching ACK without Observe; later increasing CON notifications still use the original registration token and reach the client with matching ACKs.
- OBS_12: registration and acknowledged CON delivery; explicit CON GET /obs Observe=1 using the original token; full matching ACK without Observe; three attempted updates over three one-second quiet intervals yield neither traffic nor delivered notifications; fresh same-endpoint registration recovers.
- Strict endpoint, resource, token, MID, Observe, content-format and complete-body wire oracles. Trace mutations must refuse incomplete or altered cases.
- Live wrong-path and wrong-endpoint deregister_call attempts refuse before network I/O and preserve the original observation, followed by valid cancellation and recovery.
- Unsupported peer hooks refuse by default; both coap-rs directions remain SKIP until complete supported behavior is captured.

No core API changes. Plaintext loopback qualification does not prove authenticated peer ownership, hardware, sustained availability or the full mixed-peer matrix. Focused local checks only. Close after companion and required final core integration pin merge.
