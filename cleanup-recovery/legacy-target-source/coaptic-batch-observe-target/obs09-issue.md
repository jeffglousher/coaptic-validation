Parent: #199; related #202. Prerequisite: #419 same-owner client requests.

Qualify literal TD_COAP_OBS_09 with actual bounded in-memory resource updates in the Coaptic server fixture, not notification-only payload substitution. No core API changes.

Acceptance:
- Initial CON registration and delivered/acknowledged CON notifications.
- Two successive local /obs updates retain the original content format and commit one of two fixed representations in fixture state. The subsequent CON notification carries the complete new representation, original token and increasing Observe value; client delivery and ACK are required.
- A same-owner GET after each update confirms the persisted resource representation without replacing the observation or endpoint.
- Strict capture oracle binds resource paths, endpoints, token/MID ownership, format, full notification/read-back payloads and ordering. Altered/incomplete traces refuse.
- Invalid path/payload updates refuse without changing resource state or emitting traffic, followed by valid update/recovery.
- Keep state bounded and reset under the existing serialized harness ownership; no cross-test leakage.
- Initially Coaptic client/server only; unsupported peer directions remain SKIP.

This is volatile fixture state and plaintext loopback qualification, not durable storage, authenticated ownership, hardware or sustained availability. Publish after #419 merges and close only after companion and required final integration pin merge.
