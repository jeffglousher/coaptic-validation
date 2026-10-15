Parent: #199. Related implementation: #202; prerequisite: #410 (literal OBS_01 qualification and explicit CON notifications).

Qualify the complete vendored TD_COAP_OBS_06 against a Coaptic server and Coaptic client over captured loopback UDP. This follows OBS_01; the existing NON reset proof is not a literal OBS_06 PASS.

Acceptance:
- CON GET /obs with Observe=0, matching ACK registration and complete representation.
- At least one complete CON notification is delivered to the client and acknowledged.
- Restart the client protocol state while retaining the same UDP endpoint. Consume the old App with into_io and bind a fresh App around that transport; retain no observation registration.
- The server sends a subsequent CON notification for the old registration. The restarted client discards it, delivers no representation, and emits an empty RST matching its MID and endpoint.
- After the RST, attempt further valid updates and observe a bounded quiet interval with no further notification or delivered update. Record the exact interval and limits.
- Demonstrate wrong MID/endpoint controls cannot cancel the owner, and fresh registration succeeds afterward. Keep adversarial/recovery evidence separate from the literal trace where appropriate.
- Strict grading binds registration, resource, endpoints, token, bodies, sequence progression, ACK and RST; mutation tests refuse incomplete or altered traces. Retain a real capture with source identities.

Supported direction for this increment: Coaptic client -> Coaptic server. The coap-rs client restart direction and coap-rs server direction remain SKIP until their complete prerequisite behavior is implemented and captured. This proves bounded loopback behavior, not physical device reboot or sustained availability.

No core API change is presently required: App::into_io preserves caller transport ownership and unmatched CON responses already receive RST. Focused tests only; keep version 0.0.10. Close only after the companion PR and required integration pin are merged with passing applicable checks.
