Extend the literal seven-method resource workflow to PSK DTLS and IPv6 UDP in both directions with coap-rs/libcoap and the Coaptic self-pair. Each pairing checks 29 ordered status/body/state outcomes. DTLS additionally rejects a wrong-key replacement PUT and confirms the original state survives; IPv6 requires an independent AF_INET6 socket probe before mutations.

The declared suite has 51 cases; the local Windows build runs 44 with seven explicit libcoap-DTLS exclusions. Manifest accounting rejects missing cases. Two adversarial harness tests reject missing IPv6 service and a successful wrong-key write. These remain bounded octet-stream fixture workflows, not standardized patch formats, conditional-option coverage or IPv6 DTLS qualification.

Validation at c58ee15: all 15 CONTRIBUTING checks and both dogfood baselines pass; peer clippy, tests and Release build pass; 18 Python tests pass. Windows process run passes all 44 enabled cases with 100 fresh GET samples in each of eight enabled benchmark pairings. Clean-source evidence: D:\coaptic-build\method-transports-process.json; validation logs method-transports-validation-*.log. Hosted Linux/OpenSSL run must qualify the other seven cases before merge. Timings are shared-host smoke samples, not controlled performance rankings.

Refs #200. Depends on #258.
