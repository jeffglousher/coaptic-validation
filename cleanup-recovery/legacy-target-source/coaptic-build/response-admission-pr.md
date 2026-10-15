Keep ordinary protected request bindings until App collects or retires the Call, instead of retiring them immediately after authentication. Response rejection and failed ACK transmission can leave the Call pending; a subsequent acceptable response or byte-identical CON retry must remain usable. Continuations still replace their request binding, and terminal cleanup releases it.

Tests cover critical-option rejection for CON/NON/ACK followed by an acceptable protected response, failed CON ACK followed by a byte-identical retry, and 16 rounds of four concurrent protected Calls with reverse reply delivery. A fifth Call is refused before sending/protection, including while four replies await collection; all bindings and slots become reusable after collection.

Validation at f83b372: all 15 CONTRIBUTING checks and both two-iteration dogfood baselines passed on Windows MSVC; 618 all-feature library tests. Logs retained at D:\coaptic-build\response-admission-validation-*.log. Hosted checks required before merge. This does not qualify protected Observe/Q replay-state commit ordering after failed ACKs, late terminal CON duplicate acknowledgment, or independent OSCORE interoperability.

Refs #201. Depends on #255.
