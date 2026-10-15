# Security Policy

Report vulnerabilities through GitHub private security advisories:

https://github.com/jeffglousher/coaptic/security/advisories/new

Do not open a public issue for a security report.

## Supported security boundary

Optional pairwise OSCORE uses caller-owned `oscore::SecurityContext` and
AES-CCM-16-64-128. See rustdoc for context lifetime and protocol behavior.
Group OSCORE, other ciphers and library-owned DTLS are not supported. DTLS in
the [test peers](tools/interop/README.md) does not add a library DTLS API.

When a context is attached, App is fail-closed: a non-empty message without an OSCORE option is rejected (unprotected 4.01 on a request; a token-matching plain 2.xx, plaintext Observe notification, or unprotected Block1/Block2 completion does not complete a Call). Empty ACK/RST (RFC 7252 reliability) stay unprotected. AEAD / replay / OSCORE-option processing failures are a silent drop — no unprotected 4.00 that would distinguish decrypt.

## Security validation

The [App harness](crates/coaptic-plugtest/README.md) exercises protected requests,
Observe notifications and Inner Block1/Block2, and rejects plaintext completion.
OSCORE dogfood is Coaptic-to-Coaptic; it does not establish interoperability with
an independent OSCORE implementation. CI checks coverage counters against its
baseline; those timings are not a security or performance qualification.

The [independent process suite](tools/interop/README.md) verifies PSK DTLS
interoperability and wrong-key refusal. Legacy peer/harness dependency advisories
are tracked in [#193](https://github.com/jeffglousher/coaptic/issues/193).
