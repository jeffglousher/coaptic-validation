# Scoped and routed UDP

Run [39246185107](https://github.com/jeffglousher/coaptic-validation/actions/runs/39246185107)
passes all four directions on core `edfd1eb1669e8c164fc318e47f531d1c7e41e7a5`
and suite `d5e93eb4f4b8b91bf51878ce6ec76d1dbc629e0f`. Both source guards are clean.
Two roles use actual nonzero IPv6 interface scopes; wrong-zone sends return
ENETUNREACH (101), followed by fresh exact Content. Two roles cross the ULA
routes through a forwarding namespace. The independent peer uses the aiocoap
codec and Python UDP sockets, not the full aiocoap server stack.

`addressing-pass/` preserves original build, source and result receipts, including
actual interfaces, routes, socket endpoints, raw datagrams, toolchain and binary
hashes. Cleanup completed without retained resources. Result SHA-256:
`ecfdcc0c2667613519609d3c35e6e45627848b324b571cb36c80e37645cdb9da`.

`first-failure/` preserves run
[39245248417](https://github.com/jeffglousher/coaptic-validation/actions/runs/39245248417)
at suite `4c3f7772283d6c4d89699c674829b7e7ce13c296`, same core. It failed because
the fixture omitted explicit unprotected selection and cleanup misclassified an
asynchronously retained owned veth peer. It is not a protocol pass. The corrected
run preserves the exact interface ownership checks.

PMTU/ICMP and compound traffic are separate cases, initially unexecuted. These
four addressing results alone do not close the broader interoperability scope.
