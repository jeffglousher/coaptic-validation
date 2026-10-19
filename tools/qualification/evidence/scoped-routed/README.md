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

Run [39247160176](https://github.com/jeffglousher/coaptic-validation/actions/runs/39247160176)
passes the separate compound and host PMTU cases on core
`567899121ace814ebfb417b55705adbcb1299215` and suite
`d290314823343b0f6caf8f0b7a5cc0d0c6e39569`. `network-errors-pass/` preserves
the original receipts plus a compact independent regrading result. Sources remain
clean and unchanged, and cleanup completes with no retained resources.

The compound capture contains one dropped reply, one malformed packet and one
wrong-token ACK received by Coaptic, one byte-identical retransmission from the
same endpoint, then a valid response and a fresh distinct call. All client,
relay and independent server packet captures agree.

The host PMTU probe records an actual ICMPv6 Packet Too Big (origin 3, type 2,
code 0, MTU 1280) from the owned router, quoting 1184 bytes of the exact 1400-byte
nonce-bearing probe to its actual destination. The Linux socket reports MTU
1500 then 1280 and subsequent EMSGSIZE (90). A fresh small CoAP call succeeds.
This is Linux host socket behavior, not automatic App PMTU adaptation; no App
capacity changed. Result SHA-256:
`c7ce870d21a4c6cb16daad00693ed002a32f0f319e49cf4c5a5e63b5eb607c51`.

These six finite cases complete the selected Q3 addressing/network-error slice.
They do not imply physical LAN qualification or close other issue #200 profiles.
