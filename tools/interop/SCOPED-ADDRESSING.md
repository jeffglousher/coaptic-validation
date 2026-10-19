# Finite scoped and routed UDP addressing

Four addressing directions pass in the retained source-bound
[hosted result](../qualification/evidence/scoped-routed/README.md). All network
configuration belongs to freshly owned namespaces on the isolated Linux runner.

## Software boundary

RFC 7252 sections 4.1 and 4.2 define transport endpoint identity and optional
ICMP handling; section 4.6 discusses datagram sizing. This fixture proves the
selected OS socket/addressing contract, not an additional mandatory CoAP feature.
Original text: `coaptic/knowledge/rfcs/rfc7252.txt`.

The host binary is `crates/peer-coaptic/src/bin/addressing.rs`. It uses the
existing crate dependencies and public App/UdpSocketIo APIs. Existing peer Args,
all 181 process cases, and Q4 peer contracts remain unchanged. Bind and remote are
separate numeric SocketAddr arguments. Link-local IPv6 requires a nonzero numeric
zone; Endpoint conversion and observed receive peers retain it. No DNS or zone-name
resolution occurs. Wrong-zone input is not silently normalized to the bind zone.

One Constrained App, blockwise disabled, one route, Call capacity 4, deferred capacity 0, request capacity 4 and one unused security
association slot, and 1153 bytes caller-owned receive scratch (1152+oversize sentinel).
The host allocates JSON formatting strings; these are fixture overhead, not core
no-allocation claims. Maximum 64 I/O events and 30-second lifetime. Actual socket
errors include operation, Rust kind and raw OS error. No raw error is reported as
a CoAP refusal. A separately configured Python UDP socket with aiocoap's codec
provides the independent role and exact request/response captures.

## Finite operation list

1. Coaptic client to independent server on directly attached IPv6 link-local:
   explicit client bind and remote scope; exact body/MID/token and actual nonzero
   send/receive scope. Repeat with the *existing wrong interface's* numeric index;
   require actual I/O error or bounded silence and no accepted response, then a
   fresh correctly scoped client operation against the same server succeeds.
2. Reverse client/server implementations, same positive/wrong-zone/fresh sequence.
3. Each implementation direction across a routed ULA path: exact bytes and source
   endpoint, two links and a forwarding namespace. Link-local is never called
   routed proof. No DNS, multicast, proxy or DTLS contribution scenario is added.
4. Optional Linux host-I/O PMTU control, only if requisite socket options and error
   queue are available: client ingress MTU 1500/router egress MTU 1280. A 1400-byte UDP
   payload with PMTUDISC_DO causes router ICMPv6 Packet Too Big. Record exact ICMP
   type/code/MTU from recvmsg(MSG_ERRQUEUE), and actual subsequent EMSGSIZE from the
   caller's socket. A small datagram then succeeds. Decode the native Linux
   sock_extended_err structure using verified system headers; do not fabricate
   an error from a timeout or use a relay length cap as PMTU proof.

The PMTU control exercises Python's configured kernel socket, not automatic App
path-MTU adaptation. Constrained App packets 1152+IPv6/UDP48 fit IPv6's 1280 minimum;
an oversized transport probe is a distinct diagnostic, not a reason to enlarge
core buffers. Coaptic transport-error reporting is exercised by the actual wrong-
zone case. If the kernel cannot return the required error, retain an explicit
unsupported control and its cause; do not substitute PASS.

## Isolated hosted-Linux topology (manual advisory execution only)

Require Linux, iproute2, CAP_NET_ADMIN/root, Python/aiocoap and the source-qualified
Rust binary. A single run chooses a random identifier, e.g. `cq3-<8hex>`, then owns
three new namespaces `<id>-c`, `<id>-r`, `<id>-s`. Refuse to adopt any existing name.
Use two veth pairs, moving *both ends* into owned namespaces before configuration:
`c0 ? r0` and `r1 ? s0`. The temporary host-side names are unique and <=15 bytes.
Record each successful creation and actual ifindex before subsequent mutations.

Configure only those namespaces/interfaces:

- C c0: `fd42:c0a:1::2/64`, explicit `fe80::c/64`; R r0: `fd42:c0a:1::1/64`, `fe80::1/64`.
- R r1: `fd42:c0a:2::1/64`, `fe80::2/64`; S s0: `fd42:c0a:2::2/64`, `fe80::5/64`.
- Scoped tests use C?R/r0 only, replacing the independent/Rust role as needed.
- Routed tests use C to S; routes within C/S name the adjacent R ULA address and device.
- Enable IPv6 forwarding only inside R. Set ingress interfaces MTU 1500 and egress
  R/r1+S/s0 MTU 1280 only for the optional PMTU control. Keep loopback up in all three.
- Assign explicit test addresses with `nodad` only on owned interfaces. Record
  `ip -j link`, `ip -j -6 addr`, `ip -j -6 route` and the router forwarding value.
- Discover namespace-local ifindices; never hardcode 2 or assume a host ifindex is
  valid inside a namespace. C's existing loopback index is the wrong-zone control.
- Launch bounded children via argv `ip netns exec NAME ...`; record pid and exact
  binary/source hashes. No shell interpolation, global sysctl or host route changes.

Cleanup is guarded by the in-memory creation ledger and saved ownership record.
Stop only children started by this run, verify the namespaces contain no unknown
processes, then delete only namespaces created successfully by this run. Verify
every non-loopback interface against its name/ifindex/alias/peer ledger before
deleting any namespace; repeat before each deletion. The ledger records each
successful move and rename. Partial-setup failure removes only
confirmed created resources. Unexpected consumers or changed ownership stop cleanup
and leave an explicit retained-resource report. Never sweep similarly named routes,
interfaces or namespaces after a crash. No daemon or scheduled cleanup is added.

## Windows scope

An existing Ethernet link-local address and its actual interface index can prove
local-interface scoped addressing after explicit runtime approval. It cannot prove
a routed LAN or the Linux namespace/PMTU schedule. No Windows route, adapter,
firewall or security setting change is needed or authorized by this draft.

## Evidence and readiness

Capture source/binary identities before/after, actual socket local/remote tuples,
namespace and ifindex ownership, bounded raw datagrams, code/body/operation matching,
negative error/timeout, and fresh recovery. Do not reuse host-loopback claims as
route proof. Parser and oracle tests can run without network setup; runtime begins
only after review of this finite slice. Three Rust tests and ten pure cleanup
and scope tests pass; the four addressing directions have executed. This fixture uses the aiocoap
codec with a Python UDP socket, not the full aiocoap server stack. The manual
workflow is `.github/workflows/scoped-addressing.yml`. Added source is under
96 KB; no new Rust dependencies or Cargo target directory. The 256 KB subprocess
output check bounds retained evidence after capture, not streaming subprocess
memory. Trusted finite ip/sysctl commands and bounded peer trace producers keep
this workload finite. PMTU and compound scenarios execute separately with their
own source-bound receipts; these finite results do not close other issue #200 profiles.

## Separate network-error mode

`--mode network-errors` executes only two additional cases; both pass in
[run 39247160176](https://github.com/jeffglousher/coaptic-validation/actions/runs/39247160176),
with exact sources and limits in the retained evidence above. The compound relay
drops one reply, injects a malformed datagram and an ACK with an unmatched token,
then records retransmission/recovery and a fresh operation. Exact client, relay
and independent server traces must agree. ACK matching and response matching are
separate RFC 7252 contracts; a failure is retained for interpretation, not relabeled
automatically as a core defect or a pass.

The PMTU case sets only the owned router egress and server interface to MTU 1280.
A separate Python socket submits a 1400-byte nonce-bearing UDP probe, validates
ICMPv6 Packet Too Big origin/type/code/MTU, quoted bytes, destination and offender,
and requires an actual subsequent EMSGSIZE plus fresh small CoAP exchange. The
probe verifies installed Linux UAPI constants and records header hashes. Original
definitions are in Linux [errqueue.h](https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/errqueue.h)
and [in6.h](https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/in6.h).
This is kernel socket behavior, not automatic App PMTU adaptation. No App buffer
or capacity changes are involved. Four pure PMTU/compound tests reject missing
loss, altered ownership, absent malformed traffic and mismatched error receipts.

