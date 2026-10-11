# Independent process interoperability

Three executables talk over loopback UDP or DTLS:

- `peer-coaptic`: Coaptic App, webrtc-dtls 0.12 / util 0.11.
- `peer-coap-rs`: coap 0.28.1, same DTLS crates, no Coaptic types.
- `peer-libcoap`: libcoap 4.3.5b at `851533c3cf63d16984d370ce39d586ecb3694971`. CMake checks that revision. CI builds OpenSSL DTLS and OSCORE.

libcoap is BSD-2-Clause and is not linked into the library. OpenSSL is a test-machine dependency. The PSK `sesame` is a fixture.

## Build and run

Requires stable Rust, Python 3.10+, CMake 3.20+, a C compiler, and OpenSSL headers.

```sh
cargo build --locked --release -p peer-coaptic -p peer-coap-rs
git init /tmp/libcoap
git -C /tmp/libcoap fetch --depth 1 https://github.com/obgm/libcoap.git 851533c3cf63d16984d370ce39d586ecb3694971
git -C /tmp/libcoap checkout --detach FETCH_HEAD
cmake -S tools/interop/libcoap -B target/libcoap-peer -DLIBCOAP_SOURCE=/tmp/libcoap -DCMAKE_BUILD_TYPE=Release -DENABLE_DTLS=ON -DDTLS_BACKEND=openssl -DENABLE_OSCORE=ON
cmake --build target/libcoap-peer --parallel 2
python3 -m unittest discover -s tools/interop -p 'test_*.py'
python3 tools/interop/run.py --coaptic target/release/peer-coaptic --coap-rs target/release/peer-coap-rs --libcoap target/libcoap-peer/peer-libcoap --iterations 100 --output target/process-interop.json
```

Windows: MSVC (`-G "Visual Studio 17 2022" -A x64`, `--config Release`) and `.exe` paths. Without OpenSSL, configure `-DENABLE_DTLS=OFF -DENABLE_OSCORE=OFF` and pass `--libcoap-udp-only`. CI does not use that flag.

## Result

[`capabilities.json`](capabilities.json) is the case list. A report passes when every enabled case appears once, passes, and keeps evidence. Gaps in that file are open. Linux and Windows are the declared platforms.

`--libcoap-udp-only` and `--libcoap-oscore-unavailable` mark the matching C cases build-excluded. An empty run fails. Wrong-key and blackhole cases need the peer's error exit. A timeout is not a DTLS alert.

Upload readback is `accepted:calls`. `sesame` selects the public RFC 8613 C.1 secret. Any other key label mismatches on purpose.

The Coaptic OSCORE client retries one authenticated 4.01 that carries Echo, once, with the same request. The libcoap direction uses its B.1.2 challenge.

coap-rs answers a skipped Block1 number with 2.31. coap-rs and libcoap apply a duplicated counter POST twice.

The standalone coap-rs UDP fixture also serves `/separate`: an empty request ACK,
then a complete CON response with the original token and a new MID. The relay
checks both MID bindings, the full payload and the client's empty response ACK.
Admission and queued responses are each bounded to eight, with a 2,048-byte
datagram limit. Separate-CON state retains at most eight complete requests and
responses, and permits only one outstanding separate response per endpoint.
Oversized or saturated input receives no ACK. Matching empty ACK/RST releases
the response slot; wrong endpoint/MID or malformed controls do not. A ten-second
backend deadline rejects late replies by reservation identity. Response retries
use randomized 2–3 second initial timeouts, exponential backoff and at most four
retransmissions within the RFC 7252 transmission span; final expiry releases the
slot. These are standalone fixture rules, not an upstream coap-rs reliability
claim. DTLS remains unqualified.

The separate-response loss cases use Coaptic and coap-rs clients against the
Coaptic server, and a Coaptic client against the standalone coap-rs fixture,
over IPv4 loopback UDP. The relay forwards the empty request ACK,
drops exactly the first separate CON 2.05, and requires an identical complete
retransmission followed by the client's matching ACK. The request deadline is
eight seconds; the relay retains at most 256 datagrams. Missing, changed or
out-of-order evidence fails. A fresh client must then complete against the same
server. These cases do not qualify protected transports, other address families
or hardware.
The coap-rs client can repeat the original GET despite its empty ACK. The trace
retains those retries and matching repeated ACKs; every delivered separate
response must still match the dropped bytes exactly. This checks recovery and
bindings, not a complete retransmission-timer conformance schedule.

The Coaptic-to-libcoap Q-Block2 missing-block case uses explicit NON requests
(`qblock2-non` in the Coaptic peer). The fixture knows that both peers support
Q-Block; this case does not qualify capability discovery. RFC 9177 sections 7.1
and 7.2 distinguish NON transfer recovery from CON congestion control: with
libcoap's default NSTART of one, dropping a CON payload prevents a higher block
from arriving. Existing CON cases retain their original request type.

The IPv6 variant also retains each datagram's exact source, destination and
relay endpoints and requires AF_INET6 with IPV6_V6ONLY on both relay sockets.
An independent `::1` GET verifies server reachability. Three schedules run
against the same server: selective missing-block recovery to the full 2000-byte
body, permanent block-1 loss with 1744 delivered bytes and a protocol timeout,
then fresh full recovery. The refusal deadline is six seconds, allowing the
RFC 9177 four-second NON_RECEIVE_TIMEOUT to trigger a selective retry. Complete
transfers have a twenty-second deadline; each trace is bounded to 256 datagrams.
Partial evidence cannot pass the complete-response oracle. Endpoint/family,
loss, representation and timeout mutations are rejected. This is loopback UDP
qualification, not scoped link-local, routed, protected or hardware evidence.

The relay selects 256-byte blocks, withholds block 1 until the client requests
it, and requires a higher block to arrive before that selective recovery. The
20-second deadline and 256-datagram trace bound apply. Delivered payloads must
reassemble the exact 2000-byte pattern with stable ETag, Size2 and block size,
contiguous numbers and a final block. The report retains the full trace,
including original and forwarded bytes. Mutation tests reject absent loss,
wrong recovery options, CON fallback and incomplete or changed body evidence.
These cases cover IPv4 and IPv6 loopback UDP; protected recovery, scoped/routed
networks and hardware remain unqualified.

The `con-qblock2-loss` and `ipv6-con-qblock2-loss` cases qualify Coaptic-to-libcoap CON recovery
with libcoap's unchanged default NSTART of one. It drops the first later CON
block 1, requires a byte-identical retransmission with the same MID and token,
and binds every empty ACK to the exact client/server relay endpoints. Each
outstanding CON must be ACKed before the next block. Complete delivery requires
the exact 2000-byte body with stable ETag, Size2 and SZX; losing block 1 permanently
must instead produce a protocol timeout with only 256 verified partial bytes.
A fresh client process and relay, with new endpoints, then recover the full body
from the same server; this is not reuse of the timed-out Call. Each successful
schedule has a 20-second deadline; refusal has a 6-second deadline and must include
an actual retransmission. Capture bounds remain 256 datagrams, with monotonic
capture times retained. The IPv6 case independently probes `::1`, requires
AF_INET6/IPV6_V6ONLY on both relay sockets and checks every exact IPv6 endpoint,
including zero flow and scope identifiers. These finite IPv4/IPv6 loopback schedules do not qualify
post-MAX_TRANSMIT_SPAN selective retry, every retransmission timer boundary,
protected transfers or sustained availability. RFC 9177 sections 4.4 and 7.1 describe
this CON reliability behavior separately from NON selective recovery.

`ipv6-separate-loss:coaptic->coap-rs` applies the same standalone fixture to
IPv6 loopback, with strict AF_INET6/IPV6_V6ONLY relay sockets and exact `::1`
endpoint evidence. After an independent reachability probe, it loses the first
separate CON response and requires identical retransmission, an owned empty ACK
and the complete `separate-payload`. A second schedule permanently drops replies,
retains the initial request ACK and repeated CON attempts, and requires a protocol
timeout without an application response. A fresh IPv6 request to the same server
then completes normally. The successful loss schedule has a 12-second deadline;
refusal and fresh recovery have six seconds, with at most 256 captured datagrams
per schedule. Mutations reject wrong endpoints/family, changed peer or forwarded
bytes, missing loss/retry proof and ACK-before-delivery. This qualifies the
bounded standalone fixture, not upstream coap-rs reliability, scoped/routed
networks, protected transport or sustained availability.


`con-qblock1-loss:coaptic->libcoap` and `ipv6-con-qblock1-loss:coaptic->libcoap`
qualify the existing independent CON upload fixture over IPv4 and IPv6 loopback.
The IPv6 case requires an independent `::1` probe, IPv6-only relay sockets and
exact four-component endpoint ownership; IPv4, mapped or scoped addresses refuse.
The 2000-byte request uses two Q-Block1 payloads
(SZX 6), one Request-Tag and Size1. The relay forwards the initial 1024 bytes and
requires their owned empty ACK before dropping the later payload. A successful
schedule requires byte-identical retransmission and a matching final 2.01 ACK;
the libcoap handler checks the entire pattern and its `accepted:calls` readback
must advance exactly once. Permanently dropping the later payload must produce
a protocol timeout, with only 1024 partial bytes delivered and neither counter
changed. A fresh client process and relay then complete against the same server.
The successful schedules have twelve-second deadlines; refusal has six seconds
and must retain a genuine retry. Traces are limited to 256 datagrams and bind
each packet to exact endpoints, monotonic capture time and unchanged wire bytes.
The first retry must match the fixture's unchanged 2–3 second initial RTO, allowing
50 ms early capture skew and one second of late host scheduling. Zero/compressed
capture intervals refuse; this is not qualification of every timer boundary.
The readback counts are in-memory fixture application effects, not durable receipts.
This finite CON case uses existing RFC 7252 reliability as referenced by RFC 9177
section 7.1; it does not qualify NON missing-block recovery, timed-out Call reuse,
protected transport, routed networks, hardware or sustained availability.


`relay-cap-256:coaptic->libcoap` qualifies a finite IPv4 UDP loopback
refusal/recovery boundary. Against one libcoap server, fresh client processes
first assemble the exact 2000-byte representation, complete a small response
through a silent 256-byte wire-datagram cap, time out while the cap drops every
oversized first Block2 response, and assemble all 2000 bytes after the cap is
removed. The trace binds exact endpoints, unchanged relay bytes, Block2 size and
body metadata, and an identical CON request retry. Its first retry uses the
unchanged RTO of 2 to 3 seconds with 50 ms early capture and one second late scheduling
tolerance. Each request has a 6.5-second peer deadline and a distinct process
deadline; a killed or stuck process is a failure. The relay limits each trace to
256 records. A retry of a rejected first block may obtain a new server ETag;
delivered blocks of a complete representation must retain one ETag.

This case records a silent relay limit, not an IP MTU or ICMP discovery result,
adaptive block shrinking, continuation of the timed-out Call, protected traffic,
routed/scoped networking, hardware or sustained availability. The original RFC
7252 section 4.6 and RFC 7959 block-size rules remain separate from this finite
fault schedule.

The `oscore-qblock1-recovery:coaptic->libcoap` case uses the pinned libcoap
OpenSSL/OSCORE build over IPv4 loopback. Its offline aiocoap oracle authenticates
inner Q-Block1 options and every slice of the 2000-byte upload; it rejects a
classic-Block1 substitution. One intact authenticated upload request is lost
to exercise exact client retransmission. The server acknowledges each request
then sends a separate protected CON Created; losing that reply once exercises
exact server retransmission and the client ACK with the server's MID. Created
replies are also lost permanently. The latter records a client timeout alongside the independently
observed application effect, then exercises fresh recovery. Wrong-key traffic
must leave handler counts unchanged. Captures retain exact endpoints, ciphertext
retries and source identities. Native NoSec-only libcoap builds explicitly
exclude this case; synthetic tests do not establish peer interoperability.

Run the focused oracle tests in an isolated environment populated from the
existing pinned `tools/security-interop/requirements.txt`:

```sh
python -m unittest discover -s tools/interop -p 'oscore_qblock1_tests.py'
```

This finite fixture uses public RFC 8613 test keys, not production credentials,
enrollment or a sustained-availability qualification.

The first hosted campaign (run `38129603008`, artifact `11698328540`) completed
the baseline upload but the original piggyback-only oracle refused libcoap's
legitimate separate CON response. That failed trace is retained. The revised
oracle authenticates against the same exact final request binding and separately
checks server response retransmission and client ACK ownership. Offline baseline
re-evaluation does not establish the subsequent loss schedules; those require a
new hosted campaign.

The second hosted campaign (`38130677875`) passed baseline, request-loss,
response-loss and permanent-loss checks, then its silence-only wrong-key oracle
refused libcoap's unprotected ACK 4.00 diagnostic. RFC 8613 section 8.2 step 6
permits that decryption-failure response. The fixture-specific oracle now requires
its exact endpoint/MID/token, Max-Age zero and `Decryption failed` payload, while
still requiring client timeout, no authenticated upload progress and unchanged
handler counts. This diagnostic establishes no authenticated success. The failed
campaign remains retained; the final fresh-recovery schedule was not reached in
that failed run. The later actual campaign (`38131267282`) passed all six schedules,
including fresh recovery; [source-bound results](https://github.com/jeffglousher/coaptic/issues/468#issuecomment-6108057349)
retain the successful trace separately from both failed campaigns.

The separate `oscore_qblock2.py` baseline observer records the protected
Coaptic-to-libcoap `/large` response using the same pinned aiocoap decoder.
Its report records exact sources, executable hashes, endpoint ownership,
authenticated Q-Block2/ETag/Size2/body evidence, and the observed ACK/CON
sequence. Run it with `--coaptic PATH --libcoap PATH --output REPORT.json`
after building the same OSCORE-enabled peers and installing the pinned decoder
requirements used above. This is a baseline prerequisite for
[#472](https://github.com/jeffglousher/coaptic/issues/472), not a complete
loss/refusal/recovery qualification or an enabled capability-matrix case.
A failed baseline retains its trace and failure; synthetic oracle tests do
not establish independent-peer interoperability.


The [original pinned libcoap license and notices](libcoap/LICENSE.libcoap) are retained with the dependency patch.

The companion-owned prerequisite patch for [#477](https://github.com/jeffglousher/coaptic/issues/477)
retains an immutable request binding per protected UDP Q-Block2 transfer, separate
from libcoap's mutable token association. Session-monotonic generations revoke
superseded queued and timer continuations. A separate authenticated-request
generation is committed only after successful authentication and complete inner
decoding, then stamped on the response before the application callback. Missing
or stale stamps (including unsupported asynchronous copies) refuse transfer
binding. This does not qualify proxy/async behavior or preclude their earlier
upstream empty ACK. Same-token replacement and recipient recreation cannot retarget an old
response. Failed decoding or replacement allocation preserves the prior request
association and receive replay state, including valid zero-valued sequence/window
boundaries. Request replay validation uses one fixed stack recipient-context view
only for scalar staging; it does not own or free its borrowed references. This
adds stack use and is not a stack or whole-process ceiling. Distinct response blocks use fresh
server PIVs; ciphertext retransmissions remain unchanged. The exact upstream,
patch and modified-source hashes are checked before building and reported with
the binary identity; this is a patched peer, not unmodified libcoap qualification.

The bounded patch supports ordinary CON exchanges and one explicit cached block
per fresh request. Protected NON/Observe transfer binding and cached M=1 or
repeated-selector bursts are refused. It does not add an independent-peer PASS
for those combinations. Retained binding metadata is limited to one token of at
most eight bytes, 200 AAD bytes, a 13-byte nonce and an eight-byte request PIV per
live transfer, plus allocator/structure overhead. This is not a total libcoap
memory ceiling. The authenticated-request generation adds one 64-bit field to
each OSCORE PDU, session and association even when Q-Block is disabled; structure
padding and allocator overhead are additional. Dynamic recipient deletion conservatively refuses while a
protected-Q response is encrypting, and otherwise invalidates only the exact
OSCORE context/recipient's bindings. Context teardown follows upstream's documented
prohibition on calling `coap_free_context()` from a libcoap callback.

The mandatory hosted ASan/UBSan lifetime executable uses in-memory transport
writes and allocation refusal injection before any patched process campaign.
Local synthetic oracle/source-hash checks cannot establish that this C gate or
the patched wire baseline succeeds. Both remain required before qualification;
[#472's original failure](https://github.com/jeffglousher/coaptic/issues/472#issuecomment-6108231594)
and its full loss/refusal/recovery acceptance remain separate.


### Protected Q-Block2 finite recovery campaign

`oscore_qblock2.py --campaign` adds five bounded exchanges on one running patched
libcoap server: complete baseline, one intact later-block loss, permanent
later-block loss, wrong-key refusal, and fresh complete recovery. It retains the
same source, patch-manifest and executable hashes as the baseline observer.
The observed baseline form is one protected CON GET, an empty ACK, and two
separate protected CON responses (1,024 and 976 bytes), each explicitly ACKed.
The relay only drops intact authenticated block 1; it does not modify ciphertext.

The maintained aiocoap decoder binds every response to the exact current request.
The grader requires the full 2,000-byte body, stable ETag and Size2, distinct
explicit response PIVs, and exact ciphertext/MID/PIV retransmission after the
original exponential RTO. Permanent loss must end in the peer's protocol timeout
with an authenticated 1,024-byte forwarded prefix, its exact ACK and no complete
application response. This is wire evidence, not instrumentation of the client's
internal buffer. Only the pinned peer's exact `request timed out` error qualifies;
a subprocess deadline or crash fails qualification. The wrong-key case
requires the pinned peer's exact unprotected 4.00 diagnostic (RFC 8613 section
8.2 step 6), with no authenticated response. Fresh request bindings and distinct
server PIVs across the five exchanges establish fresh same-server recovery.
Different relay ports mean this is not a same-endpoint stale-transfer expiry test.

Hosted execution is required before claiming this campaign passed. The existing
180-case inventory remains unchanged. The separate retained campaign report is
limited to IPv4 loopback, CON, SZX 1,024 and this explicitly patched peer; it does
not qualify NON, other peers, routed networks, sustained availability, or all
OSCORE/Q-Block combinations. The mandatory lifetime sanitizer gate remains before
all patched traffic. Original unpatched failure evidence remains applicable to
the unmodified upstream revision.
