//! Finite functional proof of a fixed SmallDevice's Block2 + Observe over UDP.
//! Both endpoints are Coaptic Apps, so this is not independent interoperability,
//! CPU timing, peak memory, physical-device qualification or an RFC-wide claim.
//! RFC 7959 section 2.6: consume every block of each observed representation.
#![forbid(unsafe_code)]

use coaptic::{
    App, Call, CallFailure, Code, ContentFormat, Endpoint, Request, Response, get,
    message::{BlockValue, MessageId, Token, Type, decode},
    oscore::{DeriveParams, SecurityContext},
    storage::{AllocMemory, Capacities, DatagramIo, MemoryLayout, ObserveKey, UdpSocketIo},
};
use std::{
    net::UdpSocket,
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, &'static str>;
const USAGE: &str = "usage: bench-observe-proof unprotected|oscore";
const WIRE: usize = 1152;
const BYTES: usize = 4096;
const ROUNDS: usize = 128;
const PER_ENDPOINT_DATAGRAMS: usize = 128;
const DEADLINE: Duration = Duration::from_secs(3);
static VERSION_0: [u8; BYTES] = fixture(0);
static VERSION_1: [u8; BYTES] = fixture(1);
static VERSION: AtomicU8 = AtomicU8::new(0);

const fn fixture(version: u8) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    let mut i = 0;
    while i < BYTES {
        bytes[i] = ((i * 31 + i / 251) as u8).wrapping_add(version.wrapping_mul(97));
        i += 1;
    }
    bytes
}
fn snapshot() -> Response<'static> {
    if VERSION.load(Ordering::Relaxed) == 0 {
        representation(&VERSION_0, b"v0")
    } else {
        representation(&VERSION_1, b"v1")
    }
}
fn representation(body: &'static [u8], etag: &[u8]) -> Response<'static> {
    Response::content(body)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(etag)
        .max_age(60)
}
fn handler(_: Request<'_>) -> Response<'static> {
    snapshot()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Server,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Header {
    mid: MessageId,
    ty: Type,
    token: Token,
    observe: Option<u32>,
}

// One outstanding exchange per endpoint. These fields validate EACH actual wire
// datagram; the assembled response's MID is used only for its first fragment.
struct Io {
    udp: UdpSocketIo<[u8; WIRE + 1]>,
    side: Side,
    peer: Endpoint,
    protected: bool,
    token: Option<Token>,
    request_mid: Option<MessageId>,
    control_mid: Option<MessageId>,
    first: Option<Header>,
    sent: usize,
    received: usize,
    protected_sent: usize,
    protected_received: usize,
    controls_sent: usize,
    mids: [u16; PER_ENDPOINT_DATAGRAMS],
    mid_count: usize,
}
impl Io {
    fn new(socket: UdpSocket, peer: Endpoint, side: Side, protected: bool) -> Result<Self> {
        socket
            .set_nonblocking(true)
            .map_err(|_| "nonblocking_socket")?;
        Ok(Self {
            udp: UdpSocketIo::new(socket, [0; WIRE + 1]).map_err(|_| "udp_adapter")?,
            side,
            peer,
            protected,
            token: None,
            request_mid: None,
            control_mid: None,
            first: None,
            sent: 0,
            received: 0,
            protected_sent: 0,
            protected_received: 0,
            controls_sent: 0,
            mids: [0; PER_ENDPOINT_DATAGRAMS],
            mid_count: 0,
        })
    }
    fn begin(&mut self) {
        self.first = None;
    }
    fn check(&mut self, bytes: &[u8], sending: bool) -> std::io::Result<()> {
        let p = decode(bytes).map_err(|_| invalid("wire_decode"))?;
        let from_client = (self.side == Side::Client) == sending;
        if p.code() == Code::EMPTY {
            if !p.token().is_empty()
                || p.options().next().is_some()
                || !p.payload().is_empty()
                || !matches!(p.ty(), Type::Acknowledgement | Type::Reset)
                || self.control_mid != Some(p.message_id())
            {
                return Err(invalid("control_mid_or_shape"));
            }
            if sending {
                self.controls_sent += 1;
            }
            return Ok(());
        }
        if p.oscore().is_some() != self.protected {
            return Err(invalid("wire_security"));
        }
        let code = match (from_client, self.protected) {
            (true, false) => Code::GET,
            (true, true) => Code::POST,
            (false, false) => Code::CONTENT,
            (false, true) => Code::CHANGED,
        };
        if p.code() != code {
            return Err(invalid("wire_code"));
        }
        let observe = p
            .observe()
            .transpose()
            .map_err(|_| invalid("wire_observe"))?;
        if from_client {
            if p.ty() != Type::Confirmable {
                return Err(invalid("request_type"));
            }
            // First send learns App's generated Token before send returns Call.
            self.token = Some(p.token());
            self.request_mid = Some(p.message_id());
        } else {
            if self.token != Some(p.token()) {
                return Err(invalid("response_token"));
            }
            match p.ty() {
                Type::Acknowledgement if self.request_mid == Some(p.message_id()) => {}
                Type::Confirmable | Type::NonConfirmable => {
                    self.control_mid = Some(p.message_id());
                }
                _ => return Err(invalid("response_mid_or_type")),
            }
            if self.side == Side::Client && !sending && self.first.is_none() {
                self.first = Some(Header {
                    mid: p.message_id(),
                    ty: p.ty(),
                    token: p.token(),
                    observe,
                });
            }
        }
        if sending && (from_client || matches!(p.ty(), Type::Confirmable | Type::NonConfirmable)) {
            // This deliberately finite no-loss proof rejects a retransmission;
            // it does not claim that retransmissions are forbidden by CoAP.
            let mid = p.message_id().get();
            if self.mids[..self.mid_count].contains(&mid) || self.mid_count == self.mids.len() {
                return Err(invalid("proof_mid_reuse_or_budget"));
            }
            self.mids[self.mid_count] = mid;
            self.mid_count += 1;
        }
        Ok(())
    }
}
fn invalid(why: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, why)
}
impl coaptic::storage::DatagramTransport for Io {
    type Error = std::io::Error;
}
impl DatagramIo for Io {
    fn recv(&mut self, bytes: &mut [u8]) -> std::io::Result<Option<(usize, Endpoint)>> {
        // UdpSocketIo receives into len+1 scratch and rejects oversize/platform
        // truncation before copying. Never accept a silently shortened datagram.
        let Some((n, peer)) = self.udp.recv(bytes)? else {
            return Ok(None);
        };
        if peer != self.peer || n > WIRE || self.received >= PER_ENDPOINT_DATAGRAMS {
            return Err(invalid("receive_peer_or_budget"));
        }
        self.check(&bytes[..n], false)?;
        self.received += 1;
        self.protected_received += usize::from(
            decode(&bytes[..n])
                .map_err(|_| invalid("decode"))?
                .oscore()
                .is_some(),
        );
        Ok(Some((n, peer)))
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        if peer != self.peer || bytes.len() > WIRE || self.sent >= PER_ENDPOINT_DATAGRAMS {
            return Err(invalid("send_peer_or_budget"));
        }
        self.check(bytes, true)?;
        let n = self.udp.send(peer, bytes)?;
        if n != bytes.len() {
            return Err(invalid("short_udp_send"));
        }
        self.sent += 1;
        self.protected_sent += usize::from(
            decode(bytes)
                .map_err(|_| invalid("decode"))?
                .oscore()
                .is_some(),
        );
        Ok(n)
    }
}

type ServerProfile = coaptic::profiles::WithObserve<coaptic::profiles::Constrained, 1>;
type Server = App<ServerProfile, Io, 4, true, <ServerProfile as MemoryLayout<true>>::Store, 0, 1>;
// Separate client resource name and owner; it is not part of the SmallDevice.
type ProofClient = App<coaptic::profiles::Default, Io, 1, true, AllocMemory, 0, 1>;
fn client_caps() -> Capacities {
    Capacities {
        rx_datagram_slots: 2,
        rx_datagram_bytes: WIRE,
        tx_datagram_slots: 2,
        tx_datagram_bytes: WIRE,
        dedup_entries: 4,
        observe_entries: 1,
        rx_body_slots: Some(1),
        rx_body_bytes: Some(BYTES),
        tx_body_slots: Some(1),
        tx_body_bytes: Some(1024),
    }
}
fn contexts(protected: bool) -> Result<(Option<SecurityContext>, Option<SecurityContext>)> {
    if !protected {
        return Ok((None, None));
    }
    let mut material = [0; 24];
    getrandom::fill(&mut material).map_err(|_| "context_randomness")?;
    let derive = |sender_id, recipient_id| {
        SecurityContext::derive(DeriveParams {
            master_secret: &material[..16],
            master_salt: &material[16..],
            sender_id,
            recipient_id,
            id_context: &[],
        })
        .map_err(|_| "context_derivation")
    };
    // A context moves into exactly one App. No cloned context, external crypto
    // peer, reset sequence counter or duplicated request-binding owner exists.
    let pair = (derive(&[1], &[2]), derive(&[2], &[1]));
    material.fill(0);
    Ok((Some(pair.0?), Some(pair.1?)))
}
fn server(io: Io, context: Option<SecurityContext>) -> Result<Server> {
    let builder = App::with_resources(
        coaptic::resources::SmallDevice::new()
            .block_wise::<true>()
            .observe_entries::<1>(),
    )
    .randomness(|bytes| getrandom::fill(bytes).is_ok())
    .route("obs", get(handler).observe(snapshot));
    let builder = if let Some(context) = context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    builder.bind(io).map_err(|_| "server_bind")
}
fn client(io: Io, context: Option<SecurityContext>, heap: usize) -> Result<ProofClient> {
    let builder = App::builder()
        .routes::<1>()
        .client_calls::<1>()
        .block_wise::<true>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok());
    let builder = if let Some(context) = context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    let memory = AllocMemory::try_new(client_caps(), heap).map_err(|_| "client_heap")?;
    builder.bind_storage(io, memory).map_err(|_| "client_bind")
}
fn now(origin: Instant) -> u64 {
    origin.elapsed().as_millis() as u64
}
fn first_block() -> BlockValue {
    BlockValue::new(0, false, 6).expect("valid constant Block2")
}

#[derive(Clone, Copy)]
struct Expected {
    call: Call,
    version: u8,
    observe: Option<u32>,
    ty: Type,
}
fn verify_body(response: &Response<'_>, version: u8) -> Result<()> {
    if response.code() != Code::CONTENT {
        return Err("response_code");
    }
    if response.format() != Some(ContentFormat::OCTET_STREAM) {
        return Err("response_format");
    }
    if response.etag_bytes() != Some(if version == 0 { &b"v0"[..] } else { &b"v1"[..] }) {
        return Err("response_etag");
    }
    if response.max_age_secs() != Some(60) {
        return Err("response_max_age");
    }
    verify_bytes(response.body(), version)
}
fn verify_bytes(body: Option<&[u8]>, version: u8) -> Result<()> {
    let expected = if version == 0 { &VERSION_0 } else { &VERSION_1 };
    if body != Some(&expected[..]) {
        return Err("incomplete_or_corrupt_body");
    }
    Ok(())
}
fn verify(
    response: &Response<'_>,
    expected: Expected,
    first: Header,
    protected: bool,
) -> Result<()> {
    verify_body(response, expected.version)?;
    if response.token() != Some(expected.call.token())
        || first.token != expected.call.token()
        || response.peer() != Some(expected.call.peer())
    {
        return Err("response_identity");
    }
    if response.message_id() != Some(first.mid)
        || response.ty() != Some(expected.ty)
        || first.ty != expected.ty
    {
        return Err("first_fragment_header");
    }
    if response.observe_seq() != expected.observe {
        return Err("response_observe");
    }
    // Protected Inner Observe is empty; OSCORE authenticates freshness via PIV.
    // Outer Observe is an unauthenticated hint, never an authentication oracle.
    if !protected && first.observe != expected.observe {
        return Err("wire_observe_sequence");
    }
    if response.received_at_ms().is_none() {
        return Err("missing_receive_clock");
    }
    Ok(())
}
#[derive(Default)]
struct Counts {
    completed: usize,
    verified_bytes: usize,
    polls: usize,
    call_refusals: usize,
    deregistrations: usize,
}
fn complete(
    server: &mut Server,
    client: &mut ProofClient,
    origin: Instant,
    expected: Expected,
    counts: &mut Counts,
) -> Result<Header> {
    let start = Instant::now();
    let protected = client.transport().protected;
    for _ in 0..ROUNDS {
        if start.elapsed() >= DEADLINE {
            return Err("operation_deadline");
        }
        server.poll(now(origin)).map_err(|_| "server_poll")?;
        client.poll(now(origin)).map_err(|_| "client_poll")?;
        counts.polls += 2;
        let first = client.transport().first;
        if let Some(outcome) = client.take_response(expected.call) {
            let response = outcome.map_err(|_| "terminal_call_failure")?;
            let first = first.ok_or("no_wire_first_fragment")?;
            verify(&response, expected, first, protected)?;
            counts.completed += 1;
            counts.verified_bytes += BYTES;
            // Flush the client's actual notification ACK before the next phase.
            server.poll(now(origin)).map_err(|_| "server_ack_poll")?;
            counts.polls += 1;
            return Ok(first);
        }
    }
    Err("operation_round_limit")
}
fn registered(server: &Server, call: Call, client_peer: Endpoint) -> bool {
    server
        .engine()
        .lookup_observe(ObserveKey::new(call.token(), client_peer))
        .is_some()
}
fn refuse_extra_call(client: &mut ProofClient, peer: Endpoint, clock: u64) -> Result<()> {
    let sent = client.transport().sent;
    if !matches!(
        client.get("obs").to(peer).send(clock),
        Err(coaptic::app::Error::Saturated)
    ) {
        return Err("missing_call_capacity_refusal");
    }
    if client.transport().sent != sent {
        return Err("refusal_performed_io");
    }
    Ok(())
}
fn deregister(
    server: &mut Server,
    client: &mut ProofClient,
    origin: Instant,
    call: Call,
    counts: &mut Counts,
) -> Result<()> {
    client.transport_mut().begin();
    let stop = client
        .get("obs")
        .block2(first_block())
        .deregister_call(call)
        .to(call.peer())
        .send(now(origin))
        .map_err(|_| "deregister_send")?;
    if stop != call {
        return Err("deregister_call_identity");
    }
    complete(
        server,
        client,
        origin,
        Expected {
            call,
            version: 1,
            observe: None,
            ty: Type::Acknowledgement,
        },
        counts,
    )?;
    let local = Endpoint::from(
        client
            .transport()
            .udp
            .socket()
            .local_addr()
            .map_err(|_| "client_address")?,
    );
    if registered(server, call, local) {
        return Err("server_interest_not_released");
    }
    if client.cancel(call) || client.take_response(call).is_some() {
        return Err("deregister_local_lifetime");
    }
    if server
        .notify(now(origin), &["obs"], snapshot())
        .map_err(|_| "notify_after_deregister")?
        != 0
    {
        return Err("notification_after_deregister");
    }
    counts.deregistrations += 1;
    Ok(())
}

// Isolate construction of the fixed App; no stack override, workers or unsafe
// placement initialization. Construction/peak-stack costs remain unknown.
#[inline(never)]
fn run(protected: bool) -> Result<String> {
    VERSION.store(0, Ordering::Relaxed);
    let server_socket = UdpSocket::bind("127.0.0.1:0").map_err(|_| "server_socket")?;
    let client_socket = UdpSocket::bind("127.0.0.1:0").map_err(|_| "client_socket")?;
    let server_peer = Endpoint::from(server_socket.local_addr().map_err(|_| "server_address")?);
    let client_peer = Endpoint::from(client_socket.local_addr().map_err(|_| "client_address")?);
    let (client_context, server_context) = contexts(protected)?;
    let heap = AllocMemory::<Token>::required_heap_bytes(client_caps())
        .map_err(|_| "client_heap_layout")?;
    let mut server = server(
        Io::new(server_socket, client_peer, Side::Server, protected)?,
        server_context,
    )?;
    let mut client = client(
        Io::new(client_socket, server_peer, Side::Client, protected)?,
        client_context,
        heap,
    )?;
    let origin = Instant::now();
    let mut counts = Counts::default();
    let call = client
        .get("obs")
        .block2(first_block())
        .observe()
        .to(server_peer)
        .send(now(origin))
        .map_err(|_| "register_send")?;
    complete(
        &mut server,
        &mut client,
        origin,
        Expected {
            call,
            version: 0,
            observe: Some(0),
            ty: Type::Acknowledgement,
        },
        &mut counts,
    )?;
    if !registered(&server, call, client_peer) {
        return Err("missing_server_interest");
    }
    refuse_extra_call(&mut client, server_peer, now(origin))?;
    counts.call_refusals += 1;
    VERSION.store(1, Ordering::Relaxed);
    client.transport_mut().begin();
    if server
        .notify_confirmable(now(origin), &["obs"], snapshot())
        .map_err(|_| "notification_send")?
        != 1
    {
        return Err("notification_not_admitted");
    }
    complete(
        &mut server,
        &mut client,
        origin,
        Expected {
            call,
            version: 1,
            observe: Some(if protected { 0 } else { 1 }),
            ty: Type::Confirmable,
        },
        &mut counts,
    )?;
    if !registered(&server, call, client_peer) {
        return Err("notification_identity_or_lifetime");
    }
    refuse_extra_call(&mut client, server_peer, now(origin))?;
    counts.call_refusals += 1;
    deregister(&mut server, &mut client, origin, call, &mut counts)?;

    // Local cancellation is exercised before delivery. Deliberately consume
    // that ONE guarded UDP datagram without dispatching it to the server App.
    // This proves local Call/Observe/security-binding release; it makes no claim
    // that local cancel sends deregistration or reverses a delivered request.
    client.transport_mut().begin();
    let cancelled = client
        .get("obs")
        .block2(first_block())
        .observe()
        .to(server_peer)
        .send(now(origin))
        .map_err(|_| "cancel_probe_send")?;
    if !client.cancel(cancelled) {
        return Err("cancel_refused");
    }
    if !matches!(
        client.take_response(cancelled),
        Some(Err(CallFailure::Cancelled))
    ) || client.take_response(cancelled).is_some()
        || client.cancel(cancelled)
    {
        return Err("cancel_terminal_lifetime");
    }
    let mut discard = [0; WIRE];
    let start = Instant::now();
    let mut discarded = false;
    for _ in 0..ROUNDS {
        if start.elapsed() >= DEADLINE {
            return Err("cancel_discard_deadline");
        }
        if let Some((n, peer)) = server
            .transport_mut()
            .recv(&mut discard)
            .map_err(|_| "cancel_discard_receive")?
        {
            let p = decode(&discard[..n]).map_err(|_| "cancel_discard_decode")?;
            if peer != client_peer || p.token() != cancelled.token() || p.observe() != Some(Ok(0)) {
                return Err("cancel_discard_identity");
            }
            discarded = true;
            break;
        }
    }
    if !discarded || registered(&server, cancelled, client_peer) {
        return Err("cancel_not_undelivered");
    }
    client.transport_mut().begin();
    let fresh = client
        .get("obs")
        .block2(first_block())
        .to(server_peer)
        .send(now(origin))
        .map_err(|_| "recovery_get_send")?;
    complete(
        &mut server,
        &mut client,
        origin,
        Expected {
            call: fresh,
            version: 1,
            observe: None,
            ty: Type::Acknowledgement,
        },
        &mut counts,
    )?;
    client.transport_mut().begin();
    let again = client
        .get("obs")
        .block2(first_block())
        .observe()
        .to(server_peer)
        .send(now(origin))
        .map_err(|_| "recovery_register_send")?;
    complete(
        &mut server,
        &mut client,
        origin,
        Expected {
            call: again,
            version: 1,
            observe: Some(0),
            ty: Type::Acknowledgement,
        },
        &mut counts,
    )?;
    if !registered(&server, again, client_peer) {
        return Err("recovery_interest_missing");
    }
    deregister(&mut server, &mut client, origin, again, &mut counts)?;
    let s = server.transport();
    let c = client.transport();
    if s.sent != c.received || c.sent != s.received {
        return Err("datagram_accounting");
    }
    if protected
        && (s.protected_sent == 0
            || c.protected_sent == 0
            || s.protected_sent != c.protected_received
            || c.protected_sent != s.protected_received)
    {
        return Err("security_accounting");
    }
    let security = if protected { "oscore" } else { "unprotected" };
    let report = format!(
        concat!(
            "{{\"schema\":\"coaptic-native-observe-proof/1\",\"cohort\":\"small-device-blockwise-observe\",\"security\":\"{}\",\"success\":true,\"functional_only\":true,",
            "\"body_bytes\":4096,\"completed\":{},\"verified_bytes\":{},\"initial_registrations\":1,\"changed_notifications\":1,\"recovery_registrations\":1,\"fresh_gets\":1,\"deregistrations\":{},\"local_cancellations\":1,\"controlled_undelivered_datagrams\":1,\"call_capacity_refusals\":{},\"poll_calls\":{},",
            "\"bounds\":{{\"rounds_per_operation\":128,\"deadline_ms_per_operation\":3000,\"combined_send_limit\":256,\"combined_receive_limit\":256,\"json_limit_bytes\":16384}},",
            "\"counts\":{{\"server_sent\":{},\"server_received\":{},\"client_sent\":{},\"client_received\":{},\"server_protected_sent\":{},\"client_protected_sent\":{},\"client_controls_sent\":{}}},",
            "\"server\":{{\"profile\":\"SmallDevice\",\"pools\":\"Constrained+WithObserve<1>\",\"storage\":\"fixed\",\"routes\":4,\"populated_routes\":1,\"calls\":1,\"deferred\":0,\"associations\":1,\"security_requests\":4,\"observe\":1,\"blockwise\":true,\"rx_slots\":2,\"tx_slots\":2,\"datagram_bytes\":1152,\"dedup\":4,\"rx_body_slots\":1,\"tx_body_slots\":1,\"rx_body_bytes\":4096,\"tx_body_bytes\":4096}},",
            "\"client\":{{\"profile\":\"observe-proof-client\",\"storage\":\"allocated\",\"routes\":1,\"populated_routes\":0,\"calls\":1,\"deferred\":0,\"associations\":1,\"security_requests\":4,\"observe\":1,\"blockwise\":true,\"rx_slots\":2,\"tx_slots\":2,\"datagram_bytes\":1152,\"dedup\":4,\"rx_body_slots\":1,\"tx_body_slots\":1,\"rx_body_bytes\":4096,\"tx_body_bytes\":1024}},",
            "\"memory\":{{\"server_app_including_transport_inline_bytes\":{},\"server_pool_requested_heap_bytes\":0,\"client_app_including_transport_inline_bytes\":{},\"client_pool_requested_heap_bytes\":{},\"each_transport_nested_in_app_inline_bytes\":{},\"each_udp_scratch_nested_in_transport_bytes\":1153,\"each_mid_audit_nested_in_transport_bytes\":256,\"separate_body_fixtures_static_bytes\":8192,\"separate_version_static_bytes\":1,\"separate_cancel_discard_stack_bytes\":1152,\"separate_counts_stack_bytes\":{},\"nesting\":\"fixed pools and crypto state inside server App; client pool layouts including metadata in requested heap; transport including socket handle, scratch and audit inside each App; report and fixture owners separate; do not add nested owners twice\",\"allocator_overhead_bytes\":null,\"initialization_stack_bytes\":null,\"peak_stack_bytes\":null,\"kernel_socket_bytes\":null,\"runtime_bytes\":null,\"report_heap_bytes\":null}},",
            "\"validation\":\"each wire MID/token/security envelope; exact complete body, ETag, format, Max-Age, peer and Observe; OSCORE App authenticates every accepted fragment with its sole context; first-fragment metadata checked only against first wire fragment\",",
            "\"scope\":\"two Coaptic Apps over real loopback UDP; client Call refusal and recovery; explicit remote deregistration; local cancellation with controlled undelivered registration; no CPU timing, independent peer, server Observe overflow, whole-memory or either 50% acceptance\"}}"
        ),
        security,
        counts.completed,
        counts.verified_bytes,
        counts.deregistrations,
        counts.call_refusals,
        counts.polls,
        s.sent,
        s.received,
        c.sent,
        c.received,
        s.protected_sent,
        c.protected_sent,
        c.controls_sent,
        std::mem::size_of_val(&server),
        std::mem::size_of_val(&client),
        heap,
        std::mem::size_of::<Io>(),
        std::mem::size_of::<Counts>()
    );
    if report.len() > 16 * 1024 {
        return Err("json_budget");
    }
    Ok(report)
}
fn parse_mode(value: Option<&str>, extra: bool) -> Result<bool> {
    if extra {
        return Err(USAGE);
    }
    match value {
        Some("unprotected") => Ok(false),
        Some("oscore") => Ok(true),
        _ => Err(USAGE),
    }
}
fn main() -> std::process::ExitCode {
    let mut args = std::env::args();
    let _ = args.next();
    let mode = args.next();
    let protected = match parse_mode(mode.as_deref(), args.next().is_some()) {
        Ok(mode) => mode,
        Err(why) => {
            eprintln!("{why}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match run(protected) {
        Ok(report) => {
            println!("{report}");
            std::process::ExitCode::SUCCESS
        }
        Err(why) => {
            // Every error is a fixed internal label; no escaping/unbounded log.
            println!(
                "{{\"schema\":\"coaptic-native-observe-proof/1\",\"cohort\":\"small-device-blockwise-observe\",\"security\":\"{}\",\"success\":false,\"functional_only\":true,\"failure\":\"{why}\"}}",
                if protected { "oscore" } else { "unprotected" }
            );
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coaptic::message::{Message, Opt, encode};

    fn sockets(side: Side, protected: bool) -> (Io, UdpSocket) {
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        let address = Endpoint::from(peer.local_addr().unwrap());
        (Io::new(local, address, side, protected).unwrap(), peer)
    }
    fn packet(
        ty: Type,
        code: Code,
        mid: u16,
        token: &[u8],
        options: &[Opt<'_>],
    ) -> ([u8; WIRE], usize) {
        let message = Message::new(ty, code, MessageId::new(mid))
            .with_token(Token::new(token).unwrap())
            .with_options(options);
        let mut bytes = [0; WIRE];
        let len = encode(&message, &mut bytes).unwrap();
        (bytes, len)
    }
    fn request() -> ([u8; WIRE], usize) {
        packet(Type::Confirmable, Code::GET, 17, b"owner", &[])
    }

    #[test]
    fn fixtures_change_every_byte_in_every_block() {
        assert!(VERSION_0.iter().zip(VERSION_1.iter()).all(|(a, b)| a != b));
        assert!(verify_bytes(Some(&VERSION_0), 0).is_ok());
        assert!(verify_bytes(Some(&VERSION_1), 1).is_ok());
        assert!(verify_bytes(Some(&VERSION_0), 1).is_err());
    }
    #[test]
    fn corruption_in_each_block_is_refused() {
        for block in 0..4 {
            let mut bytes = VERSION_1;
            bytes[block * 1024 + 997] ^= 1;
            assert_eq!(
                verify_bytes(Some(&bytes), 1),
                Err("incomplete_or_corrupt_body")
            );
        }
    }
    #[test]
    fn incomplete_representations_are_never_completions() {
        for n in [0, 128, 1024, 2048, 3072, 4095] {
            assert!(verify_bytes(Some(&VERSION_0[..n]), 0).is_err());
        }
        assert!(verify_bytes(None, 0).is_err());
    }
    #[test]
    fn response_metadata_errors_precede_body_acceptance() {
        assert_eq!(verify_body(&Response::not_found(), 0), Err("response_code"));
    }
    #[test]
    fn wrong_format_etag_and_age_are_refused() {
        let response = representation(&VERSION_0, b"v0");
        assert_eq!(
            verify_body(&response.content_format(ContentFormat::TEXT_PLAIN), 0),
            Err("response_format")
        );
        assert_eq!(
            verify_body(&response.etag(b"wrong"), 0),
            Err("response_etag")
        );
        assert_eq!(
            verify_body(&response.max_age(59), 0),
            Err("response_max_age")
        );
        assert_eq!(verify_body(&response, 0), Err("incomplete_or_corrupt_body"));
    }
    #[test]
    fn cli_requires_one_explicit_security_selection() {
        assert_eq!(parse_mode(Some("oscore"), false), Ok(true));
        assert_eq!(parse_mode(Some("unprotected"), false), Ok(false));
        for (mode, extra) in [(None, false), (Some("dtls"), false), (Some("oscore"), true)] {
            assert!(parse_mode(mode, extra).is_err());
        }
    }
    #[test]
    fn wire_ack_matches_each_request_mid() {
        let (mut io, _) = sockets(Side::Client, false);
        let (bytes, len) = request();
        io.check(&bytes[..len], true).unwrap();
        let (wrong, n) = packet(Type::Acknowledgement, Code::CONTENT, 18, b"owner", &[]);
        assert!(io.check(&wrong[..n], false).is_err());
        let (right, n) = packet(Type::Acknowledgement, Code::CONTENT, 17, b"owner", &[]);
        io.check(&right[..n], false).unwrap();
    }
    #[test]
    fn wire_response_token_is_exact() {
        let (mut io, _) = sockets(Side::Client, false);
        let (bytes, len) = request();
        io.check(&bytes[..len], true).unwrap();
        let (wrong, n) = packet(Type::Acknowledgement, Code::CONTENT, 17, b"other", &[]);
        assert!(io.check(&wrong[..n], false).is_err());
    }
    #[test]
    fn security_envelope_cannot_silently_downgrade() {
        let (mut io, _) = sockets(Side::Client, true);
        let (bytes, len) = request();
        assert!(io.check(&bytes[..len], true).is_err());
        let (bytes, len) = packet(
            Type::Confirmable,
            Code::POST,
            17,
            b"owner",
            &[Opt::oscore(&[0])],
        );
        io.check(&bytes[..len], true).unwrap();
        let (mut plain, _) = sockets(Side::Client, false);
        assert!(plain.check(&bytes[..len], true).is_err());
    }
    #[test]
    fn notification_ack_requires_exact_mid_and_empty_shape() {
        let (mut io, _) = sockets(Side::Client, false);
        let (bytes, len) = request();
        io.check(&bytes[..len], true).unwrap();
        let (note, n) = packet(Type::Confirmable, Code::CONTENT, 90, b"owner", &[]);
        io.check(&note[..n], false).unwrap();
        let (wrong, n) = packet(Type::Acknowledgement, Code::EMPTY, 91, b"", &[]);
        assert!(io.check(&wrong[..n], true).is_err());
        // Intentionally malformed empty ACK with TKL=1, bypassing the encoder
        // which correctly refuses to construct such a message.
        assert!(io.check(&[0x61, 0, 0, 90, b'x'], true).is_err());
        let (ack, n) = packet(Type::Acknowledgement, Code::EMPTY, 90, b"", &[]);
        io.check(&ack[..n], true).unwrap();
    }
    #[test]
    fn send_budget_refuses_before_socket_io() {
        let (mut io, peer) = sockets(Side::Client, false);
        io.sent = PER_ENDPOINT_DATAGRAMS;
        let (bytes, len) = request();
        assert!(io.send(io.peer, &bytes[..len]).is_err());
        let mut received = [0; WIRE];
        assert_eq!(
            peer.recv_from(&mut received).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn guarded_udp_refuses_oversize_then_accepts_fresh_complete_datagram() {
        let (mut io, peer) = sockets(Side::Server, false);
        let dest = io.udp.socket().local_addr().unwrap();
        peer.send_to(&[0; WIRE + 1], dest).unwrap();
        let mut buf = [0; WIRE];
        assert!(io.recv(&mut buf).is_err());
        assert_eq!(io.received, 0);
        let (bytes, n) = request();
        peer.send_to(&bytes[..n], dest).unwrap();
        let (got, _) = io.recv(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..got], &bytes[..n]);
        assert_eq!(io.received, 1);
    }
    #[test]
    fn udp_rejects_unexpected_peer() {
        let (mut io, _) = sockets(Side::Server, false);
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (bytes, n) = request();
        stranger
            .send_to(&bytes[..n], io.udp.socket().local_addr().unwrap())
            .unwrap();
        assert!(io.recv(&mut [0; WIRE]).is_err());
    }
    #[test]
    fn local_cancel_and_collection_release_call_capacity() {
        let (io, _receiver) = sockets(Side::Client, false);
        let peer = io.peer;
        let heap = AllocMemory::<Token>::required_heap_bytes(client_caps()).unwrap();
        let mut app = client(io, None, heap).unwrap();
        let call = app
            .get("obs")
            .block2(first_block())
            .observe()
            .to(peer)
            .send(0)
            .unwrap();
        refuse_extra_call(&mut app, peer, 0).unwrap();
        assert!(app.cancel(call));
        assert_eq!(
            app.take_response(call).unwrap().unwrap_err(),
            CallFailure::Cancelled
        );
        assert!(app.take_response(call).is_none());
        assert!(!app.cancel(call));
        assert!(
            app.get("obs")
                .block2(first_block())
                .observe()
                .to(peer)
                .send(0)
                .is_ok()
        );
    }
    #[test]
    fn server_resources_are_exact_small_device_with_one_observer() {
        let caps = coaptic::resources::SmallDevice::new()
            .block_wise::<true>()
            .observe_entries::<1>()
            .pool_capacities();
        assert_eq!(
            (
                caps.rx_datagram_slots,
                caps.tx_datagram_slots,
                caps.rx_datagram_bytes,
                caps.tx_datagram_bytes
            ),
            (2, 2, WIRE, WIRE)
        );
        assert_eq!((caps.dedup_entries, caps.observe_entries), (4, 1));
        assert_eq!(
            (
                caps.rx_body_slots,
                caps.tx_body_slots,
                caps.rx_body_bytes,
                caps.tx_body_bytes
            ),
            (Some(1), Some(1), Some(BYTES), Some(BYTES))
        );
    }
}
