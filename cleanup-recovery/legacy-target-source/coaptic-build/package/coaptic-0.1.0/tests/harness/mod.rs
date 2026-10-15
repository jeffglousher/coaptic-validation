//! Shared validation-harness helpers for Block/Q-Block sweep and plugtest.
//!
//! Integration tests may use `std`. The library under test stays `no_std`.
//! A large [`SweepProfile`] (32 × 1024 body bytes) is used so Default 4096
//! is not the ceiling.
#![allow(dead_code)]

use coaptic::message::{BlockValue, Ids, Message, MessageId, Opt, OptionsBuilder, Token, Type};
use coaptic::storage::{
    BlockKey, BodyPool, DatagramPool, DatagramScratch, DedupTable, Engine, EngineBuilder,
    ExchangeTable, Memory, MemoryProfile, ObserveTable, SlotId, WithBodies,
};
use coaptic::{Code, ContentFormat, Endpoint};

/// Body capacity for the sweep: 32 × 1024 (25 × 1024 must fit).
pub const SWEEP_BODY_BYTES: usize = 32 * 1024;

/// Datagram slot count: enough for one Q-Block `MAX_PAYLOADS` window.
pub const SWEEP_DGRAM_SLOTS: usize = 16;

/// Datagram slot bytes (crate default, IPv4 UDP max on Ethernet).
pub const SWEEP_DGRAM_BYTES: usize = 1472;

/// Legal SZX sizes, smallest to largest (RFC 7959 / RFC 9177).
pub const SZX_SIZES: [u16; 7] = [16, 32, 64, 128, 256, 512, 1024];

/// Body length in blocks, inclusive (policy: 1 through 25).
pub const BLOCK_COUNTS: core::ops::RangeInclusive<u32> = 1..=25;

/// Large test profile. Not a shipped profile; Default 4096 is not the ceiling.
pub struct SweepProfile;

impl MemoryProfile for SweepProfile {
    const RX_DATAGRAM_SLOTS: usize = SWEEP_DGRAM_SLOTS;
    const RX_DATAGRAM_BYTES: usize = SWEEP_DGRAM_BYTES;
    const TX_DATAGRAM_SLOTS: usize = SWEEP_DGRAM_SLOTS;
    const TX_DATAGRAM_BYTES: usize = SWEEP_DGRAM_BYTES;
    const DEDUP_ENTRIES: usize = 16;
    const OBSERVE_ENTRIES: usize = 8;
    const RX_BODY_SLOTS: usize = 2;
    const RX_BODY_BYTES: usize = SWEEP_BODY_BYTES;
    const TX_BODY_SLOTS: usize = 2;
    const TX_BODY_BYTES: usize = SWEEP_BODY_BYTES;

    type RxDatagram = DatagramPool<SWEEP_DGRAM_SLOTS, SWEEP_DGRAM_BYTES>;
    type TxDatagram = DatagramPool<SWEEP_DGRAM_SLOTS, SWEEP_DGRAM_BYTES>;
    type RxBody = BodyPool<2, SWEEP_BODY_BYTES>;
    type TxBody = BodyPool<2, SWEEP_BODY_BYTES>;
    type Dedup = DedupTable<16>;
    type Observe = ObserveTable<8>;
    type Exchange = ExchangeTable<SWEEP_DGRAM_SLOTS>;
    type RxScratch = DatagramScratch<SWEEP_DGRAM_BYTES>;
    type TxScratch = DatagramScratch<SWEEP_DGRAM_BYTES>;
}

/// Engine used by the harness (block-wise on, large body).
pub type HarnessEngine = Engine<Memory<SweepProfile, WithBodies<SweepProfile>>>;

/// Build one large-body engine. Heap-box it at the call site if stack is tight.
#[must_use]
pub fn build_engine() -> HarnessEngine {
    EngineBuilder::new()
        .profile::<SweepProfile>()
        .block_wise(true)
        .build(Memory::<SweepProfile>::with_block_wise())
        .expect("SweepProfile block-wise build")
}

/// Deterministic body: `len` bytes, value `i % 251`.
#[must_use]
pub fn patterned_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Slice of `body` for classic / Q-Block NUM `num` at `size` bytes.
#[must_use]
pub fn block_slice(body: &[u8], num: u32, size: u16) -> &[u8] {
    let size = usize::from(size);
    let start = (num as usize)
        .checked_mul(size)
        .unwrap_or_else(|| panic!("NUM {num} × {size} overflow"));
    assert!(
        start < body.len() || (start == body.len() && body.is_empty()),
        "NUM {num} starts at {start} past body {}",
        body.len()
    );
    let end = start.saturating_add(size).min(body.len());
    &body[start..end]
}

/// Client / server loopback pair: two Engines exchanging datagram bytes.
pub struct Pair {
    /// Client engine (requests originate here).
    pub client: Box<HarnessEngine>,
    /// Server engine (resources live here).
    pub server: Box<HarnessEngine>,
    /// Client UDP identity (sidecar on server RX).
    pub client_ep: Endpoint,
    /// Server UDP identity (sidecar on client RX).
    pub server_ep: Endpoint,
    /// Client Message ID sequence.
    pub client_ids: Ids,
    /// Server Message ID sequence.
    pub server_ids: Ids,
    /// Caller clock for pending CON / progress.
    pub now_ms: u64,
}

impl Pair {
    /// Two engines, distinct documentation endpoints.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Box::new(build_engine()),
            server: Box::new(build_engine()),
            client_ep: Endpoint::v4([192, 0, 2, 1], 5683),
            server_ep: Endpoint::v4([192, 0, 2, 2], 5683),
            client_ids: Ids::new(0x1000),
            server_ids: Ids::new(0x8000),
            now_ms: 0,
        }
    }

    /// Copy occupied client TX bytes into a new server RX slot.
    pub fn client_to_server(&mut self, tx: SlotId) -> SlotId {
        deliver(&mut self.client, tx, &mut self.server, self.client_ep)
    }

    /// Copy occupied server TX bytes into a new client RX slot.
    pub fn server_to_client(&mut self, tx: SlotId) -> SlotId {
        deliver(&mut self.server, tx, &mut self.client, self.server_ep)
    }

    /// Build a CON/NON request (path + extras + payload) and send it.
    pub fn client_request(
        &mut self,
        ty: Type,
        code: Code,
        token: Token,
        path: &[&str],
        extra: &[Opt<'_>],
        payload: &[u8],
    ) -> (SlotId, MessageId) {
        let mut opts = OptionsBuilder::<16>::new();
        push_path(&mut opts, path, extra);
        let msg = request_skeleton(&mut self.client_ids, ty, code, token)
            .with_options(opts.as_slice())
            .with_payload(payload);
        let mid = msg.message_id();
        (self.client_send(&msg), mid)
    }

    /// Record pending CON on an already-sent client TX (`NSTART` is 1).
    pub fn client_track_con(&mut self, tx: SlotId, mid: MessageId) {
        self.client
            .record_pending_con(tx, self.server_ep, mid, self.now_ms, 0)
            .expect("pending CON");
    }

    /// Encode a response on the server and send it. Caller supplies options.
    pub fn server_reply(
        &mut self,
        ty: Type,
        code: Code,
        mid: MessageId,
        token: Token,
        extra: &[Opt<'_>],
        payload: &[u8],
    ) -> SlotId {
        let mut opts = OptionsBuilder::<16>::new();
        for opt in extra {
            opts.push(*opt).expect("extra");
        }
        let msg = Message::new(ty, code, mid)
            .with_token(token)
            .with_options(opts.as_slice())
            .with_payload(payload);
        self.server_send(&msg)
    }

    /// Piggybacked 2.05 with Content-Format 0 and `payload`.
    pub fn server_content(
        &mut self,
        mid: MessageId,
        token: Token,
        extra: &[Opt<'_>],
        payload: &[u8],
    ) -> SlotId {
        let cf = ContentFormat::TEXT_PLAIN.encode();
        let mut opts = OptionsBuilder::<16>::new();
        opts.push(Opt::content_format(&cf)).expect("cf");
        for opt in extra {
            opts.push(*opt).expect("extra");
        }
        let msg = Message::new(Type::Acknowledgement, Code::CONTENT, mid)
            .with_token(token)
            .with_options(opts.as_slice())
            .with_payload(payload);
        self.server_send(&msg)
    }

    /// Encode `msg` on the client TX pool, record exchange (+ pending CON).
    pub fn client_send(&mut self, msg: &Message<'_>) -> SlotId {
        let tx = self.client.acquire_tx().expect("client TX");
        self.client.encode_tx(tx, msg).expect("encode client TX");
        self.client
            .set_tx_endpoint(tx, self.server_ep)
            .expect("client TX endpoint");
        self.client
            .record_request(tx, self.server_ep)
            .expect("record request");
        tx
    }

    /// Encode `msg` on the server TX pool (optional pending CON).
    pub fn server_send(&mut self, msg: &Message<'_>) -> SlotId {
        let tx = self.server.acquire_tx().expect("server TX");
        self.server.encode_tx(tx, msg).expect("encode server TX");
        self.server
            .set_tx_endpoint(tx, self.client_ep)
            .expect("server TX endpoint");
        if msg.ty() == Type::Confirmable {
            self.server
                .record_pending_con(tx, self.client_ep, msg.message_id(), self.now_ms, 0)
                .expect("pending CON");
        }
        tx
    }

    /// Deliver client TX to server. Pending CON TX stays occupied for ACK/RST match.
    pub fn exchange_client(&mut self, tx: SlotId) -> SlotId {
        let rx = self.client_to_server(tx);
        if self.client.pending_con(tx).is_none() {
            self.client.release_tx(tx).expect("release client TX");
        }
        rx
    }

    /// Deliver server TX to client. Pending CON TX stays occupied for ACK/RST match.
    pub fn exchange_server(&mut self, tx: SlotId) -> SlotId {
        let rx = self.server_to_client(tx);
        if self.server.pending_con(tx).is_none() {
            self.server.release_tx(tx).expect("release server TX");
        }
        rx
    }

    /// Mint a client Token of `len` bytes (1..=8) from a fixed entropy stream.
    #[must_use]
    pub fn client_token(len: usize) -> Token {
        Token::mint(len, &[0xC0, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07]).expect("token length")
    }
}

impl Default for Pair {
    fn default() -> Self {
        Self::new()
    }
}

fn deliver(
    from: &mut HarnessEngine,
    tx: SlotId,
    to: &mut HarnessEngine,
    from_ep: Endpoint,
) -> SlotId {
    let mut buf = [0u8; SWEEP_DGRAM_BYTES];
    let n = {
        let access = from.access_tx(tx).expect("pin source TX");
        let bytes = access.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        bytes.len()
    };
    let rx = to
        .acquire_rx()
        .unwrap_or_else(|| panic!("RX saturated (from {from_ep})"));
    to.write_rx(rx, &buf[..n], from_ep)
        .unwrap_or_else(|e| panic!("write_rx from {from_ep}: {e:?}"));
    rx
}

/// Collect Uri-Path segments (fail on non-UTF-8).
#[must_use]
pub fn uri_path(parsed: coaptic::message::ParsedMessage<'_>) -> Vec<String> {
    parsed
        .uri_path()
        .map(|item| item.expect("Uri-Path UTF-8").to_owned())
        .collect()
}

/// Collect Uri-Query values (fail on non-UTF-8).
#[must_use]
pub fn uri_query(parsed: coaptic::message::ParsedMessage<'_>) -> Vec<String> {
    parsed
        .uri_query()
        .map(|item| item.expect("Uri-Query UTF-8").to_owned())
        .collect()
}

/// Whether Uri-Path equals `segs`.
#[must_use]
pub fn path_is(parsed: coaptic::message::ParsedMessage<'_>, segs: &[&str]) -> bool {
    uri_path(parsed) == segs
}

/// Fill `opts` with Uri-Path `path` then `extra`.
pub fn push_path<'a>(opts: &mut OptionsBuilder<'a, 16>, path: &[&'a str], extra: &[Opt<'a>]) {
    for seg in path {
        opts.push(Opt::uri_path(seg)).expect("path room");
    }
    for opt in extra {
        opts.push(*opt).expect("extra room");
    }
}

/// CON/NON skeleton with the next Message ID (caller attaches options).
#[must_use]
pub fn request_skeleton(ids: &mut Ids, ty: Type, code: Code, token: Token) -> Message<'static> {
    let mid = ids.next();
    match ty {
        Type::Confirmable => Message::con(code, mid, token),
        Type::NonConfirmable => Message::non(code, mid, token),
        Type::Acknowledgement | Type::Reset => panic!("request_skeleton is CON/NON only"),
    }
}

/// RFC 7959 2.31 Continue (not a crate-root constant; Engine does not invent it).
#[must_use]
pub fn code_continue() -> Code {
    Code::from_class_detail(2, 31).expect("2.31")
}

/// Block identity for `token` toward `endpoint`.
#[must_use]
pub fn block_key(token: Token, endpoint: Endpoint) -> BlockKey {
    BlockKey::new(token, endpoint)
}

/// Legal [`BlockValue`] for `num` / `more` / `size`.
#[must_use]
pub fn block_at(num: u32, more: bool, size: u16) -> BlockValue {
    BlockValue::from_size(num, more, size)
        .unwrap_or_else(|e| panic!("illegal Block NUM={num} more={more} size={size}: {e:?}"))
}

/// Release the incoming / outgoing body slots for `key`, if occupied.
pub fn release_bodies(engine: &mut HarnessEngine, key: BlockKey) {
    if let Some(id) = engine.lookup_rx_body(key) {
        let _ = engine.release_rx_body(id);
    }
    if let Some(id) = engine.lookup_tx_body(key) {
        let _ = engine.release_tx_body(id);
    }
}
