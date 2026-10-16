//! USB commissioning, durable device identity/policy and automatic EDHOC recovery.
//!
//! USB is a privileged local administration channel. The trusted host verifies
//! the operator's hardware proof before sending an exact update. Never forward
//! these commands from UDP, discovery or an untrusted host. Ordinary NVS survives
//! normal restart; physical flash rollback/custody hardening is a separate option.
//! A single complete CBOR blob commits the private identity, public policy and
//! endpoint together. Failed or uncertain writes stop every live session.
#![forbid(unsafe_code)]

use coaptic::platform::{CheckedClock, ClockError};
use coaptic::provisioning::{
    CommissioningDecoder, CommissioningReply, CommissioningRequest, Identity, LocalPairing,
    ManagedConnection, ManagedError, PairingCommitError, PairingRecord,
};
use coaptic::storage::DatagramIo;
use coaptic::{Code, ContentFormat, Endpoint, Method, Response, profiles};
use zeroize::Zeroizing;

pub const STORE_BYTES: usize = 320;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Storage,
    Identity,
    Console,
    Protocol,
    Clock,
    Network,
    Permissions,
}

/// The backend compares the complete prior blob and confirms commit/readback.
/// An empty read means an explicitly uninitialized store, never a parse fallback.
pub trait Store {
    fn read(&mut self, output: &mut [u8; STORE_BYTES]) -> Result<usize, Error>;
    fn commit(&mut self, expected: &[u8], next: &[u8]) -> Result<(), Error>;
}

/// Synchronous borrowed buffers on the sole privileged USB channel.
pub trait Console {
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, Error>;
    fn write(&mut self, bytes: &[u8]) -> Result<(), Error>;
    fn restart(&mut self) -> Result<(), Error>;
    /// Public counters only: 1 recovered, 2 initialized, 3 connected, 4 receipt.
    fn event(&mut self, event: u32);
}

struct Device {
    identity: Identity,
    private: Zeroizing<[u8; 32]>,
    pairing: LocalPairing,
    endpoint: Option<Endpoint>,
    stored: Zeroizing<[u8; STORE_BYTES]>,
    stored_len: usize,
}

impl Device {
    fn recover(store: &mut impl Store) -> Result<Option<Self>, Error> {
        let mut stored = Zeroizing::new([0; STORE_BYTES]);
        let len = store.read(&mut stored)?;
        if len == 0 {
            return Ok(None);
        }
        if len > STORE_BYTES {
            return Err(Error::Storage);
        }
        let (private, kid, record, endpoint) = decode_store(&stored[..len])?;
        let identity = Identity::from_private_key(*private, kid).map_err(|_| Error::Identity)?;
        let pairing = LocalPairing::restore(&identity, record).map_err(|_| Error::Storage)?;
        if pairing.checkpoint().enabled() && endpoint.is_none() {
            return Err(Error::Storage);
        }
        Ok(Some(Self {
            identity,
            private,
            pairing,
            endpoint,
            stored,
            stored_len: len,
        }))
    }

    fn initialize(
        store: &mut impl Store,
        kid: u8,
        random: fn(&mut [u8]) -> bool,
    ) -> Result<Self, Error> {
        let mut store_id = [0; 32];
        if !random(&mut store_id) || store_id == [0; 32] {
            return Err(Error::Identity);
        }
        let mut private = Zeroizing::new([0; 32]);
        let mut record = None;
        let mut stored = Zeroizing::new([0; STORE_BYTES]);
        let mut stored_len = 0;
        let identity = Identity::provision(kid, random, |scalar, _| {
            let candidate =
                Identity::from_private_key(*scalar, kid).map_err(|_| Error::Identity)?;
            let next =
                PairingRecord::unpaired(&candidate, store_id).map_err(|_| Error::Identity)?;
            let len = encode_store(scalar, kid, &next, None, &mut stored)?;
            store.commit(&[], &stored[..len])?;
            private.copy_from_slice(scalar);
            stored_len = len;
            record = Some(next);
            Ok::<_, Error>(())
        })
        .map_err(|_| Error::Storage)?;
        let pairing = LocalPairing::restore(&identity, record.ok_or(Error::Storage)?)
            .map_err(|_| Error::Storage)?;
        Ok(Self {
            identity,
            private,
            pairing,
            endpoint: None,
            stored,
            stored_len,
        })
    }

    fn reply(&self) -> CommissioningReply {
        CommissioningReply::State {
            device: self.identity.peer(),
            record: self.pairing.checkpoint().clone(),
        }
    }
}

/// The factory reuses the platform-owned socket after dropping the previous
/// whole session owner. It must never expose two live owners simultaneously.
/// Clock callbacks yield fairly, remain monotonic and return None to stop.
pub fn run<T: DatagramIo, S: Store, C: Console>(
    mut socket: impl FnMut() -> T,
    random: fn(&mut [u8]) -> bool,
    mut clock: impl FnMut() -> Option<u64>,
    mut store: S,
    mut console: C,
) -> Result<(), Error> {
    let mut device = Device::recover(&mut store)?;
    if device.is_some() {
        console.event(1);
    }
    let mut decoder = CommissioningDecoder::new();
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    let mut pending = None;
    loop {
        let Some(now) = next_time(&mut clock)? else {
            return Ok(());
        };
        let request = if let Some(request) = pending.take() {
            Some(request)
        } else {
            receive(&mut console, &mut decoder)?
        };
        if let Some(request) = request {
            match request {
                CommissioningRequest::Inspect => {
                    send(
                        &mut console,
                        &device
                            .as_ref()
                            .map_or(CommissioningReply::Empty, Device::reply),
                    )?;
                }
                CommissioningRequest::Initialize { kid } => {
                    if device.is_some() {
                        send(&mut console, &CommissioningReply::Refused(1))?;
                    } else {
                        // An ambiguous identity write stops instead of returning to
                        // an apparent empty state and generating another key.
                        device = Some(Device::initialize(&mut store, kid, random)?);
                        console.event(2);
                        send(
                            &mut console,
                            &device.as_ref().ok_or(Error::Identity)?.reply(),
                        )?;
                    }
                }
                CommissioningRequest::Challenge => {
                    if let Some(device) = &mut device {
                        let challenge = device
                            .pairing
                            .begin(&device.identity, now, random)
                            .map_err(|_| Error::Protocol)?;
                        send(&mut console, &CommissioningReply::Challenge(challenge))?;
                    } else {
                        send(&mut console, &CommissioningReply::Refused(2))?;
                    }
                }
                CommissioningRequest::Update { update, endpoint } => {
                    let Some(device) = &mut device else {
                        send(&mut console, &CommissioningReply::Refused(2))?;
                        continue;
                    };
                    let mut next = Zeroizing::new([0; STORE_BYTES]);
                    let mut next_len = 0;
                    let result = update.apply(&mut device.pairing, now, |_, record| {
                        next_len = encode_store(
                            &device.private,
                            device.identity.peer().kid(),
                            record,
                            Some(endpoint),
                            &mut next,
                        )?;
                        store.commit(&device.stored[..device.stored_len], &next[..next_len])
                    });
                    match result {
                        Ok(()) => {
                            device.stored = next;
                            device.stored_len = next_len;
                            device.endpoint = Some(endpoint);
                            send(
                                &mut console,
                                &CommissioningReply::Committed(device.pairing.checkpoint().clone()),
                            )?;
                        }
                        Err(PairingCommitError::State(_)) => {
                            send(&mut console, &CommissioningReply::Refused(3))?
                        }
                        Err(PairingCommitError::Store(_)) => {
                            // No more network work after an uncertain write.
                            let _ = send(&mut console, &CommissioningReply::Refused(4));
                            return Err(Error::Storage);
                        }
                    }
                }
                CommissioningRequest::Restart => {
                    send(&mut console, &CommissioningReply::Restarting)?;
                    console.restart()?;
                    return Ok(());
                }
            }
        }
        if let Some(device) = &device
            && device.pairing.checkpoint().enabled()
        {
            // Returning a management request drops all old protocol caches,
            // exchanges and sessions before any policy mutation above.
            pending = session(
                device,
                socket(),
                random,
                &mut clock,
                &mut console,
                &mut decoder,
            )?;
            if pending.is_none() {
                return Ok(());
            }
        }
    }
}

fn next_time<F: FnMut() -> Result<u64, ()>>(
    clock: &mut CheckedClock<F>,
) -> Result<Option<u64>, Error> {
    match clock.now_ms() {
        Ok(now) => Ok(Some(now)),
        Err(ClockError::Source(())) => Ok(None),
        Err(ClockError::Regressed { .. }) => Err(Error::Clock),
    }
}

fn receive(
    console: &mut impl Console,
    decoder: &mut CommissioningDecoder,
) -> Result<Option<CommissioningRequest>, Error> {
    // One byte per read preserves bytes following a complete command. Work is
    // capped at64 bytes per scheduler iteration, including console log noise.
    for _ in 0..64 {
        let mut byte = [0];
        match console.read(&mut byte)? {
            0 => break,
            1 => {
                if let Some(payload) = decoder.feed(byte[0]) {
                    return CommissioningRequest::decode(payload)
                        .map(Some)
                        .map_err(|_| Error::Protocol);
                }
            }
            _ => return Err(Error::Console),
        }
    }
    Ok(None)
}

fn send(console: &mut impl Console, reply: &CommissioningReply) -> Result<(), Error> {
    let mut payload = [0; 512];
    let len = reply.encode(&mut payload).map_err(|_| Error::Protocol)?;
    let mut frame = [0; 518];
    let len =
        CommissioningDecoder::frame(&payload[..len], &mut frame).map_err(|_| Error::Protocol)?;
    console.write(&frame[..len])
}

fn permissions(write: bool) -> [u8; 32] {
    blake3::derive_key(
        "coaptic local service permissions v1",
        if write {
            b"GET /identity;POST /echo".as_slice()
        } else {
            b"GET /identity".as_slice()
        },
    )
}

fn session<T: DatagramIo, F: FnMut() -> Result<u64, ()>>(
    device: &Device,
    socket: T,
    random: fn(&mut [u8]) -> bool,
    clock: &mut CheckedClock<F>,
    console: &mut impl Console,
    decoder: &mut CommissioningDecoder,
) -> Result<Option<CommissioningRequest>, Error> {
    let endpoint = device.endpoint.ok_or(Error::Storage)?;
    let peer = device
        .pairing
        .peer()
        .map_err(|_| Error::Network)?
        .principal();
    let permission = device
        .pairing
        .checkpoint()
        .policy()
        .ok_or(Error::Storage)?
        .resource_policy();
    let write = *permission == permissions(true);
    if !write && *permission != permissions(false) {
        return Err(Error::Permissions);
    }
    let Some(start) = next_time(clock)? else {
        return Ok(None);
    };
    let mut connection = ManagedConnection::<_, profiles::Constrained>::from_local_pairing(
        &device.identity,
        &device.pairing,
        endpoint,
        socket,
        random,
        start,
    )
    .map_err(|_| Error::Network)?;
    match connection.connect(start) {
        Ok(()) | Err(ManagedError::Recovery(_) | ManagedError::Busy | ManagedError::Capacity) => {}
        Err(_) => return Err(Error::Network),
    }
    let mut retry_at = start.saturating_add(30_000);
    let mut next_probe = start;
    let mut call = None;
    let mut connected_reported = false;
    let mut failed_polls = 0u8;
    let mut reply = [0; 128];
    let mut sample = [0; 45];
    sample[..4].copy_from_slice(&[0x83, 1, 0x58, 32]);
    sample[4..36].copy_from_slice(device.identity.peer().principal().fingerprint());
    sample[36] = 0x1b;
    loop {
        let Some(now) = next_time(clock)? else {
            return Ok(None);
        };
        if let Some(request) = receive(console, decoder)? {
            if matches!(request, CommissioningRequest::Inspect) {
                send(console, &device.reply())?;
            } else {
                return Ok(Some(request));
            }
        }
        match connection.poll_with(now, |_, request, _| {
            if request.path() == ["identity"] && request.method() == Some(Method::Get) {
                Response::content_copy(device.identity.peer().principal().fingerprint())
            } else if request.path() == ["echo"] && request.method() == Some(Method::Post) {
                if !write {
                    Response::new(Code::FORBIDDEN)
                } else if request.payload().len() > 128 {
                    Response::new(Code::REQUEST_ENTITY_TOO_LARGE)
                } else {
                    Response::content_copy(request.payload())
                }
            } else {
                Response::new(Code::NOT_FOUND)
            }
        }) {
            Ok(()) => failed_polls = 0,
            // A refused candidate preserves the old authenticated App. It is not
            // a plaintext command to replace that App or its keys.
            Err(ManagedError::Recovery(_)) => {}
            // A radio/link outage must not terminate USB management or require
            // another approval. This owner retains its encrypted call and timers.
            Err(ManagedError::Application(coaptic::app::Error::Io(_))) => {}
            Err(ManagedError::Trust(_) | ManagedError::Clock) => return Err(Error::Network),
            Err(_) => {
                failed_polls = failed_polls.saturating_add(1);
                if failed_polls >= 32 {
                    return Err(Error::Network);
                }
            }
        }
        if let Some(current) = call
            && let Some(response) = connection
                .take_response_into(current, &mut reply, now)
                .map_err(|_| Error::Network)?
        {
            call = None;
            match response {
                Ok(response)
                    if response.code() == Code::CONTENT
                        && response.payload()
                            == if write {
                                &sample[..]
                            } else {
                                peer.fingerprint()
                            } =>
                {
                    if !connected_reported {
                        console.event(3);
                        connected_reported = true;
                    }
                    console.event(4);
                    next_probe = now.saturating_add(5_000);
                    retry_at = u64::MAX;
                }
                _ => {
                    // A completed protected call's liveness failure permits
                    // a fresh handshake; keep this owner's MID/cache history.
                    retry_at = now;
                    next_probe = now.saturating_add(5_000);
                }
            }
        }
        if call.is_none() && now >= retry_at {
            match connection.connect(now) {
                Ok(()) => retry_at = now.saturating_add(30_000),
                Err(ManagedError::Busy | ManagedError::Capacity) => {
                    retry_at = now.saturating_add(1_000)
                }
                Err(_) => retry_at = now.saturating_add(5_000),
            }
        }
        if call.is_none() && connection.is_connected() && now >= next_probe {
            // A small native CBOR sample receives an exact protected receipt.
            // Read-only pairing uses an authenticated identity read instead.
            sample[37..].copy_from_slice(&now.to_be_bytes());
            let (method, path, payload, format) = if write {
                (Method::Post, "echo", &sample[..], Some(ContentFormat::CBOR))
            } else {
                (Method::Get, "identity", &[][..], None)
            };
            match connection.request(method, path, payload, format, now) {
                Ok(request) => call = Some(request),
                Err(ManagedError::Busy | ManagedError::NotConnected)
                | Err(ManagedError::Application(coaptic::app::Error::Io(_))) => {}
                Err(_) => return Err(Error::Network),
            }
        }
    }
}

fn encode_store(
    private: &[u8; 32],
    kid: u8,
    record: &PairingRecord,
    endpoint: Option<Endpoint>,
    output: &mut [u8; STORE_BYTES],
) -> Result<usize, Error> {
    let mut public = [0; 224];
    let length = record.encode(&mut public).map_err(|_| Error::Storage)?;
    let mut pos = 0;
    put(output, &mut pos, &[0x86, 1])?;
    if kid < 24 {
        put(output, &mut pos, &[kid])?;
    } else {
        put(output, &mut pos, &[0x18, kid])?;
    }
    put(output, &mut pos, &[0x58, 32])?;
    put(output, &mut pos, private)?;
    put(output, &mut pos, &[0x58, length as u8])?;
    put(output, &mut pos, &public[..length])?;
    if let Some(endpoint) = endpoint {
        let (address, port) = endpoint.as_ipv4().ok_or(Error::Storage)?;
        if address == [0; 4] || address[0] >= 224 || port == 0 {
            return Err(Error::Storage);
        }
        put(output, &mut pos, &[0x46])?;
        put(output, &mut pos, &address)?;
        put(output, &mut pos, &port.to_be_bytes())?;
    } else {
        put(output, &mut pos, &[0xf6])?;
    }
    let checksum = blake3::derive_key("coaptic device custody integrity v1", &output[..pos]);
    put(output, &mut pos, &[0x58, 32])?;
    put(output, &mut pos, &checksum)?;
    Ok(pos)
}

type Stored = (Zeroizing<[u8; 32]>, u8, PairingRecord, Option<Endpoint>);
fn decode_store(input: &[u8]) -> Result<Stored, Error> {
    if input.len() > STORE_BYTES {
        return Err(Error::Storage);
    }
    let mut cursor = Cursor {
        bytes: input,
        pos: 0,
    };
    cursor.exact(&[0x86, 1])?;
    let kid = match cursor.take(1)?[0] {
        value @ 0..=23 => value,
        0x18 => {
            let value = cursor.take(1)?[0];
            if value < 24 {
                return Err(Error::Storage);
            }
            value
        }
        _ => return Err(Error::Storage),
    };
    cursor.exact(&[0x58, 32])?;
    let private = Zeroizing::new(cursor.take(32)?.try_into().map_err(|_| Error::Storage)?);
    cursor.exact(&[0x58])?;
    let len = usize::from(cursor.take(1)?[0]);
    if !(24..=224).contains(&len) {
        return Err(Error::Storage);
    }
    let record = PairingRecord::decode(cursor.take(len)?).map_err(|_| Error::Storage)?;
    let endpoint = match cursor.take(1)?[0] {
        0xf6 => None,
        0x46 => {
            let bytes = cursor.take(6)?;
            let address: [u8; 4] = bytes[..4].try_into().map_err(|_| Error::Storage)?;
            let port = u16::from_be_bytes([bytes[4], bytes[5]]);
            if address == [0; 4] || address[0] >= 224 || port == 0 {
                return Err(Error::Storage);
            }
            Some(Endpoint::v4(address, port))
        }
        _ => return Err(Error::Storage),
    };
    let checksum = blake3::derive_key("coaptic device custody integrity v1", &input[..cursor.pos]);
    cursor.exact(&[0x58, 32])?;
    cursor.exact(&checksum)?;
    if cursor.pos != input.len() {
        return Err(Error::Storage);
    }
    Ok((private, kid, record, endpoint))
}

fn put(output: &mut [u8], pos: &mut usize, bytes: &[u8]) -> Result<(), Error> {
    let end = pos.checked_add(bytes.len()).ok_or(Error::Storage)?;
    output
        .get_mut(*pos..end)
        .ok_or(Error::Storage)?
        .copy_from_slice(bytes);
    *pos = end;
    Ok(())
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::Storage)?;
        let bytes = self.bytes.get(self.pos..end).ok_or(Error::Storage)?;
        self.pos = end;
        Ok(bytes)
    }
    fn exact(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.take(bytes.len())? != bytes {
            return Err(Error::Storage);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc, vec::Vec};

    #[derive(Default)]
    struct Memory {
        bytes: Vec<u8>,
        uncertain: bool,
    }
    impl Store for Memory {
        fn read(&mut self, output: &mut [u8; STORE_BYTES]) -> Result<usize, Error> {
            if self.bytes.len() > output.len() {
                return Err(Error::Storage);
            }
            output[..self.bytes.len()].copy_from_slice(&self.bytes);
            Ok(self.bytes.len())
        }
        fn commit(&mut self, expected: &[u8], next: &[u8]) -> Result<(), Error> {
            if self.bytes != expected {
                return Err(Error::Storage);
            }
            self.bytes = next.to_vec();
            if self.uncertain {
                Err(Error::Storage)
            } else {
                Ok(())
            }
        }
    }
    fn random(bytes: &mut [u8]) -> bool {
        getrandom::fill(bytes).is_ok()
    }

    #[test]
    fn unique_identity_recovers_and_corruption_never_authorizes_reinitialization() {
        let mut store = Memory::default();
        assert!(Device::recover(&mut store).unwrap().is_none());
        let device = Device::initialize(&mut store, 17, random).unwrap();
        let principal = device.identity.peer().principal();
        assert_eq!(
            Device::recover(&mut store)
                .unwrap()
                .unwrap()
                .identity
                .peer()
                .principal(),
            principal
        );
        assert!(Device::initialize(&mut store, 18, random).is_err());
        assert_eq!(
            Device::recover(&mut store)
                .unwrap()
                .unwrap()
                .identity
                .peer()
                .principal(),
            principal
        );
        for position in 0..store.bytes.len() {
            store.bytes[position] ^= 1;
            assert!(Device::recover(&mut store).is_err());
            store.bytes[position] ^= 1;
        }
    }

    #[test]
    fn committed_but_uncertain_identity_is_not_exposed_or_replaced() {
        let mut store = Memory {
            uncertain: true,
            ..Memory::default()
        };
        assert!(Device::initialize(&mut store, 17, random).is_err());
        assert!(!store.bytes.is_empty());
        let committed = store.bytes.clone();
        assert!(Device::initialize(&mut store, 18, random).is_err());
        assert_eq!(store.bytes, committed);
        store.uncertain = false;
        assert_eq!(
            Device::recover(&mut store)
                .unwrap()
                .unwrap()
                .identity
                .peer()
                .kid(),
            17
        );
    }

    struct Shared(Rc<RefCell<Memory>>);
    impl Store for Shared {
        fn read(&mut self, output: &mut [u8; STORE_BYTES]) -> Result<usize, Error> {
            self.0.borrow_mut().read(output)
        }
        fn commit(&mut self, expected: &[u8], next: &[u8]) -> Result<(), Error> {
            self.0.borrow_mut().commit(expected, next)
        }
    }
    struct Io;
    impl DatagramIo for Io {
        type Error = ();
        fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
            Ok(None)
        }
        fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
            Ok(bytes.len())
        }
    }
    #[derive(Clone, Copy)]
    enum Plan {
        Pair,
        Inspect,
        Revoke,
    }
    struct Usb {
        plan: Plan,
        incoming: VecDeque<u8>,
        replies: Rc<RefCell<Vec<CommissioningReply>>>,
        prior: Option<coaptic::provisioning::EnrollmentPolicy>,
        peer: coaptic::provisioning::PinnedPeer,
    }
    impl Usb {
        fn enqueue(&mut self, request: CommissioningRequest) {
            let mut payload = [0; 512];
            let len = request.encode(&mut payload).unwrap();
            let mut frame = [0; 518];
            let len = CommissioningDecoder::frame(&payload[..len], &mut frame).unwrap();
            self.incoming.extend(&frame[..len]);
        }
    }
    impl Console for Usb {
        fn read(&mut self, bytes: &mut [u8]) -> Result<usize, Error> {
            if let Some(byte) = self.incoming.pop_front() {
                bytes[0] = byte;
                Ok(1)
            } else {
                Ok(0)
            }
        }
        fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
            let mut decoder = CommissioningDecoder::new();
            let mut reply = None;
            for byte in bytes {
                if let Some(payload) = decoder.feed(*byte) {
                    reply = Some(CommissioningReply::decode(payload).unwrap());
                }
            }
            let reply = reply.unwrap();
            match &reply {
                CommissioningReply::State { record, .. } => {
                    self.prior = record.policy().cloned();
                    if !matches!(self.plan, Plan::Inspect) {
                        self.enqueue(CommissioningRequest::Challenge);
                    }
                }
                CommissioningReply::Challenge(challenge) => {
                    let revoke = matches!(self.plan, Plan::Revoke);
                    let policy = if revoke {
                        self.prior.clone().unwrap()
                    } else {
                        coaptic::provisioning::EnrollmentPolicy::new(
                            self.peer.clone(),
                            [7; 32],
                            permissions(true),
                        )
                        .unwrap()
                    };
                    self.enqueue(CommissioningRequest::Update {
                        update: coaptic::provisioning::PairingUpdate::new(
                            challenge.clone(),
                            policy,
                            revoke,
                        ),
                        endpoint: Endpoint::v4([127, 0, 0, 1], 5683),
                    });
                }
                _ => {}
            }
            self.replies.borrow_mut().push(reply);
            Ok(())
        }
        fn restart(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn event(&mut self, _: u32) {}
    }
    fn campaign(
        store: Rc<RefCell<Memory>>,
        plan: Plan,
    ) -> (Result<(), Error>, Vec<CommissioningReply>) {
        let replies = Rc::new(RefCell::new(Vec::new()));
        let peer = Identity::from_private_key([2; 32], 2).unwrap().peer();
        let mut console = Usb {
            plan,
            incoming: VecDeque::new(),
            replies: replies.clone(),
            prior: None,
            peer,
        };
        console.enqueue(if matches!(plan, Plan::Pair) {
            CommissioningRequest::Initialize { kid: 17 }
        } else {
            CommissioningRequest::Inspect
        });
        let mut now = 0;
        let result = run(
            || Io,
            random,
            || {
                now += 1;
                (now < 200).then_some(now)
            },
            Shared(store),
            console,
        );
        let output = replies.borrow().clone();
        (result, output)
    }

    #[test]
    fn usb_commissioning_restart_and_uncertain_revoke_keep_identity_and_owner_policy() {
        let store = Rc::new(RefCell::new(Memory::default()));
        let (result, replies) = campaign(store.clone(), Plan::Pair);
        assert_eq!(result, Ok(()));
        assert!(replies.iter().any(
            |reply| matches!(reply, CommissioningReply::Committed(record) if record.enabled())
        ));
        let paired = store.borrow().bytes.clone();
        let principal = Device::recover(&mut Shared(store.clone()))
            .unwrap()
            .unwrap()
            .identity
            .peer()
            .principal();
        let (result, replies) = campaign(store.clone(), Plan::Inspect);
        assert_eq!(result, Ok(()));
        assert_eq!(store.borrow().bytes, paired);
        assert!(replies.iter().any(|reply| matches!(reply, CommissioningReply::State { device, record } if device.principal() == principal && record.enabled())));
        store.borrow_mut().uncertain = true;
        let (result, replies) = campaign(store.clone(), Plan::Revoke);
        assert_eq!(result, Err(Error::Storage));
        assert!(
            replies
                .iter()
                .any(|reply| matches!(reply, CommissioningReply::Refused(4)))
        );
        store.borrow_mut().uncertain = false;
        let device = Device::recover(&mut Shared(store)).unwrap().unwrap();
        assert_eq!(device.identity.peer().principal(), principal);
        assert!(!device.pairing.checkpoint().enabled());
        assert_eq!(
            device.pairing.checkpoint().policy().unwrap().owner(),
            &[7; 32]
        );
    }
}
