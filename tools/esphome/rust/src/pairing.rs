//! USB commissioning, durable device identity/policy and automatic EDHOC recovery.
//!
//! USB is a privileged local administration channel. The trusted host verifies
//! the operator's hardware proof before sending an exact update. Never forward
//! these commands from UDP, discovery or an untrusted host. Ordinary NVS survives
//! normal restart; physical flash rollback/custody hardening is a separate option.
//! A single complete CBOR blob commits the private identity, public policy and
//! endpoint together. Failed or uncertain writes stop every live session.
//! The greater pinned principal initiates; the other responds, avoiding startup
//! collisions without another user setting. Both monitor authenticated liveness.
#![forbid(unsafe_code)]

use coaptic::platform::{CheckedClock, ClockError};
#[cfg(test)]
use coaptic::profiles;
use coaptic::provisioning::{
    CommissioningDecoder, CommissioningReply, CommissioningRequest, Identity, LocalPairing,
    ManagedConnection, ManagedError, ManagedSubscription, PairingCommitError, PairingRecord,
};
use coaptic::storage::DatagramIo;
use coaptic::{Code, ContentFormat, Endpoint, Method, Response};
#[cfg(feature = "async-network")]
mod async_service;
#[cfg(all(feature = "async-network", target_os = "none"))]
pub(crate) use async_service::managed_owner_bytes;
#[cfg(feature = "async-network")]
pub use async_service::{ConsoleWait, run_async};
mod legacy_custody;
mod reconciliation;
pub use legacy_custody::{LEGACY_CUSTODY_PERMIT_BYTES, initialize_legacy_custody};

use zeroize::Zeroizing;

// Persistent Observe and one ordinary call require two response credits plus
// the shared receive headroom. Every other pool dimension remains Constrained.
coaptic::memory_profile! {
    EnrolledDevice {
        rx_datagram: (3, 1152), tx_datagram: (2, 1152),
        rx_body: (1, 4096), tx_body: (1, 4096),
        dedup: 4, observe: 2,
    }
}

// Stop originating application work after failed authenticated liveness so
// the existing owner can admit a fresh handshake without discarding history.
struct SessionLiveness {
    last_authenticated: u64,
    generation: Option<u64>,
    quiet: bool,
}
impl SessionLiveness {
    fn new(now: u64) -> Self {
        Self {
            last_authenticated: now,
            generation: None,
            quiet: false,
        }
    }
    fn authenticated(&mut self, now: u64) {
        self.last_authenticated = now;
        self.quiet = false;
    }
    fn generation(&mut self, generation: Option<u64>, now: u64) -> bool {
        if generation.is_some() && generation != self.generation {
            self.generation = generation;
            self.authenticated(now);
            true
        } else {
            false
        }
    }
    fn expired(&self, now: u64) -> bool {
        self.generation.is_some()
            && !self.quiet
            && now.saturating_sub(self.last_authenticated) >= 30_000
    }
}

// One service-state owner replaces the former network-stopped boolean.
// Draining retries existing durable work; Held prevents all new production.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServiceState {
    Running,
    Draining(u64),
    Held(u64),
    Failed,
}
impl ServiceState {
    fn network(self) -> bool {
        matches!(self, Self::Running | Self::Draining(_))
    }
    #[cfg(feature = "async-network")]
    fn deadline(self) -> Option<u64> {
        match self {
            Self::Draining(at) | Self::Held(at) => Some(at),
            _ => None,
        }
    }
    fn expire_hold(&mut self, now: u64) {
        if matches!(*self, Self::Held(at) if now >= at) {
            *self = Self::Running;
        }
    }
    fn permits_probe(self, unresolved: bool) -> bool {
        matches!(self, Self::Running) || matches!(self, Self::Draining(_)) && unresolved
    }
    fn release_hold(&mut self) {
        if matches!(*self, Self::Held(_) | Self::Draining(_)) {
            *self = Self::Running;
        }
    }
    fn drain(
        &mut self,
        now: u64,
        custody: coaptic::provisioning::CommissioningPending,
        can_retry: bool,
        call: bool,
    ) -> Option<bool> {
        let Self::Draining(deadline) = *self else {
            return None;
        };
        use coaptic::provisioning::CommissioningPending as Status;
        if matches!(custody, Status::Missing | Status::Unverifiable)
            || custody == Status::Unresolved && !can_retry
        {
            self.release_hold();
            return Some(false);
        }
        if custody == Status::Complete && !call {
            *self = Self::Held(now.saturating_add(60_000));
            Some(true)
        } else if now >= deadline {
            *self = Self::Running;
            Some(false)
        } else {
            None
        }
    }
}

pub const STORE_BYTES: usize = 332;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Storage,
    Identity,
    Console,
    Protocol,
    Clock,
    Network,
    Permissions,
    Pending,
}

/// The backend compares the complete prior blob and confirms commit/readback.
/// An empty read means an explicitly uninitialized store, never a parse fallback.
pub trait Store {
    fn read(&mut self, output: &mut [u8; STORE_BYTES]) -> Result<usize, Error>;
    fn commit(&mut self, expected: &[u8], next: &[u8]) -> Result<(), Error>;
    fn pending_read(
        &mut self,
    ) -> Result<Option<[u8; crate::pending_telemetry::RECORD_BYTES]>, Error> {
        Err(Error::Storage)
    }
    fn pending_commit(
        &mut self,
        _: &[u8; crate::pending_telemetry::RECORD_BYTES],
    ) -> Result<(), Error> {
        Err(Error::Storage)
    }
    /// Durably create a one-use migration claim only when its separate key has
    /// never been set. Existing, unreadable or ambiguous claims refuse, including
    /// an exact repeat. Confirm commit and exact readback before success.
    fn claim_legacy_custody(&mut self, _claim: &[u8; 32]) -> Result<(), Error> {
        Err(Error::Storage)
    }
}

struct PendingStore<'a, S>(&'a mut S);
impl<S: Store> crate::pending_telemetry::Store for PendingStore<'_, S> {
    fn read(
        &mut self,
    ) -> Result<Option<[u8; crate::pending_telemetry::RECORD_BYTES]>, crate::pending_telemetry::Error>
    {
        self.0
            .pending_read()
            .map_err(|_| crate::pending_telemetry::Error::Storage)
    }
    fn commit(
        &mut self,
        bytes: &[u8; crate::pending_telemetry::RECORD_BYTES],
    ) -> Result<(), crate::pending_telemetry::Error> {
        self.0
            .pending_commit(bytes)
            .map_err(|_| crate::pending_telemetry::Error::Storage)
    }
}

fn pending_binding<'a>(
    private: &'a [u8; 32],
    record: &PairingRecord,
) -> crate::pending_telemetry::Binding<'a> {
    crate::pending_telemetry::Binding::Enrolled {
        private,
        grant: record.commitment(),
    }
}

// Called only inside an authenticated policy update's durable commit callback.
// Prepare pending storage first; ambiguous writes never activate the new grant.
fn prepare_pending(
    store: &mut impl Store,
    private: &[u8; 32],
    identity: &Identity,
    old: &PairingRecord,
    record: &PairingRecord,
) -> Result<(), Error> {
    let binding = pending_binding(private, record);
    if !record.enabled() {
        // Revocation never waits for a remote receipt or relies on readable
        // pending storage. Preserve unresolved work exactly. Completed custody
        // may follow the tombstone, but any local failure remains fail-closed
        // when a future grant attempts to recover it.
        if let Ok(mut pending) = crate::pending_telemetry::Pending::recover_bound(
            PendingStore(store),
            pending_binding(private, old),
            identity.peer().principal(),
        ) && matches!(pending.pending(), Ok(None))
        {
            let _ = pending.rebind(binding, identity.peer().principal());
        }
        return Ok(());
    }
    // Every initialized device provisions this record by construction. Missing
    // storage under an older nontelemetry grant is still unknown history.
    if store.pending_read()?.is_none() {
        return Err(Error::Storage);
    } else if crate::pending_telemetry::Pending::recover_bound(
        PendingStore(&mut *store),
        binding,
        identity.peer().principal(),
    )
    .is_err()
    {
        let mut pending = crate::pending_telemetry::Pending::recover_bound(
            PendingStore(store),
            pending_binding(private, old),
            identity.peer().principal(),
        )
        .map_err(|_| Error::Storage)?;
        pending
            .rebind(binding, identity.peer().principal())
            .map_err(|error| {
                if error == crate::pending_telemetry::Error::Pending {
                    Error::Pending
                } else {
                    Error::Storage
                }
            })?;
    }
    Ok(())
}

// Recovery cannot abandon a durable effect, including when the destination
// selects read-only access. Missing storage for an approved telemetry grant is
// ambiguous, not proof that no operation exists.
fn recovery_ready(
    store: &mut impl Store,
    private: &[u8; 32],
    identity: &Identity,
    old: &PairingRecord,
) -> Result<(), Error> {
    if store.pending_read()?.is_none() {
        return if old
            .policy()
            .is_some_and(|policy| *policy.resource_policy() == permissions(true))
        {
            Err(Error::Storage)
        } else {
            Ok(())
        };
    }
    let pending = crate::pending_telemetry::Pending::recover_bound(
        PendingStore(store),
        pending_binding(private, old),
        identity.peer().principal(),
    )
    .map_err(|_| Error::Storage)?;
    if pending.pending().map_err(|_| Error::Storage)?.is_some() {
        return Err(Error::Storage);
    }
    Ok(())
}

/// Optional resource-observation boundaries; no protocol state is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ResourcePhase {
    BeforeOwnerConstruction = 1,
    OwnerConstructed = 2,
    SessionEstablished = 3,
    AuthenticatedCompletion = 4,
}

/// Synchronous borrowed buffers on the sole privileged USB channel.
pub trait Console {
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, Error>;
    fn write(&mut self, bytes: &[u8]) -> Result<(), Error>;
    fn restart(&mut self) -> Result<(), Error>;
    /// Public counters only: 1 recovered, 2 initialized, 3 connected, 4 receipt,
    /// 5 network stopped (USB remains available for inspection/restart).
    fn event(&mut self, event: u32);
    /// Optional local observation. Never retain the borrow or alter protocol policy.
    /// Counters belong to the retained App and may reset with a fresh session.
    fn diagnostics(&mut self, _snapshot: &coaptic::app::diagnostics::Snapshot) {}
    /// Optional synchronous observation on the worker; retain no borrows or data.
    /// A generation is present only after an authenticated session is installed.
    fn resource_phase(&mut self, _phase: ResourcePhase, _generation: Option<u64>) {}
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
        if store.pending_read()?.is_some() {
            return Err(Error::Storage);
        }
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
            crate::pending_telemetry::provision_bound(
                &mut PendingStore(store),
                pending_binding(scalar, &next),
                candidate.peer().principal(),
            )
            .map_err(|_| Error::Storage)?;
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

    fn reply(&self, pending: coaptic::provisioning::CommissioningPending) -> CommissioningReply {
        CommissioningReply::State {
            device: self.identity.peer(),
            record: self.pairing.checkpoint().clone(),
            pending,
        }
    }

    // Synchronous temporary storage is gone before an async owner is suspended.
    #[inline(never)]
    fn pending_custody<S: Store>(
        &self,
        store: &mut S,
    ) -> coaptic::provisioning::CommissioningPending {
        use coaptic::provisioning::CommissioningPending as Status;
        match store.pending_read() {
            Ok(None) => Status::Missing,
            Ok(Some(bytes)) => {
                match crate::pending_telemetry::Pending::<PendingStore<'_, S>>::inspect_bound(
                    &bytes,
                    pending_binding(&self.private, self.pairing.checkpoint()),
                    self.identity.peer().principal(),
                ) {
                    Ok(true) => Status::Unresolved,
                    Ok(false) => Status::Complete,
                    Err(_) => Status::Unverifiable,
                }
            }
            Err(_) => Status::Unverifiable,
        }
    }
    fn inspect(&self, store: &mut impl Store) -> CommissioningReply {
        self.reply(self.pending_custody(store))
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
    let mut decoder = ConsoleFrames::new();
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    let mut pending = None;
    let mut service = ServiceState::Running;
    loop {
        let Some(now) = next_time(&mut clock)? else {
            return Ok(());
        };
        service.expire_hold(now);
        let request = if let Some(request) = pending.take() {
            Some(request)
        } else {
            receive(&mut console, &mut decoder, now)?
        };
        if let Some(request) = request {
            match request {
                CommissioningRequest::Inspect => {
                    send(
                        &mut console,
                        &device.as_ref().map_or(CommissioningReply::Empty, |device| {
                            device.inspect(&mut store)
                        }),
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
                            &device.as_ref().ok_or(Error::Identity)?.inspect(&mut store),
                        )?;
                    }
                }
                CommissioningRequest::Quiesce => {
                    if matches!(service, ServiceState::Held(_)) {
                        service = ServiceState::Held(now.saturating_add(60_000));
                        send(&mut console, &CommissioningReply::Quiesced)?;
                    } else if device
                        .as_ref()
                        .is_some_and(|device| device.pairing.checkpoint().enabled())
                        && service == ServiceState::Running
                    {
                        service = ServiceState::Draining(now.saturating_add(30_000));
                    } else {
                        send(&mut console, &CommissioningReply::Refused(6))?;
                    }
                }
                CommissioningRequest::Challenge => {
                    if matches!(service, ServiceState::Held(_)) {
                        service = ServiceState::Held(now.saturating_add(60_000));
                    }
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
                    let next_endpoint = if update.is_recovery_configuration() {
                        device.endpoint
                    } else {
                        Some(endpoint)
                    };
                    let mut next = Zeroizing::new([0; STORE_BYTES]);
                    let mut next_len = 0;
                    let result = update.apply(&mut device.pairing, now, |old, record| {
                        if update.is_recovery() {
                            recovery_ready(&mut store, &device.private, &device.identity, old)?;
                        }
                        prepare_pending(
                            &mut store,
                            &device.private,
                            &device.identity,
                            old,
                            record,
                        )?;
                        next_len = encode_store(
                            &device.private,
                            device.identity.peer().kid(),
                            record,
                            next_endpoint,
                            &mut next,
                        )?;
                        store.commit(&device.stored[..device.stored_len], &next[..next_len])
                    });
                    match result {
                        Ok(()) => {
                            device.stored = next;
                            device.stored_len = next_len;
                            device.endpoint = next_endpoint;
                            service = ServiceState::Running;
                            send(
                                &mut console,
                                &CommissioningReply::Committed(device.pairing.checkpoint().clone()),
                            )?;
                        }
                        Err(PairingCommitError::State(_)) => {
                            service.release_hold();
                            send(&mut console, &CommissioningReply::Refused(3))?
                        }
                        Err(PairingCommitError::Store(Error::Pending)) => {
                            // Only a verified unresolved record reaches this path:
                            // no policy or pending content was changed. Restore the
                            // old live authority after its consumed challenge.
                            device.pairing = LocalPairing::restore(
                                &device.identity,
                                device.pairing.checkpoint().clone(),
                            )
                            .map_err(|_| Error::Storage)?;
                            service.release_hold();
                            send(&mut console, &CommissioningReply::Refused(6))?;
                        }
                        Err(PairingCommitError::Store(_)) => {
                            // No more network work after an uncertain write.
                            let _ = send(&mut console, &CommissioningReply::Refused(4));
                            return Err(Error::Storage);
                        }
                    }
                }
                CommissioningRequest::Pending { prior } => {
                    let reply = device
                        .as_ref()
                        .map_or(CommissioningReply::Refused(2), |device| {
                            device.pending_reply(&mut store, &prior)
                        });
                    send(&mut console, &reply)?;
                }
                CommissioningRequest::Reconcile {
                    challenge,
                    prior,
                    receipt,
                } => {
                    let Some(device) = &mut device else {
                        send(&mut console, &CommissioningReply::Refused(2))?;
                        continue;
                    };
                    match device.reconcile_receipt(&mut store, &challenge, &prior, receipt, now) {
                        Ok(receipt) => {
                            send(&mut console, &CommissioningReply::Reconciled(receipt))?
                        }
                        Err(PairingCommitError::State(_)) => {
                            send(&mut console, &CommissioningReply::Refused(3))?
                        }
                        Err(PairingCommitError::Store(_)) => {
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
            && service.network()
        {
            // Returning a management request drops all old protocol caches,
            // exchanges and sessions before any policy mutation above.
            let result = session(
                device,
                &mut store,
                socket(),
                random,
                &mut clock,
                &mut console,
                &mut decoder,
                &mut service,
            );
            match result {
                Ok(Some(request)) => pending = Some(request),
                Ok(None) => return Ok(()),
                Err(Error::Network) => {
                    // Drop the failed volatile owner, but keep USB administration.
                    // Do not repeatedly discard protocol history on remote input:
                    // only an explicit restart or committed policy update resumes it.
                    service = ServiceState::Failed;
                    console.event(5);
                }
                Err(error) => return Err(error),
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

struct ConsoleFrames {
    decoder: CommissioningDecoder,
    last_byte: Option<u64>,
}

impl ConsoleFrames {
    fn new() -> Self {
        Self {
            decoder: CommissioningDecoder::new(),
            last_byte: None,
        }
    }
}

fn receive(
    console: &mut impl Console,
    frames: &mut ConsoleFrames,
    now: u64,
) -> Result<Option<CommissioningRequest>, Error> {
    // A disconnected sender can leave a partial frame. Expire it after one
    // second without a byte, so the next host can inspect without rebooting.
    // This bounds transport framing only; hardware approval happens before a
    // complete update is sent and retains its separate commissioning deadline.
    if frames
        .last_byte
        .is_some_and(|last| now.saturating_sub(last) >= 1000)
    {
        *frames = ConsoleFrames::new();
    }
    // One byte per read preserves bytes following a complete command. Work is
    // capped at64 bytes per scheduler iteration, including console log noise.
    for _ in 0..64 {
        let mut byte = [0];
        match console.read(&mut byte) {
            // A disconnected host must not stop local management or network
            // service. The next scheduler iteration can inspect current state.
            Err(Error::Console) => {
                *frames = ConsoleFrames::new();
                break;
            }
            Ok(0) => break,
            Ok(1) => {
                frames.last_byte = Some(now);
                if let Some(payload) = frames.decoder.feed(byte[0]) {
                    frames.last_byte = None;
                    return match CommissioningRequest::decode(payload) {
                        Ok(request) => Ok(Some(request)),
                        Err(_) => {
                            send(console, &CommissioningReply::Refused(5))?;
                            Ok(None)
                        }
                    };
                }
            }
            Ok(_) => return Err(Error::Console),
            Err(error) => return Err(error),
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
    match console.write(&frame[..len]) {
        // A lost reply cannot undo a confirmed write, and is not a reason to
        // disable USB. Never retry the mutation: let a fresh inspection recover
        // the committed state. Serialization and non-console failures stay fatal.
        Err(Error::Console) => Ok(()),
        result => result,
    }
}

fn permissions(write: bool) -> [u8; 32] {
    blake3::derive_key(
        "coaptic local service permissions v1",
        if write {
            b"GET /identity;POST /echo;POST /telemetry".as_slice()
        } else {
            b"GET /identity".as_slice()
        },
    )
}

fn echo_permissions() -> [u8; 32] {
    blake3::derive_key(
        "coaptic local service permissions v1",
        b"GET /identity;POST /echo",
    )
}

fn telemetry_resource() -> [u8; 32] {
    blake3::derive_key("coaptic local service resource v1", b"POST /telemetry")
}

fn recover_pending<'a, S: Store>(
    device: &'a Device,
    store: &'a mut S,
    telemetry: bool,
) -> Result<Option<crate::pending_telemetry::Pending<'a, PendingStore<'a, S>>>, Error> {
    if !telemetry {
        return Ok(None);
    }
    crate::pending_telemetry::Pending::recover_bound(
        PendingStore(store),
        pending_binding(&device.private, device.pairing.checkpoint()),
        device.identity.peer().principal(),
    )
    .map(Some)
    .map_err(|_| Error::Storage)
}

fn live_custody<S: Store>(
    pending: &Option<crate::pending_telemetry::Pending<'_, PendingStore<'_, S>>>,
    initial: coaptic::provisioning::CommissioningPending,
) -> coaptic::provisioning::CommissioningPending {
    use coaptic::provisioning::CommissioningPending as Status;
    pending
        .as_ref()
        .map_or(initial, |pending| match pending.pending() {
            Ok(Some(_)) => Status::Unresolved,
            Ok(None) => Status::Complete,
            Err(_) => Status::Unverifiable,
        })
}

fn prepare_sample<S: Store>(
    pending: &mut Option<crate::pending_telemetry::Pending<'_, PendingStore<'_, S>>>,
    sample: &mut [u8; 61],
    now: u64,
    random: fn(&mut [u8]) -> bool,
) -> Result<(), Error> {
    let Some(pending) = pending.as_mut() else {
        sample[53..].copy_from_slice(&now.to_be_bytes());
        return Ok(());
    };
    if pending.pending().map_err(|_| Error::Storage)?.is_none() {
        sample[53..].copy_from_slice(&now.to_be_bytes());
        let mut id = [0; 16];
        if !random(&mut id) || id == [0; 16] {
            return Err(Error::Identity);
        }
        pending
            .begin(
                coaptic::provisioning::OperationId::new(id),
                telemetry_resource(),
                Some(ContentFormat::CBOR.get()),
                &sample[16..],
            )
            .map_err(|_| Error::Storage)?;
    }
    let operation = pending
        .pending()
        .map_err(|_| Error::Storage)?
        .ok_or(Error::Storage)?;
    if operation.payload().len() != 45
        || operation.resource() != &telemetry_resource()
        || operation.content_format() != Some(ContentFormat::CBOR.get())
    {
        return Err(Error::Storage);
    }
    sample[..16].copy_from_slice(operation.id().as_bytes());
    sample[16..].copy_from_slice(operation.payload());
    Ok(())
}

fn accept_sample<S: Store>(
    pending: &mut Option<crate::pending_telemetry::Pending<'_, PendingStore<'_, S>>>,
    code: Code,
    payload: &[u8],
    expected: &[u8],
) -> Result<bool, Error> {
    if let Some(pending) = pending.as_mut() {
        if code != Code::CHANGED {
            return Ok(false);
        }
        match pending.accept_authenticated_receipt(payload) {
            Ok(_) => Ok(true),
            Err(crate::pending_telemetry::Error::InvalidReceipt) => Ok(false),
            Err(_) => Err(Error::Storage),
        }
    } else {
        Ok(code == Code::CONTENT && payload == expected)
    }
}

#[allow(clippy::too_many_arguments)] // Separate borrowed storage, transport and administration owners.
fn session<T: DatagramIo, F: FnMut() -> Result<u64, ()>>(
    device: &Device,
    store: &mut impl Store,
    socket: T,
    random: fn(&mut [u8]) -> bool,
    clock: &mut CheckedClock<F>,
    console: &mut impl Console,
    decoder: &mut ConsoleFrames,
    service: &mut ServiceState,
) -> Result<Option<CommissioningRequest>, Error> {
    let endpoint = device.endpoint.ok_or(Error::Storage)?;
    let peer = device
        .pairing
        .peer()
        .map_err(|_| Error::Network)?
        .principal();
    let initiates = device.identity.peer().principal().fingerprint() > peer.fingerprint();
    let permission = device
        .pairing
        .checkpoint()
        .policy()
        .ok_or(Error::Storage)?
        .resource_policy();
    let telemetry = *permission == permissions(true);
    let write = telemetry || *permission == echo_permissions();
    if !write && *permission != permissions(false) {
        return Err(Error::Permissions);
    }
    let initial_custody = device.pending_custody(store);
    let mut pending = recover_pending(device, store, telemetry)?;
    let Some(start) = next_time(clock)? else {
        return Ok(None);
    };
    console.resource_phase(ResourcePhase::BeforeOwnerConstruction, None);
    let mut connection = ManagedConnection::<_, EnrolledDevice>::from_local_pairing(
        &device.identity,
        &device.pairing,
        endpoint,
        socket,
        random,
        start,
    )
    .map_err(|_| Error::Network)?;
    connection
        .observable_manual("identity")
        .map_err(|_| Error::Network)?;
    console.resource_phase(ResourcePhase::OwnerConstructed, None);
    let mut subscription = ManagedSubscription::new("identity");
    if initiates {
        match connection.connect(start) {
            Ok(())
            | Err(ManagedError::Recovery(_) | ManagedError::Busy | ManagedError::Capacity) => {}
            Err(_) => return Err(Error::Network),
        }
    }
    let mut liveness = SessionLiveness::new(start);
    let mut retry_at = start.saturating_add(30_000);
    let mut next_probe = start;
    let mut call = None;
    let mut call_started = start;
    let mut connected_reported = false;
    let mut failed_polls = 0u8;
    let mut reply = [0; 128];
    let mut sample = [0; 61];
    sample[16..20].copy_from_slice(&[0x83, 1, 0x58, 32]);
    sample[20..52].copy_from_slice(device.identity.peer().principal().fingerprint());
    sample[52] = 0x1b;
    loop {
        let Some(now) = next_time(clock)? else {
            return Ok(None);
        };
        if let Some(request) = receive(console, decoder, now)? {
            if matches!(request, CommissioningRequest::Inspect) {
                send(
                    console,
                    &device.reply(live_custody(&pending, initial_custody)),
                )?;
            } else if matches!(request, CommissioningRequest::Quiesce) {
                if matches!(*service, ServiceState::Running) {
                    *service = ServiceState::Draining(now.saturating_add(30_000));
                } else {
                    send(console, &CommissioningReply::Refused(6))?;
                }
            } else {
                if matches!(*service, ServiceState::Draining(_)) {
                    *service = ServiceState::Running;
                }
                return Ok(Some(request));
            }
        }
        let was_quiet = liveness.quiet;
        match connection.poll_with(now, |_, request, _| {
            liveness.authenticated(now);
            if request.path() == ["identity"] && request.method() == Some(Method::Get) {
                let response =
                    Response::content_copy(device.identity.peer().principal().fingerprint())
                        .max_age(10);
                if request.is_observe_register() {
                    response.observe(0)
                } else {
                    response
                }
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
            Err(ManagedError::Application(
                coaptic::app::Error::Io(_) | coaptic::app::Error::Saturated,
            )) => {}
            Err(ManagedError::Clock) => return Err(Error::Clock),
            Err(ManagedError::Trust(_)) => return Err(Error::Network),
            Err(_) => {
                failed_polls = failed_polls.saturating_add(1);
                if failed_polls >= 32 {
                    return Err(Error::Network);
                }
            }
        }
        if liveness.generation(connection.session_generation(), now) {
            connected_reported = false;
            console.resource_phase(ResourcePhase::SessionEstablished, liveness.generation);
        }
        if was_quiet && !liveness.quiet {
            subscription = ManagedSubscription::new("identity");
            next_probe = now;
        }
        if liveness.expired(now) {
            connection
                .stop_subscription(&mut subscription, now)
                .map_err(|_| Error::Network)?;
            if let Some(current) = call.take() {
                match connection.cancel(current, now) {
                    Ok(_) | Err(ManagedError::StaleHandle) => {}
                    Err(_) => return Err(Error::Network),
                }
            }
            liveness.quiet = true;
            retry_at = now;
        }
        if connection.is_connected() && !liveness.quiet {
            match connection.take_subscription_response_into(&mut subscription, &mut reply, now) {
                Ok(Some(Ok(response)))
                    if response.code() == Code::CONTENT
                        && response.payload() == peer.fingerprint() =>
                {
                    liveness.authenticated(now)
                }
                Ok(None) => {}
                Ok(Some(_)) => retry_at = now,
                Err(
                    ManagedError::Busy | ManagedError::NotConnected | ManagedError::StaleHandle,
                ) => {}
                Err(_) => return Err(Error::Network),
            }
            match connection.poll_subscription(&mut subscription, now) {
                Ok(_) | Err(ManagedError::Busy | ManagedError::NotConnected) => {}
                Err(ManagedError::Application(
                    coaptic::app::Error::Io(_)
                    | coaptic::app::Error::Saturated
                    | coaptic::app::Error::Backoff { .. },
                )) => {}
                Err(_) => return Err(Error::Network),
            }
        }
        let response = if let Some(current) = call {
            match connection.take_response_into(current, &mut reply, now) {
                Ok(response) => response,
                Err(ManagedError::StaleHandle) => {
                    call = None;
                    next_probe = now;
                    None
                }
                Err(_) => return Err(Error::Network),
            }
        } else {
            None
        };
        if let Some(response) = response {
            call = None;
            match response {
                Ok(response)
                    if accept_sample(
                        &mut pending,
                        response.code(),
                        response.payload(),
                        if write {
                            &sample[16..]
                        } else {
                            peer.fingerprint()
                        },
                    )? =>
                {
                    if !connected_reported {
                        console.event(3);
                        connected_reported = true;
                        console.resource_phase(
                            ResourcePhase::AuthenticatedCompletion,
                            liveness.generation,
                        );
                    }
                    liveness.authenticated(now);
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
        if let Some(current) = call
            && now.saturating_sub(call_started) >= 10_000
        {
            connection
                .cancel(current, now)
                .map_err(|_| Error::Network)?;
            call = None;
            retry_at = now;
            next_probe = now.saturating_add(5_000);
        }
        if initiates && call.is_none() && now >= retry_at {
            match connection.connect(now) {
                Ok(()) => retry_at = now.saturating_add(30_000),
                Err(ManagedError::Busy | ManagedError::Capacity) => {
                    retry_at = now.saturating_add(1_000)
                }
                Err(_) => retry_at = now.saturating_add(5_000),
            }
        }
        let unresolved = pending
            .as_ref()
            .map(|pending| pending.pending())
            .transpose()
            .map_err(|_| Error::Storage)?
            .flatten()
            .is_some();
        match service.drain(
            now,
            live_custody(&pending, initial_custody),
            pending.is_some(),
            call.is_some(),
        ) {
            Some(true) => return Ok(Some(CommissioningRequest::Quiesce)),
            Some(false) => send(console, &CommissioningReply::Refused(6))?,
            None => {}
        }
        if service.permits_probe(unresolved)
            && !liveness.quiet
            && call.is_none()
            && connection.is_connected()
            && now >= next_probe
        {
            if let Some(snapshot) = connection.diagnostic_snapshot(now) {
                console.diagnostics(&snapshot);
            }
            // Durable telemetry retains exact operation bytes until a matching receipt.
            // Read-only pairing uses an authenticated identity read instead.
            prepare_sample(&mut pending, &mut sample, now, random)?;
            let (method, path, payload, format) = if telemetry {
                (
                    Method::Post,
                    "telemetry",
                    &sample[..],
                    Some(ContentFormat::CBOR),
                )
            } else if write {
                (
                    Method::Post,
                    "echo",
                    &sample[16..],
                    Some(ContentFormat::CBOR),
                )
            } else {
                (Method::Get, "identity", &[][..], None)
            };
            match connection.request(method, path, payload, format, now) {
                Ok(request) => {
                    call = Some(request);
                    call_started = now;
                }
                Err(ManagedError::Busy | ManagedError::NotConnected)
                | Err(ManagedError::Application(
                    coaptic::app::Error::Io(_)
                    | coaptic::app::Error::Saturated
                    | coaptic::app::Error::Backoff { .. },
                )) => {
                    // Observe and application calls share the bounded packet pools.
                    // Admission pressure leaves the session intact and retries later.
                    next_probe = now.saturating_add(1_000);
                }
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
    let mut public = [0; PairingRecord::MAX_ENCODED_LEN];
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
    if !(24..=PairingRecord::MAX_ENCODED_LEN).contains(&len) {
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

    mod enrolled_loopback;
    mod legacy_custody;

    #[derive(Default)]
    struct Memory {
        bytes: Vec<u8>,
        pending: Option<[u8; crate::pending_telemetry::RECORD_BYTES]>,
        uncertain: bool,
    }
    impl Store for Memory {
        fn pending_read(
            &mut self,
        ) -> Result<Option<[u8; crate::pending_telemetry::RECORD_BYTES]>, Error> {
            Ok(self.pending)
        }
        fn pending_commit(
            &mut self,
            bytes: &[u8; crate::pending_telemetry::RECORD_BYTES],
        ) -> Result<(), Error> {
            self.pending = Some(*bytes);
            Ok(())
        }
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
    fn enrolled_pending_retries_exact_bytes_and_missing_state_cannot_reinitialize_a_grant() {
        let mut store = Memory::default();
        let mut device = Device::initialize(&mut store, 17, random).unwrap();
        let old = device.pairing.checkpoint().clone();
        let peer = Identity::from_private_key([2; 32], 18).unwrap().peer();
        let challenge = device.pairing.begin(&device.identity, 0, random).unwrap();
        let policy =
            coaptic::provisioning::EnrollmentPolicy::new(peer, [7; 32], permissions(true)).unwrap();
        device
            .pairing
            .pair(&challenge, policy, 1, |prior, next| {
                prepare_pending(&mut store, &device.private, &device.identity, prior, next)
            })
            .unwrap();
        let grant = device.pairing.checkpoint().clone();
        assert_ne!(old.commitment(), grant.commitment());
        let mut pending = recover_pending(&device, &mut store, true).unwrap();
        let mut wire = [0; 61];
        prepare_sample(&mut pending, &mut wire, 42, random).unwrap();
        let original = wire;
        assert!(recovery_ready(&mut store, &device.private, &device.identity, &grant).is_err());
        let mut pending = recover_pending(&device, &mut store, true).unwrap();
        prepare_sample(&mut pending, &mut wire, 999, random).unwrap();
        assert_eq!(wire, original);
        assert!(!accept_sample(&mut pending, Code::CONTENT, &wire[16..], &[]).unwrap());
        let operation = pending.as_ref().unwrap().pending().unwrap().unwrap();
        let receipt =
            coaptic::provisioning::Receipt::from_parts(operation.id(), *operation.digest(), 1)
                .unwrap();
        assert!(accept_sample(&mut pending, Code::CHANGED, &receipt.encode(), &[]).unwrap());
        assert!(recovery_ready(&mut store, &device.private, &device.identity, &grant).is_ok());
        store.pending = None;
        assert!(recovery_ready(&mut store, &device.private, &device.identity, &grant).is_err());
        assert!(recover_pending(&device, &mut store, true).is_err());
        assert!(
            prepare_pending(
                &mut store,
                &device.private,
                &device.identity,
                &grant,
                &grant
            )
            .is_err()
        );
        assert!(store.pending.is_none());
    }

    #[test]
    fn pending_inspection_is_read_only_and_missing_is_not_first_use() {
        use coaptic::provisioning::CommissioningPending as Status;
        struct ReadOnly<'a>(&'a mut Memory);
        impl Store for ReadOnly<'_> {
            fn read(&mut self, _: &mut [u8; STORE_BYTES]) -> Result<usize, Error> {
                panic!("unexpected identity read")
            }
            fn commit(&mut self, _: &[u8], _: &[u8]) -> Result<(), Error> {
                panic!("inspection wrote identity")
            }
            fn pending_read(
                &mut self,
            ) -> Result<Option<[u8; crate::pending_telemetry::RECORD_BYTES]>, Error> {
                Ok(self.0.pending)
            }
            fn pending_commit(
                &mut self,
                _: &[u8; crate::pending_telemetry::RECORD_BYTES],
            ) -> Result<(), Error> {
                panic!("inspection reaffirmed pending")
            }
        }
        let mut store = Memory::default();
        let mut device = Device::initialize(&mut store, 17, random).unwrap();
        assert_eq!(
            device.pending_custody(&mut ReadOnly(&mut store)),
            Status::Complete
        );
        store.pending = None;
        assert_eq!(
            device.pending_custody(&mut ReadOnly(&mut store)),
            Status::Missing
        );
        let old = device.pairing.checkpoint().clone();
        let peer = Identity::from_private_key([2; 32], 18).unwrap().peer();
        let challenge = device.pairing.begin(&device.identity, 0, random).unwrap();
        assert!(
            device
                .pairing
                .pair(
                    &challenge,
                    coaptic::provisioning::EnrollmentPolicy::new(peer, [7; 32], echo_permissions())
                        .unwrap(),
                    1,
                    |old, next| prepare_pending(
                        &mut store,
                        &device.private,
                        &device.identity,
                        old,
                        next
                    )
                )
                .is_err()
        );
        assert!(store.pending.is_none());
        assert_eq!(device.pairing.checkpoint().commitment(), old.commitment());
        store.pending = Some([0; crate::pending_telemetry::RECORD_BYTES]);
        assert_eq!(
            device.pending_custody(&mut ReadOnly(&mut store)),
            Status::Unverifiable
        );
    }

    #[test]
    fn orphaned_pending_refuses_initialization_and_uncertain_pending_keeps_identity() {
        let mut orphan = Memory {
            pending: Some([7; crate::pending_telemetry::RECORD_BYTES]),
            ..Memory::default()
        };
        let original = orphan.pending;
        assert!(Device::initialize(&mut orphan, 17, random).is_err());
        assert!(orphan.bytes.is_empty());
        assert_eq!(orphan.pending, original);
        struct FailedPending(Memory);
        impl Store for FailedPending {
            fn read(&mut self, out: &mut [u8; STORE_BYTES]) -> Result<usize, Error> {
                self.0.read(out)
            }
            fn commit(&mut self, old: &[u8], next: &[u8]) -> Result<(), Error> {
                self.0.commit(old, next)
            }
            fn pending_read(
                &mut self,
            ) -> Result<Option<[u8; crate::pending_telemetry::RECORD_BYTES]>, Error> {
                self.0.pending_read()
            }
            fn pending_commit(
                &mut self,
                bytes: &[u8; crate::pending_telemetry::RECORD_BYTES],
            ) -> Result<(), Error> {
                self.0.pending_commit(bytes)?;
                Err(Error::Storage)
            }
        }
        let mut store = FailedPending(Memory::default());
        assert!(Device::initialize(&mut store, 17, random).is_err());
        let identity = store.0.bytes.clone();
        assert!(Device::recover(&mut store).unwrap().is_some());
        assert!(Device::initialize(&mut store, 18, random).is_err());
        assert_eq!(store.0.bytes, identity);
    }

    #[test]
    fn service_drain_preserves_retry_and_bounds_hold_without_new_work() {
        use coaptic::provisioning::CommissioningPending;
        for custody in [
            CommissioningPending::Missing,
            CommissioningPending::Unverifiable,
            CommissioningPending::Unresolved,
        ] {
            let mut state = ServiceState::Draining(30_000);
            assert_eq!(state.drain(0, custody, false, false), Some(false));
            assert_eq!(state, ServiceState::Running);
        }
        let mut failed = ServiceState::Failed;
        failed.release_hold();
        assert_eq!(failed, ServiceState::Failed);
        assert!(!failed.network());
        assert!(core::mem::size_of::<ServiceState>() <= 16);
        let mut state = ServiceState::Draining(30_000);
        assert!(state.permits_probe(true));
        assert!(!state.permits_probe(false));
        assert_eq!(
            state.drain(29_999, CommissioningPending::Unresolved, true, false),
            None
        );
        assert_eq!(
            state.drain(30_000, CommissioningPending::Unresolved, true, false),
            Some(false)
        );
        assert_eq!(state, ServiceState::Running);
        state = ServiceState::Draining(60_000);
        assert_eq!(
            state.drain(30_001, CommissioningPending::Complete, true, true),
            None
        );
        assert_eq!(
            state.drain(30_002, CommissioningPending::Complete, true, false),
            Some(true)
        );
        assert!(!state.network());
        assert!(!state.permits_probe(true));
        state.expire_hold(90_001);
        assert!(!state.network());
        state.expire_hold(90_002);
        assert!(state.network());
    }

    #[test]
    fn completed_pending_survives_echo_round_trip_and_unresolved_downgrade_refuses() {
        let mut store = Memory::default();
        let mut device = Device::initialize(&mut store, 17, random).unwrap();
        let peer = Identity::from_private_key([2; 32], 18).unwrap().peer();
        let policy = |permissions| {
            coaptic::provisioning::EnrollmentPolicy::new(peer.clone(), [7; 32], permissions)
                .unwrap()
        };
        let challenge = device.pairing.begin(&device.identity, 0, random).unwrap();
        device
            .pairing
            .pair(&challenge, policy(permissions(true)), 1, |old, next| {
                prepare_pending(&mut store, &device.private, &device.identity, old, next)
            })
            .unwrap();
        let grant = device.pairing.checkpoint().clone();
        let mut pending = recover_pending(&device, &mut store, true).unwrap();
        let mut wire = [0; 61];
        prepare_sample(&mut pending, &mut wire, 2, random).unwrap();
        let saved = store.pending;
        let challenge = device.pairing.begin(&device.identity, 3, random).unwrap();
        assert!(matches!(
            device
                .pairing
                .pair(&challenge, policy(echo_permissions()), 4, |old, next| {
                    prepare_pending(&mut store, &device.private, &device.identity, old, next)
                }),
            Err(PairingCommitError::Store(Error::Pending))
        ));
        assert_eq!(store.pending, saved);
        assert_eq!(device.pairing.checkpoint().commitment(), grant.commitment());
        device.pairing = LocalPairing::restore(&device.identity, grant).unwrap();
        let mut pending = recover_pending(&device, &mut store, true).unwrap();
        prepare_sample(&mut pending, &mut wire, 999, random).unwrap();
        let operation = pending.as_ref().unwrap().pending().unwrap().unwrap();
        let receipt =
            coaptic::provisioning::Receipt::from_parts(operation.id(), *operation.digest(), 1)
                .unwrap();
        assert!(accept_sample(&mut pending, Code::CHANGED, &receipt.encode(), &[]).unwrap());
        for (now, permissions) in [(1000, echo_permissions()), (1002, permissions(true))] {
            let challenge = device.pairing.begin(&device.identity, now, random).unwrap();
            device
                .pairing
                .pair(&challenge, policy(permissions), now + 1, |old, next| {
                    prepare_pending(&mut store, &device.private, &device.identity, old, next)
                })
                .unwrap();
        }
        let pending = recover_pending(&device, &mut store, true).unwrap();
        assert!(pending.as_ref().unwrap().pending().unwrap().is_none());
    }

    #[test]
    fn revocation_never_waits_for_unresolved_pending_or_erases_it() {
        let mut store = Memory::default();
        let mut device = Device::initialize(&mut store, 17, random).unwrap();
        let peer = Identity::from_private_key([2; 32], 18).unwrap().peer();
        let challenge = device.pairing.begin(&device.identity, 0, random).unwrap();
        device
            .pairing
            .pair(
                &challenge,
                coaptic::provisioning::EnrollmentPolicy::new(peer, [7; 32], permissions(true))
                    .unwrap(),
                1,
                |old, next| {
                    prepare_pending(&mut store, &device.private, &device.identity, old, next)
                },
            )
            .unwrap();
        let old = device.pairing.checkpoint().clone();
        let mut pending = recover_pending(&device, &mut store, true).unwrap();
        prepare_sample(&mut pending, &mut [0; 61], 2, random).unwrap();
        let saved = store.pending;
        let challenge = device.pairing.begin(&device.identity, 3, random).unwrap();
        device
            .pairing
            .revoke(&challenge, &[7; 32], 4, |old, next| {
                prepare_pending(&mut store, &device.private, &device.identity, old, next)
            })
            .unwrap();
        assert!(!device.pairing.checkpoint().enabled());
        assert_eq!(store.pending, saved);
        let preserved = crate::pending_telemetry::Pending::recover_bound(
            PendingStore(&mut store),
            pending_binding(&device.private, &old),
            device.identity.peer().principal(),
        )
        .unwrap();
        assert!(preserved.pending().unwrap().is_some());
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
        fn pending_read(
            &mut self,
        ) -> Result<Option<[u8; crate::pending_telemetry::RECORD_BYTES]>, Error> {
            self.0.borrow_mut().pending_read()
        }
        fn pending_commit(
            &mut self,
            bytes: &[u8; crate::pending_telemetry::RECORD_BYTES],
        ) -> Result<(), Error> {
            self.0.borrow_mut().pending_commit(bytes)
        }
        fn read(&mut self, output: &mut [u8; STORE_BYTES]) -> Result<usize, Error> {
            self.0.borrow_mut().read(output)
        }
        fn commit(&mut self, expected: &[u8], next: &[u8]) -> Result<(), Error> {
            self.0.borrow_mut().commit(expected, next)
        }
    }
    struct Io;
    impl coaptic::storage::DatagramTransport for Io {
        type Error = ();
    }
    impl DatagramIo for Io {
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
        Backup,
        Recover,
        RecoverReadOnly,
    }
    struct Usb {
        plan: Plan,
        incoming: VecDeque<u8>,
        replies: Rc<RefCell<Vec<CommissioningReply>>>,
        prior: Option<coaptic::provisioning::EnrollmentPolicy>,
        peer: coaptic::provisioning::PinnedPeer,
        read_failure: bool,
        lose_committed_reply: bool,
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
            if self.read_failure {
                self.read_failure = false;
                return Err(Error::Console);
            }
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
            if self.lose_committed_reply && matches!(reply, CommissioningReply::Committed(_)) {
                self.lose_committed_reply = false;
                self.plan = Plan::Inspect;
                self.enqueue(CommissioningRequest::Inspect);
                return Err(Error::Console);
            }
            match &reply {
                CommissioningReply::State { record, .. } => {
                    self.prior = record.policy().cloned();
                    if !matches!(self.plan, Plan::Inspect) {
                        self.enqueue(CommissioningRequest::Challenge);
                    }
                }
                CommissioningReply::Challenge(challenge) => {
                    let revoke = matches!(self.plan, Plan::Revoke);
                    let recovering = matches!(self.plan, Plan::Recover | Plan::RecoverReadOnly);
                    let policy = if revoke || matches!(self.plan, Plan::Backup) {
                        self.prior.clone().unwrap()
                    } else {
                        coaptic::provisioning::EnrollmentPolicy::new(
                            self.peer.clone(),
                            [if recovering { 9 } else { 7 }; 32],
                            permissions(!matches!(self.plan, Plan::RecoverReadOnly)),
                        )
                        .unwrap()
                    };
                    let update = if matches!(self.plan, Plan::Backup) {
                        coaptic::provisioning::PairingUpdate::set_recovery(
                            challenge.clone(),
                            policy,
                            Some([8; 32]),
                        )
                        .unwrap()
                    } else if recovering {
                        coaptic::provisioning::PairingUpdate::recover(
                            challenge.clone(),
                            [8; 32],
                            policy,
                        )
                        .unwrap()
                    } else {
                        coaptic::provisioning::PairingUpdate::new(challenge.clone(), policy, revoke)
                    };
                    self.enqueue(CommissioningRequest::Update {
                        update,
                        endpoint: Endpoint::v4(
                            [127, 0, 0, 1],
                            if matches!(self.plan, Plan::Backup) {
                                9999
                            } else {
                                5683
                            },
                        ),
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
        campaign_with_faults(store, plan, false, false, false)
    }

    fn campaign_with_faults(
        store: Rc<RefCell<Memory>>,
        plan: Plan,
        read_failure: bool,
        lose_committed_reply: bool,
        malformed: bool,
    ) -> (Result<(), Error>, Vec<CommissioningReply>) {
        let replies = Rc::new(RefCell::new(Vec::new()));
        let peer = if matches!(plan, Plan::Recover | Plan::RecoverReadOnly) {
            Identity::from_private_key([3; 32], 3).unwrap().peer()
        } else {
            Identity::from_private_key([2; 32], 2).unwrap().peer()
        };
        let mut console = Usb {
            plan,
            incoming: VecDeque::new(),
            replies: replies.clone(),
            prior: None,
            peer,
            read_failure,
            lose_committed_reply,
        };
        if malformed {
            let mut frame = [0; 16];
            // Framing is valid; the canonical CBOR request action is unsupported.
            let len = CommissioningDecoder::frame(&[0x82, 1, 99], &mut frame).unwrap();
            console.incoming.extend(&frame[..len]);
        }
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
    fn usb_recovery_preserves_identity_and_endpoint_then_clears_backup_after_restart() {
        let memory = Rc::new(RefCell::new(Memory::default()));
        assert_eq!(campaign(memory.clone(), Plan::Pair).0, Ok(()));
        let original = Device::recover(&mut Shared(memory.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(campaign(memory.clone(), Plan::Backup).0, Ok(()));
        let backup = Device::recover(&mut Shared(memory.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(backup.endpoint, original.endpoint);
        assert_eq!(backup.pairing.checkpoint().recovery_owner(), Some(&[8; 32]));
        let (result, replies) = campaign(memory.clone(), Plan::Recover);
        assert_eq!(result, Ok(()));
        assert!(replies.iter().any(|reply| matches!(reply,CommissioningReply::Committed(record) if record.recovery_owner().is_none())));
        let recovered = Device::recover(&mut Shared(memory.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(
            recovered.identity.peer().principal(),
            original.identity.peer().principal()
        );
        assert_eq!(
            recovered.pairing.checkpoint().store(),
            original.pairing.checkpoint().store()
        );
        assert_eq!(
            recovered.pairing.checkpoint().policy().unwrap().owner(),
            &[9; 32]
        );
        assert!(
            !recovered.pairing.permits(
                &Identity::from_private_key([2; 32], 2)
                    .unwrap()
                    .peer()
                    .principal()
            )
        );
        assert!(
            recovered.pairing.permits(
                &Identity::from_private_key([3; 32], 3)
                    .unwrap()
                    .peer()
                    .principal()
            )
        );
        assert!(recover_pending(&recovered, &mut Shared(memory.clone()), true).is_ok());
        let before = memory.borrow().bytes.clone();
        let (_, replies) = campaign(memory.clone(), Plan::Recover);
        assert!(
            replies
                .iter()
                .any(|reply| matches!(reply, CommissioningReply::Refused(3)))
        );
        assert_eq!(memory.borrow().bytes, before);
    }

    #[test]
    fn usb_read_only_recovery_cannot_abandon_an_unresolved_effect() {
        let memory = Rc::new(RefCell::new(Memory::default()));
        assert_eq!(campaign(memory.clone(), Plan::Pair).0, Ok(()));
        assert_eq!(campaign(memory.clone(), Plan::Backup).0, Ok(()));
        let device = Device::recover(&mut Shared(memory.clone()))
            .unwrap()
            .unwrap();
        let mut store = Shared(memory.clone());
        let mut pending = recover_pending(&device, &mut store, true).unwrap();
        prepare_sample(&mut pending, &mut [0; 61], 42, random).unwrap();
        let before = memory.borrow().bytes.clone();
        let retained = memory.borrow().pending;
        let (result, replies) = campaign(memory.clone(), Plan::RecoverReadOnly);
        assert_eq!(result, Err(Error::Storage));
        assert!(
            replies
                .iter()
                .any(|reply| matches!(reply, CommissioningReply::Refused(4)))
        );
        assert_eq!(memory.borrow().bytes, before);
        assert_eq!(memory.borrow().pending, retained);
        let device = Device::recover(&mut Shared(memory.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(device.pairing.checkpoint().recovery_owner(), Some(&[8; 32]));
    }

    #[test]
    fn failed_session_keeps_usb_available_without_restarting_network_or_writing_custody() {
        let first = Identity::from_private_key([1; 32], 17).unwrap();
        let second = Identity::from_private_key([2; 32], 18).unwrap();
        let (identity, private, peer) =
            if first.peer().principal().fingerprint() > second.peer().principal().fingerprint() {
                (first, [1; 32], second.peer())
            } else {
                (second, [2; 32], first.peer())
            };
        let record = PairingRecord::unpaired(&identity, [9; 32]).unwrap();
        let mut pairing = LocalPairing::restore(&identity, record).unwrap();
        let challenge = pairing.begin(&identity, 0, random).unwrap();
        let policy =
            coaptic::provisioning::EnrollmentPolicy::new(peer.clone(), [7; 32], echo_permissions())
                .unwrap();
        coaptic::provisioning::PairingUpdate::new(challenge, policy, false)
            .apply(&mut pairing, 1, |_, _| Ok::<_, ()>(()))
            .unwrap();
        let mut stored = [0; STORE_BYTES];
        let len = encode_store(
            &private,
            identity.peer().kid(),
            pairing.checkpoint(),
            Some(Endpoint::v4([127, 0, 0, 1], 5683)),
            &mut stored,
        )
        .unwrap();
        let memory = Rc::new(RefCell::new(Memory {
            bytes: stored[..len].to_vec(),
            uncertain: false,
            pending: None,
        }));
        let before = memory.borrow().bytes.clone();
        let replies = Rc::new(RefCell::new(Vec::new()));
        struct FaultUsb {
            inner: Usb,
            faults: usize,
            reads: usize,
        }
        impl Console for FaultUsb {
            fn read(&mut self, bytes: &mut [u8]) -> Result<usize, Error> {
                self.reads += 1;
                if self.reads == 2 {
                    // Inject a fatal session result after the outer USB poll.
                    return Err(Error::Network);
                }
                self.inner.read(bytes)
            }
            fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
                self.inner.write(bytes)
            }
            fn restart(&mut self) -> Result<(), Error> {
                Ok(())
            }
            fn event(&mut self, event: u32) {
                if event == 5 {
                    self.faults += 1;
                    assert_eq!(self.faults, 1);
                    self.inner.enqueue(CommissioningRequest::Inspect);
                }
            }
        }
        let console = FaultUsb {
            inner: Usb {
                plan: Plan::Inspect,
                incoming: VecDeque::new(),
                replies: replies.clone(),
                prior: None,
                peer,
                read_failure: false,
                lose_committed_reply: false,
            },
            faults: 0,
            reads: 0,
        };
        let mut now = 1;
        let mut owners = 0;
        let result = run(
            || {
                owners += 1;
                Io
            },
            |_| false,
            || {
                now += 1;
                (now < 100).then_some(now)
            },
            Shared(memory.clone()),
            console,
        );
        assert_eq!(result, Ok(()));
        assert_eq!(owners, 1);
        assert!(
            matches!(replies.borrow().as_slice(), [CommissioningReply::State { record, .. }]
            if record.enabled() && record.revision() == 2)
        );
        assert_eq!(memory.borrow().bytes, before);
    }

    #[test]
    fn malformed_request_is_refused_and_next_inspection_preserves_exact_custody() {
        let mut memory = Memory::default();
        Device::initialize(&mut memory, 17, random).unwrap();
        let before = memory.bytes.clone();
        let store = Rc::new(RefCell::new(memory));
        let (result, replies) =
            campaign_with_faults(store.clone(), Plan::Inspect, false, false, true);
        assert_eq!(result, Ok(()));
        assert!(matches!(
            replies.first(),
            Some(CommissioningReply::Refused(5))
        ));
        assert!(
            matches!(replies.last(), Some(CommissioningReply::State { record, .. }) if record.revision() == 1 && !record.enabled())
        );
        assert_eq!(store.borrow().bytes, before);
    }

    #[test]
    fn fragmented_command_survives_short_gaps_and_abandoned_frame_expires() {
        for abandoned in [false, true] {
            let mut console = Usb {
                plan: Plan::Inspect,
                incoming: VecDeque::new(),
                replies: Rc::new(RefCell::new(Vec::new())),
                prior: None,
                peer: Identity::from_private_key([2; 32], 2).unwrap().peer(),
                read_failure: false,
                lose_committed_reply: false,
            };
            let mut frame = [0; 16];
            let len = CommissioningDecoder::frame(&[0x82, 1, 0], &mut frame).unwrap();
            console.incoming.extend(&frame[..7]);
            let mut frames = ConsoleFrames::new();
            assert!(receive(&mut console, &mut frames, 0).unwrap().is_none());
            if abandoned {
                console.incoming.extend(&frame[..len]);
            } else {
                console.incoming.extend(&frame[7..len]);
            }
            let now = if abandoned { 1000 } else { 999 };
            assert!(matches!(
                receive(&mut console, &mut frames, now).unwrap(),
                Some(CommissioningRequest::Inspect)
            ));
        }
    }

    #[test]
    fn console_read_failure_and_lost_commit_reply_allow_inspection_without_restarting() {
        let store = Rc::new(RefCell::new(Memory::default()));
        let (result, replies) = campaign_with_faults(store.clone(), Plan::Pair, true, true, false);
        assert_eq!(result, Ok(()));
        assert!(
            !replies
                .iter()
                .any(|reply| matches!(reply, CommissioningReply::Committed(_)))
        );
        assert!(
            matches!(replies.last(), Some(CommissioningReply::State { record, .. }) if record.enabled() && record.revision() == 2)
        );
        let recovered = Device::recover(&mut Shared(store)).unwrap().unwrap();
        assert_eq!(recovered.identity.peer().kid(), 17);
        assert_eq!(recovered.pairing.checkpoint().revision(), 2);
        assert_eq!(
            recovered.pairing.checkpoint().policy().unwrap().owner(),
            &[7; 32]
        );
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
        assert!(replies.iter().any(|reply| matches!(reply, CommissioningReply::State { device, record, .. } if device.principal() == principal && record.enabled())));
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
