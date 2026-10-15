//! Bounded caller-owned OSCORE state for the qualification adapter.
//!
//! Recovery never initializes missing state. Explicit provisioning uses fresh
//! credentials in a separate offline step. The record authenticates its context,
//! sender reservation and replay checkpoint; commits require durable write and
//! exact readback. A failed/ambiguous commit poisons this session until recovery.
//! HMAC detects corruption/substitution, not rollback of a valid old record.
//! Storage freshness and key custody remain platform/operator responsibilities;
//! NVS alone is not protection against hostile flash restoration. Losing that
//! assurance requires fresh credentials (knowledge/rfcs/rfc8613.txt section 7.5).
#![forbid(unsafe_code)]

use coaptic::oscore::{DeriveParams, ReplayCheckpoint, SecurityContext};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const RECORD_BYTES: usize = 100;
pub const RESERVATION: u64 = 256;
const MAGIC: &[u8; 8] = b"COAPSEC1";
const TAG_START: usize = 68;

/// Unique, privately provisioned pairwise credentials; never public fixture keys.
/// Device/host Sender and Recipient IDs must be mirrors. No key is logged.
pub struct Credentials {
    pub secret: [u8; 32],
    pub salt: [u8; 16],
    pub context: [u8; 16],
    pub sender: u8,
    pub recipient: u8,
}

impl Credentials {
    pub fn parameters(&self) -> DeriveParams<'_> {
        DeriveParams {
            master_secret: &self.secret,
            master_salt: &self.salt,
            sender_id: core::slice::from_ref(&self.sender),
            recipient_id: core::slice::from_ref(&self.recipient),
            id_context: &self.context,
        }
    }
    fn mac(&self, domain: &[u8]) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("fixed HMAC key length");
        mac.update(domain);
        mac
    }
    fn identity(&self) -> [u8; 32] {
        let mut mac = self.mac(b"Coaptic qualification context v1\0");
        mac.update(&self.salt);
        mac.update(&self.context);
        mac.update(&[self.sender, self.recipient]);
        mac.finalize().into_bytes().into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Missing,
    Present,
    Corrupt,
    Unavailable,
    Exhausted,
    Poisoned,
}

/// Caller-owned fixed-record storage. No automatic reset, erase or fallback.
/// The caller must exclusively own this context/key and record for the entire
/// live session. No concurrent/outside writer may grant ranges or replace state.
/// Read-before-write detects a stale record, but is not an atomic compare/exchange
/// and does not establish multi-writer or hostile rollback safety.
pub trait Store {
    /// None means truly absent; wrong length/read failures must return an error.
    fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, Error>;
    /// Return success only after durable commit, not merely a buffered write.
    fn commit(&mut self, record: &[u8; RECORD_BYTES]) -> Result<(), Error>;
}

#[derive(Clone, Copy)]
struct Record {
    end: u64,
    replay: ReplayCheckpoint,
    generation: u64,
}
impl Record {
    fn encode(self, credentials: &Credentials) -> [u8; RECORD_BYTES] {
        self.encode_bound(credentials, &credentials.identity())
    }
    fn encode_bound(self, credentials: &Credentials, identity: &[u8]) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..40].copy_from_slice(identity);
        bytes[40..48].copy_from_slice(&self.end.to_be_bytes());
        let (left, bits) = self.replay.parts();
        bytes[48..56].copy_from_slice(&left.to_be_bytes());
        bytes[56..60].copy_from_slice(&bits.to_be_bytes());
        bytes[60..68].copy_from_slice(&self.generation.to_be_bytes());
        let mut mac = credentials.mac(b"Coaptic qualification durable state v1\0");
        mac.update(&bytes[..TAG_START]);
        bytes[TAG_START..].copy_from_slice(&mac.finalize().into_bytes());
        bytes
    }
    fn decode(bytes: &[u8; RECORD_BYTES], credentials: &Credentials) -> Result<Self, Error> {
        let mut mac = credentials.mac(b"Coaptic qualification durable state v1\0");
        mac.update(&bytes[..TAG_START]);
        mac.verify_slice(&bytes[TAG_START..])
            .map_err(|_| Error::Corrupt)?;
        if &bytes[..8] != MAGIC || bytes[8..40] != credentials.identity() {
            return Err(Error::Corrupt);
        }
        let end = u64::from_be_bytes(bytes[40..48].try_into().unwrap());
        let left = u64::from_be_bytes(bytes[48..56].try_into().unwrap());
        let bits = u32::from_be_bytes(bytes[56..60].try_into().unwrap());
        let generation = u64::from_be_bytes(bytes[60..68].try_into().unwrap());
        if end > (1 << 40) || generation == 0 {
            return Err(Error::Corrupt);
        }
        let replay = ReplayCheckpoint::from_parts(left, bits).map_err(|_| Error::Corrupt)?;
        Ok(Self {
            end,
            replay,
            generation,
        })
    }
}

/// Offline initialization only. The consuming mode must expose no network service.
/// Never retry with reused credentials if previous storage freshness is uncertain.
pub fn provision(store: &mut impl Store, credentials: &Credentials) -> Result<(), Error> {
    SecurityContext::derive(credentials.parameters()).map_err(|_| Error::Corrupt)?;
    if store.read()?.is_some() {
        return Err(Error::Present);
    }
    let bytes = Record {
        end: 0,
        replay: ReplayCheckpoint::from_parts(0, 0).unwrap(),
        generation: 1,
    }
    .encode(credentials);
    store.commit(&bytes)?;
    if store.read()? != Some(bytes) {
        return Err(Error::Unavailable);
    }
    Ok(())
}

/// Live state retains one additional fixed 100-byte authenticated record.
/// Storage reads and exact durable readback still occur at every changed barrier.
pub struct State<'a, S> {
    store: S,
    credentials: &'a Credentials,
    record: Record,
    // Exact authenticated recovery/readback bytes. Fixed storage avoids repeating
    // the context identity and old-record HMAC on every persistence barrier.
    committed: [u8; RECORD_BYTES],
    poisoned: bool,
}

/// Authenticate an existing record without granting a sender range or writing.
/// This is an offline preflight, not a live security context or freshness proof.
/// The caller retains exclusive ownership; only `State::recover` may create the
/// guarded context for network use.
pub fn verify_record(store: &mut impl Store, credentials: &Credentials) -> Result<(), Error> {
    let bytes = store.read()?.ok_or(Error::Missing)?;
    Record::decode(&bytes, credentials).map(|_| ())
}

impl<'a, S: Store> State<'a, S> {
    /// Authenticate and restore replay; skip every previously reserved sequence;
    /// durably grant a fresh range before the context can be used for traffic.
    pub fn recover(
        mut store: S,
        credentials: &'a Credentials,
    ) -> Result<(Self, SecurityContext), Error> {
        let bytes = store.read()?.ok_or(Error::Missing)?;
        let record = Record::decode(&bytes, credentials)?;
        let mut context =
            SecurityContext::derive(credentials.parameters()).map_err(|_| Error::Corrupt)?;
        context
            .restore_replay(record.replay)
            .map_err(|_| Error::Corrupt)?;
        context
            .restore_sender_reservation(record.end)
            .map_err(|_| Error::Corrupt)?;
        let mut state = Self {
            store,
            credentials,
            record,
            committed: bytes,
            poisoned: false,
        };
        state.refill(&mut context)?;
        Ok((state, context))
    }
    fn persist(&mut self, mut next: Record) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        next.generation = self
            .record
            .generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let bytes = next.encode_bound(self.credentials, &self.committed[8..40]);
        let expected = self.committed;
        let result = self
            .store
            .read()
            .and_then(|current| {
                if current != Some(expected) {
                    return Err(Error::Unavailable);
                }
                self.store.commit(&bytes)
            })
            .and_then(|()| {
                if self.store.read()? == Some(bytes) {
                    Ok(())
                } else {
                    Err(Error::Unavailable)
                }
            });
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        self.record = next;
        self.committed = bytes;
        Ok(())
    }
    /// Only pass the live context returned together with this state by recover.
    pub fn refill(&mut self, context: &mut SecurityContext) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if context.sender_reservation_end() != Some(self.record.end) {
            return Err(Error::Corrupt);
        }
        context
            .reserve_sender_sequences(RESERVATION, |end| {
                self.persist(Record { end, ..self.record })
            })
            .map_err(|error| match error {
                coaptic::oscore::SenderReservationError::Persistence(error) => error,
                _ => Error::Exhausted,
            })?;
        Ok(())
    }
    /// Barrier callback for App::poll_with_oscore_checkpoint. Unchanged checkpoints
    /// do not write. Refuse rollback even if the caller passes a stale checkpoint.
    pub fn checkpoint(&mut self, replay: ReplayCheckpoint) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if replay == self.record.replay {
            return Ok(());
        }
        // Both checkpoints are typed/validated and this state already
        // authenticated its immutable credential/record binding at recovery.
        // Progression is key-independent; use the core's same rollback guard
        // without repeating HKDF or retaining a second keyed context.
        self.record
            .replay
            .validate_successor(replay)
            .map_err(|_| Error::Corrupt)?;
        self.persist(Record {
            replay,
            ..self.record
        })
    }
    pub fn generation(&self) -> u64 {
        self.record.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    #[derive(Default)]
    struct Data {
        bytes: Option<[u8; RECORD_BYTES]>,
        writes: usize,
        fail: bool,
        lose_ack: bool,
        stale: bool,
    }
    #[derive(Clone, Default)]
    struct Memory(Rc<RefCell<Data>>);
    impl Store for Memory {
        fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, Error> {
            Ok(self.0.borrow().bytes)
        }
        fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> Result<(), Error> {
            let mut d = self.0.borrow_mut();
            d.writes += 1;
            if d.fail {
                return Err(Error::Unavailable);
            }
            if !d.stale {
                d.bytes = Some(*bytes);
            }
            if d.lose_ack {
                Err(Error::Unavailable)
            } else {
                Ok(())
            }
        }
    }
    fn credentials() -> Credentials {
        Credentials {
            secret: [0x39; 32],
            salt: [0x42; 16],
            context: [0x27; 16],
            sender: 1,
            recipient: 2,
        }
    }
    #[test]
    fn cached_record_matches_each_durable_barrier_and_refuses_external_corruption() {
        let c = credentials();
        for changed in 0..RECORD_BYTES {
            let mut m = Memory::default();
            provision(&mut m, &c).unwrap();
            let (mut state, _) = State::recover(m.clone(), &c).unwrap();
            for left in 1..=3 {
                state
                    .checkpoint(ReplayCheckpoint::from_parts(left, 1).unwrap())
                    .unwrap();
                assert_eq!(Some(state.committed), m.0.borrow().bytes);
                assert_eq!(state.committed, state.record.encode(&c));
            }
            let committed = state.committed;
            let generation = state.generation();
            let writes = m.0.borrow().writes;
            m.0.borrow_mut().bytes.as_mut().unwrap()[changed] ^= 1;
            let next = ReplayCheckpoint::from_parts(4, 1).unwrap();
            assert_eq!(state.checkpoint(next), Err(Error::Unavailable));
            assert_eq!(state.committed, committed);
            assert_eq!(state.generation(), generation);
            assert_eq!(m.0.borrow().writes, writes);
            assert_eq!(state.checkpoint(next), Err(Error::Poisoned));
            assert!(matches!(State::recover(m.clone(), &c), Err(Error::Corrupt)));
            // Only restoring the exact committed bytes permits a fresh recovery.
            m.0.borrow_mut().bytes = Some(committed);
            let (mut recovered, _) = State::recover(m, &c).unwrap();
            recovered.checkpoint(next).unwrap();
            assert_eq!(recovered.committed, recovered.record.encode(&c));
        }
    }

    #[test]
    fn offline_verification_authenticates_without_reserving_or_writing() {
        let c = credentials();
        let mut m = Memory::default();
        assert_eq!(verify_record(&mut m, &c), Err(Error::Missing));
        assert_eq!(m.0.borrow().writes, 0);
        provision(&mut m, &c).unwrap();
        let before = m.0.borrow().bytes;
        for _ in 0..3 {
            assert_eq!(verify_record(&mut m, &c), Ok(()));
        }
        let mut wrong = credentials();
        wrong.secret[0] ^= 1;
        assert_eq!(verify_record(&mut m, &wrong), Err(Error::Corrupt));
        assert_eq!(m.0.borrow().writes, 1);
        assert_eq!(m.0.borrow().bytes, before);
        let (_, context) = State::recover(m.clone(), &c).unwrap();
        assert_eq!(context.sender_seq(), 0);
        assert_eq!(m.0.borrow().writes, 2);
    }
    #[test]
    fn checkpoint_refusal_preserves_record_and_allows_valid_progress_without_recovery() {
        let c = credentials();
        let mut m = Memory::default();
        provision(&mut m, &c).unwrap();
        let (mut state, _) = State::recover(m.clone(), &c).unwrap();
        state
            .checkpoint(ReplayCheckpoint::from_parts(10, 0b1011).unwrap())
            .unwrap();
        let bytes = m.0.borrow().bytes;
        let writes = m.0.borrow().writes;
        let generation = state.generation();
        for checkpoint in [
            ReplayCheckpoint::from_parts(10, 1).unwrap(),
            ReplayCheckpoint::from_parts(9, u32::MAX).unwrap(),
        ] {
            assert_eq!(state.checkpoint(checkpoint), Err(Error::Corrupt));
            assert_eq!(m.0.borrow().bytes, bytes);
            assert_eq!(m.0.borrow().writes, writes);
            assert_eq!(state.generation(), generation);
        }
        // Sequence10 falls below the window; seen11/13 remain rejected.
        state
            .checkpoint(ReplayCheckpoint::from_parts(11, 0b101).unwrap())
            .unwrap();
        assert_eq!(state.generation(), generation + 1);
        assert_eq!(m.0.borrow().writes, writes + 1);
        assert_eq!(verify_record(&mut m, &c), Ok(()));
        let terminal = ReplayCheckpoint::from_parts(1u64 << 40, 0).unwrap();
        state.checkpoint(terminal).unwrap();
        let writes = m.0.borrow().writes;
        state.checkpoint(terminal).unwrap();
        assert_eq!(m.0.borrow().writes, writes);
        drop(state);
        let (_, recovered) = State::recover(m, &c).unwrap();
        assert_eq!(recovered.replay_checkpoint(), terminal);
    }

    #[test]
    fn restart_restores_replay_and_skips_the_whole_reserved_range() {
        let c = credentials();
        let mut m = Memory::default();
        assert!(matches!(State::recover(m.clone(), &c), Err(Error::Missing)));
        assert_eq!(m.0.borrow().writes, 0);
        provision(&mut m, &c).unwrap();
        assert_eq!(provision(&mut m, &c), Err(Error::Present));
        let (mut s, ctx) = State::recover(m.clone(), &c).unwrap();
        assert_eq!(ctx.sender_seq(), 0);
        assert_eq!(ctx.sender_reservation_end(), Some(256));
        let replay = ReplayCheckpoint::from_parts(0, 1).unwrap();
        s.checkpoint(replay).unwrap();
        let writes = m.0.borrow().writes;
        s.checkpoint(replay).unwrap();
        assert_eq!(m.0.borrow().writes, writes);
        assert_eq!(
            s.checkpoint(ReplayCheckpoint::from_parts(0, 0).unwrap()),
            Err(Error::Corrupt)
        );
        drop(s);
        let (s, ctx) = State::recover(m.clone(), &c).unwrap();
        assert_eq!(ctx.sender_seq(), 256);
        assert_eq!(ctx.sender_reservation_end(), Some(512));
        assert_eq!(ctx.replay_checkpoint(), replay);
        assert_eq!(s.generation(), 4);
    }
    #[test]
    fn authenticated_record_refuses_every_corrupted_byte_and_wrong_context() {
        let c = credentials();
        let mut m = Memory::default();
        provision(&mut m, &c).unwrap();
        let bytes = m.0.borrow().bytes.unwrap();
        for i in 0..RECORD_BYTES {
            let mut bad = bytes;
            bad[i] ^= 1;
            assert!(
                matches!(Record::decode(&bad, &c), Err(Error::Corrupt)),
                "byte {i}"
            );
        }
        let mut wrong = credentials();
        wrong.context[0] ^= 1;
        assert!(matches!(
            Record::decode(&bytes, &wrong),
            Err(Error::Corrupt)
        ));
        wrong = credentials();
        wrong.secret[0] ^= 1;
        assert!(matches!(
            Record::decode(&bytes, &wrong),
            Err(Error::Corrupt)
        ));
        wrong = credentials();
        core::mem::swap(&mut wrong.sender, &mut wrong.recipient);
        assert!(matches!(
            Record::decode(&bytes, &wrong),
            Err(Error::Corrupt)
        ));
        for bad in [
            Record {
                end: (1 << 40) + 1,
                replay: ReplayCheckpoint::from_parts(0, 0).unwrap(),
                generation: 1,
            },
            Record {
                end: 0,
                replay: ReplayCheckpoint::from_parts(0, 0).unwrap(),
                generation: 0,
            },
        ] {
            assert!(matches!(
                Record::decode(&bad.encode(&c), &c),
                Err(Error::Corrupt)
            ));
        }
    }
    #[test]
    fn failed_or_ambiguous_commit_poison_until_recovery_and_readback_is_required() {
        let c = credentials();
        let mut m = Memory::default();
        provision(&mut m, &c).unwrap();
        let (mut s, mut ctx) = State::recover(m.clone(), &c).unwrap();
        let committed = s.committed;
        let generation = s.generation();
        m.0.borrow_mut().lose_ack = true;
        assert_eq!(s.refill(&mut ctx), Err(Error::Unavailable));
        assert_eq!(s.committed, committed);
        assert_eq!(s.generation(), generation);
        assert_eq!(ctx.sender_reservation_end(), Some(256));
        assert_eq!(
            s.checkpoint(ReplayCheckpoint::from_parts(0, 1).unwrap()),
            Err(Error::Poisoned)
        );
        assert_eq!(s.refill(&mut ctx), Err(Error::Poisoned));
        m.0.borrow_mut().lose_ack = false;
        let (_, ctx) = State::recover(m.clone(), &c).unwrap();
        assert_eq!(ctx.sender_seq(), 512);
        assert_eq!(ctx.sender_reservation_end(), Some(768));
        m.0.borrow_mut().fail = true;
        assert!(matches!(
            State::recover(m.clone(), &c),
            Err(Error::Unavailable)
        ));
        m.0.borrow_mut().fail = false;
        m.0.borrow_mut().stale = true;
        assert!(matches!(
            State::recover(m.clone(), &c),
            Err(Error::Unavailable)
        ));
    }
    #[test]
    fn stale_writer_cannot_grant_another_owners_reserved_range() {
        let c = credentials();
        let mut m = Memory::default();
        provision(&mut m, &c).unwrap();
        let (mut first, mut first_ctx) = State::recover(m.clone(), &c).unwrap();
        let (_, second_ctx) = State::recover(m.clone(), &c).unwrap();
        assert_eq!(second_ctx.sender_seq(), 256);
        let writes = m.0.borrow().writes;
        assert_eq!(first.refill(&mut first_ctx), Err(Error::Unavailable));
        assert_eq!(first_ctx.sender_reservation_end(), Some(256));
        assert_eq!(m.0.borrow().writes, writes);
        assert_eq!(first.refill(&mut first_ctx), Err(Error::Poisoned));
    }
    #[test]
    fn exhausted_state_refuses_before_any_traffic_or_commit() {
        let c = credentials();
        let m = Memory::default();
        m.0.borrow_mut().bytes = Some(
            Record {
                end: 1 << 40,
                replay: ReplayCheckpoint::from_parts(0, 0).unwrap(),
                generation: 1,
            }
            .encode(&c),
        );
        assert!(matches!(
            State::recover(m.clone(), &c),
            Err(Error::Exhausted)
        ));
        assert_eq!(m.0.borrow().writes, 0);
        m.0.borrow_mut().bytes = Some(
            Record {
                end: 0,
                replay: ReplayCheckpoint::from_parts(0, 0).unwrap(),
                generation: u64::MAX,
            }
            .encode(&c),
        );
        assert!(matches!(
            State::recover(m.clone(), &c),
            Err(Error::Exhausted)
        ));
        assert_eq!(m.0.borrow().writes, 0);
    }
}
