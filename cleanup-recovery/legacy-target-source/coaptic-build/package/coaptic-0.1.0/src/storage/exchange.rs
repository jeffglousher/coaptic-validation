//! Outstanding request/response matching by Token and remote [`Endpoint`].
//!
//! RFC 7252 §5.3 matches a response to a request by Token plus the remote
//! endpoint. This is not the Dedup Table (Message ID + Endpoint) and not
//! pending-CON confirm (Message ID + Endpoint on a TX slot). Echo (RFC 9175)
//! sent on the request and a response challenge are sidecar on
//! [`ExchangeEntry`]. See `knowledge/rfcs/rfc7252.txt` §5.3 and
//! `knowledge/rfcs/rfc9175.txt`.
//!
//! Capacity is the TX Datagram Pool count. Occupancy is independent of TX
//! slot occupancy so a separate response or NON reply can complete after the
//! outgoing datagram is released. This is not a seventh core memory area.

use super::SlotPool;
use super::endpoint::Endpoint;
use super::occupancy::Occupancy;
use super::slot::{SlotError, SlotId};
use crate::message::{Echo, MessageId, ParsedMessage, Token, Type};

/// Lookup identity for one outstanding request.
///
/// RFC 7252 §5.3.2: the source endpoint of the response must be the
/// destination of the request, and the tokens must match.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExchangeKey {
    token: Token,
    endpoint: Endpoint,
}

impl ExchangeKey {
    /// Identity for one Token toward `endpoint`.
    #[must_use]
    pub const fn new(token: Token, endpoint: Endpoint) -> Self {
        Self { token, endpoint }
    }

    /// Client Token.
    #[must_use]
    pub const fn token(self) -> Token {
        self.token
    }

    /// Remote endpoint the request was sent to.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.endpoint
    }
}

/// Occupied exchange-table payload.
///
/// [`Self::message_id`] is the request Message ID (piggybacked ACK matching).
/// [`Self::tx_slot`] is the TX datagram that held the request at insert;
/// the caller releases it. The table does not own that slot.
/// [`Self::echo`] is the Echo sent with the request, if any.
/// [`Self::challenge`] is the Echo on a matched response (RFC 9175 freshness).
/// Not a seventh core area; sidecar on this row. See
/// `knowledge/rfcs/rfc9175.txt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExchangeEntry {
    key: ExchangeKey,
    message_id: MessageId,
    tx_slot: SlotId,
    echo: Option<Echo>,
    challenge: Option<Echo>,
}

impl ExchangeEntry {
    /// Outstanding request with `token` toward `endpoint`.
    #[must_use]
    pub const fn new(
        token: Token,
        endpoint: Endpoint,
        message_id: MessageId,
        tx_slot: SlotId,
    ) -> Self {
        Self {
            key: ExchangeKey::new(token, endpoint),
            message_id,
            tx_slot,
            echo: None,
            challenge: None,
        }
    }

    /// Same entry with the Echo sent on the request.
    #[must_use]
    pub const fn with_echo(self, echo: Echo) -> Self {
        Self {
            echo: Some(echo),
            ..self
        }
    }

    /// Same entry with the Echo challenge from a matched response.
    #[must_use]
    pub const fn with_challenge(self, challenge: Echo) -> Self {
        Self {
            challenge: Some(challenge),
            ..self
        }
    }

    /// Lookup identity.
    #[must_use]
    pub const fn key(self) -> ExchangeKey {
        self.key
    }

    /// Client Token.
    #[must_use]
    pub const fn token(self) -> Token {
        self.key.token()
    }

    /// Remote endpoint.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.key.endpoint()
    }

    /// Message ID of the outstanding request.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        self.message_id
    }

    /// TX datagram slot recorded at insert.
    #[must_use]
    pub const fn tx_slot(self) -> SlotId {
        self.tx_slot
    }

    /// Echo sent with the outstanding request, if any.
    #[must_use]
    pub const fn echo(self) -> Option<Echo> {
        self.echo
    }

    /// Echo on the matched response (freshness challenge), if any.
    ///
    /// Bound to [`Self::endpoint`]. The client echoes it only to that
    /// endpoint. See `knowledge/rfcs/rfc9175.txt`.
    #[must_use]
    pub const fn challenge(self) -> Option<Echo> {
        self.challenge
    }

    /// [`Self::challenge`] when `endpoint` is this row's remote, else `None`.
    #[must_use]
    pub fn challenge_for(self, endpoint: Endpoint) -> Option<Echo> {
        if self.endpoint() == endpoint {
            self.challenge
        } else {
            None
        }
    }

    /// Whether `parsed` is a matching response for this entry (token already
    /// compared by table lookup).
    ///
    /// Empty ACK/RST are not responses. A piggybacked ACK also requires the
    /// request Message ID. A separate CON/NON response matches by Token only.
    /// See `knowledge/rfcs/rfc7252.txt` §5.3.2.
    #[must_use]
    pub fn matches_response(self, parsed: &ParsedMessage<'_>) -> bool {
        matches_response(parsed, self.message_id())
    }
}

/// CON or NON request (not an empty message, ACK, or RST).
#[must_use]
pub(crate) fn is_con_or_non_request(parsed: &ParsedMessage<'_>) -> bool {
    parsed.code().is_request() && matches!(parsed.ty(), Type::Confirmable | Type::NonConfirmable)
}

/// Response that can complete an exchange. Empty ACK (code 0.00) is not one.
#[must_use]
pub(crate) fn is_token_response(parsed: &ParsedMessage<'_>) -> bool {
    parsed.code().is_response()
        && matches!(
            parsed.ty(),
            Type::Confirmable | Type::NonConfirmable | Type::Acknowledgement
        )
}

/// RFC 7252 §5.3.2 type/MID rules after Token + Endpoint already match.
#[must_use]
pub(crate) fn matches_response(parsed: &ParsedMessage<'_>, request_mid: MessageId) -> bool {
    if !is_token_response(parsed) {
        return false;
    }
    match parsed.ty() {
        Type::Acknowledgement => parsed.message_id() == request_mid,
        Type::Confirmable | Type::NonConfirmable => true,
        Type::Reset => false,
    }
}

/// Typed insert / lookup / take on an exchange table.
///
/// Each operation scans the configured entry count (O(n) in capacity).
pub(crate) trait ExchangeStore {
    fn insert(&mut self, entry: ExchangeEntry) -> Option<SlotId>;
    fn lookup(&self, key: ExchangeKey) -> Option<SlotId>;
    fn take(&mut self, key: ExchangeKey) -> Option<ExchangeEntry>;
    fn entry(&self, id: SlotId) -> Option<ExchangeEntry>;
}

/// Compact outstanding-request table, keyed by Token and remote [`Endpoint`].
///
/// Insert, lookup, and take scan every configured entry (O(n) in capacity).
/// Saturation returns `None` from insert; this type does not evict.
/// [`Self::rotate`] still advances the occupancy cursor used by acquire.
///
/// Capacity is provisioned as the TX Datagram Pool count. Entries are not
/// stored in TX slots: a released TX datagram must not drop the exchange.
pub struct ExchangeTable<const ENTRIES: usize> {
    entries: [Option<ExchangeEntry>; ENTRIES],
    occ: Occupancy<ENTRIES>,
}

impl<const ENTRIES: usize> ExchangeTable<ENTRIES> {
    /// Empty table. Cursor starts at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; ENTRIES],
            occ: Occupancy::new(),
        }
    }

    /// Insert `entry`, or return the existing slot if the key is already present.
    ///
    /// Returns `None` when the table is full and the key is not already stored.
    /// Scans the configured capacity (O(n)).
    pub fn insert(&mut self, entry: ExchangeEntry) -> Option<SlotId> {
        if let Some(id) = self.lookup(entry.key()) {
            return Some(id);
        }
        let id = self.occ.acquire()?;
        self.entries[id.index()] = Some(entry);
        Some(id)
    }

    /// Slot whose occupied payload matches `key`, if any.
    ///
    /// Scans the configured capacity (O(n)).
    #[must_use]
    pub fn lookup(&self, key: ExchangeKey) -> Option<SlotId> {
        (0..ENTRIES).find_map(|i| {
            let id = SlotId::from_index(i);
            match self.entry(id) {
                Some(entry) if entry.key() == key => Some(id),
                _ => None,
            }
        })
    }

    /// Remove and return the occupied payload matching `key`, if any.
    ///
    /// Scans the configured capacity (O(n)).
    pub fn take(&mut self, key: ExchangeKey) -> Option<ExchangeEntry> {
        let id = self.lookup(key)?;
        let entry = self.entry(id)?;
        let _ = self.release(id);
        Some(entry)
    }

    /// Occupied payload at `id`.
    #[must_use]
    pub fn entry(&self, id: SlotId) -> Option<ExchangeEntry> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        self.entries.get(id.index()).copied().flatten()
    }

    fn reset(&mut self, id: SlotId) {
        if let Some(slot) = self.entries.get_mut(id.index()) {
            *slot = None;
        }
    }
}

impl<const ENTRIES: usize> Default for ExchangeTable<ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const ENTRIES: usize> ExchangeStore for ExchangeTable<ENTRIES> {
    fn insert(&mut self, entry: ExchangeEntry) -> Option<SlotId> {
        ExchangeTable::insert(self, entry)
    }

    fn lookup(&self, key: ExchangeKey) -> Option<SlotId> {
        ExchangeTable::lookup(self, key)
    }

    fn take(&mut self, key: ExchangeKey) -> Option<ExchangeEntry> {
        ExchangeTable::take(self, key)
    }

    fn entry(&self, id: SlotId) -> Option<ExchangeEntry> {
        ExchangeTable::entry(self, id)
    }
}

impl<const ENTRIES: usize> SlotPool for ExchangeTable<ENTRIES> {
    fn acquire(&mut self) -> Option<SlotId> {
        let id = self.occ.acquire()?;
        self.reset(id);
        Some(id)
    }

    fn release(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.occ.release(id)?;
        self.reset(id);
        Ok(())
    }

    fn advance(&mut self, steps: usize) {
        self.occ.advance(steps);
    }

    fn slot_count(&self) -> usize {
        self.occ.slot_count()
    }

    fn occupied_count(&self) -> usize {
        self.occ.occupied_count()
    }

    fn is_occupied(&self, id: SlotId) -> bool {
        self.occ.is_occupied(id)
    }

    fn cursor(&self) -> usize {
        self.occ.cursor()
    }
}

/// Typed outstanding-request access.
///
/// Insert, lookup, and take scan the configured entry count (O(n) in
/// capacity). Capacity is the TX Datagram Pool count, with independent
/// occupancy. [`super::Memory`] and [`super::AllocMemory`] implement this.
pub trait Exchanges {
    /// Insert `entry`, or return the existing slot if the key is present.
    ///
    /// `None` when the table is full and the key is not already stored.
    fn insert_exchange(&mut self, entry: ExchangeEntry) -> Option<SlotId>;

    /// Occupied slot matching `key`, if any.
    fn lookup_exchange(&self, key: ExchangeKey) -> Option<SlotId>;

    /// Remove and return the occupied payload matching `key`, if any.
    fn take_exchange(&mut self, key: ExchangeKey) -> Option<ExchangeEntry>;

    /// Occupied payload at `id`.
    fn exchange_entry(&self, id: SlotId) -> Option<ExchangeEntry>;
}
