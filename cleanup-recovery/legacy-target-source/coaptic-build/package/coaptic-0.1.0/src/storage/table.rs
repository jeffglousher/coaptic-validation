//! [`DedupTable`] and [`ObserveTable`]: fixed entry slots plus rotating occupancy.

use super::SlotPool;
use super::endpoint::Endpoint;
use super::occupancy::Occupancy;
use super::slot::{SlotError, SlotId};
use crate::message::{MessageId, OBSERVE_SEQUENCE_MASK, ObserveTransmission, Token};

/// Lookup identity for one Dedup Table row.
///
/// Compact duplicate history is Message ID plus remote [`Endpoint`]. Token
/// matching is not this table. See `knowledge/rfcs/rfc7252.txt` §4.5.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DedupKey {
    message_id: MessageId,
    endpoint: Endpoint,
}

impl DedupKey {
    /// Identity for one remote Message ID.
    #[must_use]
    pub const fn new(message_id: MessageId, endpoint: Endpoint) -> Self {
        Self {
            message_id,
            endpoint,
        }
    }

    /// Message ID.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        self.message_id
    }

    /// Remote endpoint that sent the message.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.endpoint
    }
}

/// Occupied Dedup Table payload.
///
/// Stored in the table slot itself. [`Self::due_ms`] `0` means the row does
/// not expire (Engine-pair / manual insert). App caches the encoded ACK so a
/// CON retransmit can be answered without a second handler call: compact
/// [`Self::replay`] when the datagram fits, otherwise a TX pin for
/// `EXCHANGE_LIFETIME`. See `knowledge/rfcs/rfc7252.txt` §4.5.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DedupEntry {
    key: DedupKey,
    due_ms: u64,
    replay_len: u16,
    replay: [u8; Self::REPLAY_MAX],
    tx_pin: Option<SlotId>,
}

impl DedupEntry {
    /// Bytes of encoded ACK cached inline on this row.
    ///
    /// Larger piggybacked ACKs use [`Self::tx_pin`] (Default TX slot) so
    /// replay is still the same bytes. This is not a seventh memory area.
    pub const REPLAY_MAX: usize = 256;

    /// History row for `message_id` from `endpoint`.
    ///
    /// No expiry (`due_ms == 0`), no replay, no TX pin.
    #[must_use]
    pub const fn new(message_id: MessageId, endpoint: Endpoint) -> Self {
        Self {
            key: DedupKey::new(message_id, endpoint),
            due_ms: 0,
            replay_len: 0,
            replay: [0; Self::REPLAY_MAX],
            tx_pin: None,
        }
    }

    /// Absolute expiry on the caller clock. `0` is never.
    #[must_use]
    pub const fn with_due_ms(mut self, due_ms: u64) -> Self {
        self.due_ms = due_ms;
        self
    }

    /// Cache encoded reply bytes when they fit [`Self::REPLAY_MAX`].
    ///
    /// Larger datagrams are not truncated: replay stays empty so a later
    /// duplicate cannot send a lie. The caller may [`Self::with_tx_pin`]
    /// instead.
    #[must_use]
    pub fn with_replay(mut self, bytes: &[u8]) -> Self {
        if bytes.len() > Self::REPLAY_MAX {
            return self;
        }
        self.replay[..bytes.len()].copy_from_slice(bytes);
        self.replay_len = bytes.len() as u16;
        self.tx_pin = None;
        self
    }

    /// Hold occupied TX `id` so App can resend the same ACK bytes.
    ///
    /// Clears inline replay. The caller must not release that TX slot
    /// until this row expires or is replaced.
    #[must_use]
    pub const fn with_tx_pin(mut self, id: SlotId) -> Self {
        self.tx_pin = Some(id);
        self.replay_len = 0;
        self
    }

    /// Lookup identity.
    #[must_use]
    pub const fn key(self) -> DedupKey {
        self.key
    }

    /// Message ID.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        self.key.message_id()
    }

    /// Remote endpoint.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.key.endpoint()
    }

    /// Absolute expiry (`0` = never).
    #[must_use]
    pub const fn due_ms(self) -> u64 {
        self.due_ms
    }

    /// Cached piggybacked / empty-ACK bytes, if stored inline.
    #[must_use]
    pub fn replay(&self) -> Option<&[u8]> {
        if self.replay_len == 0 {
            None
        } else {
            Some(&self.replay[..usize::from(self.replay_len)])
        }
    }

    /// Occupied TX slot holding the encoded ACK, if pinned.
    #[must_use]
    pub const fn tx_pin(self) -> Option<SlotId> {
        self.tx_pin
    }

    /// Whether this row can answer a CON retransmit (`replay` or `tx_pin`).
    ///
    /// App never stores a timed row without one of these. Engine-pair
    /// inserts may still be metadata-only (`due_ms == 0`).
    #[must_use]
    pub fn has_usable_replay(&self) -> bool {
        self.replay().is_some() || self.tx_pin().is_some()
    }
}

impl From<DedupKey> for DedupEntry {
    fn from(key: DedupKey) -> Self {
        Self::new(key.message_id(), key.endpoint())
    }
}

/// Typed insert / lookup / remove on a Dedup Table.
///
/// Each operation scans the configured entry count (O(n) in capacity). Capacity
/// is fixed at construction.
pub(crate) trait DedupStore {
    fn insert(&mut self, entry: DedupEntry) -> Option<SlotId>;
    fn lookup(&self, key: DedupKey) -> Option<SlotId>;
    fn remove(&mut self, key: DedupKey) -> bool;
    fn entry(&self, id: SlotId) -> Option<DedupEntry>;
}

/// Lookup identity for one Observe Interest Table row.
///
/// RFC 7641 keys the observer list by client endpoint and Token. The local
/// client/server role separates independent observer lists in a dual-role App.
/// Resource
/// path is not part of that key. This is not Dedup (Message ID + Endpoint),
/// not pending CON, and not [`super::ExchangeKey`] (same Token + Endpoint
/// pair, different table). See `knowledge/rfcs/rfc7641.txt`.
///
/// [`ObserveResource`] is an optional sidecar on the same row so App can
/// notify by Uri-Path without a second table.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObserveKey {
    token: Token,
    endpoint: Endpoint,
    client: bool,
}

impl ObserveKey {
    /// Server-side observer identity for one Token at client `endpoint`.
    #[must_use]
    pub const fn new(token: Token, endpoint: Endpoint) -> Self {
        Self {
            token,
            endpoint,
            client: false,
        }
    }

    /// Client-side subscription identity at server `endpoint`.
    /// The opposite direction may independently use the same Token/endpoint.
    #[must_use]
    pub const fn new_client(token: Token, endpoint: Endpoint) -> Self {
        Self {
            token,
            endpoint,
            client: true,
        }
    }

    /// Whether this row receives notifications instead of serving an observer.
    #[must_use]
    pub const fn is_client(self) -> bool {
        self.client
    }

    /// Client Token.
    #[must_use]
    pub const fn token(self) -> Token {
        self.token
    }

    /// Client endpoint.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.endpoint
    }
}

/// Compact resource identity on an [`ObserveInterest`] row.
///
/// Advanced Engine path helpers use a non-cryptographic hash. It is not an
/// exact or adversarial resource identity. App instead assigns opaque route
/// identities after exact path-segment comparison; those identities are local
/// to its immutable site. Do not construct an Engine path hash to address an
/// App route. [`Self::NONE`] means no resource was recorded.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ObserveResource {
    hash: u64,
}

impl ObserveResource {
    /// No Uri-Path recorded (Engine insert without a path).
    pub const NONE: Self = Self { hash: 0 };

    pub(crate) fn app_route(index: usize) -> Self {
        Self {
            hash: index as u64 + 1,
        }
    }

    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    /// Hash of Uri-Path `segments` (wire order, no leading slash).
    #[must_use]
    pub fn from_path(segments: &[&str]) -> Self {
        let mut hash = Self::FNV_OFFSET;
        // Length-prefix each segment: a literal slash is data, not a separator.
        for segment in segments {
            for byte in (segment.len() as u64).to_be_bytes() {
                hash = Self::fnv_byte(hash, byte);
            }
            for byte in segment.as_bytes() {
                hash = Self::fnv_byte(hash, *byte);
            }
        }
        Self { hash }
    }

    /// Whether this key was produced by [`Self::from_path`] for `segments`.
    #[must_use]
    pub fn matches(self, segments: &[&str]) -> bool {
        self != Self::NONE && self == Self::from_path(segments)
    }

    /// Whether this is [`Self::NONE`].
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.hash == 0
    }

    const fn fnv_byte(hash: u64, byte: u8) -> u64 {
        (hash ^ byte as u64).wrapping_mul(Self::FNV_PRIME)
    }
}

/// Colocated Max-Age / CON-wait deadline on an [`ObserveInterest`] row.
///
/// Absolute `due_ms` in the caller `now_ms` domain (same posture as
/// [`super::PendingRto`]). The core has no OS clock. See
/// `knowledge/rfcs/rfc7641.txt` and Max-Age in `knowledge/rfcs/rfc7252.txt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ObserveLifetime {
    /// Freshness deadline from a caller-supplied Max-Age (typically client).
    MaxAge {
        /// Absolute millisecond time when this deadline fires.
        due_ms: u64,
    },
    /// CON notification waiting for an empty ACK (server client-OFF).
    Unacked {
        /// Absolute millisecond time when this deadline fires.
        due_ms: u64,
        /// Message ID of the outstanding CON notification.
        message_id: MessageId,
    },
}

impl ObserveLifetime {
    /// [`Self::MaxAge`] due at `now_ms + max_age_secs * 1000`.
    #[must_use]
    pub const fn max_age(now_ms: u64, max_age_secs: u32) -> Self {
        Self::MaxAge {
            due_ms: max_age_due_ms(now_ms, max_age_secs),
        }
    }

    /// [`Self::Unacked`] due at `now_ms + max_age_secs * 1000`.
    #[must_use]
    pub const fn unacked(now_ms: u64, max_age_secs: u32, message_id: MessageId) -> Self {
        Self::Unacked {
            due_ms: max_age_due_ms(now_ms, max_age_secs),
            message_id,
        }
    }

    /// Absolute millisecond time when this deadline fires (`now_ms` domain).
    #[must_use]
    pub const fn due_ms(self) -> u64 {
        match self {
            Self::MaxAge { due_ms } | Self::Unacked { due_ms, .. } => due_ms,
        }
    }

    /// Outstanding CON Message ID, if this is [`Self::Unacked`].
    #[must_use]
    pub const fn con_mid(self) -> Option<MessageId> {
        match self {
            Self::MaxAge { .. } => None,
            Self::Unacked { message_id, .. } => Some(message_id),
        }
    }

    /// Whether `now_ms` is at or past [`Self::due_ms`].
    #[must_use]
    pub const fn is_due(self, now_ms: u64) -> bool {
        now_ms >= self.due_ms()
    }
}

const fn max_age_due_ms(now_ms: u64, max_age_secs: u32) -> u64 {
    now_ms.saturating_add((max_age_secs as u64).saturating_mul(1_000))
}

/// One Observe interest whose colocated lifetime is due.
///
/// The row stays occupied. The caller drops it or stops notifying. The core
/// does not send RST or invent 4.02. See `knowledge/rfcs/rfc7641.txt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveExpiry {
    /// [`ObserveLifetime::MaxAge`] elapsed.
    MaxAge(SlotId),
    /// [`ObserveLifetime::Unacked`] elapsed (CON notify without ACK).
    ClientOff(SlotId),
}

impl ObserveExpiry {
    /// Observe table slot that is due.
    #[must_use]
    pub const fn slot(self) -> SlotId {
        match self {
            Self::MaxAge(id) | Self::ClientOff(id) => id,
        }
    }
}

/// Colocated RFC 7641 §4.5.1 outstanding-notification hold.
///
/// NSTART counts these per remote [`Endpoint`]. CON is outstanding until
/// empty ACK or give-up; NON until [`ObserveTransmission::NON_TIMEOUT_MS`].
/// Both variants store the notification Message ID so an empty RST can
/// drop the interest (RFC 7641 §4.5; RST has no Token). See
/// `knowledge/rfcs/rfc7641.txt` §4.5 / §4.5.1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ObserveNotifyHold {
    /// NON notification; outstanding until `until_ms` (`now_ms` domain).
    Non {
        /// Absolute millisecond time when this NON hold ends.
        until_ms: u64,
        /// Message ID of the NON notification (RST match).
        message_id: MessageId,
    },
    /// CON notification; outstanding until ACK or give-up.
    Con {
        /// Message ID of the outstanding CON notification.
        message_id: MessageId,
    },
}

impl ObserveNotifyHold {
    /// [`Self::Non`] until `now_ms + ObserveTransmission::NON_TIMEOUT_MS`.
    #[must_use]
    pub const fn non(now_ms: u64, message_id: MessageId) -> Self {
        Self::Non {
            until_ms: now_ms.saturating_add(ObserveTransmission::NON_TIMEOUT_MS as u64),
            message_id,
        }
    }

    /// [`Self::Con`] for `message_id`.
    #[must_use]
    pub const fn con(message_id: MessageId) -> Self {
        Self::Con { message_id }
    }

    /// Whether this hold is still outstanding at `now_ms`.
    #[must_use]
    pub const fn is_held(self, now_ms: u64) -> bool {
        match self {
            Self::Non { until_ms, .. } => now_ms < until_ms,
            Self::Con { .. } => true,
        }
    }

    /// Outstanding CON Message ID, if this is [`Self::Con`].
    #[must_use]
    pub const fn con_mid(self) -> Option<MessageId> {
        match self {
            Self::Non { .. } => None,
            Self::Con { message_id } => Some(message_id),
        }
    }

    /// Notification Message ID on either hold (CON or NON).
    ///
    /// Empty RST is matched by this ID plus endpoint, not by Token.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        match self {
            Self::Non { message_id, .. } | Self::Con { message_id } => message_id,
        }
    }
}

/// Occupied Observe Interest Table payload.
///
/// Relation identity plus small pending/coalescing state, the last
/// library-assigned 24-bit notification sequence, optional Max-Age /
/// CON-wait lifetime, RFC 7641 §4.5 / §4.5.1 confirm / NSTART hold, and
/// an optional [`ObserveResource`] path key. Notification bodies are not
/// stored here. See `knowledge/rfcs/rfc7641.txt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObserveInterest {
    key: ObserveKey,
    resource: ObserveResource,
    content_format: Option<crate::message::ContentFormat>,
    seq: u32,
    pending: bool,
    deleted: bool,
    lifetime: Option<ObserveLifetime>,
    confirm_due_ms: Option<u64>,
    notify_hold: Option<ObserveNotifyHold>,
    #[cfg(feature = "oscore")]
    oscore: Option<crate::oscore::RequestRef>,
}

impl ObserveInterest {
    /// Interest row for `token` at `endpoint`.
    ///
    /// Sequence starts at 0, is not pending, and has no lifetime or hold.
    #[must_use]
    pub const fn new(token: Token, endpoint: Endpoint) -> Self {
        Self {
            key: ObserveKey::new(token, endpoint),
            resource: ObserveResource::NONE,
            content_format: None,
            seq: 0,
            pending: false,
            deleted: false,
            lifetime: None,
            confirm_due_ms: None,
            notify_hold: None,
            #[cfg(feature = "oscore")]
            oscore: None,
        }
    }

    /// Client-side subscription. It is never a server notification target.
    #[must_use]
    pub const fn new_client(token: Token, endpoint: Endpoint) -> Self {
        Self {
            key: ObserveKey::new_client(token, endpoint),
            ..Self::new(token, endpoint)
        }
    }

    /// Lookup identity.
    #[must_use]
    pub const fn key(self) -> ObserveKey {
        self.key
    }

    /// Client Token.
    #[must_use]
    pub const fn token(self) -> Token {
        self.key.token()
    }

    /// Client endpoint.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.key.endpoint()
    }

    /// Uri-Path resource key, if recorded.
    #[must_use]
    pub const fn resource(self) -> ObserveResource {
        self.resource
    }

    /// Set the Uri-Path resource key (or [`ObserveResource::NONE`]).
    #[must_use]
    pub const fn with_resource(self, resource: ObserveResource) -> Self {
        Self { resource, ..self }
    }

    /// Content-Format of the initial representation, retained for notifications.
    #[must_use]
    pub const fn content_format(self) -> Option<crate::message::ContentFormat> {
        self.content_format
    }

    /// Retain the initial representation's Content-Format, including absence.
    #[must_use]
    pub const fn with_content_format(
        self,
        content_format: Option<crate::message::ContentFormat>,
    ) -> Self {
        Self {
            content_format,
            ..self
        }
    }

    /// OSCORE request binding for protected notifications, if any.
    #[cfg(feature = "oscore")]
    #[must_use]
    pub const fn oscore(self) -> Option<crate::oscore::RequestRef> {
        self.oscore
    }

    /// Bind the registration Partial IV so later notifies can protect.
    #[cfg(feature = "oscore")]
    #[must_use]
    pub const fn with_oscore(self, request: Option<crate::oscore::RequestRef>) -> Self {
        Self {
            oscore: request,
            ..self
        }
    }

    pub(crate) const fn is_deleted(self) -> bool {
        self.deleted
    }

    pub(crate) fn mark_deleted(&mut self) {
        if !self.key.is_client() {
            self.deleted = true;
            self.pending = true;
        }
    }

    /// Last library-assigned notification sequence (24-bit).
    ///
    /// Zero for a new registration; App re-registration continues the previous
    /// sequence for the same peer, Token and route. See
    /// `knowledge/rfcs/rfc7641.txt`.
    #[must_use]
    pub const fn seq(self) -> u32 {
        self.seq
    }

    /// Whether a notification is waiting to be surfaced by progress.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        self.pending
    }

    /// Set the last-assigned sequence (masked to 24 bits).
    #[must_use]
    pub const fn with_seq(self, seq: u32) -> Self {
        Self {
            seq: seq & OBSERVE_SEQUENCE_MASK,
            ..self
        }
    }

    /// Colocated Max-Age / CON-wait lifetime, if set.
    #[must_use]
    pub const fn lifetime(self) -> Option<ObserveLifetime> {
        self.lifetime
    }

    /// Replace the colocated lifetime (or clear it with `None`).
    #[must_use]
    pub const fn with_lifetime(self, lifetime: Option<ObserveLifetime>) -> Self {
        Self { lifetime, ..self }
    }

    /// Whether `now_ms` is at or past a colocated lifetime deadline.
    #[must_use]
    pub const fn is_lifetime_due(self, now_ms: u64) -> bool {
        match self.lifetime {
            Some(life) => life.is_due(now_ms),
            None => false,
        }
    }

    /// Absolute millisecond time when a CON notify becomes mandatory, if any.
    ///
    /// Set when the first NON is recorded, or reset by each CON. See
    /// `knowledge/rfcs/rfc7641.txt` §4.5.
    #[must_use]
    pub const fn confirm_due_ms(self) -> Option<u64> {
        self.confirm_due_ms
    }

    /// Whether `now_ms` is at or past the 24-hour NON-confirm deadline.
    #[must_use]
    pub const fn must_confirm(self, now_ms: u64) -> bool {
        match self.confirm_due_ms {
            Some(due) => now_ms >= due,
            None => false,
        }
    }

    /// Colocated NSTART / NON-rate hold, if set.
    #[must_use]
    pub const fn notify_hold(self) -> Option<ObserveNotifyHold> {
        self.notify_hold
    }

    /// Whether this row still counts toward per-endpoint notification NSTART.
    ///
    /// True while [`ObserveLifetime::Unacked`] is set, or while
    /// [`Self::notify_hold`] is outstanding at `now_ms`.
    #[must_use]
    pub const fn is_notify_held(self, now_ms: u64) -> bool {
        if matches!(self.lifetime, Some(ObserveLifetime::Unacked { .. })) {
            return true;
        }
        match self.notify_hold {
            Some(hold) => hold.is_held(now_ms),
            None => false,
        }
    }

    /// Record a sent notification: 24-hour confirm clock and NSTART hold.
    ///
    /// `confirmable` is a CON notify (resets the 24-hour clock; hold until
    /// ACK). Otherwise NON (starts the 24-hour clock if unset; hold for
    /// [`ObserveTransmission::NON_TIMEOUT_MS`]). `message_id` is stored on
    /// either hold so an empty RST can drop this row. Does not encode or
    /// send. See `knowledge/rfcs/rfc7641.txt` §4.5 / §4.5.1.
    pub fn record_notify(&mut self, now_ms: u64, message_id: MessageId, confirmable: bool) {
        if self.key.is_client() {
            return;
        }
        if confirmable {
            // A previous representation's Max-Age must not end CON delivery.
            self.lifetime = None;
            self.confirm_due_ms =
                Some(now_ms.saturating_add(ObserveTransmission::CONFIRM_INTERVAL_MS));
            self.notify_hold = Some(ObserveNotifyHold::con(message_id));
        } else {
            if self.confirm_due_ms.is_none() {
                self.confirm_due_ms =
                    Some(now_ms.saturating_add(ObserveTransmission::CONFIRM_INTERVAL_MS));
            }
            self.notify_hold = Some(ObserveNotifyHold::non(now_ms, message_id));
        }
    }

    /// Clear the NSTART / NON-rate hold. Does not drop the row.
    pub fn clear_notify_hold(&mut self) {
        self.notify_hold = None;
    }

    /// Surface and clear a due lifetime. Only CON-wait expiry clears pending
    /// work and notification hold; stale representation data does not cancel
    /// a notification or relax its congestion-control hold.
    ///
    /// Surfaces once. The row stays occupied. See
    /// `knowledge/rfcs/rfc7641.txt`.
    pub fn take_expired(&mut self, now_ms: u64) -> Option<ObserveLifetime> {
        let life = self.lifetime?;
        if !life.is_due(now_ms) {
            return None;
        }
        self.lifetime = None;
        if matches!(life, ObserveLifetime::Unacked { .. }) {
            self.pending = false;
            self.notify_hold = None;
        }
        Some(life)
    }

    /// Mark this row as needing one notification.
    ///
    /// A second mark before [`Self::take_due`] still yields one work item.
    /// Client-side subscriptions do not produce server notifications.
    pub fn mark_due(&mut self) {
        if !self.key.is_client() {
            self.pending = true;
        }
    }

    /// If pending, assign the next 24-bit sequence, clear pending, return it.
    ///
    /// Wraps through [`OBSERVE_SEQUENCE_MASK`]. See
    /// `knowledge/rfcs/rfc7641.txt`.
    pub fn take_due(&mut self) -> Option<u32> {
        if !self.pending {
            return None;
        }
        self.pending = false;
        self.seq = self.seq.wrapping_add(1) & OBSERVE_SEQUENCE_MASK;
        Some(self.seq)
    }

    /// Undo [`Self::take_due`] when the notification was not sent.
    ///
    /// No-op unless this row still holds `assigned_seq` and is not pending
    /// (already restored, or a later `take_due`, leaves the row alone).
    pub fn restore_due(&mut self, assigned_seq: u32) {
        if self.pending || self.seq != assigned_seq {
            return;
        }
        self.pending = true;
        self.seq = assigned_seq.wrapping_sub(1) & OBSERVE_SEQUENCE_MASK;
    }
}

impl From<ObserveKey> for ObserveInterest {
    fn from(key: ObserveKey) -> Self {
        Self {
            key,
            ..Self::new(key.token(), key.endpoint())
        }
    }
}

/// Typed insert / lookup / remove / take on an Observe Interest Table.
///
/// Each operation scans the configured entry count (O(n) in capacity).
pub(crate) trait ObserveStore {
    fn insert(&mut self, interest: ObserveInterest) -> Option<SlotId>;
    fn lookup(&self, key: ObserveKey) -> Option<SlotId>;
    fn remove(&mut self, key: ObserveKey) -> bool;
    fn take(&mut self, key: ObserveKey) -> Option<ObserveInterest>;
    fn entry(&self, id: SlotId) -> Option<ObserveInterest>;
    fn set_entry(&mut self, id: SlotId, interest: ObserveInterest) -> Result<(), SlotError>;
}

/// Dedup table: compact duplicate history slots.
///
/// Insert, lookup, and remove scan every configured entry (O(n) in capacity).
/// Saturation returns `None` from insert; this type does not evict. [`Self::rotate`]
/// still advances the occupancy cursor used by acquire.
pub struct DedupTable<const ENTRIES: usize> {
    entries: [Option<DedupEntry>; ENTRIES],
    occ: Occupancy<ENTRIES>,
}

impl<const ENTRIES: usize> DedupTable<ENTRIES> {
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
    pub fn insert(&mut self, entry: DedupEntry) -> Option<SlotId> {
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
    pub fn lookup(&self, key: DedupKey) -> Option<SlotId> {
        (0..ENTRIES).find_map(|i| {
            let id = SlotId::from_index(i);
            match self.entry(id) {
                Some(entry) if entry.key() == key => Some(id),
                _ => None,
            }
        })
    }

    /// Release the slot matching `key`, if occupied.
    ///
    /// Scans the configured capacity (O(n)).
    pub fn remove(&mut self, key: DedupKey) -> bool {
        match self.lookup(key) {
            Some(id) => self.release(id).is_ok(),
            None => false,
        }
    }

    /// Occupied payload at `id`.
    #[must_use]
    pub fn entry(&self, id: SlotId) -> Option<DedupEntry> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        self.entries.get(id.index()).copied().flatten()
    }

    /// Write payload into an already-acquired slot.
    pub fn set_entry(&mut self, id: SlotId, entry: DedupEntry) -> Result<(), SlotError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < ENTRIES {
                SlotError::NotOccupied
            } else {
                SlotError::InvalidSlot
            });
        }
        self.entries[id.index()] = Some(entry);
        Ok(())
    }

    fn reset(&mut self, id: SlotId) {
        if let Some(slot) = self.entries.get_mut(id.index()) {
            *slot = None;
        }
    }
}

impl<const ENTRIES: usize> Default for DedupTable<ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const ENTRIES: usize> DedupStore for DedupTable<ENTRIES> {
    fn insert(&mut self, entry: DedupEntry) -> Option<SlotId> {
        DedupTable::insert(self, entry)
    }

    fn lookup(&self, key: DedupKey) -> Option<SlotId> {
        DedupTable::lookup(self, key)
    }

    fn remove(&mut self, key: DedupKey) -> bool {
        DedupTable::remove(self, key)
    }

    fn entry(&self, id: SlotId) -> Option<DedupEntry> {
        DedupTable::entry(self, id)
    }
}

impl<const ENTRIES: usize> SlotPool for DedupTable<ENTRIES> {
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

/// Observe interest table: long-lived relation slots, not notification bodies.
///
/// Insert, lookup, remove, and take scan every configured entry (O(n) in
/// capacity). Saturation returns `None` from insert; this type does not evict.
/// [`Self::rotate`] still advances the occupancy cursor used by acquire.
pub struct ObserveTable<const ENTRIES: usize> {
    entries: [Option<ObserveInterest>; ENTRIES],
    occ: Occupancy<ENTRIES>,
}

impl<const ENTRIES: usize> ObserveTable<ENTRIES> {
    /// Empty table. Cursor starts at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; ENTRIES],
            occ: Occupancy::new(),
        }
    }

    /// Insert `interest`, or return the existing slot if the key is already present.
    ///
    /// Returns `None` when the table is full and the key is not already stored.
    /// Scans the configured capacity (O(n)).
    pub fn insert(&mut self, interest: ObserveInterest) -> Option<SlotId> {
        if let Some(id) = self.lookup(interest.key()) {
            return Some(id);
        }
        let id = self.occ.acquire()?;
        self.entries[id.index()] = Some(interest);
        Some(id)
    }

    /// Slot whose occupied payload matches `key`, if any.
    ///
    /// Scans the configured capacity (O(n)).
    #[must_use]
    pub fn lookup(&self, key: ObserveKey) -> Option<SlotId> {
        (0..ENTRIES).find_map(|i| {
            let id = SlotId::from_index(i);
            match self.entry(id) {
                Some(interest) if interest.key() == key => Some(id),
                _ => None,
            }
        })
    }

    /// Release the slot matching `key`, if occupied.
    ///
    /// Scans the configured capacity (O(n)).
    pub fn remove(&mut self, key: ObserveKey) -> bool {
        match self.lookup(key) {
            Some(id) => self.release(id).is_ok(),
            None => false,
        }
    }

    /// Remove and return the occupied payload matching `key`, if any.
    ///
    /// Scans the configured capacity (O(n)).
    pub fn take(&mut self, key: ObserveKey) -> Option<ObserveInterest> {
        let id = self.lookup(key)?;
        let interest = self.entry(id)?;
        let _ = self.release(id);
        Some(interest)
    }

    /// Occupied payload at `id`.
    #[must_use]
    pub fn entry(&self, id: SlotId) -> Option<ObserveInterest> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        self.entries.get(id.index()).copied().flatten()
    }

    /// Write payload into an already-acquired slot.
    pub fn set_entry(&mut self, id: SlotId, interest: ObserveInterest) -> Result<(), SlotError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < ENTRIES {
                SlotError::NotOccupied
            } else {
                SlotError::InvalidSlot
            });
        }
        self.entries[id.index()] = Some(interest);
        Ok(())
    }

    fn reset(&mut self, id: SlotId) {
        if let Some(slot) = self.entries.get_mut(id.index()) {
            *slot = None;
        }
    }
}

impl<const ENTRIES: usize> Default for ObserveTable<ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const ENTRIES: usize> ObserveStore for ObserveTable<ENTRIES> {
    fn insert(&mut self, interest: ObserveInterest) -> Option<SlotId> {
        ObserveTable::insert(self, interest)
    }

    fn lookup(&self, key: ObserveKey) -> Option<SlotId> {
        ObserveTable::lookup(self, key)
    }

    fn remove(&mut self, key: ObserveKey) -> bool {
        ObserveTable::remove(self, key)
    }

    fn take(&mut self, key: ObserveKey) -> Option<ObserveInterest> {
        ObserveTable::take(self, key)
    }

    fn entry(&self, id: SlotId) -> Option<ObserveInterest> {
        ObserveTable::entry(self, id)
    }

    fn set_entry(&mut self, id: SlotId, interest: ObserveInterest) -> Result<(), SlotError> {
        ObserveTable::set_entry(self, id, interest)
    }
}

impl<const ENTRIES: usize> SlotPool for ObserveTable<ENTRIES> {
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
