//! Caller-owned pairwise security context.

use crate::message::Token;

use super::aead;
use super::header::PartialIv;
use super::{Error, KEY_LEN, MAX_ID_CONTEXT_LEN, MAX_ID_LEN, NONCE_LEN, REPLAY_WINDOW};

/// Recipient replay-window checkpoint for caller-owned durable storage.
///
/// This contains no key material and is not a wire format. Store its parts with
/// an authenticated context/epoch identity and an anti-rollback generation.
/// A stale checkpoint restored into a newly derived context cannot be detected
/// by this crate. Commit the updated checkpoint after successful unprotection
/// and before acknowledging application acceptance or performing effects.
/// Sender sequence reservation and live request/Observe state are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayCheckpoint {
    left: u64,
    received: u32,
}

impl ReplayCheckpoint {
    /// Validate a persisted lower bound and bitmap (bit zero names `left`).
    /// `left == 2^40` with an empty bitmap conservatively refuses all sequences.
    /// Invalid bounds or bits beyond the five-byte sequence space are refused.
    pub const fn from_parts(left: u64, received: u32) -> Result<Self, Error> {
        let end = 1u64 << 40;
        if left > end
            || (received != 0
                && (left == end || (31 - received.leading_zeros()) as u64 >= end - left))
        {
            return Err(Error::ReplayState);
        }
        Ok(Self { left, received })
    }

    /// Persist these parts without loss, together with context identity and
    /// a freshness/anti-rollback mechanism owned by the caller.
    #[must_use]
    pub const fn parts(self) -> (u64, u32) {
        (self.left, self.received)
    }
}

/// Inputs for [`SecurityContext::derive`].
///
/// `master_salt` and `id_context` may be empty. Sender and Recipient IDs
/// must differ. Length limits are those of AES-CCM-16-64-128.
#[derive(Clone, Copy)]
pub struct DeriveParams<'a> {
    /// Shared Master Secret (IKM).
    pub master_secret: &'a [u8],
    /// Optional Master Salt (empty if unused).
    pub master_salt: &'a [u8],
    /// This endpoint's Sender ID (`kid` on requests it protects).
    pub sender_id: &'a [u8],
    /// The peer's Sender ID (`kid` this endpoint accepts).
    pub recipient_id: &'a [u8],
    /// Optional ID Context (empty if unused).
    pub id_context: &'a [u8],
}

impl core::fmt::Debug for DeriveParams<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeriveParams")
            .field("master_secret", &"[REDACTED]")
            .field("master_salt", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Binding of a request Partial IV (and `kid`) to a Token.
///
/// Both endpoints keep this association until the matching response is
/// protected or verified. Observe registrations keep it for later
/// notifications (`request_piv`). See `knowledge/rfcs/rfc8613.txt` §8 / §4.1.3.5.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestRef {
    kid: Id,
    piv: PartialIv,
}

impl RequestRef {
    pub(crate) fn from_kid(kid: &[u8], piv: PartialIv) -> Result<Self, Error> {
        Ok(Self {
            kid: Id::new(kid)?,
            piv,
        })
    }

    /// `kid` of the request (client Sender ID).
    #[must_use]
    pub fn kid(&self) -> &[u8] {
        self.kid.as_bytes()
    }

    /// Partial IV of the request.
    #[must_use]
    pub const fn piv(self) -> PartialIv {
        self.piv
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Id {
    bytes: [u8; MAX_ID_LEN],
    len: u8,
}

impl Id {
    fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_ID_LEN {
            return Err(Error::Id);
        }
        let mut id = Self {
            bytes: [0; MAX_ID_LEN],
            len: bytes.len() as u8,
        };
        id.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(id)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Pairwise OSCORE context: keys, Sender Sequence Number, replay window.
///
/// You own this value. [`crate::App`] stores it only after
/// [`crate::App::set_oscore`]. A live context is intentionally not `Clone`:
/// copying its sender state could reuse a nonce (RFC 8613 section 7.2.1).
///
/// ```compile_fail
/// # use coaptic::oscore::SecurityContext;
/// fn duplicate(context: SecurityContext) {
///     let _duplicate = context.clone();
/// }
/// ```
pub struct SecurityContext {
    sender_id: Id,
    recipient_id: Id,
    id_context: [u8; MAX_ID_CONTEXT_LEN],
    id_context_len: u8,
    sender_key: [u8; KEY_LEN],
    recipient_key: [u8; KEY_LEN],
    common_iv: [u8; NONCE_LEN],
    sender_seq: u64,
    replay_left: u64,
    replay_bits: u32,
    live: [Option<LiveRequest>; super::LIVE_REQUESTS],
}

/// Token→[`RequestRef`] row. Observe registrations keep the row so
/// notifications can reuse `request_piv` (RFC 8613 §4.1.3.5 / §7.4.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveRequest {
    token: Token,
    request: RequestRef,
    observe: bool,
    observe_request: Option<RequestRef>,
    response_no_piv: bool,
    notify_no_piv: bool,
    notify_number: Option<u64>,
}

impl core::fmt::Debug for SecurityContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecurityContext")
            .field("key_material", &"[REDACTED]")
            .field("sender_seq", &self.sender_seq)
            .finish_non_exhaustive()
    }
}

impl SecurityContext {
    /// Derive Sender Key, Recipient Key, and Common IV.
    pub fn derive(params: DeriveParams<'_>) -> Result<Self, Error> {
        if params.master_secret.is_empty() || params.master_secret.len() > 64 {
            return Err(Error::MasterSecret);
        }
        if params.master_salt.len() > 64 {
            return Err(Error::MasterSalt);
        }
        if params.id_context.len() > MAX_ID_CONTEXT_LEN {
            return Err(Error::Id);
        }
        let sender_id = Id::new(params.sender_id)?;
        let recipient_id = Id::new(params.recipient_id)?;
        if sender_id.as_bytes() == recipient_id.as_bytes() {
            return Err(Error::IdCollision);
        }
        let id_context = if params.id_context.is_empty() {
            None
        } else {
            Some(params.id_context)
        };

        let mut sender_key = [0u8; KEY_LEN];
        aead::hkdf_expand(
            params.master_secret,
            params.master_salt,
            sender_id.as_bytes(),
            id_context,
            "Key",
            &mut sender_key,
        )?;
        let mut recipient_key = [0u8; KEY_LEN];
        aead::hkdf_expand(
            params.master_secret,
            params.master_salt,
            recipient_id.as_bytes(),
            id_context,
            "Key",
            &mut recipient_key,
        )?;
        let mut common_iv = [0u8; NONCE_LEN];
        aead::hkdf_expand(
            params.master_secret,
            params.master_salt,
            &[],
            id_context,
            "IV",
            &mut common_iv,
        )?;

        let mut stored_ctx = [0u8; MAX_ID_CONTEXT_LEN];
        stored_ctx[..params.id_context.len()].copy_from_slice(params.id_context);

        Ok(Self {
            sender_id,
            recipient_id,
            id_context: stored_ctx,
            id_context_len: params.id_context.len() as u8,
            sender_key,
            recipient_key,
            common_iv,
            sender_seq: 0,
            replay_left: 0,
            replay_bits: 0,
            live: [None; super::LIVE_REQUESTS],
        })
    }

    /// Sender ID.
    #[must_use]
    pub fn sender_id(&self) -> &[u8] {
        self.sender_id.as_bytes()
    }

    /// Recipient ID.
    #[must_use]
    pub fn recipient_id(&self) -> &[u8] {
        self.recipient_id.as_bytes()
    }

    /// ID Context (empty if unused).
    #[must_use]
    pub fn id_context(&self) -> &[u8] {
        &self.id_context[..self.id_context_len as usize]
    }

    /// Sender Key (16 bytes).
    #[must_use]
    pub const fn sender_key(&self) -> &[u8; KEY_LEN] {
        &self.sender_key
    }

    /// Recipient Key (16 bytes).
    #[must_use]
    pub const fn recipient_key(&self) -> &[u8; KEY_LEN] {
        &self.recipient_key
    }

    /// Common IV (13 bytes).
    #[must_use]
    pub const fn common_iv(&self) -> &[u8; NONCE_LEN] {
        &self.common_iv
    }

    /// Next Sender Sequence Number (used as the next request Partial IV).
    #[must_use]
    pub const fn sender_seq(&self) -> u64 {
        self.sender_seq
    }

    /// Advance the next Sender Sequence Number, for example past a durably
    /// reserved range after reboot (RFC 8613 section 7.5 and Appendix B.1).
    ///
    /// Refuses rollback and values beyond the exhausted sentinel `2^40`.
    /// Refusal leaves the context unchanged. This does not persist state:
    /// the caller must durably reserve numbers before using them and restore
    /// recipient replay protection separately. Deriving the same context again
    /// starts at zero and is not a safe restart procedure by itself.
    pub const fn set_sender_seq(&mut self, seq: u64) -> Result<(), Error> {
        if seq < self.sender_seq {
            return Err(Error::SequenceRollback);
        }
        if seq > (1u64 << 40) {
            return Err(Error::SequenceExhausted);
        }
        self.sender_seq = seq;
        Ok(())
    }

    /// Whether `kid` (and optional `kid context`) selects this Recipient Context.
    #[must_use]
    pub fn matches_recipient(&self, kid: Option<&[u8]>, kid_context: Option<&[u8]>) -> bool {
        let kid = kid.unwrap_or(&[]);
        if kid != self.recipient_id.as_bytes() {
            return false;
        }
        match kid_context {
            None => self.id_context_len == 0,
            Some(ctx) => ctx == self.id_context(),
        }
    }

    /// Remember `(token, request)` for the matching response.
    ///
    /// Replaces an existing row for `token`. The table holds
    /// [`crate::oscore::LIVE_REQUESTS`] (4) bindings — the same cap as the
    /// App client inbox. A fifth distinct Token is [`Error::Saturated`].
    pub fn remember(&mut self, token: Token, request: RequestRef) -> Result<(), Error> {
        self.remember_live(token, request, false)
    }

    pub(crate) fn remember_live(
        &mut self,
        token: Token,
        request: RequestRef,
        observe: bool,
    ) -> Result<(), Error> {
        let binding = LiveRequest {
            token,
            request,
            observe,
            observe_request: observe.then_some(request),
            response_no_piv: false,
            notify_no_piv: false,
            notify_number: None,
        };
        for row in &mut self.live {
            if row.as_ref().is_some_and(|r| r.token == token) {
                *row = Some(binding);
                return Ok(());
            }
        }
        for row in &mut self.live {
            if row.is_none() {
                *row = Some(binding);
                return Ok(());
            }
        }
        Err(Error::Saturated)
    }

    // A body request replaces only the latest response binding. Its parent
    // Observe registration and notification replay history remain authoritative.
    pub(crate) fn remember_download(
        &mut self,
        token: Token,
        request: RequestRef,
    ) -> Result<(), Error> {
        if let Some(row) = self
            .live
            .iter_mut()
            .flatten()
            .find(|row| row.token == token && row.observe)
        {
            row.request = request;
            row.response_no_piv = false;
            return Ok(());
        }
        self.remember(token, request)
    }

    pub(crate) fn observe_request(&self, token: Token) -> Option<RequestRef> {
        self.live
            .iter()
            .flatten()
            .find(|row| row.token == token)
            .and_then(|row| row.observe_request)
    }

    pub(crate) fn response_without_piv_fresh(&self, token: Token) -> Result<(), Error> {
        let row = self
            .live
            .iter()
            .flatten()
            .find(|row| row.token == token)
            .ok_or(Error::Context)?;
        if row.response_no_piv {
            Err(Error::Replay)
        } else {
            Ok(())
        }
    }

    pub(crate) fn accept_response_without_piv(&mut self, token: Token) -> Result<(), Error> {
        self.response_without_piv_fresh(token)?;
        self.live
            .iter_mut()
            .flatten()
            .find(|row| row.token == token)
            .ok_or(Error::Context)?
            .response_no_piv = true;
        Ok(())
    }

    /// Look up the latest request binding by Token.
    /// Observe download follow-ups retain the original registration separately.
    #[must_use]
    pub fn lookup(&self, token: Token) -> Option<RequestRef> {
        self.live
            .iter()
            .find_map(|row| row.and_then(|r| (r.token == token).then_some(r.request)))
    }

    /// Whether this Token retains an Observe registration, including during body downloads.
    #[must_use]
    pub fn is_observe(&self, token: Token) -> bool {
        self.live
            .iter()
            .any(|row| row.is_some_and(|r| r.token == token && r.observe))
    }

    /// Remove and return a request binding.
    pub fn take(&mut self, token: Token) -> Option<RequestRef> {
        for row in &mut self.live {
            if row.as_ref().is_some_and(|r| r.token == token) {
                return row.take().map(|r| r.request);
            }
        }
        None
    }

    /// Read-only admission check; App commits only after response ACK succeeds.
    pub(crate) fn notification_fresh(
        &self,
        token: Token,
        piv: Option<PartialIv>,
    ) -> Result<(), Error> {
        let row = self
            .live
            .iter()
            .find_map(|row| row.as_ref().filter(|r| r.token == token))
            .ok_or(Error::Context)?;
        if match piv {
            None => row.notify_no_piv,
            Some(piv) => row.notify_number.is_some_and(|n| piv.seq() <= n),
        } {
            Err(Error::Replay)
        } else {
            Ok(())
        }
    }

    /// Replay-protect an Observe notification (RFC 8613 §7.4.1).
    ///
    /// At most one notification without Partial IV. A Partial IV must be
    /// strictly greater than the Notification Number (largest accepted).
    /// The piggybacked register ACK (`protect_response` without Partial
    /// IV) is not a notification for this budget — App does not call this
    /// with `None` for that ACK.
    pub fn accept_notification(
        &mut self,
        token: Token,
        piv: Option<PartialIv>,
    ) -> Result<(), Error> {
        self.notification_fresh(token, piv)?;
        let row = self
            .live
            .iter_mut()
            .find_map(|row| row.as_mut().filter(|r| r.token == token))
            .ok_or(Error::Context)?;
        match piv {
            None => row.notify_no_piv = true,
            Some(piv) => row.notify_number = Some(piv.seq()),
        }
        Ok(())
    }

    pub(crate) fn take_sender_piv(&mut self) -> Result<PartialIv, Error> {
        if self.sender_seq >= (1 << 40) {
            return Err(Error::SequenceExhausted);
        }
        let piv = PartialIv::from_seq(self.sender_seq)?;
        self.sender_seq += 1;
        Ok(piv)
    }

    pub(crate) fn request_ref(&self, piv: PartialIv) -> RequestRef {
        RequestRef {
            kid: self.sender_id,
            piv,
        }
    }

    pub(crate) fn request_nonce(&self, piv: PartialIv) -> [u8; NONCE_LEN] {
        aead::nonce(&self.common_iv, self.sender_id.as_bytes(), piv)
    }

    pub(crate) fn recipient_nonce(&self, piv: PartialIv) -> [u8; NONCE_LEN] {
        aead::nonce(&self.common_iv, self.recipient_id.as_bytes(), piv)
    }

    /// Snapshot recipient replay protection for a caller-owned durable barrier.
    /// This does not persist or authenticate the checkpoint.
    #[must_use]
    pub const fn replay_checkpoint(&self) -> ReplayCheckpoint {
        ReplayCheckpoint {
            left: self.replay_left,
            received: self.replay_bits,
        }
    }

    /// Restore a validated recipient checkpoint without weakening this live
    /// context's replay protection. Any currently rejected sequence must remain
    /// rejected. A refusal leaves the context unchanged.
    ///
    /// Before reusing keys after reboot, the caller must supply the latest
    /// durable checkpoint for this exact context, reserve/restore sender
    /// sequence numbers, and account for lost live bindings/Observe state.
    /// This comparison cannot detect an old checkpoint in a freshly derived
    /// context. Use a fresh cryptographic context if recovery is uncertain
    /// (RFC 8613 section 7.5). App does not provide a durable pre-handler barrier;
    /// use the lower-level unprotect API to commit before application effects.
    pub fn restore_replay(&mut self, checkpoint: ReplayCheckpoint) -> Result<(), Error> {
        if checkpoint.left < self.replay_left {
            return Err(Error::ReplayRollback);
        }
        let shift = checkpoint.left - self.replay_left;
        let retained = if shift >= REPLAY_WINDOW {
            0
        } else {
            self.replay_bits >> shift as u32
        };
        if retained & !checkpoint.received != 0 {
            return Err(Error::ReplayRollback);
        }
        self.replay_left = checkpoint.left;
        self.replay_bits = checkpoint.received;
        Ok(())
    }

    /// `true` if `seq` may be accepted (not yet marked). Does not update.
    #[must_use]
    pub fn replay_fresh(&self, seq: u64) -> bool {
        if seq >= (1u64 << 40) || seq < self.replay_left {
            return false;
        }
        let delta = seq - self.replay_left;
        if delta >= REPLAY_WINDOW {
            return true;
        }
        let bit = 1u32 << (delta as u32);
        self.replay_bits & bit == 0
    }

    /// Mark `seq` received after a successful decrypt. Out-of-range and stale
    /// sequences leave the window unchanged.
    pub fn replay_accept(&mut self, seq: u64) {
        if seq >= (1u64 << 40) || seq < self.replay_left {
            return;
        }
        let delta = seq - self.replay_left;
        if delta >= REPLAY_WINDOW {
            let shift = delta - (REPLAY_WINDOW - 1);
            if shift >= 32 {
                self.replay_bits = 0;
            } else {
                self.replay_bits >>= shift as u32;
            }
            self.replay_left = seq - (REPLAY_WINDOW - 1);
            let bit = 1u32 << ((REPLAY_WINDOW - 1) as u32);
            self.replay_bits |= bit;
            return;
        }
        self.replay_bits |= 1u32 << (delta as u32);
    }
}
