//! App-side OSCORE hook. Zero-sized when the `oscore` feature is off.
//!
//! Each live Token retains the Observe registration and the latest Block2/Q-Block2
//! request independently. Response authentication tries at most these two bindings
//! using one fixed scratch buffer; older download requests are not retained.
//! Download follow-ups omit Observe and preserve notification replay history.

use crate::error::{EncodeError, SlotMessageError};
use crate::message::{Message, ParsedMessage};
use crate::storage::{DatagramSlots, Engine, SlotId, Storage};

#[cfg(feature = "oscore")]
use crate::oscore::{Error as OscoreError, RequestRef, SecurityContext};

/// [`App`](super::App) field: a caller-owned context, or an empty marker.
#[cfg(feature = "oscore")]
pub(crate) type Field = Option<SecurityContext>;
#[cfg(not(feature = "oscore"))]
#[derive(Clone, Copy)]
pub(crate) struct Field;

/// Request binding carried on an inbound OSCORE exchange.
#[cfg(feature = "oscore")]
pub(crate) type Request = Option<RequestRef>;
#[cfg(not(feature = "oscore"))]
#[derive(Clone, Copy)]
pub(crate) struct Request;

/// Authenticated, checked response state, committed after critical-option
/// validation and successful CON acknowledgment. No persistent storage barrier.
#[derive(Clone, Copy)]
pub(crate) enum ResponseState {
    None,
    #[cfg(feature = "oscore")]
    Notification(crate::message::Token, Option<crate::oscore::PartialIv>),
    #[cfg(feature = "oscore")]
    Replay(u64),
    #[cfg(feature = "oscore")]
    ResponseWithoutPiv(crate::message::Token),
}

pub(crate) fn commit_response<E>(
    ctx: &mut Field,
    state: ResponseState,
) -> Result<(), super::Error<E>> {
    #[cfg(feature = "oscore")]
    if let Some(ctx) = ctx.as_mut() {
        match state {
            ResponseState::None => {}
            ResponseState::Notification(token, piv) => ctx
                .accept_notification(token, piv)
                .map_err(super::Error::Oscore)?,
            ResponseState::ResponseWithoutPiv(token) => ctx
                .accept_response_without_piv(token)
                .map_err(super::Error::Oscore)?,
            ResponseState::Replay(sequence) => {
                if !ctx.replay_fresh(sequence) {
                    return Err(super::Error::Oscore(OscoreError::Replay));
                }
                ctx.replay_accept(sequence);
            }
        }
    }
    #[cfg(not(feature = "oscore"))]
    let _ = (ctx, state);
    Ok(())
}

/// Opened inner message after unprotect.
#[cfg(feature = "oscore")]
pub(crate) type Opened<'a> = (ParsedMessage<'a>, RequestRef, ResponseState);
#[cfg(not(feature = "oscore"))]
pub(crate) type Opened<'a> = (ParsedMessage<'a>, Request, ResponseState);

#[cfg(feature = "oscore")]
pub(crate) type InboundError = OscoreError;
#[cfg(not(feature = "oscore"))]
pub(crate) type InboundError = core::convert::Infallible;

#[cfg(feature = "oscore")]
pub(crate) const fn no_request() -> Request {
    None
}

#[cfg(not(feature = "oscore"))]
pub(crate) const fn no_request() -> Request {
    Request
}

#[cfg(feature = "oscore")]
pub(crate) const fn empty_field() -> Field {
    None
}

#[cfg(not(feature = "oscore"))]
pub(crate) const fn empty_field() -> Field {
    Field
}

#[cfg(feature = "oscore")]
pub(crate) fn is_active(ctx: &Field) -> bool {
    ctx.is_some()
}

/// Request binding stored on an Observe interest (notifications).
pub(crate) fn request_from_interest(interest: crate::storage::ObserveInterest) -> Request {
    #[cfg(feature = "oscore")]
    {
        interest.oscore()
    }
    #[cfg(not(feature = "oscore"))]
    {
        let _ = interest;
        no_request()
    }
}

#[cfg(not(feature = "oscore"))]
pub(crate) fn is_active(_ctx: &Field) -> bool {
    false
}

/// After decode: unprotect an OSCORE message, or reject plaintext.
///
/// When a context is attached, a message without an OSCORE option is
/// fail-closed except empty ACK/RST (and other empty code-0.00 control
/// datagrams). Those are RFC 7252 reliability / ping; they carry no
/// application body. A token-matching unprotected 2.xx/4.xx/5.xx must
/// not complete a [`Call`](super::Call).
#[cfg(feature = "oscore")]
pub(crate) fn inbound<'a>(
    ctx: &mut Field,
    parsed: &ParsedMessage<'_>,
    scratch: &'a mut [u8],
) -> Result<Option<Opened<'a>>, InboundError> {
    let Some(ctx) = ctx.as_mut() else {
        return Ok(None);
    };
    if parsed.oscore().is_some() {
        let mut response_state = ResponseState::None;
        let (inner, request) = if parsed.code().is_request() {
            ctx.unprotect_request(parsed, scratch)?
        } else {
            let (inner, request) = ctx.unprotect_bound_response(parsed, scratch)?;
            let header =
                crate::oscore::OscoreHeader::parse(parsed.oscore().ok_or(OscoreError::Header)?)?;
            let observe = inner.observe().is_some();
            if observe && ctx.observe_request(parsed.token()) != Some(request) {
                // Response to a non-Observe request must not carry Inner Observe.
                return Err(OscoreError::Replay);
            }
            if observe {
                // Piggybacked register ACK (`protect_response`, no Partial
                // IV) is bound to the request. Do not spend the RFC 8613
                // §7.4.1 no-PIV notification budget on it.
                let register_ack =
                    parsed.ty() == crate::message::Type::Acknowledgement && header.piv.is_none();
                if !register_ack {
                    ctx.notification_fresh(parsed.token(), header.piv)?;
                    response_state = ResponseState::Notification(parsed.token(), header.piv);
                }
            } else if inner.q_block2().next().is_some()
                || (inner.code() == crate::message::Code::REQUEST_ENTITY_INCOMPLETE
                    && inner.content_format()
                        == Some(Ok(crate::message::ContentFormat::MISSING_BLOCKS)))
            {
                // Q response sets and missing-block reports may keep the Call
                // active. Authenticate
                // before updating replay state; keep the binding until Call
                // completion/cancellation, including an out-of-order final block.
                if let Some(piv) = header.piv {
                    if !ctx.replay_fresh(piv.seq()) {
                        return Err(OscoreError::Replay);
                    }
                    response_state = ResponseState::Replay(piv.seq());
                } else {
                    // One no-PIV response is permitted for a request, including
                    // from independent peers. Others need fresh response PIVs.
                    if ctx.observe_request(parsed.token()) == Some(request) {
                        ctx.notification_fresh(parsed.token(), None)?;
                        response_state = ResponseState::Notification(parsed.token(), None);
                    } else {
                        ctx.response_without_piv_fresh(parsed.token())?;
                        response_state = ResponseState::ResponseWithoutPiv(parsed.token());
                    }
                }
            }
            // Authentication is not application admission. Unknown critical
            // options or a failed CON ACK can leave the Call pending. Retire
            // ordinary bindings when App collects/completes/cancels the Call,
            // or replace them when a continuation encodes a fresh request.
            (inner, request)
        };
        return Ok(Some((inner, request, response_state)));
    }
    if parsed.is_empty() {
        return Ok(None);
    }
    Err(OscoreError::Unprotected)
}

#[cfg(not(feature = "oscore"))]
pub(crate) fn inbound<'a>(
    _ctx: &mut Field,
    _parsed: &ParsedMessage<'_>,
    _scratch: &'a mut [u8],
) -> Result<Option<Opened<'a>>, InboundError> {
    Ok(None)
}

/// Encode `msg`, or OSCORE-protect a request into `tx`.
///
/// Size failures stay [`EncodeError::BufferTooSmall`] so the client may
/// start Inner Block1. Other protect failures (feature `oscore`) are the
/// App `Oscore` error and must not look like a size miss.
pub(crate) fn encode_request<S: Storage + DatagramSlots, E>(
    ctx: &mut Field,
    engine: &mut Engine<S>,
    tx: SlotId,
    msg: &Message<'_>,
) -> Result<(), super::Error<E>> {
    let _ = ctx;
    #[cfg(feature = "oscore")]
    if let Some(ctx) = ctx.as_mut() {
        let mut wire = S::TxScratch::default();
        let n = ctx
            .protect_request(msg, wire.as_mut())
            .map_err(protect_err)?;
        return fill_tx(engine, tx, &wire.as_ref()[..n]).map_err(super::Error::from);
    }
    engine
        .encode_tx(tx, msg)
        .map(|_| ())
        .map_err(super::Error::from)
}

/// Encode `msg`, or OSCORE-protect a response bound to `request`.
///
/// Fail-closed: an attached context without a stored [`RequestRef`] does
/// not fall back to plaintext. Size misses stay
/// [`EncodeError::BufferTooSmall`] so the server may start Inner Block2.
pub(crate) fn encode_message<S: Storage + DatagramSlots, E>(
    ctx: &Field,
    request: Request,
    engine: &mut Engine<S>,
    tx: SlotId,
    msg: &Message<'_>,
) -> Result<(), super::Error<E>> {
    let _ = (ctx, request);
    #[cfg(feature = "oscore")]
    if let Some(ctx) = ctx.as_ref() {
        let Some(request) = request else {
            return Err(protect_err(OscoreError::Context));
        };
        let mut wire = S::TxScratch::default();
        let n = ctx
            .protect_response(msg, request, wire.as_mut())
            .map_err(protect_err)?;
        return fill_tx(engine, tx, &wire.as_ref()[..n]).map_err(super::Error::from);
    }
    engine
        .encode_tx(tx, msg)
        .map(|_| ())
        .map_err(super::Error::from)
}

/// Protect a notification with a new Partial IV (RFC 8613 §4.1.3.5.2).
///
/// Fail-closed: an attached context without a stored [`RequestRef`] does
/// not fall back to plaintext.
pub(crate) fn encode_notification<S: Storage + DatagramSlots, E>(
    ctx: &mut Field,
    request: Request,
    engine: &mut Engine<S>,
    tx: SlotId,
    msg: &Message<'_>,
) -> Result<(), super::Error<E>> {
    #[cfg(not(feature = "oscore"))]
    let _ = (ctx, request);
    #[cfg(feature = "oscore")]
    if let Some(oscore) = ctx.as_mut() {
        let Some(request) = request else {
            return Err(protect_err(OscoreError::Context));
        };
        let mut wire = S::TxScratch::default();
        let n = oscore
            .protect_response_with_piv(msg, request, wire.as_mut())
            .map_err(protect_err)?;
        return fill_tx(engine, tx, &wire.as_ref()[..n]).map_err(super::Error::from);
    }
    engine
        .encode_tx(tx, msg)
        .map(|_| ())
        .map_err(super::Error::from)
}

#[cfg_attr(not(feature = "oscore"), allow(dead_code))]
pub(crate) fn fill_tx<S: Storage + DatagramSlots>(
    engine: &mut Engine<S>,
    tx: SlotId,
    bytes: &[u8],
) -> Result<(), SlotMessageError> {
    let mut access = engine.access_tx_mut(tx)?;
    if bytes.len() > access.capacity() {
        return Err(SlotMessageError::Encode(EncodeError::BufferTooSmall));
    }
    access.bytes_mut()[..bytes.len()].copy_from_slice(bytes);
    access
        .set_len(bytes.len())
        .map_err(SlotMessageError::Slot)?;
    Ok(())
}

/// Map a protect failure onto App encode (request, response, notification).
///
/// Only size misses become [`EncodeError::BufferTooSmall`] (Inner Block1 /
/// Block2 may start). Protocol failures (`SequenceExhausted`, `Encrypt`,
/// `Context`, …) stay [`super::Error::Oscore`] so they are not mistaken
/// for a too-large body.
#[cfg(feature = "oscore")]
fn protect_err<E>(err: OscoreError) -> super::Error<E> {
    match err {
        OscoreError::BufferTooSmall | OscoreError::MessageLength => {
            super::Error::Message(SlotMessageError::Encode(EncodeError::BufferTooSmall))
        }
        OscoreError::Encode(e) => super::Error::Message(SlotMessageError::Encode(e)),
        OscoreError::Options | OscoreError::Saturated => {
            super::Error::Message(SlotMessageError::Encode(EncodeError::OptionsFull))
        }
        other => super::Error::Oscore(other),
    }
}

/// Release a terminal client's request binding without resetting crypto state.
pub(crate) fn cancel(ctx: &mut Field, token: crate::message::Token) {
    #[cfg(feature = "oscore")]
    if let Some(ctx) = ctx.as_mut() {
        let _ = ctx.take(token);
    }
    #[cfg(not(feature = "oscore"))]
    let _ = (ctx, token);
}

#[cfg(feature = "oscore")]
pub(crate) fn send_qblock1_recover<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut super::AppIds,
    ctx: &mut Field,
    now_ms: u64,
    recover: crate::storage::QBlockRecover,
) -> Result<(), super::Error<T::Error>>
where
    S: Storage
        + DatagramSlots
        + crate::storage::BodySlots
        + crate::storage::PendingCons
        + crate::storage::DedupSlots,
    T: crate::storage::DatagramIo,
{
    use crate::message::{Code, ContentFormat, Opt, Type};
    use crate::storage::BlockRole;
    let binding = engine
        .rx_body_transfer(recover.id())
        .filter(|transfer| {
            recover.role() == BlockRole::IncomingQBlock1
                && transfer.role() == BlockRole::IncomingQBlock1
                && transfer.key() == recover.key()
        })
        .and_then(|transfer| transfer.oscore_request);
    let Some((token, request)) = binding else {
        return Err(super::Error::Oscore(OscoreError::Unsupported));
    };
    let mut nums = [0; 16];
    let n = recover.copy_missing_nums(&mut nums);
    let response = super::Response::missing_blocks(nums.into_iter().take(n));
    let format = ContentFormat::MISSING_BLOCKS.encode();
    let options = [Opt::content_format(&format)];
    let message = Message::new(
        Type::NonConfirmable,
        Code::REQUEST_ENTITY_INCOMPLETE,
        ids.next_for(engine, now_ms)?,
    )
    .with_token(token)
    .with_options(&options)
    .with_payload(response.payload());
    let tx = engine.acquire_tx().ok_or(super::Error::Saturated)?;
    let result = encode_notification(ctx, Some(request), engine, tx, &message).and_then(|()| {
        engine
            .set_tx_endpoint(tx, recover.key().endpoint())
            .map_err(super::Error::Slot)?;
        engine
            .send_tx(io, tx)
            .map(|_| ())
            .map_err(super::Error::from)
    });
    let _ = engine.release_tx(tx);
    result
}
