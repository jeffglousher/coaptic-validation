//! Protect / unprotect a CoAP [`Message`] / [`ParsedMessage`].

use crate::error::EncodeError;
use crate::message::{
    Code, Message, MessageId, Opt, OptionNumber, OptionsBuilder, ParsedMessage, Token, Type,
    decode, write_option,
};

use super::aead::{self, Aad};
use super::context::{RequestRef, SecurityContext};
use super::header::{self, OptionClass, OscoreHeader, PartialIv};
use super::{Error, MAX_ID_CONTEXT_LEN, MAX_ID_LEN, MAX_PIV_LEN, TAG_LEN};

/// Maximum Class E / U options this slice copies (path + query + extras).
const OPT_SLOTS: usize = 16;
/// Inner plaintext / ciphertext scratch.
const INNER: usize = 1280;

/// Plug-in a caller can implement instead of [`SecurityContext`].
///
/// [`crate::App::set_oscore`] takes [`SecurityContext`]. Use this trait when
/// you drive protect/unprotect yourself (tests, a later group-OSCORE
/// context, or a side table of pairwise contexts).
pub trait OscoreContext {
    /// Protect a request. Writes a complete OSCORE datagram into `out`.
    fn protect_request(&mut self, plain: &Message<'_>, out: &mut [u8]) -> Result<usize, Error>;

    /// Open a request. Writes the inner CoAP datagram into `out`.
    fn unprotect_request<'a>(
        &mut self,
        protected: &ParsedMessage<'_>,
        out: &'a mut [u8],
    ) -> Result<(ParsedMessage<'a>, RequestRef), Error>;

    /// Protect a response bound to `request`.
    fn protect_response(
        &self,
        plain: &Message<'_>,
        request: RequestRef,
        out: &mut [u8],
    ) -> Result<usize, Error>;

    /// Open a response bound to `request`.
    fn unprotect_response<'a>(
        &self,
        protected: &ParsedMessage<'_>,
        request: RequestRef,
        out: &'a mut [u8],
    ) -> Result<ParsedMessage<'a>, Error>;
}

impl OscoreContext for SecurityContext {
    fn protect_request(&mut self, plain: &Message<'_>, out: &mut [u8]) -> Result<usize, Error> {
        protect_request(self, plain, out)
    }

    fn unprotect_request<'a>(
        &mut self,
        protected: &ParsedMessage<'_>,
        out: &'a mut [u8],
    ) -> Result<(ParsedMessage<'a>, RequestRef), Error> {
        unprotect_request(self, protected, out)
    }

    fn protect_response(
        &self,
        plain: &Message<'_>,
        request: RequestRef,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        protect_response(self, plain, request, out)
    }

    fn unprotect_response<'a>(
        &self,
        protected: &ParsedMessage<'_>,
        request: RequestRef,
        out: &'a mut [u8],
    ) -> Result<ParsedMessage<'a>, Error> {
        unprotect_response(self, protected, request, out)
    }
}

impl SecurityContext {
    /// Protect `plain` as an OSCORE request. See [`OscoreContext::protect_request`].
    pub fn protect_request(&mut self, plain: &Message<'_>, out: &mut [u8]) -> Result<usize, Error> {
        protect_request(self, plain, out)
    }

    /// Unprotect an OSCORE request. See [`OscoreContext::unprotect_request`].
    pub fn unprotect_request<'a>(
        &mut self,
        protected: &ParsedMessage<'_>,
        out: &'a mut [u8],
    ) -> Result<(ParsedMessage<'a>, RequestRef), Error> {
        unprotect_request(self, protected, out)
    }

    /// Protect the single response without a new Partial IV for this request.
    /// The caller must use this for at most one distinct response plaintext per
    /// [`RequestRef`]. Retransmit retained bytes; use
    /// [`Self::protect_response_with_piv`] for additional responses such as Q
    /// payloads or notifications. This low-level API does not retain that budget.
    pub fn protect_response(
        &self,
        plain: &Message<'_>,
        request: RequestRef,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        protect_response(self, plain, request, out)
    }

    /// Protect a response that carries a new Partial IV (Appendix C.8).
    pub fn protect_response_with_piv(
        &mut self,
        plain: &Message<'_>,
        request: RequestRef,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        protect_response_piv(self, plain, request, out)
    }

    /// Unprotect an OSCORE response.
    pub fn unprotect_response<'a>(
        &self,
        protected: &ParsedMessage<'_>,
        request: RequestRef,
        out: &'a mut [u8],
    ) -> Result<ParsedMessage<'a>, Error> {
        unprotect_response(self, protected, request, out)
    }
}

/// See [`SecurityContext::protect_request`].
pub fn protect_request(
    ctx: &mut SecurityContext,
    plain: &Message<'_>,
    out: &mut [u8],
) -> Result<usize, Error> {
    if !plain.code().is_request() {
        return Err(Error::MessageLength);
    }
    let piv = ctx.take_sender_piv()?;
    let request = ctx.request_ref(piv);
    let nonce = ctx.request_nonce(piv);
    let aad = Aad::new(request.kid(), piv.as_bytes())?;
    let mut plaintext = [0u8; INNER];
    let pt_len = encode_plaintext(plain, &mut plaintext)?;
    let mut ciphertext = [0u8; INNER];
    let ct_len = aead::seal(
        ctx.sender_key(),
        &nonce,
        aad.as_bytes(),
        &plaintext[..pt_len],
        &mut ciphertext,
    )?;
    let kid_ctx = if ctx.id_context().is_empty() {
        None
    } else {
        Some(ctx.id_context())
    };
    let n = encode_outer(
        plain.ty(),
        outer_code(plain.code(), plain.options()),
        plain.message_id(),
        plain.token(),
        plain.options(),
        Some(piv),
        kid_ctx,
        Some(ctx.sender_id()),
        &ciphertext[..ct_len],
        out,
    )?;
    let observe = plain.options().iter().any(is_observe);
    if !observe
        && plain.options().iter().any(|option| {
            matches!(
                option.number(),
                OptionNumber::BLOCK2 | OptionNumber::Q_BLOCK2
            )
        })
    {
        ctx.remember_download(plain.token(), request)?;
    } else {
        ctx.remember_live(plain.token(), request, observe)?;
    }
    Ok(n)
}

/// See [`SecurityContext::unprotect_request`].
pub fn unprotect_request<'a>(
    ctx: &mut SecurityContext,
    protected: &ParsedMessage<'_>,
    out: &'a mut [u8],
) -> Result<(ParsedMessage<'a>, RequestRef), Error> {
    let header = parse_protected(protected)?;
    if !ctx.matches_recipient(header.kid, header.kid_context) {
        return Err(Error::Context);
    }
    let piv = header.piv.ok_or(Error::PartialIv)?;
    if !ctx.replay_fresh(piv.seq()) {
        return Err(Error::Replay);
    }
    if protected.payload().len() < TAG_LEN {
        return Err(Error::MessageLength);
    }
    let kid = header.kid.unwrap_or(&[]);
    let aad = Aad::new(kid, piv.as_bytes())?;
    let nonce = ctx.recipient_nonce(piv);
    let mut plaintext = [0u8; INNER];
    let pt_len = aead::open(
        ctx.recipient_key(),
        &nonce,
        aad.as_bytes(),
        protected.payload(),
        &mut plaintext,
    )?;
    ctx.replay_accept(piv.seq());
    let n = stitch_inner(
        protected.ty(),
        protected.message_id(),
        protected.token(),
        protected.options(),
        &plaintext[..pt_len],
        out,
    )?;
    let inner = decode(&out[..n])?;
    let request = RequestRef::from_kid(kid, piv)?;
    // Caller (App) holds `request` on the inbound exchange for
    // `protect_response`. The live Token table is the client in-flight
    // set (`protect_request` → `unprotect_response`); do not remember
    // here or sequential server Tokens saturate `LIVE_REQUESTS`.
    Ok((inner, request))
}

/// See [`SecurityContext::protect_response`].
pub fn protect_response(
    ctx: &SecurityContext,
    plain: &Message<'_>,
    request: RequestRef,
    out: &mut [u8],
) -> Result<usize, Error> {
    if !plain.code().is_response() {
        return Err(Error::MessageLength);
    }
    let aad = Aad::new(request.kid(), request.piv().as_bytes())?;
    let nonce = aead::nonce(ctx.common_iv(), request.kid(), request.piv());
    let mut plaintext = [0u8; INNER];
    let pt_len = encode_plaintext(plain, &mut plaintext)?;
    let mut ciphertext = [0u8; INNER];
    let ct_len = aead::seal(
        ctx.sender_key(),
        &nonce,
        aad.as_bytes(),
        &plaintext[..pt_len],
        &mut ciphertext,
    )?;
    encode_outer(
        plain.ty(),
        outer_code(plain.code(), plain.options()),
        plain.message_id(),
        plain.token(),
        plain.options(),
        None,
        None,
        None,
        &ciphertext[..ct_len],
        out,
    )
}

/// Protect a response and optionally include a new Partial IV.
pub fn protect_response_piv(
    ctx: &mut SecurityContext,
    plain: &Message<'_>,
    request: RequestRef,
    out: &mut [u8],
) -> Result<usize, Error> {
    if !plain.code().is_response() {
        return Err(Error::MessageLength);
    }
    let piv = ctx.take_sender_piv()?;
    let aad = Aad::new(request.kid(), request.piv().as_bytes())?;
    let nonce = ctx.request_nonce(piv);
    let mut plaintext = [0u8; INNER];
    let pt_len = encode_plaintext(plain, &mut plaintext)?;
    let mut ciphertext = [0u8; INNER];
    let ct_len = aead::seal(
        ctx.sender_key(),
        &nonce,
        aad.as_bytes(),
        &plaintext[..pt_len],
        &mut ciphertext,
    )?;
    encode_outer(
        plain.ty(),
        outer_code(plain.code(), plain.options()),
        plain.message_id(),
        plain.token(),
        plain.options(),
        Some(piv),
        None,
        None,
        &ciphertext[..ct_len],
        out,
    )
}

/// See [`SecurityContext::unprotect_response`].
pub fn unprotect_response<'a>(
    ctx: &SecurityContext,
    protected: &ParsedMessage<'_>,
    request: RequestRef,
    out: &'a mut [u8],
) -> Result<ParsedMessage<'a>, Error> {
    unprotect_response_candidates(ctx, protected, request, None, out).map(|(message, _)| message)
}

impl SecurityContext {
    pub(crate) fn unprotect_bound_response<'a>(
        &self,
        protected: &ParsedMessage<'_>,
        out: &'a mut [u8],
    ) -> Result<(ParsedMessage<'a>, RequestRef), Error> {
        let request = self.lookup(protected.token()).ok_or(Error::Context)?;
        let observation = self
            .observe_request(protected.token())
            .filter(|old| *old != request);
        unprotect_response_candidates(self, protected, request, observation, out)
    }
}

fn unprotect_response_candidates<'a>(
    ctx: &SecurityContext,
    protected: &ParsedMessage<'_>,
    request: RequestRef,
    fallback: Option<RequestRef>,
    out: &'a mut [u8],
) -> Result<(ParsedMessage<'a>, RequestRef), Error> {
    let header = parse_protected(protected)?;
    if protected.payload().len() < TAG_LEN {
        return Err(Error::MessageLength);
    }
    let mut plaintext = [0u8; INNER];
    let mut accepted = None;
    // At most two AEAD attempts, using the same fixed scratch. Decode and
    // admission happen only after authentication identifies the request.
    for candidate in [Some(request), fallback].into_iter().flatten() {
        let aad = Aad::new(candidate.kid(), candidate.piv().as_bytes())?;
        let nonce = match header.piv {
            Some(piv) => aead::nonce(ctx.common_iv(), ctx.recipient_id(), piv),
            None => aead::nonce(ctx.common_iv(), candidate.kid(), candidate.piv()),
        };
        match aead::open(
            ctx.recipient_key(),
            &nonce,
            aad.as_bytes(),
            protected.payload(),
            &mut plaintext,
        ) {
            Ok(len) => {
                accepted = Some((len, candidate));
                break;
            }
            Err(Error::Decrypt) => {}
            Err(error) => return Err(error),
        }
    }
    let (len, request) = accepted.ok_or(Error::Decrypt)?;
    let n = stitch_inner(
        protected.ty(),
        protected.message_id(),
        protected.token(),
        protected.options(),
        &plaintext[..len],
        out,
    )?;
    Ok((decode(&out[..n])?, request))
}

fn parse_protected<'a>(protected: &ParsedMessage<'a>) -> Result<OscoreHeader<'a>, Error> {
    let value = protected.oscore().ok_or(Error::Header)?;
    if protected.payload().is_empty() {
        return Err(Error::MessageLength);
    }
    OscoreHeader::parse(value)
}

fn is_observe(opt: &Opt<'_>) -> bool {
    opt.number().get() == 6
}

/// Outer Code: FETCH / Content when Observe is present (RFC 8613 §4.1.3.5).
fn outer_code(inner: Code, opts: &[Opt<'_>]) -> Code {
    if !opts.iter().any(is_observe) {
        return if inner.is_request() {
            Code::POST
        } else {
            Code::CHANGED
        };
    }
    if inner.is_request() {
        Code::FETCH
    } else {
        Code::CONTENT
    }
}

fn encode_plaintext(plain: &Message<'_>, out: &mut [u8]) -> Result<usize, Error> {
    if out.is_empty() {
        return Err(Error::BufferTooSmall);
    }
    out[0] = plain.code().as_raw();
    let mut i = 1;
    let mut prev = 0u16;
    let notify = plain.code().is_response();
    for opt in plain.options() {
        let n = opt.number().get();
        if header::is_oscore(n) || !header::classify(n).in_plaintext() {
            continue;
        }
        if n < prev {
            return Err(Error::Encode(EncodeError::OptionsNotAscending));
        }
        // Notifications: Inner Observe MUST be empty (RFC 8613 §4.1.3.5.2).
        let value = if n == 6 && notify {
            &[][..]
        } else {
            opt.value()
        };
        i = write_option(out, i, u32::from(n - prev), value)?;
        prev = n;
    }
    if !plain.payload().is_empty() {
        if i >= out.len() {
            return Err(Error::BufferTooSmall);
        }
        out[i] = 0xff;
        i += 1;
        let end = i
            .checked_add(plain.payload().len())
            .ok_or(Error::BufferTooSmall)?;
        if end > out.len() {
            return Err(Error::BufferTooSmall);
        }
        out[i..end].copy_from_slice(plain.payload());
        i = end;
    }
    Ok(i)
}

#[allow(clippy::too_many_arguments)]
fn encode_outer(
    ty: Type,
    code: Code,
    mid: MessageId,
    token: Token,
    inner_opts: &[Opt<'_>],
    piv: Option<PartialIv>,
    kid_context: Option<&[u8]>,
    kid: Option<&[u8]>,
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut oscore = [0u8; 1 + MAX_PIV_LEN + 1 + MAX_ID_CONTEXT_LEN + MAX_ID_LEN];
    let oscore_n = header::encode_option(&mut oscore, piv, kid_context, kid)?;
    let mut opts = OptionsBuilder::<OPT_SLOTS>::new();
    for opt in inner_opts {
        let n = opt.number().get();
        if header::is_oscore(n) || !header::encode_as_outer(n) {
            continue;
        }
        opts.push(*opt).map_err(|_| Error::Options)?;
    }
    opts.push(Opt::oscore(&oscore[..oscore_n]))
        .map_err(|_| Error::Options)?;
    // Observe responses appear as 2.05 Content (cacheable) to
    // OSCORE-unaware proxies. Outer Max-Age 0 is the Dual Class U
    // field (`knowledge/rfcs/rfc8613.txt` §4.1.3.1). Application
    // Max-Age stays Inner (`encode_as_outer(14)` is false). A full
    // outer builder is OptionsFull — do not skip the inject.
    if code.is_response() && inner_opts.iter().any(is_observe) {
        opts.push(Opt::new(OptionNumber::MAX_AGE, &[]))
            .map_err(|_| Error::Encode(EncodeError::OptionsFull))?;
    }
    let msg = Message::new(ty, code, mid)
        .with_token(token)
        .with_options(opts.as_slice())
        .with_payload(ciphertext);
    Ok(msg.encode(out)?)
}

fn stitch_inner(
    ty: Type,
    mid: MessageId,
    token: Token,
    outer_opts: crate::message::Options<'_>,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if plaintext.is_empty() {
        return Err(Error::MessageLength);
    }
    let tkl = token.len();
    let header_end = 4 + tkl;
    let rest = &plaintext[1..];
    if out.len() < header_end + rest.len() {
        return Err(Error::BufferTooSmall);
    }
    out[0] = (1 << 6) | (ty.to_bits() << 4) | (tkl as u8);
    out[1] = plaintext[0];
    let mid_be = mid.get().to_be_bytes();
    out[2] = mid_be[0];
    out[3] = mid_be[1];
    out[4..header_end].copy_from_slice(token.as_bytes());
    out[header_end..header_end + rest.len()].copy_from_slice(rest);

    // Re-encode so Class U-only outer options (Uri-Host, Hop-Limit, …)
    // sit beside Class E. Dual options on the outer datagram are not
    // merged: Observe stays Inner (§4.1.3.5.2); Block/Size stay Inner
    // (§4.1.3.4.2); Max-Age Outer is discarded (§8.4); No-Response
    // Outer is ignored (§4.1.3.6). Class E on the outer (ETag, …) is
    // discarded (§8.2 / §8.4).
    let mut merged = [0u8; INNER];
    let n = {
        let fake = decode(&out[..header_end + rest.len()])?;
        let mut opts = OptionsBuilder::<OPT_SLOTS>::new();
        for opt in outer_opts {
            let n = opt.number().get();
            if header::is_oscore(n) || header::classify(n) != OptionClass::Outer {
                continue;
            }
            opts.push(opt).map_err(|_| Error::Options)?;
        }
        for opt in fake.options() {
            opts.push(opt).map_err(|_| Error::Options)?;
        }
        let msg = Message::new(ty, fake.code(), mid)
            .with_token(token)
            .with_options(opts.as_slice())
            .with_payload(fake.payload());
        msg.encode(&mut merged)?
    };
    if n > out.len() {
        return Err(Error::BufferTooSmall);
    }
    out[..n].copy_from_slice(&merged[..n]);
    Ok(n)
}
