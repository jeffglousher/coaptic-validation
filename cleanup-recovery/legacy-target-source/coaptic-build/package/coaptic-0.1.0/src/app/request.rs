//! [`Request`]: borrowed view of inbound work [`App::poll`](super::App::poll)
//! already holds.

use crate::error::ValueError;
use crate::message::{
    BlockValue, Code, ContentFormat, HopLimit, MessageId, NoResponse, Opt, OptionNumber, Options,
    ParsedMessage, Precondition, Token, Type,
};
use crate::message::{OpaqueOptions, StringOptions};
use crate::storage::Endpoint;

use super::routing::Method;

/// Maximum Uri-Path segments stored on a [`Request`] or a site entry.
pub const MAX_PATH_SEGMENTS: usize = 8;

/// Failure to turn a bind or client path into Uri-Path segments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    /// A Uri-Path option value is not UTF-8.
    BadUtf8,
    /// More than [`MAX_PATH_SEGMENTS`] segments.
    TooLong,
    /// An empty segment (`""`, `"sensors//temp"`, or a trailing `/`).
    EmptySegment,
}

/// Convert a bind or client path into Uri-Path segments without allocating.
///
/// Accepts `&[&'static str]` (and `&[&'static str; N]`), or a `'static`
/// slash-separated string (`"sensors/temp"`). Leading `/` is ignored.
/// Empty segments (`""`, `"sensors//temp"`, trailing `/`) are
/// [`PathError::EmptySegment`]. Used by [`super::AppBuilder::route`] and
/// [`crate::App::get`] / [`crate::App::put`].
pub trait IntoPath {
    /// Fill `out` with Uri-Path segments. Returns the count.
    fn fill_path(self, out: &mut [&'static str]) -> Result<usize, PathError>;
}

impl IntoPath for &[&'static str] {
    fn fill_path(self, out: &mut [&'static str]) -> Result<usize, PathError> {
        path_from_segments(self, out)
    }
}

impl<const N: usize> IntoPath for &[&'static str; N] {
    fn fill_path(self, out: &mut [&'static str]) -> Result<usize, PathError> {
        path_from_segments(self, out)
    }
}

impl IntoPath for &'static str {
    fn fill_path(self, out: &mut [&'static str]) -> Result<usize, PathError> {
        split_path(self, out)
    }
}

/// Split a `'static` URI-Path (`"sensors/temp"` or `"/sensors/temp"`) into
/// Uri-Path segments.
///
/// Leading `/` is ignored. A remaining empty string is the root (zero
/// segments). Empty segments (`"sensors//temp"`, trailing `/`) are
/// [`PathError::EmptySegment`]. More segments than `out.len()` is
/// [`PathError::TooLong`].
pub fn split_path(path: &'static str, out: &mut [&'static str]) -> Result<usize, PathError> {
    let rest = path.trim_start_matches('/');
    if rest.is_empty() {
        return Ok(0);
    }
    let mut n = 0;
    for segment in rest.split('/') {
        if segment.is_empty() {
            return Err(PathError::EmptySegment);
        }
        if n >= out.len() {
            return Err(PathError::TooLong);
        }
        out[n] = segment;
        n += 1;
    }
    Ok(n)
}

fn path_from_segments(
    segments: &[&'static str],
    out: &mut [&'static str],
) -> Result<usize, PathError> {
    if segments.len() > out.len() {
        return Err(PathError::TooLong);
    }
    for (i, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            return Err(PathError::EmptySegment);
        }
        out[i] = *segment;
    }
    Ok(segments.len())
}

pub(crate) fn path_from_into(path: impl IntoPath) -> Result<Path<'static>, PathError> {
    let mut segs = [""; MAX_PATH_SEGMENTS];
    let n = path.fill_path(&mut segs)?;
    Path::from_segments(&segs[..n])
}

/// Borrowed view of one inbound request.
///
/// Handlers see path, method, token, message ID, peer, options, and
/// [`Self::payload`] (this datagram). When Block1 / Q-Block1 has assembled
/// a complete body, [`Self::body`] borrows those bytes. Ordinary handlers
/// do not see Engine slot identifiers. The borrow lasts only for the
/// handler call — [`App::poll`](super::App::poll) encodes the
/// [`Response`](super::Response) and then releases.
///
/// ```
/// use coaptic::{Request, Response};
///
/// fn echo(req: Request<'_>) -> Response<'static> {
///     let body = req.body().unwrap_or(req.payload());
///     Response::content_copy(body)
/// }
/// # let _ = echo;
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    message: ParsedMessage<'a>,
    path: Path<'a>,
    peer: Endpoint,
    method: Option<Method>,
    body: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    pub(crate) fn from_decoded(
        message: ParsedMessage<'a>,
        peer: Endpoint,
        body: Option<&'a [u8]>,
    ) -> Result<Self, PathError> {
        let path = Path::from_message(&message)?;
        let method = Method::from_code(message.code());
        Ok(Self {
            message,
            path,
            peer,
            method,
            body,
        })
    }

    /// Request method, if `code` is a known class-0 method.
    #[must_use]
    pub const fn method(&self) -> Option<Method> {
        self.method
    }

    /// Wire code (GET / PUT / …).
    #[must_use]
    pub const fn code(&self) -> Code {
        self.message.code()
    }

    /// Uri-Path segments in wire order (no leading slash).
    #[must_use]
    pub fn path(&self) -> &[&str] {
        self.path.segments()
    }

    /// Remote peer that sent this datagram.
    #[must_use]
    pub const fn peer(&self) -> Endpoint {
        self.peer
    }

    /// This datagram's payload (empty if the 0xFF marker is absent).
    ///
    /// For a Block1 fragment this is the current block, not the assembled
    /// body. See [`Self::body`].
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.message.payload()
    }

    /// Complete assembled request body, if Block1 / Q-Block1 filled an RX body area.
    ///
    /// `None` when this datagram is not a completed block-wise body.
    /// The slice borrows body-area memory for this handler call only.
    #[must_use]
    pub const fn body(&self) -> Option<&'a [u8]> {
        self.body
    }

    /// Whether [`Self::body`] is present (including an empty complete body).
    #[must_use]
    pub const fn has_body(&self) -> bool {
        self.body.is_some()
    }

    /// Token (echo this on the response).
    #[must_use]
    pub const fn token(&self) -> Token {
        self.message.token()
    }

    /// Message ID (echo this on a piggybacked ACK).
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message.message_id()
    }

    /// CON / NON / ACK / RST.
    #[must_use]
    pub const fn ty(&self) -> Type {
        self.message.ty()
    }

    /// Options in wire order.
    #[must_use]
    pub const fn options(&self) -> Options<'a> {
        self.message.options()
    }

    /// First option with `number`, if any.
    #[must_use]
    pub fn get_option(&self, number: OptionNumber) -> Option<Opt<'a>> {
        self.message.get_option(number)
    }

    /// Uri-Host, if present.
    #[must_use]
    pub fn uri_host(&self) -> Option<Result<&'a str, ValueError>> {
        self.message.uri_host()
    }

    /// Uri-Port, if present.
    #[must_use]
    pub fn uri_port(&self) -> Option<Result<u16, ValueError>> {
        self.message.uri_port()
    }

    /// Uri-Query values in wire order.
    #[must_use]
    pub fn uri_query(&self) -> StringOptions<'a> {
        self.message.uri_query()
    }

    /// Content-Format, if present.
    #[must_use]
    pub fn content_format(&self) -> Option<Result<ContentFormat, ValueError>> {
        self.message.content_format()
    }

    /// Accept, if present.
    #[must_use]
    pub fn accept(&self) -> Option<Result<ContentFormat, ValueError>> {
        self.message.accept()
    }

    /// Observe value, if present.
    #[must_use]
    pub fn observe(&self) -> Option<Result<u32, ValueError>> {
        self.message.observe()
    }

    /// GET or FETCH with Observe register (value 0).
    #[must_use]
    pub fn is_observe_register(&self) -> bool {
        self.message.is_observe_register()
    }

    /// GET or FETCH with Observe deregister (value 1).
    #[must_use]
    pub fn is_observe_deregister(&self) -> bool {
        self.message.is_observe_deregister()
    }

    /// ETag values in wire order.
    #[must_use]
    pub fn etag(&self) -> OpaqueOptions<'a> {
        self.message.etag()
    }

    /// If-Match values in wire order.
    #[must_use]
    pub fn if_match(&self) -> OpaqueOptions<'a> {
        self.message.if_match()
    }

    /// Whether If-None-Match is present.
    #[must_use]
    pub fn if_none_match(&self) -> bool {
        self.message.if_none_match()
    }

    /// Classify If-Match / If-None-Match. The library does not invent 4.12.
    #[must_use]
    pub fn precondition(&self, exists: bool, etag: Option<&[u8]>) -> Precondition {
        self.message.precondition(exists, etag)
    }

    /// Block1, if present.
    #[must_use]
    pub fn block1(&self) -> Option<Result<BlockValue, ValueError>> {
        self.message.block1()
    }

    /// Q-Block1, if present.
    #[must_use]
    pub fn q_block1(&self) -> Option<Result<BlockValue, ValueError>> {
        self.message.q_block1()
    }

    /// Size1, if present.
    #[must_use]
    pub fn size1(&self) -> Option<Result<u32, ValueError>> {
        self.message.size1()
    }

    /// Request-Tag values in wire order.
    #[must_use]
    pub fn request_tag(&self) -> OpaqueOptions<'a> {
        self.message.request_tag()
    }

    /// Echo value, if present.
    #[must_use]
    pub fn echo(&self) -> Option<&'a [u8]> {
        self.message.echo()
    }

    /// Hop-Limit, if present.
    #[must_use]
    pub fn hop_limit(&self) -> Option<Result<HopLimit, ValueError>> {
        self.message.hop_limit()
    }

    /// No-Response, if present.
    #[must_use]
    pub fn no_response(&self) -> Option<Result<NoResponse, ValueError>> {
        self.message.no_response()
    }

    /// Full decoded datagram. Advanced: remaining options, Block2, …
    #[must_use]
    pub const fn message(&self) -> ParsedMessage<'a> {
        self.message
    }
}

/// Uri-Path segments, capped at [`MAX_PATH_SEGMENTS`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Path<'a> {
    segs: [&'a str; MAX_PATH_SEGMENTS],
    len: u8,
}

impl<'a> Path<'a> {
    pub(crate) const fn empty() -> Self {
        Self {
            segs: [""; MAX_PATH_SEGMENTS],
            len: 0,
        }
    }

    pub(crate) fn from_segments(segments: &[&'a str]) -> Result<Self, PathError> {
        if segments.len() > MAX_PATH_SEGMENTS {
            return Err(PathError::TooLong);
        }
        let mut path = Self::empty();
        for (i, segment) in segments.iter().enumerate() {
            if segment.is_empty() {
                return Err(PathError::EmptySegment);
            }
            path.segs[i] = segment;
        }
        path.len = segments.len() as u8;
        Ok(path)
    }

    pub(crate) fn from_message(parsed: &ParsedMessage<'a>) -> Result<Self, PathError> {
        let mut path = Self::empty();
        for segment in parsed.uri_path() {
            let segment = segment.map_err(|_| PathError::BadUtf8)?;
            let i = usize::from(path.len);
            if i >= MAX_PATH_SEGMENTS {
                return Err(PathError::TooLong);
            }
            path.segs[i] = segment;
            path.len += 1;
        }
        Ok(path)
    }

    pub(crate) fn segments(&self) -> &[&'a str] {
        &self.segs[..usize::from(self.len)]
    }

    pub(crate) fn matches(self, other: &[&str]) -> bool {
        self.segments() == other
    }
}
