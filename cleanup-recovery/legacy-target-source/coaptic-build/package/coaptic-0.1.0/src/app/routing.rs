//! Method routers and handler fns (`Request` → `Response`).
//!
//! Taste is Axum (`get(h).put(p)`) and Ohkami (per-method bits on one path).
//! Stored handlers are fn pointers — no boxes, no allocator, no `unsafe`.
//! These are the **site** routers ([`get`], [`put`], …). Distinct from the
//! outbound builders [`App::get`](super::App::get) / [`App::put`](super::App::put).
//! Domain data that outlives a request stays outside [`App`](super::App).

use crate::message::Code;

use super::request::Request;
use super::response::Response;

/// Function pointer stored in a [`MethodRouter`].
///
/// Default handlers are relatively stateless: `Request` → [`Response`].
pub type HandlerFn = fn(Request<'_>) -> Response<'static>;

/// Snapshot for a due Observe notification (`App::poll` / [`App::signal`](super::App::signal)).
///
/// Domain data stays outside `App`. This fn builds the current
/// representation when Engine pacing surfaces a notify.
pub type ObserveSource = fn() -> Response<'static>;

/// Per-path method table (Ohkami-style bits; Axum-style `.get().put()` chain).
///
/// Built with [`get`], [`put`], [`post`], [`delete`], [`fetch`], [`patch`],
/// [`ipatch`]. One route occupies one site slot regardless of how many
/// methods are set. Unknown method on a matching path is 4.05
/// ([`Response::problem`]).
///
/// ```
/// use coaptic::{Request, Response, get};
///
/// fn read(_: Request<'_>) -> Response<'static> { Response::content(b"ok") }
/// fn write(_: Request<'_>) -> Response<'static> { Response::changed() }
///
/// let methods = get(read).put(write);
/// # let _ = methods;
/// ```
#[derive(Clone, Copy)]
pub struct MethodRouter {
    handlers: [Option<HandlerFn>; METHOD_COUNT],
    observe: Option<ObserveSource>,
}

const METHOD_COUNT: usize = 7;

impl MethodRouter {
    /// No methods. Unknown method on a matching path is 4.05 (RFC 9290 CBOR).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            handlers: [None; METHOD_COUNT],
            observe: None,
        }
    }

    /// Register a poll-time snapshot for Observe notifications.
    ///
    /// A successful GET/FETCH with Observe=0 that includes Observe on the
    /// [`Response`] still registers without this. This hook lets
    /// [`App::poll`](super::App::poll) encode a notification when Engine
    /// progress yields `observe_notify` (after [`App::signal`](super::App::signal)).
    #[must_use]
    pub const fn observe(self, source: ObserveSource) -> Self {
        let mut this = self;
        this.observe = Some(source);
        this
    }

    pub(crate) const fn observe_source(self) -> Option<ObserveSource> {
        self.observe
    }

    /// Bind GET (0.01).
    #[must_use]
    pub const fn get(self, handler: HandlerFn) -> Self {
        self.on(Method::Get, handler)
    }

    /// Bind POST (0.02).
    #[must_use]
    pub const fn post(self, handler: HandlerFn) -> Self {
        self.on(Method::Post, handler)
    }

    /// Bind PUT (0.03).
    #[must_use]
    pub const fn put(self, handler: HandlerFn) -> Self {
        self.on(Method::Put, handler)
    }

    /// Bind DELETE (0.04).
    #[must_use]
    pub const fn delete(self, handler: HandlerFn) -> Self {
        self.on(Method::Delete, handler)
    }

    /// Bind FETCH (0.05).
    #[must_use]
    pub const fn fetch(self, handler: HandlerFn) -> Self {
        self.on(Method::Fetch, handler)
    }

    /// Bind PATCH (0.06).
    #[must_use]
    pub const fn patch(self, handler: HandlerFn) -> Self {
        self.on(Method::Patch, handler)
    }

    /// Bind iPATCH (0.07).
    #[must_use]
    pub const fn ipatch(self, handler: HandlerFn) -> Self {
        self.on(Method::IPatch, handler)
    }

    const fn on(mut self, method: Method, handler: HandlerFn) -> Self {
        self.handlers[method.index()] = Some(handler);
        self
    }

    pub(crate) fn call(&self, method: Method, req: Request<'_>) -> Response<'static> {
        match self.handlers[method.index()] {
            Some(handler) => handler(req),
            None => Response::problem(Code::METHOD_NOT_ALLOWED).title("Method Not Allowed"),
        }
    }
}

impl Default for MethodRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// GET (0.01) **site** router. Chain [`.put`](MethodRouter::put) and siblings.
///
/// Distinct from the outbound builder [`App::get`](super::App::get).
#[must_use]
pub const fn get(handler: HandlerFn) -> MethodRouter {
    MethodRouter::new().get(handler)
}

/// POST (0.02) router.
#[must_use]
pub const fn post(handler: HandlerFn) -> MethodRouter {
    MethodRouter::new().post(handler)
}

/// PUT (0.03) router.
#[must_use]
pub const fn put(handler: HandlerFn) -> MethodRouter {
    MethodRouter::new().put(handler)
}

/// DELETE (0.04) router.
#[must_use]
pub const fn delete(handler: HandlerFn) -> MethodRouter {
    MethodRouter::new().delete(handler)
}

/// FETCH (0.05) router.
#[must_use]
pub const fn fetch(handler: HandlerFn) -> MethodRouter {
    MethodRouter::new().fetch(handler)
}

/// PATCH (0.06) router.
#[must_use]
pub const fn patch(handler: HandlerFn) -> MethodRouter {
    MethodRouter::new().patch(handler)
}

/// iPATCH (0.07) router.
#[must_use]
pub const fn ipatch(handler: HandlerFn) -> MethodRouter {
    MethodRouter::new().ipatch(handler)
}

/// Request method (class 0 codes).
///
/// Unknown class-0 codes are not a [`Method`]. The site still answers 4.05
/// when the path exists.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Method {
    /// GET (0.01).
    Get,
    /// POST (0.02).
    Post,
    /// PUT (0.03).
    Put,
    /// DELETE (0.04).
    Delete,
    /// FETCH (0.05).
    Fetch,
    /// PATCH (0.06).
    Patch,
    /// iPATCH (0.07).
    IPatch,
}

impl Method {
    /// Known request method for `code`, if any.
    #[must_use]
    pub const fn from_code(code: Code) -> Option<Self> {
        match code {
            Code::GET => Some(Self::Get),
            Code::POST => Some(Self::Post),
            Code::PUT => Some(Self::Put),
            Code::DELETE => Some(Self::Delete),
            Code::FETCH => Some(Self::Fetch),
            Code::PATCH => Some(Self::Patch),
            Code::IPATCH => Some(Self::IPatch),
            _ => None,
        }
    }

    /// Wire code for this method.
    #[must_use]
    pub const fn code(self) -> Code {
        match self {
            Self::Get => Code::GET,
            Self::Post => Code::POST,
            Self::Put => Code::PUT,
            Self::Delete => Code::DELETE,
            Self::Fetch => Code::FETCH,
            Self::Patch => Code::PATCH,
            Self::IPatch => Code::IPATCH,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Get => 0,
            Self::Post => 1,
            Self::Put => 2,
            Self::Delete => 3,
            Self::Fetch => 4,
            Self::Patch => 5,
            Self::IPatch => 6,
        }
    }
}
