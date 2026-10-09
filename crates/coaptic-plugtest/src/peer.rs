//! Peer adapter: start/stop a server, send a client request, expose the local UDP addr.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use coaptic::message::{Code, Type};

use crate::pcap::Capture;

/// Observe-notify mailbox shared with a background server thread.
pub type NotifyMailbox = Arc<Mutex<Option<(Vec<String>, Vec<u8>)>>>;

/// How a peer is used in a TD run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// This peer is the CoAP server.
    Server,
    /// This peer is the CoAP client.
    Client,
}

/// One client request the runner asks a peer to send.
#[derive(Clone, Debug)]
pub struct ClientRequest {
    /// CON / NON / empty CON (ping).
    pub ty: Type,
    /// Request code (`GET` / `PUT` / …) or [`Code::EMPTY`] for ping.
    pub code: Code,
    /// Uri-Path segments.
    pub path: Vec<String>,
    /// Uri-Query values.
    pub query: Vec<String>,
    /// Request payload.
    pub payload: Vec<u8>,
    /// Content-Format option, if any.
    pub content_format: Option<u16>,
    /// Accept option, if any.
    pub accept: Option<u16>,
    /// ETag options.
    pub etag: Vec<Vec<u8>>,
    /// If-Match options.
    pub if_match: Vec<Vec<u8>>,
    /// If-None-Match.
    pub if_none_match: bool,
    /// Observe value (`0` register, `1` deregister).
    pub observe: Option<u32>,
    /// Block2 NUM/M/SZX when the client wants early negotiation.
    pub block2: Option<(u32, bool, u16)>,
    /// Token length hint (`None` = peer default). `Some(0)` is empty token.
    pub token_len: Option<usize>,
    /// How long to wait for a response.
    pub timeout: Duration,
}

impl ClientRequest {
    /// CON GET `path`.
    #[must_use]
    pub fn get(path: &[&str]) -> Self {
        Self {
            ty: Type::Confirmable,
            code: Code::GET,
            path: path.iter().map(|s| (*s).to_owned()).collect(),
            query: Vec::new(),
            payload: Vec::new(),
            content_format: None,
            accept: None,
            etag: Vec::new(),
            if_match: Vec::new(),
            if_none_match: false,
            observe: None,
            block2: None,
            token_len: None,
            timeout: Duration::from_millis(1500),
        }
    }

    /// CON request with `code` and `path`.
    #[must_use]
    pub fn request(code: Code, path: &[&str]) -> Self {
        let mut req = Self::get(path);
        req.code = code;
        req
    }

    /// Empty CON ping (RFC 7252).
    #[must_use]
    pub fn ping() -> Self {
        Self {
            ty: Type::Confirmable,
            code: Code::EMPTY,
            path: Vec::new(),
            query: Vec::new(),
            payload: Vec::new(),
            content_format: None,
            accept: None,
            etag: Vec::new(),
            if_match: Vec::new(),
            if_none_match: false,
            observe: None,
            block2: None,
            token_len: Some(0),
            timeout: Duration::from_millis(1500),
        }
    }
}

/// One response (or empty RST/ACK) a client peer collected.
#[derive(Clone, Debug)]
pub struct ClientResponse {
    /// Message type.
    pub ty: Type,
    /// Response code (0.00 for empty ACK/RST).
    pub code: Code,
    /// Payload of this datagram (not an assembled Block2 body).
    pub payload: Vec<u8>,
    /// Assembled Block2 body when the client collected one.
    pub body: Option<Vec<u8>>,
    /// Content-Format, if present.
    pub content_format: Option<u16>,
    /// Observe sequence, if present.
    pub observe: Option<u32>,
    /// ETag values.
    pub etag: Vec<Vec<u8>>,
    /// Location-Path segments.
    pub location_path: Vec<String>,
    /// Location-Query values.
    pub location_query: Vec<String>,
    /// Whether this was an empty RST (ping).
    pub rst: bool,
}

/// Failure of a peer operation.
#[derive(Debug)]
pub struct PeerError(pub String);

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PeerError {}

impl From<String> for PeerError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for PeerError {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// A CoAP implementation the harness can drive.
///
/// New libraries implement this trait (see [`crate::coap_rs::CoapRsPeer`]
/// for the first external backend).
pub trait Peer {
    /// Stable name for logs and pcap comments (`coaptic`, `coap-rs`).
    fn name(&self) -> &'static str;

    /// Bind a server for the plugtest site. Returns the local UDP address.
    fn start_server(&mut self) -> Result<SocketAddr, PeerError>;

    /// Stop the server and join background work.
    fn stop_server(&mut self);

    /// Send `req` to `dest` and wait for a response (or handshake error).
    fn send_request(
        &mut self,
        dest: SocketAddr,
        req: &ClientRequest,
    ) -> Result<ClientResponse, PeerError>;

    /// Drive a poll loop (`now_ms` is the caller clock). No-op for async peers.
    fn poll(&mut self, now_ms: u64) -> Result<(), PeerError>;

    /// Local UDP address of the last started server or client socket.
    fn local_addr(&self) -> Option<SocketAddr>;

    /// Take captured datagrams (wire UDP and/or decrypted CoAP).
    fn take_capture(&mut self) -> Capture;

    /// Register Observe and return the first notification, keeping the client up.
    fn begin_observe(
        &mut self,
        dest: SocketAddr,
        req: &ClientRequest,
    ) -> Result<ClientResponse, PeerError> {
        let _ = (dest, req);
        Err(PeerError("observe collect not supported".into()))
    }

    /// Next notification on the client started by [`Self::begin_observe`].
    fn take_notification(&mut self, timeout: Duration) -> Result<ClientResponse, PeerError> {
        let _ = timeout;
        Err(PeerError("observe collect not supported".into()))
    }

    /// Ask a running server to emit an Observe notification for `path`.
    fn notify(&mut self, path: &[&str], payload: &[u8]) -> Result<(), PeerError> {
        let _ = (path, payload);
        Err(PeerError("notify not supported".into()))
    }

    /// Whether this peer can terminate DTLS (feature `dtls`).
    fn supports_dtls(&self) -> bool {
        false
    }
}
