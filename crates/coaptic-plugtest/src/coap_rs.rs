//! [`CoapRsPeer`]: first external backend (`coap` / coap-rs on crates.io).

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use coap::Server;
use coap::client::{ObserveMessage, UdpCoAPClient};
use coap::request::RequestBuilder;
use coap::server::{Listener, Responder, TransportRequestSender};
use coap_lite::{
    CoapOption, CoapRequest, ContentFormat as LiteCf, MessageClass, MessageType as LiteType,
    RequestType, ResponseType,
};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

use crate::pcap::Capture;
use crate::peer::{ClientRequest, ClientResponse, Peer, PeerError};
use crate::site;
use coaptic::message::{Code, Type};

/// coap-rs backend (tokio server + [`UdpCoAPClient`]).
pub struct CoapRsPeer {
    rt: Runtime,
    capture: Capture,
    stop: Option<oneshot::Sender<()>>,
    addr: Option<SocketAddr>,
    notify: crate::peer::NotifyMailbox,
    observe: Option<ObserveHold>,
}

const OBSERVE_QUEUE: usize = 8;
const OBSERVE_WIRE_LIMIT: usize = 2048;

struct ObserveHold {
    notifications: std::sync::mpsc::Receiver<Result<ClientResponse, PeerError>>,
    failed: Arc<AtomicBool>,
    cancel: Option<oneshot::Sender<ObserveMessage>>,
}

impl ObserveHold {
    fn receive(&self, timeout: Duration) -> Result<ClientResponse, PeerError> {
        if self.failed.load(Ordering::Acquire) {
            return Err("observe notification queue or wire limit exceeded".into());
        }
        let response = self.notifications.recv_timeout(timeout);
        if self.failed.load(Ordering::Acquire) {
            return Err("observe notification queue or wire limit exceeded".into());
        }
        response.map_err(|error| PeerError(error.to_string()))?
    }
}

impl Drop for ObserveHold {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(ObserveMessage::Terminate);
        }
    }
}

fn queue_notification(
    sender: &std::sync::mpsc::SyncSender<Result<ClientResponse, PeerError>>,
    failed: &AtomicBool,
    packet: std::io::Result<coap_lite::Packet>,
) {
    if failed.load(Ordering::Acquire) {
        return;
    }
    let response = match packet {
        Ok(packet) => {
            if packet.to_bytes_with_limit(OBSERVE_WIRE_LIMIT).is_err() {
                failed.store(true, Ordering::Release);
                return;
            }
            Ok(from_lite(&packet))
        }
        Err(error) => Err(PeerError(error.to_string())),
    };
    if sender.try_send(response).is_err() {
        failed.store(true, Ordering::Release);
    }
}

impl Default for CoapRsPeer {
    fn default() -> Self {
        Self::new()
    }
}

impl CoapRsPeer {
    /// New peer on a current-thread-friendly multi-thread runtime.
    #[must_use]
    pub fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name("coap-rs-plugtest")
            .build()
            .expect("tokio runtime");
        Self {
            rt,
            capture: Capture::new(),
            stop: None,
            addr: None,
            notify: Arc::new(Mutex::new(None)),
            observe: None,
        }
    }
}

impl Peer for CoapRsPeer {
    fn name(&self) -> &'static str {
        "coap-rs"
    }

    fn start_server(&mut self) -> Result<SocketAddr, PeerError> {
        self.stop_server();
        site::reset();
        let (tx, rx) = oneshot::channel();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let notify = Arc::clone(&self.notify);
        self.rt.spawn(async move {
            let listener = match SeparateListener::bind("127.0.0.1:0").await {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!("coap-rs bind: {e}");
                    return;
                }
            };
            let Ok(addr) = listener.local_addr() else {
                return;
            };
            let _ = addr_tx.send(addr);
            let mut server = Server::from_listeners(vec![Box::new(listener)]);
            // Built-in observe returns 4.04 unless the resource was PUTted first.
            // Plugtest /obs is GET-only; the handler owns Observe.
            server.automatic_observe_handling(true).await;
            let run = server.run(move |req| {
                let n = Arc::clone(&notify);
                async move { handle_request(req, &n) }
            });
            tokio::select! {
                _ = run => {}
                _ = rx => {}
            }
        });
        let addr = addr_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|e| e.to_string())?;
        // Let the listen task enter recv before the first client datagram.
        std::thread::sleep(Duration::from_millis(40));
        self.stop = Some(tx);
        self.addr = Some(addr);
        Ok(addr)
    }

    fn stop_server(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        self.addr = None;
    }

    fn send_request(
        &mut self,
        dest: SocketAddr,
        req: &ClientRequest,
    ) -> Result<ClientResponse, PeerError> {
        if req.code == Code::EMPTY {
            return raw_ping(dest, req.timeout, &self.capture);
        }
        let dest_s = dest.to_string();
        let built = build_lite_request(req, &dest_s)?;
        let timeout = req.timeout;
        let resp = self
            .rt
            .block_on(async move {
                let client = UdpCoAPClient::new(&dest_s).await?;
                tokio::time::timeout(timeout, client.send(built))
                    .await
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "client"))?
            })
            .map_err(|e| PeerError(e.to_string()))?;
        Ok(from_lite(&resp.message))
    }

    fn poll(&mut self, _now_ms: u64) -> Result<(), PeerError> {
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.addr
    }

    fn begin_observe(
        &mut self,
        dest: SocketAddr,
        req: &ClientRequest,
    ) -> Result<ClientResponse, PeerError> {
        self.observe = None;
        let destination = dest.to_string();
        let registration = build_lite_request(req, &destination)?;
        let (sender, notifications) = std::sync::mpsc::sync_channel(OBSERVE_QUEUE);
        let failed = Arc::new(AtomicBool::new(false));
        let callback_failed = Arc::clone(&failed);
        let timeout = req.timeout;
        let cancel = self
            .rt
            .block_on(async move {
                let mut client = UdpCoAPClient::new(&destination).await?;
                client.set_receive_timeout(timeout);
                client
                    .observe_with(registration, move |response| {
                        queue_notification(&sender, &callback_failed, response);
                    })
                    .await
            })
            .map_err(|error| PeerError(error.to_string()))?;
        self.observe = Some(ObserveHold {
            notifications,
            failed,
            cancel: Some(cancel),
        });
        let response = self.take_notification(req.timeout);
        if response.is_err() {
            self.observe = None;
        }
        response
    }

    fn take_notification(&mut self, timeout: Duration) -> Result<ClientResponse, PeerError> {
        self.observe
            .as_ref()
            .ok_or("no observe client")?
            .receive(timeout)
    }

    fn take_capture(&mut self) -> Capture {
        self.capture.clone()
    }

    fn notify(&mut self, path: &[&str], payload: &[u8]) -> Result<(), PeerError> {
        *self.notify.lock().expect("n") = Some((
            path.iter().map(|s| (*s).to_owned()).collect(),
            payload.to_vec(),
        ));
        Ok(())
    }

    fn supports_dtls(&self) -> bool {
        cfg!(feature = "dtls")
    }
}

impl Drop for CoapRsPeer {
    fn drop(&mut self) {
        self.observe = None;
        self.stop_server();
    }
}

fn handle_request(
    mut request: Box<CoapRequest<SocketAddr>>,
    _notify: &crate::peer::NotifyMailbox,
) -> Box<CoapRequest<SocketAddr>> {
    // RFC 7252 ping: empty CON → empty RST.
    if request.message.header.code == MessageClass::Empty
        && request.message.header.get_type() == LiteType::Confirmable
    {
        if let Some(resp) = request.response.as_mut() {
            resp.message.header.set_type(LiteType::Reset);
            resp.message.header.code = MessageClass::Empty;
            resp.message.payload.clear();
        }
        return request;
    }
    let path = request.get_path();
    let method = *request.get_method();
    let query = request
        .message
        .get_option(CoapOption::UriQuery)
        .map(|vals| {
            vals.iter()
                .filter_map(|v| std::str::from_utf8(v).ok().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if let Some(resp) = request.response.as_mut() {
        match (method, path.as_str()) {
            (RequestType::Get, "test") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::TEST_BODY.to_vec();
                resp.message.set_content_format(LiteCf::TextPlain);
            }
            (RequestType::Put, "test") => {
                resp.set_status(ResponseType::Changed);
            }
            (RequestType::Post, "test") => {
                resp.set_status(ResponseType::Created);
                resp.message
                    .add_option(CoapOption::LocationPath, b"location1".to_vec());
                resp.message
                    .add_option(CoapOption::LocationPath, b"location2".to_vec());
                resp.message
                    .add_option(CoapOption::LocationQuery, b"first=1".to_vec());
                resp.message
                    .add_option(CoapOption::LocationQuery, b"second=2".to_vec());
            }
            (RequestType::Delete, "test") => {
                resp.set_status(ResponseType::Deleted);
            }
            (RequestType::Get, "separate") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::SEP_BODY.to_vec();
                resp.message.set_content_format(LiteCf::TextPlain);
                let req_ty = request.message.header.get_type();
                let req_mid = request.message.header.message_id;
                let fresh = next_server_mid(req_mid);
                match req_ty {
                    LiteType::Confirmable => {
                        resp.message.header.set_type(LiteType::Confirmable);
                        resp.message.header.message_id = fresh;
                    }
                    LiteType::NonConfirmable => {
                        resp.message.header.set_type(LiteType::NonConfirmable);
                        resp.message.header.message_id = fresh;
                    }
                    LiteType::Acknowledgement | LiteType::Reset => {}
                }
            }
            (RequestType::Get, "query") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::TEST_BODY.to_vec();
                resp.message.set_content_format(LiteCf::TextPlain);
            }
            (RequestType::Get, "seg1/seg2/seg3") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::TEST_BODY.to_vec();
                resp.message.set_content_format(LiteCf::TextPlain);
            }
            (RequestType::Get, "validate") => {
                let etags = request
                    .message
                    .get_option(CoapOption::ETag)
                    .map(|v| v.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                if etags.iter().any(|t| t.as_slice() == b"etag1") {
                    resp.set_status(ResponseType::Valid);
                    resp.message.add_option(CoapOption::ETag, b"etag1".to_vec());
                } else {
                    resp.set_status(ResponseType::Content);
                    resp.message.payload = site::TEST_BODY.to_vec();
                    resp.message.set_content_format(LiteCf::TextPlain);
                    resp.message.add_option(CoapOption::ETag, b"etag1".to_vec());
                }
            }
            (RequestType::Put, "validate") => {
                let if_match = request.message.get_option(CoapOption::IfMatch);
                let if_none = request.message.get_option(CoapOption::IfNoneMatch);
                if if_none.is_some() {
                    resp.set_status(ResponseType::PreconditionFailed);
                } else if let Some(tags) = if_match {
                    if tags.iter().any(|t| t.as_slice() == b"etag1") {
                        resp.set_status(ResponseType::Changed);
                    } else {
                        resp.set_status(ResponseType::PreconditionFailed);
                    }
                } else {
                    resp.set_status(ResponseType::Changed);
                }
            }
            (RequestType::Get, "large") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::large_body();
                resp.message.set_content_format(LiteCf::TextPlain);
            }
            (RequestType::Put, "large-update") => {
                site::set_large_update(&request.message.payload);
                resp.set_status(ResponseType::Changed);
            }
            (RequestType::Post, "large-create") => {
                resp.set_status(ResponseType::Created);
                resp.message
                    .add_option(CoapOption::LocationPath, b"large-create".to_vec());
                resp.message
                    .add_option(CoapOption::LocationPath, b"ps".to_vec());
            }
            (RequestType::Post, "large-post") => {
                resp.set_status(ResponseType::Changed);
                resp.message.payload = site::large_body();
                resp.message.set_content_format(LiteCf::TextPlain);
            }
            (RequestType::Get, "obs" | "obs-non") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::OBS_BODY.to_vec();
                resp.message.set_content_format(LiteCf::TextPlain);
                resp.message.set_observe_value(0);
            }
            (RequestType::Delete, "obs") => {
                resp.set_status(ResponseType::Deleted);
            }
            (RequestType::Get, ".well-known/core") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::filter_catalog(&query).into_bytes();
                resp.message
                    .set_content_format(LiteCf::try_from(40).unwrap_or(LiteCf::TextPlain));
            }
            (RequestType::Get, "path") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::PATH_LINKS.as_bytes().to_vec();
                resp.message
                    .set_content_format(LiteCf::try_from(40).unwrap_or(LiteCf::TextPlain));
            }
            (RequestType::Get, "path/sub1") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::PATH_SUB1.to_vec();
            }
            (RequestType::Get, "path/sub2") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = b"/path/sub2".to_vec();
            }
            (RequestType::Get, "secure") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = site::SECURE_BODY.to_vec();
                resp.message.set_content_format(LiteCf::TextPlain);
            }
            (RequestType::Get, "link1" | "link2" | "link3") => {
                resp.set_status(ResponseType::Content);
                resp.message.payload = b"link1".to_vec();
            }
            _ => {
                resp.set_status(ResponseType::NotFound);
            }
        }
    }
    request
}

fn build_lite_request(
    req: &ClientRequest,
    dest: &str,
) -> Result<CoapRequest<SocketAddr>, PeerError> {
    let method = match req.code {
        Code::GET => RequestType::Get,
        Code::POST => RequestType::Post,
        Code::PUT => RequestType::Put,
        Code::DELETE => RequestType::Delete,
        other => return Err(PeerError(format!("coap-rs: unsupported method {other}"))),
    };
    let path = if req.path.is_empty() {
        String::new()
    } else {
        format!("/{}", req.path.join("/"))
    };
    let payload = if req.payload.is_empty() {
        None
    } else {
        Some(req.payload.clone())
    };
    let query = req
        .query
        .iter()
        .map(|q| q.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let mut options = Vec::new();
    if let Some(cf) = req.content_format {
        options.push((CoapOption::ContentFormat, cf.to_be_bytes().to_vec()));
    }
    if let Some(acc) = req.accept {
        options.push((CoapOption::Accept, acc.to_be_bytes().to_vec()));
    }
    for t in &req.etag {
        options.push((CoapOption::ETag, t.clone()));
    }
    for t in &req.if_match {
        options.push((CoapOption::IfMatch, t.clone()));
    }
    if req.if_none_match {
        options.push((CoapOption::IfNoneMatch, Vec::new()));
    }
    if let Some(obs) = req.observe {
        options.push((CoapOption::Observe, encode_u32(obs)));
    }
    if let Some((num, more, size)) = req.block2 {
        let v = coaptic::message::BlockValue::from_size(num, more, size)
            .map_err(|e| format!("block2: {e:?}"))?;
        options.push((CoapOption::Block2, v.encode().as_bytes().to_vec()));
    }
    let token = match req.token_len {
        Some(0) => Some(Vec::new()),
        Some(n) => Some((0..n).map(|i| 0xC0u8.wrapping_add(i as u8)).collect()),
        None => None,
    };
    Ok(
        RequestBuilder::request_path(&path, method, payload, query, Some(dest.to_owned()))
            .confirmable(req.ty == Type::Confirmable)
            .token(token)
            .options(options)
            .build(),
    )
}

fn encode_u32(n: u32) -> Vec<u8> {
    let b = n.to_be_bytes();
    let start = b.iter().position(|x| *x != 0).unwrap_or(3);
    b[start..].to_vec()
}

fn from_lite(msg: &coap_lite::Packet) -> ClientResponse {
    let code = Code::from_raw(u8::from(msg.header.code));
    let ty = match msg.header.get_type() {
        coap_lite::MessageType::Confirmable => Type::Confirmable,
        coap_lite::MessageType::NonConfirmable => Type::NonConfirmable,
        coap_lite::MessageType::Acknowledgement => Type::Acknowledgement,
        coap_lite::MessageType::Reset => Type::Reset,
    };
    let content_format = msg
        .get_option(CoapOption::ContentFormat)
        .and_then(|v| v.front())
        .map(|b| u16::try_from(uint_from_bytes(b)).unwrap_or(u16::MAX));
    let observe = msg
        .get_option(CoapOption::Observe)
        .and_then(|v| v.front())
        .map(|b| uint_from_bytes(b));
    let etag = msg
        .get_option(CoapOption::ETag)
        .map(|v| v.iter().cloned().collect())
        .unwrap_or_default();
    let location_path = opt_strings(msg, CoapOption::LocationPath);
    let location_query = opt_strings(msg, CoapOption::LocationQuery);
    ClientResponse {
        ty,
        code,
        payload: msg.payload.clone(),
        body: None,
        content_format,
        observe,
        etag,
        location_path,
        location_query,
        rst: ty == Type::Reset && code == Code::EMPTY,
    }
}

fn opt_strings(msg: &coap_lite::Packet, opt: CoapOption) -> Vec<String> {
    msg.get_option(opt)
        .map(|v| {
            v.iter()
                .filter_map(|b| std::str::from_utf8(b).ok().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn uint_from_bytes(b: &[u8]) -> u32 {
    let mut n = 0u32;
    for x in b {
        n = n.saturating_mul(256).saturating_add(u32::from(*x));
    }
    n
}

fn raw_ping(
    dest: SocketAddr,
    timeout: Duration,
    capture: &Capture,
) -> Result<ClientResponse, PeerError> {
    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    let local = sock.local_addr().map_err(|e| e.to_string())?;
    // Empty CON, MID 0x5049.
    let wire = [0x40, 0x00, 0x50, 0x49];
    sock.send_to(&wire, dest).map_err(|e| e.to_string())?;
    capture.push(local, dest, &wire, false);
    let mut buf = [0u8; 64];
    let (n, from) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
    capture.push(from, local, &buf[..n], false);
    let parsed = coaptic::message::decode(&buf[..n]).map_err(|e| format!("{e:?}"))?;
    if parsed.is_empty_rst() {
        Ok(ClientResponse {
            ty: Type::Reset,
            code: Code::EMPTY,
            payload: Vec::new(),
            body: None,
            content_format: None,
            observe: None,
            etag: Vec::new(),
            location_path: Vec::new(),
            location_query: Vec::new(),
            rst: true,
        })
    } else {
        Err(PeerError(format!(
            "ping expected RST, got {} {}",
            parsed.ty(),
            parsed.code()
        )))
    }
}

/// Silence unused-import noise when `ContentFormat` try_from needs a path.
#[allow(dead_code)]
static _KEEP: AtomicBool = AtomicBool::new(false);

static SERVER_MID: AtomicU16 = AtomicU16::new(0x4000);

fn next_server_mid(avoid: u16) -> u16 {
    let mid = SERVER_MID.fetch_add(1, Ordering::Relaxed);
    if mid == avoid {
        SERVER_MID.fetch_add(1, Ordering::Relaxed)
    } else {
        mid
    }
}

fn empty_ack_wire(mid: u16) -> [u8; 4] {
    let bytes = mid.to_be_bytes();
    [0x60, 0x00, bytes[0], bytes[1]]
}

fn uri_path(packet: &coap_lite::Packet) -> String {
    packet
        .get_option(CoapOption::UriPath)
        .map(|vals| {
            vals.iter()
                .filter_map(|v| std::str::from_utf8(v).ok())
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default()
}

/// CON GET `/separate` → request Message ID, so the listener can empty-ACK
/// before the handler's separate CON.
fn separate_con_mid(bytes: &[u8]) -> Option<u16> {
    let packet = coap_lite::Packet::from_bytes(bytes).ok()?;
    if packet.header.get_type() != LiteType::Confirmable {
        return None;
    }
    if packet.header.code != MessageClass::Request(RequestType::Get) {
        return None;
    }
    (uri_path(&packet) == "separate").then_some(packet.header.message_id)
}

struct SeparateListener {
    socket: tokio::net::UdpSocket,
    response_rx: tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    response_tx: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
}

impl SeparateListener {
    async fn bind(addr: &str) -> std::io::Result<Self> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        let (response_tx, response_rx) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            socket,
            response_rx,
            response_tx,
        })
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

struct SeparateResponder {
    address: SocketAddr,
    tx: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
}

#[async_trait]
impl Responder for SeparateResponder {
    async fn respond(&self, response: Vec<u8>) {
        let _ = self.tx.send((response, self.address));
    }

    fn address(&self) -> SocketAddr {
        self.address
    }
}

#[async_trait]
impl Listener for SeparateListener {
    async fn listen(
        mut self: Box<Self>,
        sender: TransportRequestSender,
    ) -> std::io::Result<tokio::task::JoinHandle<std::io::Result<()>>> {
        Ok(tokio::spawn(async move { self.receive_loop(sender).await }))
    }
}

impl SeparateListener {
    async fn receive_loop(&mut self, sender: TransportRequestSender) -> std::io::Result<()> {
        let mut buf = vec![0u8; 2048];
        loop {
            tokio::select! {
                message = self.socket.recv_from(&mut buf) => {
                    let (n, from) = message?;
                    let bytes = buf[..n].to_vec();
                    if let Some(mid) = separate_con_mid(&bytes) {
                        self.socket.send_to(&empty_ack_wire(mid), from).await?;
                    }
                    sender
                        .send((
                            bytes,
                            Arc::new(SeparateResponder {
                                address: from,
                                tx: self.response_tx.clone(),
                            }),
                        ))
                        .map_err(|_| std::io::Error::other("server channel error"))?;
                }
                response = self.response_rx.recv() => {
                    let Some((bytes, to)) = response else {
                        return Ok(());
                    };
                    self.socket.send_to(&bytes, to).await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod observe_tests {
    use super::*;

    fn packet(payload: usize) -> coap_lite::Packet {
        let mut packet = coap_lite::Packet::new();
        packet.header.set_type(LiteType::NonConfirmable);
        packet.header.code = MessageClass::Response(ResponseType::Content);
        packet.set_token(vec![1]);
        packet.payload = vec![7; payload];
        packet
    }

    fn queue() -> (
        std::sync::mpsc::SyncSender<Result<ClientResponse, PeerError>>,
        ObserveHold,
    ) {
        let (sender, notifications) = std::sync::mpsc::sync_channel(OBSERVE_QUEUE);
        (
            sender,
            ObserveHold {
                notifications,
                failed: Arc::new(AtomicBool::new(false)),
                cancel: None,
            },
        )
    }

    #[test]
    fn complete_notification_boundary_and_refusal_after_overflow() {
        let (sender, hold) = queue();
        let complete = packet(OBSERVE_WIRE_LIMIT - 6);
        assert_eq!(
            complete
                .to_bytes_with_limit(OBSERVE_WIRE_LIMIT)
                .unwrap()
                .len(),
            OBSERVE_WIRE_LIMIT
        );
        queue_notification(&sender, &hold.failed, Ok(complete));
        assert_eq!(
            hold.receive(Duration::ZERO).unwrap().payload,
            vec![7; OBSERVE_WIRE_LIMIT - 6]
        );
        for _ in 0..OBSERVE_QUEUE {
            queue_notification(&sender, &hold.failed, Ok(packet(2)));
        }
        queue_notification(&sender, &hold.failed, Ok(packet(2)));
        assert!(hold.receive(Duration::ZERO).is_err());
        assert_eq!(hold.notifications.try_iter().count(), OBSERVE_QUEUE);
        // Loss remains visible even after capacity becomes available.
        queue_notification(&sender, &hold.failed, Ok(packet(2)));
        assert!(hold.receive(Duration::ZERO).is_err());
    }

    #[test]
    fn oversized_transport_failure_empty_queue_and_drop_cancel() {
        let (sender, mut hold) = queue();
        assert!(hold.receive(Duration::ZERO).is_err());
        queue_notification(
            &sender,
            &hold.failed,
            Err(std::io::Error::other("transport failed")),
        );
        assert_eq!(
            hold.receive(Duration::ZERO).unwrap_err().0,
            "transport failed"
        );
        queue_notification(&sender, &hold.failed, Ok(packet(OBSERVE_WIRE_LIMIT - 5)));
        assert!(hold.receive(Duration::ZERO).is_err());
        let (cancel, mut receiver) = oneshot::channel();
        hold.cancel = Some(cancel);
        drop(hold);
        assert!(matches!(receiver.try_recv(), Ok(ObserveMessage::Terminate)));
        // A fresh registration owns fresh refusal state.
        let (sender, hold) = queue();
        queue_notification(&sender, &hold.failed, Ok(packet(2)));
        assert_eq!(hold.receive(Duration::ZERO).unwrap().payload, vec![7; 2]);
    }
}
