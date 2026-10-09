//! [`CoapticPeer`]: App server + App client over a capturing [`DatagramIo`].

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use coaptic::app::DEFAULT_ROUTES;
use coaptic::message::{BlockValue, Code, ContentFormat, Message, MessageId, Type, decode, encode};
use coaptic::storage::{DatagramIo, Endpoint, Engine, EngineBuilder, Memory};
use coaptic::{App, Call, Method, Response, profiles};

type ClientApp<T> = App<profiles::Default, T, DEFAULT_ROUTES, true>;

use crate::pcap::{Capture, CapturingIo, bind_loopback};
use crate::peer::{ClientRequest, ClientResponse, Peer, PeerError};
use crate::site;

/// Coaptic backend (library App/Engine; no extra runtime deps).
pub struct CoapticPeer {
    capture: Capture,
    server: Option<ServerCtl>,
    client_addr: Option<SocketAddr>,
    observe: Option<ObserveHold>,
}

struct ObserveHold {
    app: ClientApp<CapturingIo<UdpSocket>>,
    call: Call,
    origin: Instant,
}

struct ServerCtl {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    notify: crate::peer::NotifyMailbox,
    join: Option<JoinHandle<()>>,
}

impl Default for CoapticPeer {
    fn default() -> Self {
        Self::new()
    }
}

impl CoapticPeer {
    /// New peer with a fresh capture log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            capture: Capture::new(),
            server: None,
            client_addr: None,
            observe: None,
        }
    }
}

impl Peer for CoapticPeer {
    fn name(&self) -> &'static str {
        "coaptic"
    }

    fn start_server(&mut self) -> Result<SocketAddr, PeerError> {
        self.stop_server();
        site::reset();
        let (sock, addr) = bind_loopback().map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(Mutex::new(None));
        let capture = self.capture.clone();
        let stop_t = Arc::clone(&stop);
        let notify_t = Arc::clone(&notify);
        let join = thread::Builder::new()
            .name("coaptic-plugtest-server".into())
            .spawn(move || server_loop(sock, addr, capture, stop_t, notify_t))
            .map_err(|e| e.to_string())?;
        // Let the thread bind the App.
        thread::sleep(Duration::from_millis(20));
        self.server = Some(ServerCtl {
            addr,
            stop,
            notify,
            join: Some(join),
        });
        Ok(addr)
    }

    fn stop_server(&mut self) {
        if let Some(mut srv) = self.server.take() {
            srv.stop.store(true, Ordering::SeqCst);
            if let Some(join) = srv.join.take() {
                let _ = join.join();
            }
        }
    }

    fn send_request(
        &mut self,
        dest: SocketAddr,
        req: &ClientRequest,
    ) -> Result<ClientResponse, PeerError> {
        self.observe = None;
        let (sock, local) = bind_loopback().map_err(|e| e.to_string())?;
        self.client_addr = Some(local);
        let io = CapturingIo::new(sock, local, self.capture.clone());
        app_exchange(io, dest, req)
    }

    fn begin_observe(
        &mut self,
        dest: SocketAddr,
        req: &ClientRequest,
    ) -> Result<ClientResponse, PeerError> {
        self.observe = None;
        let (sock, local) = bind_loopback().map_err(|e| e.to_string())?;
        self.client_addr = Some(local);
        let io = CapturingIo::new(sock, local, self.capture.clone());
        let (mut app, call) = start_client(io, dest, req)?;
        let origin = Instant::now();
        let response = wait_response(&mut app, call, origin, req.timeout)?;
        self.observe = Some(ObserveHold { app, call, origin });
        Ok(response)
    }

    fn take_notification(&mut self, timeout: Duration) -> Result<ClientResponse, PeerError> {
        let hold = self.observe.as_mut().ok_or("no observe client")?;
        wait_response(&mut hold.app, hold.call, hold.origin, timeout)
    }

    fn poll(&mut self, _now_ms: u64) -> Result<(), PeerError> {
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.server.as_ref().map(|s| s.addr).or(self.client_addr)
    }

    fn take_capture(&mut self) -> Capture {
        self.capture.clone()
    }

    fn notify(&mut self, path: &[&str], payload: &[u8]) -> Result<(), PeerError> {
        let srv = self.server.as_ref().ok_or("no server")?;
        *srv.notify.lock().expect("notify") = Some((
            path.iter().map(|s| (*s).to_owned()).collect(),
            payload.to_vec(),
        ));
        Ok(())
    }

    fn supports_dtls(&self) -> bool {
        cfg!(feature = "dtls")
    }
}

impl Drop for CoapticPeer {
    fn drop(&mut self) {
        self.stop_server();
    }
}

fn server_loop(
    sock: UdpSocket,
    addr: SocketAddr,
    capture: Capture,
    stop: Arc<AtomicBool>,
    notify: crate::peer::NotifyMailbox,
) {
    let io = CapturingIo::new(sock, addr, capture);
    let mut app = bind_site(io);
    let origin = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        let now = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let _ = app.poll(now);
        if let Some((path, payload)) = notify.lock().expect("n").take() {
            let segs: Vec<&str> = path.iter().map(String::as_str).collect();
            let body: &'static [u8] = if payload == site::OBS_BODY_2 {
                site::OBS_BODY_2
            } else if payload == site::OBS_BODY {
                site::OBS_BODY
            } else {
                site::OBS_BODY_2
            };
            let _ = app.notify(
                now,
                &segs,
                Response::content(body).content_format(ContentFormat::TEXT_PLAIN),
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// Bind the plugtest site onto `io` (plaintext UDP or a harness DTLS adapter).
pub(crate) fn bind_site<T: DatagramIo>(io: T) -> App<profiles::Default, T, 24, true>
where
    T::Error: std::fmt::Debug,
{
    let mut b = App::profile::<profiles::Default>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .routes::<24>();
    for (path, router) in site::routers() {
        b = b.route(path, router);
    }
    for (path, router) in site::extra_routers() {
        b = b.route(path, router);
    }
    b.allow_plaintext().bind(io).expect("bind plugtest App")
}

/// Drive one client request through [`App::get`] / [`App::put`] / observe,
/// then [`App::poll`] + [`App::take_response`]. Same path as DTLS GET `/secure`.
///
/// Empty CON (CORE_31 ping) is not an App method; it still uses the socket
/// so the server App can RST.
pub(crate) fn app_exchange<T: DatagramIo<Error = std::io::Error>>(
    io: T,
    dest: SocketAddr,
    req: &ClientRequest,
) -> Result<ClientResponse, PeerError> {
    let dest_ep = Endpoint::from(dest);
    if req.code == Code::EMPTY {
        let mut io = io;
        return client_ping(&mut io, dest_ep, req.timeout);
    }
    let (mut app, call) = start_client(io, dest, req)?;
    let origin = Instant::now();
    wait_response(&mut app, call, origin, req.timeout)
}

fn start_client<T: DatagramIo<Error = std::io::Error>>(
    io: T,
    dest: SocketAddr,
    req: &ClientRequest,
) -> Result<(ClientApp<T>, Call), PeerError> {
    let dest_ep = Endpoint::from(dest);
    let mut app = App::profile::<profiles::Default>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .allow_plaintext()
        .bind(io)
        .map_err(|e| format!("bind: {e}"))?;
    let path = intern_path(&req.path)?;
    let method = Method::from_code(req.code).ok_or_else(|| {
        PeerError(format!(
            "App client has no method for {} {}",
            req.code,
            req.path.join("/")
        ))
    })?;
    let mut outgoing = app.request(method, path).to(dest_ep);
    if req.ty == Type::NonConfirmable {
        outgoing = outgoing.non();
    }
    if !req.payload.is_empty() {
        outgoing = outgoing.payload(&req.payload);
    }
    if let Some(cf) = req.content_format {
        outgoing = outgoing.content_format(ContentFormat::new(cf));
    }
    if let Some(acc) = req.accept {
        outgoing = outgoing.accept(ContentFormat::new(acc));
    }
    if let Some(tag) = req.etag.first() {
        outgoing = outgoing.etag(tag);
    }
    if let Some(tag) = req.if_match.first() {
        outgoing = outgoing.if_match(tag);
    }
    if req.if_none_match {
        outgoing = outgoing.if_none_match();
    }
    for q in &req.query {
        outgoing = outgoing.query(q);
    }
    match req.observe {
        Some(0) => outgoing = outgoing.observe(),
        Some(1) => outgoing = outgoing.deregister(),
        _ => {}
    }
    if let Some((num, more, size)) = req.block2 {
        let block = BlockValue::from_size(num, more, size).map_err(|e| format!("block2: {e:?}"))?;
        outgoing = outgoing.block2(block);
    }
    let call = outgoing
        .send(1)
        .map_err(|e| format!("send {} {}: {e}", req.code, req.path.join("/")))?;
    Ok((app, call))
}

fn wait_response<T: DatagramIo<Error = std::io::Error>>(
    app: &mut ClientApp<T>,
    call: Call,
    origin: Instant,
    timeout: Duration,
) -> Result<ClientResponse, PeerError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let now = u64::try_from(origin.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        app.poll(now).map_err(|e| format!("poll: {e}"))?;
        if let Some(resp) = app.take_response(call) {
            return Ok(view_app(resp.map_err(|e| PeerError(e.to_string()))?));
        }
        thread::sleep(Duration::from_millis(2));
    }
    let _ = call;
    Err(PeerError("timeout waiting for response".into()))
}

fn intern_path(path: &[String]) -> Result<&'static str, PeerError> {
    let segs: Vec<&str> = path.iter().map(String::as_str).collect();
    Ok(match segs.as_slice() {
        [] => "",
        ["test"] => "test",
        ["separate"] => "separate",
        ["query"] => "query",
        ["validate"] => "validate",
        ["seg1", "seg2", "seg3"] => "seg1/seg2/seg3",
        ["large"] => "large",
        ["large-update"] => "large-update",
        ["large-create"] => "large-create",
        ["large-post"] => "large-post",
        [".well-known", "core"] => ".well-known/core",
        ["path"] => "path",
        ["path", "sub1"] => "path/sub1",
        ["obs"] => "obs",
        ["obs-non"] => "obs-non",
        ["secure"] => "secure",
        other => {
            return Err(PeerError(format!(
                "unmapped client path /{}",
                other.join("/")
            )));
        }
    })
}

fn view_app(resp: Response) -> ClientResponse {
    ClientResponse {
        ty: resp.ty().unwrap_or(Type::Acknowledgement),
        code: resp.code(),
        payload: resp.payload().to_vec(),
        body: resp.body().map(|b| b.to_vec()),
        content_format: resp.format().map(ContentFormat::get),
        observe: resp.observe_seq(),
        etag: resp
            .etag_bytes()
            .map(|tag| vec![tag.to_vec()])
            .unwrap_or_default(),
        location_path: resp
            .location_paths()
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        location_query: resp
            .location_queries()
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        rst: resp.ty() == Some(Type::Reset),
    }
}

/// RFC 7252 empty CON ping. Not [`App::get`]; the server App answers RST.
fn client_ping<T: DatagramIo<Error = std::io::Error>>(
    io: &mut T,
    dest: Endpoint,
    timeout: Duration,
) -> Result<ClientResponse, PeerError> {
    let mid = MessageId::new(0x5049);
    let ping = Message::new(Type::Confirmable, Code::EMPTY, mid);
    let mut buf = [0u8; 64];
    let n = encode(&ping, &mut buf).map_err(|e| format!("encode: {e:?}"))?;
    io.send(dest, &buf[..n]).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let mut buf = [0u8; 64];
        match io.recv(&mut buf) {
            Ok(Some((n, _))) => {
                let parsed = decode(&buf[..n]).map_err(|e| format!("{e:?}"))?;
                if parsed.message_id() == mid && parsed.is_empty_rst() {
                    return Ok(ClientResponse {
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
                    });
                }
            }
            Ok(None) => thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(PeerError(e.to_string())),
        }
    }
    Err(PeerError("ping timeout (no RST)".into()))
}

/// Build a boxed Engine (used by in-crate harness tests).
#[must_use]
pub fn build_engine()
-> Box<Engine<Memory<profiles::Default, coaptic::storage::WithBodies<profiles::Default>>>> {
    Box::new(
        EngineBuilder::new()
            .profile::<profiles::Default>()
            .block_wise(true)
            .build(Memory::<profiles::Default>::with_block_wise())
            .expect("engine"),
    )
}
