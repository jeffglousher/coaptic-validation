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
    notify: NotifyMailbox,
    join: Option<JoinHandle<()>>,
}

enum NotifyCommand {
    Notification { path: Vec<String>, payload: Vec<u8>, confirmable: bool },
    UpdateObserved { body: &'static [u8] },
}
type NotifyMailbox = Arc<Mutex<Option<NotifyCommand>>>;

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
        let io = if let Some(previous) = self.observe.take() {
            previous.app.into_io()
        } else {
            let (sock, local) = bind_loopback().map_err(|e| e.to_string())?;
            self.client_addr = Some(local);
            CapturingIo::new(sock, local, self.capture.clone())
        };
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

    fn request_on_observe(
        &mut self,
        dest: SocketAddr,
        req: &ClientRequest,
    ) -> Result<ClientResponse, PeerError> {
        if req.code != Code::GET || !matches!(req.observe, None | Some(1)) {
            return Err(PeerError(
                "same-owner request must be GET or cancellation".into(),
            ));
        }
        let hold = self.observe.as_mut().ok_or("no observe client")?;
        let now = u64::try_from(hold.origin.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let call = send_client(&mut hold.app, dest, req, now, Some(hold.call))?;
        wait_response(&mut hold.app, call, hold.origin, req.timeout)
    }

    fn restart_observe_client(&mut self) -> Result<(), PeerError> {
        let previous = self.observe.take().ok_or("no observe client")?;
        let app = bind_client(previous.app.into_io())?;
        self.observe = Some(ObserveHold {
            app,
            call: previous.call,
            origin: Instant::now(),
        });
        Ok(())
    }

    fn observe_quiet_for(&mut self, duration: Duration) -> Result<(), PeerError> {
        let hold = self.observe.as_mut().ok_or("no observe client")?;
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            let now = u64::try_from(hold.origin.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            hold.app.poll(now).map_err(|e| format!("quiet poll: {e}"))?;
            if hold.app.take_response(hold.call).is_some() {
                return Err(PeerError(
                    "restarted client delivered an old observation".into(),
                ));
            }
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
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
        *srv.notify.lock().expect("notify") = Some(NotifyCommand::Notification {
            path: path.iter().map(|s| (*s).to_owned()).collect(),
            payload: payload.to_vec(),
            confirmable: false,
        });
        Ok(())
    }

    fn update_observed(&mut self, path: &[&str], payload: &[u8]) -> Result<(), PeerError> {
        if path != ["obs"] {
            return Err(PeerError("update requires /obs".into()));
        }
        let body = site::observe_update_body(payload).ok_or("unsupported bounded representation")?;
        let server = self.server.as_ref().ok_or("no server")?;
        let mut command = server.notify.lock().expect("update");
        if command.is_some() { return Err(PeerError("notification command occupied".into())); }
        *command = Some(NotifyCommand::UpdateObserved { body });
        Ok(())
    }

    fn notify_confirmable(&mut self, path: &[&str], payload: &[u8]) -> Result<(), PeerError> {
        let srv = self.server.as_ref().ok_or("no server")?;
        *srv.notify.lock().expect("notify") = Some(NotifyCommand::Notification {
            path: path.iter().map(|s| (*s).to_owned()).collect(),
            payload: payload.to_vec(),
            confirmable: true,
        });
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
    notify: NotifyMailbox,
) {
    let io = CapturingIo::new(sock, addr, capture);
    let mut app = bind_site(io);
    let origin = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        let now = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let _ = app.poll(now);
        if let Some(command) = notify.lock().expect("n").take() {
            match command {
                NotifyCommand::Notification { path, payload, confirmable } => {
                    let segs: Vec<&str> = path.iter().map(String::as_str).collect();
                    let body = site::observe_update_body(&payload).unwrap_or(site::OBS_BODY_2);
                    let response = Response::content(body).content_format(ContentFormat::TEXT_PLAIN);
                    let _ = if confirmable { app.notify_confirmable(now, &segs, response) }
                        else { app.notify(now, &segs, response) };
                }
                NotifyCommand::UpdateObserved { body } => {
                    // The GET handler and retransmission snapshot see the new
                    // representation before its notification can reach a client.
                    site::commit_observe_update(body);
                    let response = Response::content(body).content_format(ContentFormat::TEXT_PLAIN);
                    let _ = app.notify_confirmable(now, &["obs"], response);
                }
            }
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

fn bind_client<T: DatagramIo<Error = std::io::Error>>(io: T) -> Result<ClientApp<T>, PeerError> {
    App::profile::<profiles::Default>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .allow_plaintext()
        .bind(io)
        .map_err(|e| PeerError(format!("bind: {e}")))
}

fn start_client<T: DatagramIo<Error = std::io::Error>>(
    io: T,
    dest: SocketAddr,
    req: &ClientRequest,
) -> Result<(ClientApp<T>, Call), PeerError> {
    let mut app = bind_client(io)?;
    let call = send_client(&mut app, dest, req, 1, None)?;
    Ok((app, call))
}

fn send_client<T: DatagramIo<Error = std::io::Error>>(
    app: &mut ClientApp<T>,
    dest: SocketAddr,
    req: &ClientRequest,
    now: u64,
    observe_call: Option<Call>,
) -> Result<Call, PeerError> {
    let dest_ep = Endpoint::from(dest);
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
        Some(1) => {
            outgoing = if let Some(call) = observe_call {
                outgoing.deregister_call(call)
            } else {
                outgoing.deregister()
            };
        }
        _ => {}
    }
    if let Some((num, more, size)) = req.block2 {
        let block = BlockValue::from_size(num, more, size).map_err(|e| format!("block2: {e:?}"))?;
        outgoing = outgoing.block2(block);
    }
    outgoing
        .send(now)
        .map_err(|e| PeerError(format!("send {} {}: {e}", req.code, req.path.join("/"))))
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

#[cfg(test)]
mod observe_restart_tests {
    use super::*;

    #[test]
    fn wrong_endpoint_and_mid_resets_preserve_live_con_observation() {
        let _guard = crate::runner::harness_lock();
        let mut server = CoapticPeer::new();
        let dest = server.start_server().unwrap();
        let mut client = CoapticPeer::new();
        let mut request = ClientRequest::get(&["obs"]);
        request.observe = Some(0);
        assert_eq!(
            client.begin_observe(dest, &request).unwrap().payload,
            site::OBS_BODY
        );
        server
            .notify_confirmable(&["obs"], site::OBS_BODY_2)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mid = loop {
            if let Some(mid) = server.take_capture().snapshot().iter().find_map(|packet| {
                let p = decode(&packet.bytes).ok()?;
                (packet.src == dest && p.ty() == Type::Confirmable && p.code() == Code::CONTENT)
                    .then_some(p.message_id())
            }) {
                break mid;
            }
            assert!(Instant::now() < deadline, "notification missing");
            thread::sleep(Duration::from_millis(2));
        };
        let (attacker, _) = bind_loopback().unwrap();
        let mut wire = [0; 4];
        let n = encode(&Message::new(Type::Reset, Code::EMPTY, mid), &mut wire).unwrap();
        attacker.send_to(&wire[..n], dest).unwrap();
        let wrong = MessageId::new(mid.get() ^ 1);
        let n = encode(&Message::new(Type::Reset, Code::EMPTY, wrong), &mut wire).unwrap();
        client
            .observe
            .as_mut()
            .unwrap()
            .app
            .transport_mut()
            .send(Endpoint::from(dest), &wire[..n])
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let received = server
                .take_capture()
                .snapshot()
                .iter()
                .filter(|packet| {
                    packet.dst == dest && decode(&packet.bytes).is_ok_and(|p| p.ty() == Type::Reset)
                })
                .count();
            if received == 2 {
                break;
            }
            assert!(Instant::now() < deadline, "reset controls not received");
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            client
                .take_notification(Duration::from_secs(1))
                .unwrap()
                .payload,
            site::OBS_BODY_2
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let settled = server.take_capture().snapshot().iter().any(|packet| {
                packet.dst == dest
                    && decode(&packet.bytes)
                        .is_ok_and(|p| p.is_empty_ack() && p.message_id() == mid)
            });
            if settled {
                break;
            }
            assert!(Instant::now() < deadline, "valid ACK not received");
            thread::sleep(Duration::from_millis(2));
        }
        server.notify_confirmable(&["obs"], site::OBS_BODY).unwrap();
        assert_eq!(
            client
                .take_notification(Duration::from_secs(1))
                .unwrap()
                .payload,
            site::OBS_BODY
        );
    }
}

#[cfg(test)]
mod observe_owner_tests {
    use super::*;

    #[test]
    fn cancellation_identity_refuses_before_io_then_valid_cancel_recovers() {
        let _guard = crate::runner::harness_lock();
        let mut server = CoapticPeer::new();
        let dest = server.start_server().unwrap();
        let mut client = CoapticPeer::new();
        let mut registration = ClientRequest::get(&["obs"]);
        registration.observe = Some(0);
        assert_eq!(
            client.begin_observe(dest, &registration).unwrap().payload,
            site::OBS_BODY
        );
        let endpoint = client.local_addr();
        let before = client.take_capture().snapshot().len();
        let (other_socket, other) = bind_loopback().unwrap();
        let mut cancel = ClientRequest::get(&["obs"]);
        cancel.observe = Some(1);
        let mut wrong_path = cancel.clone();
        wrong_path.path = vec!["test".into()];
        for (target, request) in [(dest, &wrong_path), (other, &cancel), (dest, &registration)] {
            assert!(client.request_on_observe(target, request).is_err());
            assert_eq!(
                client.take_capture().snapshot().len(),
                before,
                "refusal performed I/O"
            );
            assert_eq!(client.local_addr(), endpoint);
        }
        drop(other_socket);
        server
            .notify_confirmable(&["obs"], site::OBS_BODY_2)
            .unwrap();
        assert_eq!(
            client
                .take_notification(Duration::from_secs(1))
                .unwrap()
                .payload,
            site::OBS_BODY_2
        );
        let response = client.request_on_observe(dest, &cancel).unwrap();
        assert_eq!(response.payload, site::OBS_BODY);
        assert!(response.observe.is_none());
        let before = server.take_capture().snapshot().len();
        server.notify_confirmable(&["obs"], site::OBS_BODY).unwrap();
        client
            .observe_quiet_for(Duration::from_millis(100))
            .unwrap();
        assert_eq!(server.take_capture().snapshot().len(), before);
        assert_eq!(
            client.begin_observe(dest, &registration).unwrap().payload,
            site::OBS_BODY
        );
        assert_eq!(client.local_addr(), endpoint);
        server
            .notify_confirmable(&["obs"], site::OBS_BODY_2)
            .unwrap();
        assert_eq!(
            client
                .take_notification(Duration::from_secs(1))
                .unwrap()
                .payload,
            site::OBS_BODY_2
        );
    }

    #[test]
    fn unsupported_same_owner_request_refuses_without_io() {
        let mut peer = crate::runner::peer_by_name("coap-rs").unwrap();
        let request = ClientRequest::get(&["obs"]);
        let error = peer
            .request_on_observe("127.0.0.1:5683".parse().unwrap(), &request)
            .unwrap_err();
        assert!(error.0.contains("not supported"));
        assert!(peer.take_capture().snapshot().is_empty());
    }
}
