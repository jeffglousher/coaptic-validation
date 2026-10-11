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
    notification_error: Arc<Mutex<Option<String>>>,
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
    loss: crate::observe_loss::ObserveLoss,
    join: Option<JoinHandle<()>>,
}

enum NotifyCommand {
    UpdatePumpingObserved {
        version: u8,
        completion: std::sync::mpsc::SyncSender<Result<usize, String>>,
    },
    UpdateLargeObserved(u8),
    SetObservedState(u8),
    Notification {
        path: Vec<String>,
        payload: Vec<u8>,
        confirmable: bool,
    },
    UpdateObserved {
        body: &'static [u8],
    },
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
            notification_error: Arc::new(Mutex::new(None)),
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
        let loss = crate::observe_loss::ObserveLoss::default();
        let loss_t = loss.clone();
        *self.notification_error.lock().expect("notification error") = None;
        let notification_error = Arc::clone(&self.notification_error);
        let join = thread::Builder::new()
            .name("coaptic-plugtest-server".into())
            .spawn(move || {
                server_loop(
                    sock,
                    addr,
                    capture,
                    stop_t,
                    notify_t,
                    loss_t,
                    notification_error,
                )
            })
            .map_err(|e| e.to_string())?;
        // Let the thread bind the App.
        thread::sleep(Duration::from_millis(20));
        self.server = Some(ServerCtl {
            addr,
            stop,
            notify,
            loss,
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

    fn arm_observe_loss(
        &mut self,
        peer: SocketAddr,
        token: &[u8],
        ack: bool,
    ) -> Result<(), PeerError> {
        let (loss, local) = if ack {
            let server = self.server.as_ref().ok_or("ACK loss requires server")?;
            (server.loss.clone(), server.addr)
        } else {
            let hold = self
                .observe
                .as_ref()
                .ok_or("CON loss requires observation")?;
            (
                hold.app.transport().observe_loss(),
                self.client_addr.ok_or("missing client endpoint")?,
            )
        };
        let registered = self.capture.snapshot().iter().any(|packet| {
            packet.src == if ack { peer } else { local }
                && packet.dst == if ack { local } else { peer }
                && decode(&packet.bytes).is_ok_and(|p| {
                    p.code() == Code::GET
                        && p.observe() == Some(Ok(0))
                        && p.token().as_bytes() == token
                        && p.uri_path().collect::<Vec<_>>() == [Ok("obs")]
                })
        });
        if !registered {
            return Err(PeerError("loss owner not registered".into()));
        }
        loss.arm(peer, token, ack).map_err(Into::into)
    }
    fn observe_losses(&self) -> usize {
        if let Some(server) = &self.server {
            server.loss.consumed()
        } else {
            self.observe
                .as_ref()
                .map_or(0, |hold| hold.app.transport().observe_loss().consumed())
        }
    }

    fn notification_error(&self) -> Option<String> {
        self.notification_error
            .lock()
            .expect("notification error")
            .clone()
    }

    fn update_pumping_observed(&mut self, path: &[&str], version: u8) -> Result<(), PeerError> {
        if path != ["obs-pumping"] || site::observe_pumping(version).is_none() {
            return Err(PeerError(
                "unsupported bounded pumping representation".into(),
            ));
        }
        let server = self.server.as_ref().ok_or("no server")?;
        let (completion, result) = std::sync::mpsc::sync_channel(1);
        {
            let mut command = server.notify.lock().expect("pumping update");
            if command.is_some() {
                return Err(PeerError("notification command occupied".into()));
            }
            *command = Some(NotifyCommand::UpdatePumpingObserved {
                version,
                completion,
            });
        }
        result
            .recv_timeout(Duration::from_secs(1))
            .map_err(|error| PeerError(format!("pumping command completion: {error}")))?
            .map(|_| ())
            .map_err(PeerError)
    }

    fn update_large_observed(&mut self, path: &[&str], version: u8) -> Result<(), PeerError> {
        if path != ["obs-large"] || site::observe_large(version).is_none() {
            return Err(PeerError("unsupported bounded large representation".into()));
        }
        let server = self.server.as_ref().ok_or("no server")?;
        let mut command = server.notify.lock().expect("large update");
        if command.is_some() {
            return Err(PeerError("notification command occupied".into()));
        }
        *command = Some(NotifyCommand::UpdateLargeObserved(version));
        Ok(())
    }

    fn set_observed_state(&mut self, path: &[&str], state: u8) -> Result<(), PeerError> {
        if path != ["obs"] || state > 2 {
            return Err(PeerError("unsupported bounded observed state".into()));
        }
        let server = self.server.as_ref().ok_or("no server")?;
        let mut command = server.notify.lock().expect("state");
        if command.is_some() {
            return Err(PeerError("notification command occupied".into()));
        }
        *command = Some(NotifyCommand::SetObservedState(state));
        Ok(())
    }

    fn update_observed(&mut self, path: &[&str], payload: &[u8]) -> Result<(), PeerError> {
        if path != ["obs"] {
            return Err(PeerError("update requires /obs".into()));
        }
        let body =
            site::observe_update_body(payload).ok_or("unsupported bounded representation")?;
        let server = self.server.as_ref().ok_or("no server")?;
        let mut command = server.notify.lock().expect("update");
        if command.is_some() {
            return Err(PeerError("notification command occupied".into()));
        }
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
    loss: crate::observe_loss::ObserveLoss,
    notification_error: Arc<Mutex<Option<String>>>,
) {
    let io = CapturingIo::new(sock, addr, capture).with_observe_loss(loss);
    let mut app = bind_site(io);
    let origin = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        let now = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let _ = app.poll(now);
        if let Some(command) = notify.lock().expect("n").take() {
            match command {
                NotifyCommand::UpdatePumpingObserved {
                    version,
                    completion,
                } => {
                    site::commit_observe_pumping(version);
                    let result = app
                        .notify_confirmable(now, &["obs-pumping"], site::observe_pumping_response())
                        .map_err(|error| format!("{error:?}"));
                    *notification_error.lock().expect("notification error") =
                        result.as_ref().err().cloned();
                    let _ = completion.send(result);
                }
                NotifyCommand::UpdateLargeObserved(version) => {
                    site::commit_observe_large(version);
                    let result =
                        app.notify_confirmable(now, &["obs-large"], site::observe_large_response());
                    *notification_error.lock().expect("notification error") =
                        result.err().map(|error| format!("{error:?}"));
                }
                NotifyCommand::SetObservedState(state) => {
                    site::set_observed_state(state);
                    if state != 0 {
                        let _ = app.notify_confirmable(now, &["obs"], site::observed_response());
                    }
                }
                NotifyCommand::Notification {
                    path,
                    payload,
                    confirmable,
                } => {
                    let segs: Vec<&str> = path.iter().map(String::as_str).collect();
                    let body = site::observe_update_body(&payload).unwrap_or(site::OBS_BODY_2);
                    let response =
                        Response::content(body).content_format(ContentFormat::TEXT_PLAIN);
                    let _ = if confirmable {
                        app.notify_confirmable(now, &segs, response)
                    } else {
                        app.notify(now, &segs, response)
                    };
                }
                NotifyCommand::UpdateObserved { body } => {
                    // The GET handler and retransmission snapshot see the new
                    // representation before its notification can reach a client.
                    site::commit_observe_update(body);
                    let response =
                        Response::content(body).content_format(ContentFormat::TEXT_PLAIN);
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
        ["obs-large"] => "obs-large",
        ["obs-pumping"] => "obs-pumping",
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

#[cfg(test)]
mod observe_update_tests {
    use super::*;

    #[test]
    fn occupied_update_command_refuses_without_replacing_owner() {
        let mut server = CoapticPeer::new();
        let command = Arc::new(Mutex::new(Some(NotifyCommand::Notification {
            path: vec!["obs".into()],
            payload: site::OBS_BODY.to_vec(),
            confirmable: true,
        })));
        server.server = Some(ServerCtl {
            addr: "127.0.0.1:5683".parse().unwrap(),
            stop: Arc::new(AtomicBool::new(false)),
            notify: Arc::clone(&command),
            loss: crate::observe_loss::ObserveLoss::default(),
            join: None,
        });
        assert!(
            server
                .update_observed(&["obs"], site::OBS_BODY_2)
                .unwrap_err()
                .0
                .contains("occupied")
        );
        assert!(
            matches!(&*command.lock().unwrap(), Some(NotifyCommand::Notification { path, payload, confirmable: true }) if path == &["obs"] && payload == site::OBS_BODY)
        );
        assert!(server.take_capture().snapshot().is_empty());
        *command.lock().unwrap() = None;
        server.update_observed(&["obs"], site::OBS_BODY_2).unwrap();
        assert!(
            matches!(&*command.lock().unwrap(), Some(NotifyCommand::UpdateObserved { body }) if *body == site::OBS_BODY_2)
        );
    }

    #[test]
    fn invalid_updates_preserve_state_and_next_server_starts_clean() {
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
        for body in [site::OBS_BODY_2, site::OBS_BODY] {
            let before = server.take_capture().snapshot().len();
            for (path, payload) in [
                (&["test"][..], site::OBS_BODY_2),
                (&["obs"][..], &b"invalid"[..]),
                (&["obs"][..], &[0u8; 1025][..]),
            ] {
                assert!(server.update_observed(path, payload).is_err());
            }
            client.observe_quiet_for(Duration::from_millis(30)).unwrap();
            assert_eq!(
                server.take_capture().snapshot().len(),
                before,
                "invalid update emitted traffic"
            );
            let previous = if body == site::OBS_BODY_2 {
                site::OBS_BODY
            } else {
                site::OBS_BODY_2
            };
            assert_eq!(
                client
                    .request_on_observe(dest, &ClientRequest::get(&["obs"]))
                    .unwrap()
                    .payload,
                previous
            );
            server.update_observed(&["obs"], body).unwrap();
            assert_eq!(
                client
                    .take_notification(Duration::from_secs(1))
                    .unwrap()
                    .payload,
                body
            );
            assert_eq!(
                client
                    .request_on_observe(dest, &ClientRequest::get(&["obs"]))
                    .unwrap()
                    .payload,
                body
            );
        }
        // Leave a changed value behind, then verify the next serialized fixture
        // resets both GET state and the snapshot mode, with no cross-TD leakage.
        server.update_observed(&["obs"], site::OBS_BODY_2).unwrap();
        assert_eq!(
            client
                .take_notification(Duration::from_secs(1))
                .unwrap()
                .payload,
            site::OBS_BODY_2
        );
        drop(client);
        drop(server);
        let mut fresh_server = CoapticPeer::new();
        let dest = fresh_server.start_server().unwrap();
        let mut fresh_client = CoapticPeer::new();
        assert_eq!(
            fresh_client
                .begin_observe(dest, &registration)
                .unwrap()
                .payload,
            site::OBS_BODY
        );
        let mut unsupported = crate::runner::peer_by_name("coap-rs").unwrap();
        assert!(
            unsupported
                .update_observed(&["obs"], site::OBS_BODY_2)
                .unwrap_err()
                .0
                .contains("not supported")
        );
        assert!(unsupported.take_capture().snapshot().is_empty());
    }
}

#[cfg(test)]
mod observe_terminal_tests {
    use super::*;

    #[test]
    fn terminal_fixture_refuses_invalid_and_occupied_commands() {
        let _guard = crate::runner::harness_lock();
        let mut server = CoapticPeer::new();
        let dest = server.start_server().unwrap();
        let mut client = CoapticPeer::new();
        let mut registration = ClientRequest::get(&["obs"]);
        registration.observe = Some(0);
        client.begin_observe(dest, &registration).unwrap();
        let before = server.take_capture().snapshot().len();
        for (path, state) in [(&["test"][..], 1), (&["obs"][..], 3), (&["obs"][..], 255)] {
            assert!(server.set_observed_state(path, state).is_err());
        }
        client.observe_quiet_for(Duration::from_millis(30)).unwrap();
        assert_eq!(server.take_capture().snapshot().len(), before);
        let readback = client
            .request_on_observe(dest, &ClientRequest::get(&["obs"]))
            .unwrap();
        assert_eq!(readback.payload, site::OBS_BODY);
        assert_eq!(readback.content_format, Some(0));
        server.set_observed_state(&["obs"], 2).unwrap();
        assert_eq!(
            client
                .take_notification(Duration::from_secs(1))
                .unwrap()
                .code,
            Code::NOT_ACCEPTABLE
        );
        drop(client);
        drop(server);
        let mut fresh = CoapticPeer::new();
        let dest = fresh.start_server().unwrap();
        let readback = CoapticPeer::new()
            .send_request(dest, &ClientRequest::get(&["obs"]))
            .unwrap();
        assert_eq!(readback.payload, site::OBS_BODY);
        assert_eq!(readback.content_format, Some(0));
        drop(fresh);

        let mut bounded = CoapticPeer::new();
        let command = Arc::new(Mutex::new(Some(NotifyCommand::SetObservedState(1))));
        bounded.server = Some(ServerCtl {
            addr: dest,
            stop: Arc::new(AtomicBool::new(false)),
            notify: Arc::clone(&command),
            loss: crate::observe_loss::ObserveLoss::default(),
            join: None,
        });
        assert!(
            bounded
                .set_observed_state(&["obs"], 2)
                .unwrap_err()
                .0
                .contains("occupied")
        );
        assert!(matches!(
            *command.lock().unwrap(),
            Some(NotifyCommand::SetObservedState(1))
        ));
        *command.lock().unwrap() = None;
        bounded.set_observed_state(&["obs"], 0).unwrap();
        assert!(matches!(
            *command.lock().unwrap(),
            Some(NotifyCommand::SetObservedState(0))
        ));
        assert!(bounded.take_capture().snapshot().is_empty());
        let mut unsupported = crate::runner::peer_by_name("coap-rs").unwrap();
        assert!(
            unsupported
                .set_observed_state(&["obs"], 1)
                .unwrap_err()
                .0
                .contains("not supported")
        );
        assert!(unsupported.take_capture().snapshot().is_empty());
    }
}

#[cfg(test)]
mod observe_loss_hook_tests {
    use super::*;
    #[test]
    fn invalid_loss_owner_refuses_before_io_and_valid_owner_recovers() {
        let _guard = crate::runner::harness_lock();
        let mut server = CoapticPeer::new();
        let dest = server.start_server().unwrap();
        let mut client = CoapticPeer::new();
        let mut registration = ClientRequest::get(&["obs"]);
        registration.observe = Some(0);
        client.begin_observe(dest, &registration).unwrap();
        let packets = client.take_capture().snapshot();
        let token = decode(&packets[0].bytes)
            .unwrap()
            .token()
            .as_bytes()
            .to_vec();
        let before = server.take_capture().snapshot().len();
        let mut wrong = token.clone();
        wrong[0] ^= 1;
        let mut other = dest;
        other.set_port(if dest.port() == 1 { 2 } else { 1 });
        assert!(client.arm_observe_loss(other, &token, false).is_err());
        assert!(client.arm_observe_loss(dest, &wrong, false).is_err());
        assert!(client.arm_observe_loss(dest, &token, true).is_err());
        assert!(server.arm_observe_loss(dest, &token, false).is_err());
        client.observe_quiet_for(Duration::from_millis(30)).unwrap();
        assert_eq!(server.take_capture().snapshot().len(), before);
        client.arm_observe_loss(dest, &token, false).unwrap();
        assert!(
            client
                .arm_observe_loss(dest, &token, false)
                .unwrap_err()
                .0
                .contains("occupied")
        );
        server
            .notify_confirmable(&["obs"], site::OBS_BODY_2)
            .unwrap();
        assert_eq!(
            client
                .take_notification(Duration::from_secs(4))
                .unwrap()
                .payload,
            site::OBS_BODY_2
        );
        assert_eq!(client.observe_losses(), 1);
        assert_eq!(server.observe_losses(), 0);
    }
}

#[cfg(test)]
mod observe_large_tests {
    use super::*;
    #[test]
    fn large_fixture_refusal_preserves_state_and_full_delivery_recovers() {
        let _guard = crate::runner::harness_lock();
        let mut server = CoapticPeer::new();
        let dest = server.start_server().unwrap();
        let mut client = CoapticPeer::new();
        let mut registration = ClientRequest::get(&["obs-large"]);
        registration.observe = Some(0);
        let initial = client.begin_observe(dest, &registration).unwrap();
        assert_eq!(
            initial.body.as_deref(),
            Some(site::observe_large(0).unwrap().0)
        );
        let before = server.take_capture().snapshot().len();
        for (path, version) in [
            (&["obs"][..], 1),
            (&["obs-large"][..], 3),
            (&["obs-large"][..], 255),
        ] {
            assert!(server.update_large_observed(path, version).is_err());
        }
        client.observe_quiet_for(Duration::from_millis(30)).unwrap();
        assert_eq!(server.take_capture().snapshot().len(), before);
        // Inspect the owned fixture without introducing another retained Block2
        // response owner into this one-observer capacity qualification.
        assert_eq!(
            site::observe_large_response().payload(),
            site::observe_large(0).unwrap().0
        );
        for version in [1, 2] {
            server
                .update_large_observed(&["obs-large"], version)
                .unwrap();
            let complete = client
                .take_notification(Duration::from_secs(3))
                .unwrap_or_else(|e| panic!("version {version}: {e:?}"));
            let (body, etag) = site::observe_large(version).unwrap();
            assert_eq!(complete.body.as_deref(), Some(body));
            assert_eq!(complete.etag, [etag.to_vec()]);
        }
        // An exploratory third rapid round exceeds this default fixture's
        // retained-TX budget. Keep its actual cause visible instead of reporting
        // only a client timeout; this is not a sustained-cadence success claim.
        server.update_large_observed(&["obs-large"], 1).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(error) = server.notification_error() {
                assert_eq!(error, "Saturated");
                break;
            }
            assert!(Instant::now() < deadline, "missing saturation diagnostic");
            thread::sleep(Duration::from_millis(2));
        }
        drop(client);
        drop(server);
        let mut fresh = CoapticPeer::new();
        let dest = fresh.start_server().unwrap();
        let clean = CoapticPeer::new()
            .send_request(dest, &ClientRequest::get(&["obs-large"]))
            .unwrap();
        assert_eq!(
            clean.body.as_deref(),
            Some(site::observe_large(0).unwrap().0)
        );
        let mut unsupported = crate::runner::peer_by_name("coap-rs").unwrap();
        assert!(
            unsupported
                .update_large_observed(&["obs-large"], 1)
                .is_err()
        );
        assert!(unsupported.take_capture().snapshot().is_empty());
    }
    #[test]
    fn occupied_large_update_refuses_without_replacing_snapshot() {
        let mut server = CoapticPeer::new();
        let command = Arc::new(Mutex::new(Some(NotifyCommand::UpdateLargeObserved(1))));
        server.server = Some(ServerCtl {
            addr: "127.0.0.1:5683".parse().unwrap(),
            stop: Arc::new(AtomicBool::new(false)),
            notify: Arc::clone(&command),
            loss: crate::observe_loss::ObserveLoss::default(),
            join: None,
        });
        assert!(
            server
                .update_large_observed(&["obs-large"], 2)
                .unwrap_err()
                .0
                .contains("occupied")
        );
        assert!(matches!(
            *command.lock().unwrap(),
            Some(NotifyCommand::UpdateLargeObserved(1))
        ));
        *command.lock().unwrap() = None;
        server.update_large_observed(&["obs-large"], 2).unwrap();
        assert!(matches!(
            *command.lock().unwrap(),
            Some(NotifyCommand::UpdateLargeObserved(2))
        ));
        assert!(server.take_capture().snapshot().is_empty());
    }
}

#[cfg(test)]
mod observe_pumping_tests {
    use super::*;
    #[test]
    fn pumping_refusal_preserves_state_and_valid_update_recovers() {
        let _guard = crate::runner::harness_lock();
        let mut server = CoapticPeer::new();
        assert!(server.update_pumping_observed(&["obs-pumping"], 0).is_err());
        let dest = server.start_server().unwrap();
        let mut client = CoapticPeer::new();
        let mut request = ClientRequest::get(&["obs-pumping"]);
        request.observe = Some(0);
        let initial = client.begin_observe(dest, &request).unwrap();
        assert_eq!(initial.payload, site::observe_pumping(0).unwrap().0);
        let before = server.take_capture().snapshot().len();
        for (path, version) in [
            (&["obs"][..], 1),
            (&["obs-pumping"][..], 3),
            (&["obs-pumping"][..], 255),
        ] {
            assert!(server.update_pumping_observed(path, version).is_err());
        }
        client.observe_quiet_for(Duration::from_millis(30)).unwrap();
        assert_eq!(server.take_capture().snapshot().len(), before);
        assert_eq!(
            site::observe_pumping_response().payload(),
            site::observe_pumping(0).unwrap().0
        );
        for version in [1, 2] {
            server
                .update_pumping_observed(&["obs-pumping"], version)
                .unwrap();
            let response = client.take_notification(Duration::from_secs(3)).unwrap();
            let (body, etag) = site::observe_pumping(version).unwrap();
            assert_eq!(response.body.as_deref().unwrap_or(&response.payload), body);
            assert_eq!(response.etag, [etag.to_vec()]);
            client.observe_quiet_for(Duration::from_millis(20)).unwrap();
        }
        drop(client);
        drop(server);
        let mut fresh = CoapticPeer::new();
        let dest = fresh.start_server().unwrap();
        let reset = CoapticPeer::new()
            .send_request(dest, &ClientRequest::get(&["obs-pumping"]))
            .unwrap();
        assert_eq!(reset.payload, site::observe_pumping(0).unwrap().0);
        let mut unsupported = crate::runner::peer_by_name("coap-rs").unwrap();
        assert!(
            unsupported
                .update_pumping_observed(&["obs-pumping"], 1)
                .is_err()
        );
        assert!(unsupported.take_capture().snapshot().is_empty());
    }
    #[test]
    fn occupied_pumping_command_refuses_without_replacement() {
        let mut server = CoapticPeer::new();
        let (completion, _result) = std::sync::mpsc::sync_channel(1);
        let command = Arc::new(Mutex::new(Some(NotifyCommand::UpdatePumpingObserved {
            version: 1,
            completion,
        })));
        server.server = Some(ServerCtl {
            addr: "127.0.0.1:5683".parse().unwrap(),
            stop: Arc::new(AtomicBool::new(false)),
            notify: Arc::clone(&command),
            loss: crate::observe_loss::ObserveLoss::default(),
            join: None,
        });
        assert!(
            server
                .update_pumping_observed(&["obs-pumping"], 2)
                .unwrap_err()
                .0
                .contains("occupied")
        );
        assert!(matches!(
            *command.lock().unwrap(),
            Some(NotifyCommand::UpdatePumpingObserved { version: 1, .. })
        ));
        assert!(server.take_capture().snapshot().is_empty());
    }
}
