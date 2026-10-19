//! Process-isolated Coaptic peer. No coap-rs types or dependencies.
#![forbid(unsafe_code)]
mod dtls;
#[path = "../../../tools/interop/support.rs"]
mod support;
use coaptic::storage::{DatagramIo, Endpoint};
use coaptic::{App, Code, ContentFormat, Method, get};
use std::{
    net::UdpSocket,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};
use support::{Args, Error};
use webrtc_util::conn::Listener;
type Token = coaptic::message::extended::Token<32>;
type Request<'a> = coaptic::Request<'a, Token>;
type Response<'a> = coaptic::Response<'a, Token>;
// Match the existing peer's pools, with an explicit 32-byte token bound.
coaptic::memory_profile! { PeerProfile {
    token: Token,
    rx_datagram: (4, 1472), tx_datagram: (4, 1472),
    rx_body: (2, 4096), tx_body: (2, 4096), dedup: 8, observe: 4,
} }
static SENSOR_METADATA: coaptic::link_format::Metadata<'static> = coaptic::link_format::Metadata {
    resource_types: Some("temperature-c sensor"),
    interfaces: Some("sensor"),
    content_formats: &[0, 50],
    size_estimate: Some(96),
    observable: true,
    extensions: &[coaptic::link_format::Extension {
        name: "title",
        value: Some("Room \"one\""),
    }],
};
static OBSERVED_BODIES: [[u8; 96]; 3] = [[b'a'; 96], [b'b'; 96], [b'c'; 96]];
fn large_snapshot() -> Response<'static> {
    let epoch = (COUNTER.load(Ordering::SeqCst) % 3) as usize;
    Response::content(&OBSERVED_BODIES[epoch])
        .etag(&[epoch as u8 + 1])
        .content_format(ContentFormat::TEXT_PLAIN)
}
fn observed_large(request: Request<'_>) -> Response<'static> {
    let epoch = (COUNTER.load(Ordering::SeqCst) % 3) as u8;
    if request.etag().any(|tag| tag == [epoch + 1]) {
        Response::new(Code::VALID).etag(&[epoch + 1])
    } else {
        large_snapshot()
    }
}
fn escaped(request: Request<'_>) -> Response<'static> {
    if request.uri_query().eq([Ok("key=a&b")]) {
        Response::content(b"uri-identity")
    } else {
        Response::bad_request()
    }
}
static METHOD_RESOURCE: std::sync::Mutex<support::MethodResource> =
    std::sync::Mutex::new(support::MethodResource::new());
static UPLOAD_RESOURCE: std::sync::Mutex<support::UploadResource> =
    std::sync::Mutex::new(support::UploadResource::new());
static COUNTER: AtomicU32 = AtomicU32::new(0);
static MERGE_PATCH: std::sync::Mutex<support::MergePatch> =
    std::sync::Mutex::new(support::MergePatch::new());
/// `/cond` body and its one-byte ETag version.
static CONDITIONAL: std::sync::Mutex<(Option<Vec<u8>>, u8)> = std::sync::Mutex::new((None, 0));
fn conditional(request: Request<'_>) -> Response<'static> {
    let mut state = CONDITIONAL.lock().expect("fixture lock");
    let version = [state.1];
    let etag = state.0.as_ref().map(|_| &version[..]);
    if !request.precondition(state.0.is_some(), etag).holds() {
        return Response::precondition_failed();
    }
    match request.method() {
        Some(Method::Get) => match &state.0 {
            Some(body) => Response::content_copy(body).etag(&version),
            None => Response::not_found(),
        },
        Some(Method::Put) => {
            let created = state.0.is_none();
            state.0 = Some(request.payload().to_vec());
            state.1 = state.1.wrapping_add(1);
            if created {
                Response::created()
            } else {
                Response::changed()
            }
        }
        _ => {
            if state.0.take().is_some() {
                Response::deleted()
            } else {
                Response::not_found()
            }
        }
    }
}
fn count(_: Request<'_>) -> Response<'static> {
    counter_snapshot().observe(0)
}
fn counter_snapshot() -> Response<'static> {
    Response::content_copy(COUNTER.load(Ordering::SeqCst).to_string().as_bytes())
}
fn increment(_: Request<'_>) -> Response<'static> {
    COUNTER.fetch_add(1, Ordering::SeqCst);
    Response::changed()
}
fn method_resource(request: Request<'_>) -> Response<'static> {
    let method = request.method().expect("routed method").code().as_raw();
    let (code, bytes) = METHOD_RESOURCE.lock().expect("fixture lock").respond(
        method,
        request.payload(),
        request.content_format() == Some(Ok(ContentFormat::OCTET_STREAM)),
    );
    Response::new(Code::from_raw(code)).payload_copy(&bytes)
}
fn merge_patch(request: Request<'_>) -> Response<'static> {
    let format = request
        .content_format()
        .and_then(Result::ok)
        .map(ContentFormat::get);
    let (code, bytes, response_format) = MERGE_PATCH.lock().expect("fixture lock").respond(
        request.method().expect("routed method").code().as_raw(),
        request.payload(),
        format,
    );
    let response = Response::new(Code::from_raw(code)).payload_copy(&bytes);
    match response_format {
        Some(50) => response.content_format(ContentFormat::JSON),
        Some(id) => response.content_format(ContentFormat::new(id)),
        None => response,
    }
}
fn upload_resource(request: Request<'_>) -> Response<'static> {
    let (code, bytes) = UPLOAD_RESOURCE.lock().expect("fixture lock").respond(
        request.method().expect("routed method").code().as_raw(),
        request.body().unwrap_or(request.payload()),
        request.content_format() == Some(Ok(ContentFormat::OCTET_STREAM)),
    );
    Response::new(Code::from_raw(code)).payload_copy(&bytes)
}

enum Io {
    Udp(UdpSocket),
    Dtls(dtls::DtlsIo),
}
impl coaptic::storage::DatagramTransport for Io {
    type Error = std::io::Error;
}
impl DatagramIo for Io {
    fn recv(&mut self, b: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        match self {
            Self::Udp(s) => DatagramIo::recv(s, b),
            Self::Dtls(s) => s.recv(b),
        }
    }
    fn send(&mut self, d: Endpoint, b: &[u8]) -> Result<usize, Self::Error> {
        match self {
            Self::Udp(s) => DatagramIo::send(s, d, b),
            Self::Dtls(s) => s.send(d, b),
        }
    }
}
async fn run() -> Result<(), Error> {
    let a = Args::parse()?;
    let start = Instant::now();
    if a.server && a.dtls {
        let listener =
            dtls::listener::BoundedListener::bind(a.address(), dtls::psk_config(a.key.as_bytes()))
                .await?;
        support::ready("coaptic", "webrtc-dtls 0.12.0", a.port, "dtls");
        loop {
            let (conn, peer) = listener.accept().await?;
            tokio::spawn(async move {
                // CoAP exchange/dedup/Observe state belongs to this authenticated
                // association. Resource contents (COUNTER) remain shared.
                let Ok(mut app) = fixture(Io::Dtls(dtls::DtlsIo::accepted(conn, peer)), false, 8)
                else {
                    return;
                };
                let start = Instant::now();
                let mut signalled = COUNTER.load(Ordering::SeqCst);
                loop {
                    if app.poll(start.elapsed().as_millis() as u64 + 1).is_err() {
                        break;
                    }
                    let value = COUNTER.load(Ordering::SeqCst);
                    if value != signalled {
                        signalled = value;
                        app.signal(&["counter"]);
                        app.signal(&["obs-large"]);
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            });
        }
    }
    let io = if a.dtls {
        Io::Dtls(
            dtls::DtlsIo::connect(
                a.address(),
                dtls::psk_config(a.key.as_bytes()),
                Duration::from_millis(a.timeout),
            )
            .await?,
        )
    } else {
        let socket = UdpSocket::bind(if a.server {
            a.address()
        } else {
            let mut address = a.address();
            address.set_port(0);
            address
        })?;
        socket.set_nonblocking(true)?;
        Io::Udp(socket)
    };
    let mut app = fixture(io, a.server && a.echo, a.token_length)?;
    if a.oscore {
        // Public RFC 8613 C.1 fixture material, never production credentials.
        let mut secret = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        if a.key != "sesame" {
            secret[0] ^= 0xff;
        }
        let mut context = coaptic::oscore::BoundedSecurityContext::<4, Token>::derive(
            coaptic::oscore::DeriveParams {
                master_secret: &secret,
                master_salt: &[0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40],
                sender_id: if a.server { &[1] } else { &[] },
                recipient_id: if a.server { &[] } else { &[1] },
                id_context: &[],
            },
        )
        .map_err(|e| format!("OSCORE derivation: {e:?}"))?;
        context
            .set_sender_seq(a.sequence)
            .map_err(|e| format!("OSCORE sequence: {e:?}"))?;
        if let Some((left, bits)) = a.replay {
            let checkpoint = coaptic::oscore::ReplayCheckpoint::from_parts(left, bits)
                .map_err(|e| format!("OSCORE replay checkpoint: {e:?}"))?;
            context
                .restore_replay(checkpoint)
                .map_err(|e| format!("OSCORE replay restore: {e:?}"))?;
        }
        app.set_oscore(&mut Some(context))
            .map_err(|e| format!("OSCORE context installation: {e}"))?;
    }
    if a.server {
        support::ready(
            "coaptic",
            if a.oscore {
                "coaptic OSCORE"
            } else {
                "coaptic UDP"
            },
            a.port,
            if a.oscore { "oscore" } else { "udp" },
        );
        let mut signalled = COUNTER.load(Ordering::SeqCst);
        loop {
            app.poll(start.elapsed().as_millis() as u64 + 1)
                .map_err(|e| format!("poll: {e}"))?;
            let value = COUNTER.load(Ordering::SeqCst);
            if value != signalled {
                signalled = value;
                app.signal(&["counter"]);
                app.signal(&["obs-large"]);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let encoded_path = if a.path == "escaped" {
        "escaped/a%2Fb?key=a%26b"
    } else {
        &a.path
    };
    let uri_text = format!("coap://127.0.0.1:{}/{}", a.port, encoded_path);
    let uri = coaptic::uri::Uri::parse(&uri_text).map_err(|e| format!("URI: {e:?}"))?;
    // App paths retain static descriptors; resolve only this fixture's finite
    // vocabulary after bounded URI decoding, rejecting extra components.
    let mut path_values = [""; 2];
    let mut count = 0;
    for component in uri.path_segments() {
        let slot = path_values.get_mut(count).ok_or("too many URI segments")?;
        let mut bytes = [0; 64];
        let decoded = component
            .decode(&mut bytes)
            .map_err(|e| format!("URI component: {e:?}"))?;
        *slot = [
            "test",
            "large",
            "counter",
            "missing",
            "methods",
            "upload",
            "separate",
            "patch",
            ".well-known",
            "core",
            "sensor",
            "escaped",
            "a/b",
            "obs-large",
        ]
        .into_iter()
        .find(|known| *known == decoded)
        .ok_or("unknown fixture URI segment")?;
        count += 1;
    }
    let path = &path_values[..count];
    let mut query_storage = [0; 64];
    let query = uri
        .query_arguments()
        .next()
        .map(|q| q.decode(&mut query_storage))
        .transpose()
        .map_err(|e| format!("URI query: {e:?}"))?;
    let method = match a.method {
        1 => Method::Get,
        2 => Method::Post,
        3 => Method::Put,
        4 => Method::Delete,
        5 => Method::Fetch,
        6 => Method::Patch,
        _ => Method::IPatch,
    };
    let mut outgoing = app
        .request(method, path)
        .payload(&a.payload)
        .to(Endpoint::from(a.address()));
    if matches!(a.path.as_str(), "methods" | "upload") && matches!(a.method, 2 | 3 | 5 | 6 | 7) {
        outgoing = outgoing.content_format(ContentFormat::OCTET_STREAM);
    }
    if a.path == "patch" && a.method == 6 {
        outgoing = outgoing.content_format(if a.jsonpatch {
            ContentFormat::JSON_PATCH
        } else {
            ContentFormat::MERGE_PATCH
        });
    }
    if a.q_block1 {
        outgoing = outgoing
            .request_tag(coaptic::storage::BodyTag::new(b"upload-1").expect("upload tag"))
            .q_block1();
    }
    if a.q_block2 {
        outgoing = outgoing.q_block2();
    }
    if a.q_block2_non {
        outgoing = outgoing.non();
    }
    if a.observe {
        outgoing = outgoing.observe();
    }
    if let Some(query) = query {
        outgoing = outgoing.query(query);
    }
    if let Some(number) = a.block2_start {
        outgoing = outgoing.block2(
            coaptic::message::BlockValue::new(number, false, 1)
                .map_err(|e| format!("block option: {e:?}"))?,
        );
    }
    if a.initial_valid {
        outgoing = outgoing.etag(&[1]);
    }
    if a.token_probe {
        let probe = outgoing
            .probe_token_support(1)
            .send(1)
            .map_err(|e| format!("probe send: {e}"))?;
        loop {
            let now = start.elapsed().as_millis() as u64 + 1;
            app.poll(now).map_err(|e| format!("probe poll: {e}"))?;
            if let Some(result) = app.take_response(probe.call()) {
                let evidence = probe.record(&result, now);
                println!(
                    "{}",
                    serde_json::json!({"schema":"coaptic-profiles/1","event":"probe","outcome":format!("{:?}",evidence.outcome()),"length":evidence.tested_length(),"expires_ms":evidence.expires_at()})
                );
                return Ok(());
            }
            if now > a.timeout {
                return Err("probe deadline".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let mut call = outgoing.send(1).map_err(|e| format!("send: {e}"))?;
    let mut echo_retried = false;
    // Observe prints the registration reply and two notifications, comma-separated.
    let mut observed: Vec<Vec<u8>> = Vec::new();
    let mut cancellation_sent = false;
    let mut quiet_until = None;
    let mut fresh_registration = false;
    let mut response_bytes = [0; 4096];
    while start.elapsed() < Duration::from_millis(a.timeout) {
        if quiet_until.is_some_and(|until| start.elapsed() >= until) {
            call = app
                .request(method, path)
                .to(Endpoint::from(a.address()))
                .observe()
                .send(start.elapsed().as_millis() as u64 + 1)
                .map_err(|e| format!("fresh Observe registration: {e}"))?;
            quiet_until = None;
            fresh_registration = true;
        }
        app.poll(start.elapsed().as_millis() as u64 + 1)
            .map_err(|e| format!("poll: {e}"))?;
        let response = app
            .take_response_into(call, &mut response_bytes)
            .map_err(|e| format!("response buffer: {e:?}"))?
            .transpose()?
            .map(|r| {
                (
                    r.code().as_raw(),
                    r.body().unwrap_or(r.payload()).to_vec(),
                    start.elapsed(),
                    r.echo_option(),
                )
            });
        if let Some((code, body, elapsed, echo)) = response {
            if let Some(challenge) = retry_challenge(a.oscore, echo_retried, code, echo) {
                // The configured App only admits authenticated responses. Echo
                // retry is explicit, once, to the same peer with identical
                // method/body/options; the original wall-clock deadline stays.
                let mut retry = app
                    .request(method, path)
                    .payload(&a.payload)
                    .to(Endpoint::from(a.address()))
                    .echo(challenge);
                if matches!(a.path.as_str(), "methods" | "upload")
                    && matches!(a.method, 2 | 3 | 5 | 6 | 7)
                {
                    retry = retry.content_format(ContentFormat::OCTET_STREAM);
                }
                if a.path == "patch" && a.method == 6 {
                    retry = retry.content_format(if a.jsonpatch {
                        ContentFormat::JSON_PATCH
                    } else {
                        ContentFormat::MERGE_PATCH
                    });
                }
                if a.q_block1 {
                    retry = retry
                        .request_tag(
                            coaptic::storage::BodyTag::new(b"upload-1").expect("upload tag"),
                        )
                        .q_block1();
                }
                if a.q_block2 {
                    retry = retry.q_block2();
                }
                if a.q_block2_non {
                    retry = retry.non();
                }
                if a.observe {
                    retry = retry.observe();
                }
                call = retry
                    .send(start.elapsed().as_millis() as u64 + 1)
                    .map_err(|e| format!("Echo retry: {e}"))?;
                echo_retried = true;
                continue;
            }
            if a.observe && code < 128 {
                if a.observe_cancel {
                    if quiet_until.is_some() {
                        return Err("unexpected response during cancellation hold".into());
                    }
                    if code != 69 {
                        return Err("Observe lifecycle requires Content responses".into());
                    }
                    observed.push(body);
                    if !cancellation_sent && observed.len() == 2 {
                        call = app
                            .request(method, path)
                            .to(Endpoint::from(a.address()))
                            .deregister_call(call)
                            .send(start.elapsed().as_millis() as u64 + 1)
                            .map_err(|e| format!("Observe cancellation: {e}"))?;
                        cancellation_sent = true;
                    } else if cancellation_sent && !fresh_registration && observed.len() == 3 {
                        // Keep polling the same App/socket through the bounded
                        // supervisor-controlled write and authenticated readback.
                        quiet_until = Some(start.elapsed() + Duration::from_secs(3));
                    } else if fresh_registration && observed.len() == 6 {
                        support::response(code, &observed.join(&b","[..]), elapsed, None);
                        return Ok(());
                    }
                    continue;
                }
                observed.push(body);
                if observed.len() < 3 {
                    continue;
                }
                support::response(code, &observed.join(&b","[..]), elapsed, None);
                return Ok(());
            }
            // Flush CloseNotify before the runtime exits. Response timing ends
            // at assembly; host timing includes this bounded session shutdown.
            if let Io::Dtls(io) = app.transport_mut() {
                io.close().await?;
            }
            support::response(code, &body, elapsed, Some(u8::from(echo_retried)));
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Err("request timed out".into())
}
fn retry_challenge(
    protected: bool,
    already_retried: bool,
    code: u8,
    echo: Option<coaptic::message::Echo>,
) -> Option<coaptic::message::Echo> {
    if protected && !already_retried && code == 129 {
        echo
    } else {
        None
    }
}

#[test]
fn echo_retry_requires_protection_challenge_and_unused_budget() {
    let echo = coaptic::message::Echo::new(b"authenticated-challenge").unwrap();
    assert_eq!(retry_challenge(true, false, 129, Some(echo)), Some(echo));
    for (protected, retried, code, challenge) in [
        (false, false, 129, Some(echo)),
        (true, true, 129, Some(echo)),
        (true, false, 132, Some(echo)),
        (true, false, 129, None),
    ] {
        assert_eq!(retry_challenge(protected, retried, code, challenge), None);
    }
}

fn server_echo(check: coaptic::EchoCheck) -> coaptic::EchoDecision {
    if check.oscore_protected
        && !check
            .echo
            .ok()
            .flatten()
            .is_some_and(|echo| echo.as_slice() == b"srv-echo")
    {
        coaptic::EchoDecision::Challenge(
            coaptic::message::Echo::new(b"srv-echo").expect("challenge"),
        )
    } else {
        coaptic::EchoDecision::Accept
    }
}

fn fixture(
    io: Io,
    echo: bool,
    token_length: usize,
) -> Result<App<PeerProfile, Io, 12, true>, Error> {
    let app = App::profile::<PeerProfile>()
        .token_length(token_length)
        .full_responses()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .routes::<12>()
        .route(
            "/test",
            get(|_: Request<'_>| Response::content(support::BODY)),
        )
        .route(
            "/large",
            get(|_: Request<'_>| Response::content(&support::LARGE).etag(b"lg-1")),
        )
        .route(
            "/counter",
            get(count).post(increment).observe(counter_snapshot),
        )
        .route("/upload", get(upload_resource).post(upload_resource))
        .route(
            "/methods",
            get(method_resource)
                .post(method_resource)
                .put(method_resource)
                .delete(method_resource)
                .fetch(method_resource)
                .patch(method_resource)
                .ipatch(method_resource),
        )
        .route(
            "/separate",
            get(|_: Request<'_>| {
                Response::content(b"separate-payload")
                    .content_format(coaptic::ContentFormat::TEXT_PLAIN)
                    .separate()
            }),
        )
        .route("/fail", get(|_: Request<'_>| Response::internal_error()))
        .route(
            "sensor",
            get(|_: Request<'_>| Response::content(b"sensor"))
                .observe(|| Response::content(b"sensor")),
        )
        .route(&["escaped", "a/b"], get(escaped))
        .route(
            "obs-large",
            get(observed_large).post(increment).observe(large_snapshot),
        )
        .route("/patch", get(merge_patch).patch(merge_patch))
        .route(
            "/cond",
            get(conditional).put(conditional).delete(conditional),
        )
        .well_known_core();
    let mut bound = if echo {
        app.echo_policy(server_echo).allow_unprotected().bind(io)
    } else {
        app.allow_unprotected().bind(io)
    }
    .map_err(|e| format!("bind: {e:?}"))?;
    bound
        .site()
        .set_discovery_metadata("sensor", Some(&SENSOR_METADATA))
        .map_err(|e| format!("metadata: {e:?}"))?;
    Ok(bound)
}
fn main() -> std::process::ExitCode {
    // Debug builds retain large bounded App construction temporaries. Keep this
    // desktop fixture's stack explicit, separate from embedded retained RAM.
    std::thread::Builder::new()
        .name("coaptic-peer".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("fixture runtime");
            support::finish(runtime.block_on(run()))
        })
        .expect("fixture thread")
        .join()
        .expect("fixture execution")
}
