//! Process-isolated Coaptic peer. No coap-rs types or dependencies.
#![forbid(unsafe_code)]
mod dtls;
#[path = "../../../tools/interop/support.rs"]
mod support;
use coaptic::storage::{DatagramIo, Endpoint};
use coaptic::{App, Code, ContentFormat, Method, Request, Response, get, profiles};
use std::{
    net::UdpSocket,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};
use support::{Args, Error};
use webrtc_util::conn::Listener;
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
impl DatagramIo for Io {
    type Error = std::io::Error;
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
                let Ok(mut app) = fixture(Io::Dtls(dtls::DtlsIo::accepted(conn, peer)), false)
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
    let mut app = fixture(io, a.server && a.echo)?;
    if a.oscore {
        // Public RFC 8613 C.1 fixture material, never production credentials.
        let mut secret = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        if a.key != "sesame" {
            secret[0] ^= 0xff;
        }
        let mut context = coaptic::oscore::SecurityContext::derive(coaptic::oscore::DeriveParams {
            master_secret: &secret,
            master_salt: &[0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40],
            sender_id: if a.server { &[1] } else { &[] },
            recipient_id: if a.server { &[] } else { &[1] },
            id_context: &[],
        })
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
        app.set_oscore(context);
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
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let path = match a.path.as_str() {
        "test" => &["test"][..],
        "large" => &["large"][..],
        "counter" => &["counter"][..],
        "methods" => &["methods"][..],
        "upload" => &["upload"][..],
        "separate" => &["separate"][..],
        "patch" => &["patch"][..],
        _ => &["missing"][..],
    };
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
    if a.observe {
        outgoing = outgoing.observe();
    }
    let mut call = outgoing.send(1).map_err(|e| format!("send: {e}"))?;
    let mut echo_retried = false;
    // Observe prints the registration reply and two notifications, comma-separated.
    let mut observed: Vec<Vec<u8>> = Vec::new();
    while start.elapsed() < Duration::from_millis(a.timeout) {
        app.poll(start.elapsed().as_millis() as u64 + 1)
            .map_err(|e| format!("poll: {e}"))?;
        let response = app.take_response(call).transpose()?.map(|r| {
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
                if a.observe {
                    retry = retry.observe();
                }
                call = retry
                    .send(start.elapsed().as_millis() as u64 + 1)
                    .map_err(|e| format!("Echo retry: {e}"))?;
                echo_retried = true;
                continue;
            }
            if a.observe {
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

fn fixture(io: Io, echo: bool) -> Result<App<profiles::Default, Io, 9, true>, Error> {
    let app = App::profile::<profiles::Default>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .routes::<9>()
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
        .route("/patch", get(merge_patch).patch(merge_patch))
        .route(
            "/cond",
            get(conditional).put(conditional).delete(conditional),
        )
        .well_known_core();
    if echo {
        app.echo_policy(server_echo).allow_plaintext().bind(io)
    } else {
        app.allow_plaintext().bind(io)
    }
    .map_err(|e| format!("bind: {e:?}").into())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    support::finish(run().await)
}
