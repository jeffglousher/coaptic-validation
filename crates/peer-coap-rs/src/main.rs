//! Isolated coap-rs peer, using a modern test-only DTLS transport.
#![forbid(unsafe_code)]
macro_rules! conn_as_any {
    () => {
        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
            self
        }
    };
}
#[path = "../../../tools/interop/coap_dtls.rs"]
mod coap_dtls;
#[path = "../../../tools/interop/dtls_listener.rs"]
mod dtls_listener;
#[path = "../../../tools/interop/separate_listener.rs"]
mod separate_listener;
#[path = "../../../tools/interop/support.rs"]
mod support;
use coap::{Server, client::CoAPClient, request::RequestBuilder};
use coap_lite::{CoapOption, ContentFormat, MessageClass, RequestType, ResponseType};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use support::{Args, Error};
use webrtc_dtls::{cipher_suite::CipherSuiteId, config::Config};
use webrtc_util::conn::Listener;
static MERGE_PATCH: std::sync::Mutex<support::MergePatch> =
    std::sync::Mutex::new(support::MergePatch::new());
fn content_format_id(values: Option<&std::collections::LinkedList<Vec<u8>>>) -> Option<u16> {
    let bytes = values?.front()?;
    match bytes.as_slice() {
        [b] => Some(u16::from(*b)),
        [hi, lo] => Some(u16::from_be_bytes([*hi, *lo])),
        _ => None,
    }
}
fn config(key: &str) -> Config {
    let key = key.as_bytes().to_vec();
    Config {
        psk: Some(Arc::new(move |_| Ok(key.clone()))),
        psk_identity_hint: Some(b"password".to_vec()),
        cipher_suites: vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8],
        ..Default::default()
    }
}
async fn run() -> Result<(), Error> {
    let a = Args::parse()?;
    if a.q_block1 {
        return Err("Q-Block1 is not implemented by this peer".into());
    }
    if a.q_block2 {
        return Err("Q-Block2 is not implemented by this peer".into());
    }
    if a.echo {
        return Err("Echo challenges are not issued by this peer".into());
    }
    if a.replay.is_some() {
        return Err("OSCORE replay restore is not implemented by this peer".into());
    }
    if a.observe {
        return Err("Observe collection is not implemented by this peer".into());
    }
    if a.oscore || a.sequence != 0 {
        return Err("OSCORE unsupported by this peer".into());
    }
    let start = Instant::now();
    if a.server {
        let server = if a.dtls {
            let listener =
                dtls_listener::BoundedListener::bind(a.address(), config(&a.key)).await?;
            let _ = listener.addr().await?;
            Server::from_listeners(vec![Box::new(coap_dtls::Server(listener))])
        } else {
            Server::from_listeners(vec![Box::new(
                separate_listener::SeparateListener::bind(a.address()).await?,
            )])
        };
        let resource = Arc::new(std::sync::Mutex::new(support::MethodResource::new()));
        let upload = Arc::new(std::sync::Mutex::new(support::UploadResource::new()));
        let counter = Arc::new(AtomicU32::new(0));
        support::ready(
            "coap-rs",
            "coap 0.28.1 / webrtc-dtls 0.12.0",
            a.port,
            if a.dtls { "dtls" } else { "udp" },
        );
        server
            .run(
                move |mut req: Box<coap_lite::CoapRequest<std::net::SocketAddr>>| {
                    let counter = Arc::clone(&counter);
                    let resource = Arc::clone(&resource);
                    let upload = Arc::clone(&upload);
                    async move {
                        let path = req.get_path();
                        let method = *req.get_method();
                        if method == RequestType::Get && path == "separate" {
                            let request_mid = req.message.header.message_id;
                            let kind = if req.message.header.get_type()
                                == coap_lite::MessageType::Confirmable
                            {
                                coap_lite::MessageType::Confirmable
                            } else {
                                coap_lite::MessageType::NonConfirmable
                            };
                            if let Some(response) = req.response.as_mut() {
                                response.message.header.set_type(kind);
                                response.message.header.message_id = request_mid.wrapping_add(1);
                                response.message.header.code =
                                    MessageClass::Response(ResponseType::Content);
                                response.message.payload = b"separate-payload".to_vec();
                                response
                                    .message
                                    .set_content_format(ContentFormat::TextPlain);
                            }
                            return req;
                        }
                        if path == "upload" {
                            let method: u8 = MessageClass::Request(method).into();
                            let format_ok = req
                                .message
                                .get_option(CoapOption::ContentFormat)
                                .is_some_and(|values| {
                                    values.len() == 1 && values.front().is_some_and(|v| v == &[42])
                                });
                            let (code, body) = upload.lock().expect("fixture lock").respond(
                                method,
                                &req.message.payload,
                                format_ok,
                            );
                            if let Some(r) = req.response.as_mut() {
                                r.message.header.code = code.into();
                                r.message.payload = body;
                            }
                            return req;
                        }
                        if path == "patch" {
                            let method: u8 = MessageClass::Request(method).into();
                            let format = content_format_id(
                                req.message.get_option(CoapOption::ContentFormat),
                            );
                            let (code, body, response_format) = MERGE_PATCH
                                .lock()
                                .expect("fixture lock")
                                .respond(method, &req.message.payload, format);
                            if let Some(r) = req.response.as_mut() {
                                r.message.header.code = code.into();
                                r.message.payload = body;
                                if response_format == Some(50) {
                                    r.message.set_content_format(ContentFormat::ApplicationJSON);
                                }
                            }
                            return req;
                        }
                        if path == "methods" {
                            let method: u8 = MessageClass::Request(method).into();
                            let format_ok = req
                                .message
                                .get_option(CoapOption::ContentFormat)
                                .is_some_and(|values| {
                                    values.len() == 1 && values.front().is_some_and(|v| v == &[42])
                                });
                            let (code, body) = resource.lock().expect("fixture lock").respond(
                                method,
                                &req.message.payload,
                                format_ok,
                            );
                            if let Some(r) = req.response.as_mut() {
                                r.message.header.code = code.into();
                                r.message.payload = body;
                            }
                            return req;
                        }
                        if let Some(r) = req.response.as_mut() {
                            let (code, body) = match (method, path.as_str()) {
                                (RequestType::Get, "test") => {
                                    (ResponseType::Content, support::BODY.to_vec())
                                }
                                (RequestType::Get, "large") => {
                                    (ResponseType::Content, support::LARGE.to_vec())
                                }
                                (RequestType::Get, "counter") => (
                                    ResponseType::Content,
                                    counter.load(Ordering::SeqCst).to_string().into_bytes(),
                                ),
                                (RequestType::Post, "counter") => {
                                    counter.fetch_add(1, Ordering::SeqCst);
                                    (ResponseType::Changed, vec![])
                                }
                                (RequestType::Put, "counter") => (ResponseType::Changed, vec![]),
                                _ => (ResponseType::NotFound, vec![]),
                            };
                            r.message.header.code = MessageClass::Response(code);
                            r.message.payload = body;
                        }
                        req
                    }
                },
            )
            .await?;
        return Ok(());
    }
    let operation = async {
        let request = RequestBuilder::request_path(
            &format!("/{}", a.path),
            match a.method {
                1 => RequestType::Get,
                2 => RequestType::Post,
                3 => RequestType::Put,
                4 => RequestType::Delete,
                5 => RequestType::Fetch,
                6 => RequestType::Patch,
                _ => RequestType::IPatch,
            },
            Some(a.payload.clone()),
            vec![],
            None,
        )
        .options(if a.path == "patch" && a.method == 6 {
            vec![(
                CoapOption::ContentFormat,
                vec![if a.jsonpatch { 51 } else { 52 }],
            )]
        } else if matches!(a.path.as_str(), "methods" | "upload")
            && matches!(a.method, 2 | 3 | 5 | 6 | 7)
        {
            vec![(CoapOption::ContentFormat, vec![42])]
        } else {
            vec![]
        })
        .build();
        let response = if a.dtls {
            let transport = coap_dtls::Client::connect(a.address(), config(&a.key)).await?;
            let connection = Arc::clone(&transport.0);
            let result = CoAPClient::from_transport(transport).send(request).await;
            // Stop timing before orderly shutdown, matching the other Rust peer.
            let elapsed = start.elapsed();
            let _ = tokio::time::timeout(Duration::from_secs(1), connection.close()).await;
            let response = result?;
            support::response(
                response.message.header.code.into(),
                &response.message.payload,
                elapsed,
                None,
            );
            return Ok::<(), Error>(());
        } else {
            coap::client::UdpCoAPClient::new(a.address())
                .await?
                .send(request)
                .await?
        };
        support::response(
            response.message.header.code.into(),
            &response.message.payload,
            start.elapsed(),
            None,
        );
        Ok::<(), Error>(())
    };
    tokio::time::timeout(Duration::from_millis(a.timeout), operation).await??;
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    support::finish(run().await)
}
