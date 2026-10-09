//! Independent-peer OSCORE fixture, provisioned with fresh test keys through stdin.
//!
//! The Python runner uses aiocoap's OSCORE implementation over real loopback UDP.
//! This server accepts exactly 24 provisioning bytes (16-byte secret, 8-byte salt),
//! prints only its endpoint, and never persists keys. It is a correctness fixture,
//! not a throughput fixture or a production credential provisioning service.
//!
//! Build with `cargo build --release --manifest-path tools/security-interop/Cargo.toml`.
//! Install `tools/security-interop/requirements.txt` into an isolated Python
//! environment and run `check.py --server PATH_TO_BINARY --output NEW_REPORT.json`.
//! `--plaintext` explicitly selects a separate diagnostic control; failures
//! remain failures. The runner checks aiocoap's native changing-token Block1
//! flow as well as the Request-Tag variant, and never retries through plaintext.
//! Peer configuration follows the installed aiocoap 0.4.16 implementation and
//! <https://aiocoap.readthedocs.io/en/latest/module/aiocoap.oscore.html>.
#![forbid(unsafe_code)]

use coaptic::oscore::{DeriveParams, SecurityContext};
use coaptic::storage::UdpSocketIo;
use coaptic::{App, Code, ContentFormat, Request, Response, get, profiles};
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

const fn pattern<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    let mut index = 0;
    while index < N {
        bytes[index] = (index % 251) as u8;
        index += 1;
    }
    bytes
}

const SMALL: [u8; 64] = pattern();
const LARGE: [u8; 2000] = pattern();

fn small(_: Request<'_>) -> Response<'static> {
    Response::content(&SMALL).content_format(ContentFormat::OCTET_STREAM)
}

fn large(_: Request<'_>) -> Response<'static> {
    Response::content(&LARGE)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}

fn upload(request: Request<'_>) -> Response<'static> {
    let body = request.body().unwrap_or_else(|| request.payload());
    if body == LARGE {
        Response::changed()
            .payload_copy(b"accepted")
            .content_format(ContentFormat::OCTET_STREAM)
    } else {
        Response::new(Code::BAD_REQUEST)
    }
}

fn observe(_: Request<'_>) -> Response<'static> {
    small_observation().observe(0)
}

fn small_observation() -> Response<'static> {
    Response::content(b"initial").content_format(ContentFormat::OCTET_STREAM)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    let plaintext = match args.nth(1).as_deref() {
        None => false,
        Some("--plaintext") => true,
        Some(_) => return Err("only --plaintext is accepted".into()),
    };
    if args.next().is_some() {
        return Err("only --plaintext is accepted".into());
    }
    let mut provisioning = [0; 24];
    std::io::stdin().read_exact(&mut provisioning)?;
    let context = SecurityContext::derive(DeriveParams {
        master_secret: &provisioning[..16],
        master_salt: &provisioning[16..],
        sender_id: &[1],
        recipient_id: &[],
        id_context: &[],
    })?;
    provisioning.fill(0);
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let endpoint = socket.local_addr()?;
    socket.set_nonblocking(true)?;
    let builder = App::profile::<profiles::Default>()
        .routes::<4>()
        .block_wise::<true>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("small", get(small).post(upload))
        .route("large", get(large).put(upload))
        .route("observe", get(observe));
    let builder = if plaintext {
        builder.allow_plaintext()
    } else {
        builder.oscore(context)
    };
    let mut app = builder.bind(UdpSocketIo::new(socket, [0; 1473])?)?;
    println!("{endpoint}");
    std::io::stdout().flush()?;
    let origin = Instant::now();
    let mut next_notify = 200u64;
    loop {
        let now = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        match app.poll(now) {
            Ok(()) | Err(coaptic::app::Error::Oscore(_)) => {}
            Err(error) => return Err(error.into()),
        }
        if now >= next_notify {
            app.notify(
                now,
                &["observe"],
                Response::content(b"notification").content_format(ContentFormat::OCTET_STREAM),
            )?;
            next_notify = now.saturating_add(200);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
