//! Taste of [`coaptic::App`]: stateless `Request` → `Response`, one `poll` loop.
//!
//! ```text
//! cargo run --example coap_server --features std
//! ```
//!
//! Client GET `/sensors/temp` → 2.05 Content. PUT `/leds/0` → 2.04 Changed
//! (no in-App LED bag; real LED state is firmware-owned). GET `/leds/0` →
//! demo payload. GET `/large` → a payload that does not fit one datagram,
//! shipped as outgoing Block2 from a TX body. `/.well-known/core` is
//! link-format from registered paths. Observe: return `.observe(0)` on a
//! successful GET to register; `app.notify(now_ms, path, response)` sends
//! later representations. Handlers see borrowed `Request` fields and
//! return owned `Response`. Engine slot identifiers stay off this path.

use std::net::UdpSocket;
use std::time::Instant;

use coaptic::message::{
    BlockValue, EncodedUint, Ids, Message, MessageId, Opt, OptionsBuilder, ParsedMessage, Token,
    Type, decode, encode,
};
use coaptic::storage::DatagramIo;
use coaptic::{App, Code, ContentFormat, Endpoint, Request, Response, get, profiles};

fn get_temp(_req: Request<'_>) -> Response<'static> {
    Response::content(b"21.5").content_format(ContentFormat::TEXT_PLAIN)
}

fn get_led(_: Request<'_>) -> Response<'static> {
    // Demo payload. Real LED state is firmware-owned, not an App bag.
    Response::content(b"off")
}

fn put_led(_req: Request<'_>) -> Response<'static> {
    Response::changed()
}

const LARGE: [u8; 2000] = [b'A'; 2000];

fn get_large(_: Request<'_>) -> Response<'static> {
    Response::content(&LARGE).content_format(ContentFormat::OCTET_STREAM)
}

fn now_ms(origin: Instant) -> u64 {
    u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let origin = Instant::now();

    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let mut client = UdpSocket::bind("127.0.0.1:0")?;
    let server_ep = Endpoint::from(socket.local_addr()?);
    let timeout = std::time::Duration::from_millis(200);
    socket.set_read_timeout(Some(timeout))?;
    client.set_read_timeout(Some(timeout))?;

    let mut app = App::profile::<profiles::Default>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .route("sensors/temp", get(get_temp))
        .route("leds/0", get(get_led).put(put_led))
        .route("large", get(get_large))
        .well_known_core()
        .bind(socket)?;

    send_client(&mut client, server_ep, Code::GET, &["sensors", "temp"], &[]);
    app.poll(now_ms(origin))?;
    expect_reply(&mut client, Code::CONTENT, Some(b"21.5"))?;

    send_client(&mut client, server_ep, Code::PUT, &["leds", "0"], b"1");
    app.poll(now_ms(origin))?;
    expect_reply(&mut client, Code::CHANGED, None)?;

    send_client(&mut client, server_ep, Code::GET, &["leds", "0"], &[]);
    app.poll(now_ms(origin))?;
    expect_reply(&mut client, Code::CONTENT, Some(b"off"))?;

    send_client(
        &mut client,
        server_ep,
        Code::GET,
        &[".well-known", "core"],
        &[],
    );
    app.poll(now_ms(origin))?;
    expect_reply(
        &mut client,
        Code::CONTENT,
        Some(b"</sensors/temp>,</leds/0>,</large>"),
    )?;

    fetch_large(&mut client, &mut app, server_ep, origin)?;

    eprintln!(
        "coap_server: 2.05 \"21.5\"; PUT led Changed; GET demo off; well-known/core; GET /large Block2"
    );
    Ok(())
}

fn fetch_large<T: DatagramIo>(
    client: &mut T,
    app: &mut App<profiles::Default, UdpSocket, { coaptic::app::DEFAULT_ROUTES }, true>,
    server: Endpoint,
    origin: Instant,
) -> Result<(), Box<dyn std::error::Error>>
where
    T::Error: core::fmt::Debug + std::error::Error + 'static,
{
    let token = Token::mint(2, &[0xC0, 0xA1]).expect("token");
    send_path(client, server, token, 0x2100, &["large"], None);
    app.poll(now_ms(origin))?;
    let (n0, more) = recv_block(client, 0)?;
    assert!(more);
    assert_eq!(n0, 1024);

    let next = BlockValue::from_size(1, false, 1024)
        .expect("num 1")
        .encode();
    send_path(client, server, token, 0x2101, &["large"], Some(next));
    app.poll(now_ms(origin))?;
    let (n1, more) = recv_block(client, 1)?;
    assert!(!more);
    assert_eq!(n0 + n1, LARGE.len());
    Ok(())
}

fn send_path<T: DatagramIo>(
    client: &mut T,
    server: Endpoint,
    token: Token,
    mid: u16,
    path: &[&str],
    block2: Option<EncodedUint>,
) where
    T::Error: core::fmt::Debug,
{
    let mut opts = OptionsBuilder::<4>::new();
    for segment in path {
        opts.push(Opt::uri_path(segment)).expect("path room");
    }
    if let Some(ref encoded) = block2 {
        opts.push(Opt::block2(encoded)).expect("block2");
    }
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(mid))
        .with_token(token)
        .with_options(opts.as_slice());
    let mut wire = [0u8; 1472];
    let n = encode(&msg, &mut wire).expect("encode");
    client.send(server, &wire[..n]).expect("client send");
}

fn recv_block<T: DatagramIo>(
    client: &mut T,
    want_num: u32,
) -> Result<(usize, bool), Box<dyn std::error::Error>>
where
    T::Error: core::fmt::Debug + std::error::Error + 'static,
{
    let mut buf = [0u8; 1472];
    let n = match DatagramIo::recv(client, &mut buf)? {
        Some((n, _)) => n,
        None => return Err("client expected a Block2 response".into()),
    };
    let parsed: ParsedMessage<'_> = decode(&buf[..n])?;
    assert_eq!(parsed.code(), Code::CONTENT);
    let block = parsed.block2().expect("Block2").expect("val");
    assert_eq!(block.num(), want_num);
    Ok((parsed.payload().len(), block.more()))
}

fn send_client<T: DatagramIo>(
    client: &mut T,
    server: Endpoint,
    code: Code,
    path: &[&str],
    payload: &[u8],
) where
    T::Error: core::fmt::Debug,
{
    let token = Token::mint(2, &[0xC0, 0xA1]).expect("token");
    let mut ids = Ids::new(0x1000);
    let mut opts = OptionsBuilder::<4>::new();
    for segment in path {
        opts.push(Opt::uri_path(segment)).expect("path room");
    }
    let msg = ids
        .con(code, token)
        .with_options(opts.as_slice())
        .with_payload(payload);
    let mut wire = [0u8; 1472];
    let n = encode(&msg, &mut wire).expect("encode");
    client.send(server, &wire[..n]).expect("client send");
}

fn expect_reply<T: DatagramIo>(
    client: &mut T,
    code: Code,
    payload: Option<&[u8]>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T::Error: core::fmt::Debug + std::error::Error + 'static,
{
    let mut buf = [0u8; 1472];
    let n = match DatagramIo::recv(client, &mut buf)? {
        Some((n, _)) => n,
        None => return Err("client expected a response".into()),
    };
    let parsed: ParsedMessage<'_> = decode(&buf[..n])?;
    assert_eq!(parsed.code(), code);
    if let Some(expected) = payload {
        assert_eq!(parsed.payload(), expected);
    }
    Ok(())
}
