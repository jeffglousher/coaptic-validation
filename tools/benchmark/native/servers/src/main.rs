//! Independent server fixtures; no request-path logging or shared driver code.
//!
//! `coaptic` and `coaptic-reusable` select the bare socket and caller-owned
//! scratch adapters once at startup. Both accept an optional RX capacity of
//! 1472 or 2048 bytes and share the same App configuration and polling loop.
//! TX capacity stays 1472 bytes; reusable scratch reserves 2049 bytes once.
//! Setup allocations precede the external driver's timed request phase.
//!
//! `coaptic-ready` uses Tokio's registered UDP socket, caller-owned scratch,
//! and readiness-driven bounded drain bursts. Idle waits end at the next
//! millisecond of the App clock so protocol timers still progress without
//! incoming traffic. This is a host scheduling experiment, not a core change.
//! `coaptic-mio` applies the same policy directly through Mio without an async
//! runtime. These variants retain the same protocol processing and pools.
#![forbid(unsafe_code)]
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, ResponseType};
use coaptic::storage::{AllocMemory, Capacities, DatagramIo, Endpoint, UdpSocketIo};
use coaptic::{App, ContentFormat, Request, Response, get};
use std::{
    env,
    net::UdpSocket,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

static BODY: OnceLock<&'static [u8]> = OnceLock::new();

fn representation(_: Request<'_>) -> Response<'static> {
    Response::content(BODY.get().expect("initialized fixture"))
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}

fn bind_fixture<T: DatagramIo<Error = std::io::Error>>(
    io: T,
    bytes: usize,
    rx_bytes: usize,
) -> Result<App<coaptic::profiles::Default, T, 1, true, AllocMemory>, Box<dyn std::error::Error>> {
    let capacities = Capacities {
        rx_datagram_slots: 4,
        rx_datagram_bytes: rx_bytes,
        tx_datagram_slots: 4,
        tx_datagram_bytes: 1472,
        dedup_entries: 8,
        observe_entries: 4,
        rx_body_slots: Some(1),
        rx_body_bytes: Some(bytes.div_ceil(1024) * 1024),
        tx_body_slots: Some(2),
        tx_body_bytes: Some(bytes.div_ceil(1024) * 1024),
    };
    Ok(App::builder()
        .allow_plaintext()
        .routes::<1>()
        .block_wise::<true>()
        .randomness(|buffer| getrandom::fill(buffer).is_ok())
        .route("bench", get(representation))
        .bind_alloc(io, capacities)?)
}

fn coaptic_server<T: DatagramIo<Error = std::io::Error>>(
    io: T,
    bytes: usize,
    rx_bytes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = bind_fixture(io, bytes, rx_bytes)?;
    let started = Instant::now();
    loop {
        app.poll(started.elapsed().as_millis() as u64)?;
    }
}

struct ReadyUdp {
    socket: tokio::net::UdpSocket,
    scratch: [u8; 2049],
    received: bool,
}

fn receive_guarded(
    buf: &mut [u8],
    scratch: &mut [u8],
    recv: impl FnOnce(&mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)>,
) -> std::io::Result<Option<(usize, Endpoint)>> {
    let required = buf
        .len()
        .checked_add(1)
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    let scratch = scratch
        .get_mut(..required)
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    match recv(scratch) {
        Ok((n, peer)) if n <= buf.len() => {
            buf[..n].copy_from_slice(&scratch[..n]);
            Ok(Some((n, peer.into())))
        }
        Ok(_) => Err(std::io::ErrorKind::InvalidData.into()),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

impl DatagramIo for ReadyUdp {
    type Error = std::io::Error;

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        self.received = false;
        let result = receive_guarded(buf, &mut self.scratch, |scratch| {
            self.socket.try_recv_from(scratch)
        });
        self.received = result.as_ref().is_ok_and(Option::is_some);
        result
    }

    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.socket
            .try_send_to(bytes, std::net::SocketAddr::from(dest))
    }
}

struct MioUdp {
    socket: mio::net::UdpSocket,
    scratch: [u8; 2049],
    received: bool,
}

impl DatagramIo for MioUdp {
    type Error = std::io::Error;

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        self.received = false;
        let result = receive_guarded(buf, &mut self.scratch, |scratch| {
            self.socket.recv_from(scratch)
        });
        self.received = result.as_ref().is_ok_and(Option::is_some);
        result
    }

    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.socket.send_to(bytes, std::net::SocketAddr::from(dest))
    }
}

fn mio_server(
    address: &str,
    bytes: usize,
    rx_bytes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(address)?;
    socket.set_nonblocking(true)?;
    let mut io = MioUdp {
        socket: mio::net::UdpSocket::from_std(socket),
        scratch: [0; 2049],
        received: false,
    };
    let mut poll = mio::Poll::new()?;
    poll.registry()
        .register(&mut io.socket, mio::Token(0), mio::Interest::READABLE)?;
    let mut events = mio::Events::with_capacity(8);
    let mut app = bind_fixture(io, bytes, rx_bytes)?;
    let started = Instant::now();
    loop {
        let mut idle = false;
        for _ in 0..32 {
            app.poll(started.elapsed().as_millis() as u64)?;
            if !app.transport().received {
                idle = true;
                break;
            }
        }
        let timeout = if idle {
            let now = Instant::now();
            let next_tick =
                started + Duration::from_millis(now.duration_since(started).as_millis() as u64 + 1);
            next_tick.saturating_duration_since(now)
        } else {
            Duration::ZERO
        };
        match poll.poll(&mut events, Some(timeout)) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        }
    }
}

async fn ready_server(
    address: &str,
    bytes: usize,
    rx_bytes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let io = ReadyUdp {
        socket: tokio::net::UdpSocket::bind(address).await?,
        scratch: [0; 2049],
        received: false,
    };
    let mut app = bind_fixture(io, bytes, rx_bytes)?;
    let started = Instant::now();
    loop {
        let mut idle = false;
        for _ in 0..32 {
            app.poll(started.elapsed().as_millis() as u64)?;
            if !app.transport().received {
                idle = true;
                break;
            }
        }
        if idle {
            let next_tick =
                started + Duration::from_millis(started.elapsed().as_millis() as u64 + 1);
            if let Ok(ready) =
                tokio::time::timeout_at(next_tick.into(), app.transport().socket.readable()).await
            {
                ready?;
            }
        } else {
            tokio::task::yield_now().await;
        }
    }
}

fn codec_server(address: &str, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(address)?;
    let mut bytes = [0u8; 65_535];
    loop {
        let (count, peer) = socket.recv_from(&mut bytes)?;
        let request = match Packet::from_bytes(&bytes[..count]) {
            Ok(packet) => packet,
            Err(_) => continue,
        };
        if request.header.code != MessageClass::Request(coap_lite::RequestType::Get) {
            continue;
        }
        let block = request
            .get_option(CoapOption::Block2)
            .and_then(|values| values.front())
            .map(|v| {
                v.iter()
                    .fold(0usize, |value, byte| value << 8 | usize::from(*byte))
            });
        let number = block.unwrap_or(0) >> 4;
        let size = if let Some(value) = block {
            1usize << ((value & 7).min(6) + 4)
        } else {
            1024
        };
        let offset = number * size;
        if offset >= body.len() {
            continue;
        }
        let end = (offset + size).min(body.len());
        let mut response = Packet::new();
        response
            .header
            .set_type(if request.header.get_type() == MessageType::Confirmable {
                MessageType::Acknowledgement
            } else {
                MessageType::NonConfirmable
            });
        response.header.message_id = request.header.message_id;
        response.header.code = MessageClass::Response(ResponseType::Content);
        response.set_token(request.get_token().to_vec());
        response.payload = body[offset..end].to_vec();
        response.set_option(CoapOption::ContentFormat, [vec![42]].into());
        if block.is_some() || body.len() > 1024 {
            let raw = number << 4
                | usize::from(end < body.len()) << 3
                | (size.trailing_zeros() as usize - 4);
            let value = (raw as u32).to_be_bytes();
            let first = value.iter().position(|byte| *byte != 0).unwrap_or(4);
            response.set_option(CoapOption::Block2, [value[first..].to_vec()].into());
        }
        socket.send_to(&response.to_bytes()?, peer)?;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if !(5..=6).contains(&args.len()) {
        return Err(
            "usage: bench-rust-server coaptic|coaptic-reusable|coaptic-ready|coaptic-mio|coap-rs|coap-lite-codec HOST PORT BYTES [RX_BYTES]".into(),
        );
    }
    let rx_bytes: usize = args
        .get(5)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1472);
    if ![1472, 2048].contains(&rx_bytes) {
        return Err("receive capacity must be 1472 or 2048".into());
    }
    if args.len() == 6
        && !matches!(
            args[1].as_str(),
            "coaptic" | "coaptic-reusable" | "coaptic-ready" | "coaptic-mio"
        )
    {
        return Err("receive capacity is supported only by the Coaptic fixtures".into());
    }
    let size: usize = args[4].parse()?;
    if !(1..=1_048_576).contains(&size) {
        return Err("fixture size".into());
    }
    let body: &'static [u8] = Box::leak(
        (0..size)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    BODY.set(body).map_err(|_| "fixture initialization")?;
    let address = format!("{}:{}", args[2], args[3]);
    match args[1].as_str() {
        "coaptic" | "coaptic-reusable" => {
            let socket = UdpSocket::bind(&address)?;
            socket.set_nonblocking(true)?;
            if args[1] == "coaptic-reusable" {
                coaptic_server(UdpSocketIo::new(socket, [0u8; 2049])?, size, rx_bytes)
            } else {
                coaptic_server(socket, size, rx_bytes)
            }
        }
        "coap-lite-codec" => codec_server(&address, body),
        "coaptic-mio" => mio_server(&address, size, rx_bytes),
        "coaptic-ready" => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(ready_server(&address, size, rx_bytes)),
        "coap-rs" => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(async {
                let server = coap::Server::new_udp(&address)?;
                let body: Arc<[u8]> = Arc::from(body);
                server
                    .run(
                        move |mut request: Box<coap_lite::CoapRequest<std::net::SocketAddr>>| {
                            let body = Arc::clone(&body);
                            async move {
                                if let Some(response) = request.response.as_mut() {
                                    response.message.header.code =
                                        MessageClass::Response(ResponseType::Content);
                                    response.message.payload = body.to_vec();
                                    response
                                        .message
                                        .set_option(CoapOption::ContentFormat, [vec![42]].into());
                                }
                                request
                            }
                        },
                    )
                    .await?;
                Ok(())
            }),
        _ => Err("unknown implementation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mio_readiness_receive_preserves_exact_oversized_and_recovery_datagrams() {
        for host in ["127.0.0.1:0", "[::1]:0"] {
            for capacity in [64, 1472, 2048] {
                let socket = UdpSocket::bind(host).unwrap();
                socket.set_nonblocking(true).unwrap();
                let local = socket.local_addr().unwrap();
                let sender = UdpSocket::bind(host).unwrap();
                let peer = sender.local_addr().unwrap();
                let mut io = MioUdp {
                    socket: mio::net::UdpSocket::from_std(socket),
                    scratch: [0; 2049],
                    received: false,
                };
                let mut poll = mio::Poll::new().unwrap();
                poll.registry()
                    .register(&mut io.socket, mio::Token(0), mio::Interest::READABLE)
                    .unwrap();
                let mut events = mio::Events::with_capacity(8);
                let mut buf = vec![0; capacity];
                for size in [capacity, capacity + 1, capacity + 8, 3] {
                    let payload = vec![0x39; size];
                    sender.send_to(&payload, local).unwrap();
                    buf.fill(0xa5);
                    let deadline = Instant::now() + Duration::from_secs(1);
                    let result = loop {
                        let timeout = deadline.saturating_duration_since(Instant::now());
                        assert!(!timeout.is_zero(), "receive deadline");
                        poll.poll(&mut events, Some(timeout)).unwrap();
                        match io.recv(&mut buf) {
                            Ok(None) => continue,
                            result => break result,
                        }
                    };
                    if size <= capacity {
                        assert_eq!(result.unwrap(), Some((size, peer.into())));
                        assert_eq!(&buf[..size], payload);
                        assert!(io.received);
                    } else {
                        assert!(result.is_err());
                        assert!(buf.iter().all(|byte| *byte == 0xa5));
                        assert!(!io.received);
                    }
                    assert!(io.recv(&mut buf).unwrap().is_none());
                    assert!(!io.received);
                }
                sender
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                assert_eq!(io.send(peer.into(), b"reply").unwrap(), 5);
                let mut reply = [0; 6];
                assert_eq!(sender.recv_from(&mut reply).unwrap(), (5, local));
                assert_eq!(&reply[..5], b"reply");
            }
        }
    }

    #[test]
    fn readiness_receive_preserves_exact_oversized_and_recovery_datagrams() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                for host in ["127.0.0.1:0", "[::1]:0"] {
                    for capacity in [64, 1472, 2048] {
                        let socket = tokio::net::UdpSocket::bind(host).await.unwrap();
                        let local = socket.local_addr().unwrap();
                        let sender = UdpSocket::bind(host).unwrap();
                        let peer = sender.local_addr().unwrap();
                        let mut io = ReadyUdp {
                            socket,
                            scratch: [0; 2049],
                            received: false,
                        };
                        let mut buf = vec![0; capacity];
                        for size in [capacity, capacity + 1, capacity + 8, 3] {
                            let payload = vec![0x39; size];
                            sender.send_to(&payload, local).unwrap();
                            buf.fill(0xa5);
                            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
                            let result = loop {
                                tokio::time::timeout_at(deadline, io.socket.readable())
                                    .await
                                    .unwrap()
                                    .unwrap();
                                match io.recv(&mut buf) {
                                    Ok(None) => continue,
                                    result => break result,
                                }
                            };
                            if size <= capacity {
                                assert_eq!(result.unwrap(), Some((size, peer.into())));
                                assert_eq!(&buf[..size], payload);
                                assert!(io.received);
                            } else {
                                assert!(result.is_err());
                                assert!(buf.iter().all(|byte| *byte == 0xa5));
                                assert!(!io.received);
                            }
                        }
                        sender
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        assert_eq!(io.send(peer.into(), b"reply").unwrap(), 5);
                        let mut reply = [0; 6];
                        assert_eq!(sender.recv_from(&mut reply).unwrap(), (5, local));
                        assert_eq!(&reply[..5], b"reply");
                    }
                }
            });
    }
}
