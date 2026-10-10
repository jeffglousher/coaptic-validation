//! Finite source-bound protected Waveshare checks; not a production host service.
//! Credentials/state live in an operator-private directory. State is exclusively
//! locked; every update uses sync_all and authenticated readback. This qualifies
//! normal process/device restart separately from flash/power-loss/rollback.
use coaptic::message::{Message, MessageId, Opt, Token, Type, decode};
use coaptic::oscore::SecurityContext;
use coaptic::storage::{DatagramIo, UdpSocketIo};
use coaptic::{App, Code, Endpoint, profiles};
use coaptic_esphome_probe::security_state::{
    Credentials, Error, RECORD_BYTES, State, Store, provision,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, &'static str>;

struct FileStore {
    file: File,
    initializing: bool,
}
impl FileStore {
    fn open(path: &Path, initializing: bool) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(initializing);
        let file = options.open(path).map_err(|_| "state open refused")?;
        file.try_lock()
            .map_err(|_| "state exclusively owned elsewhere")?;
        Ok(Self { file, initializing })
    }
}
impl Store for FileStore {
    fn read(&mut self) -> std::result::Result<Option<[u8; RECORD_BYTES]>, Error> {
        let length = self.file.metadata().map_err(|_| Error::Unavailable)?.len();
        if self.initializing && length == 0 {
            return Ok(None);
        }
        if length != RECORD_BYTES as u64 {
            return Err(Error::Corrupt);
        }
        let mut bytes = [0; RECORD_BYTES];
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Unavailable)?;
        self.file
            .read_exact(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        Ok(Some(bytes))
    }
    fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> std::result::Result<(), Error> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Unavailable)?;
        self.file.write_all(bytes).map_err(|_| Error::Unavailable)?;
        self.file.sync_all().map_err(|_| Error::Unavailable)?;
        self.initializing = false;
        Ok(())
    }
}

fn credentials(path: &Path) -> Result<Credentials> {
    let mut file = File::open(path).map_err(|_| "credentials unavailable")?;
    if file.metadata().map_err(|_| "credential metadata")?.len() != 66 {
        return Err("credential length");
    }
    let mut bytes = [0; 66];
    file.read_exact(&mut bytes)
        .map_err(|_| "credentials read")?;
    let c = Credentials {
        secret: bytes[..32].try_into().unwrap(),
        salt: bytes[32..48].try_into().unwrap(),
        context: bytes[48..64].try_into().unwrap(),
        sender: bytes[64],
        recipient: bytes[65],
    };
    bytes.fill(0);
    Ok(c)
}

struct CaptureIo {
    io: UdpSocketIo<[u8; 1153]>,
    first: [u8; 1152],
    length: usize,
}
impl DatagramIo for CaptureIo {
    type Error = std::io::Error;
    fn recv(&mut self, bytes: &mut [u8]) -> std::io::Result<Option<(usize, Endpoint)>> {
        self.io.recv(bytes)
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        let sent = self.io.send(peer, bytes)?;
        if self.length == 0
            && sent == bytes.len()
            && decode(bytes)
                .is_ok_and(|packet| packet.oscore().is_some() && !packet.code().is_response())
        {
            self.first[..bytes.len()].copy_from_slice(bytes);
            self.length = bytes.len();
        }
        Ok(sent)
    }
}
type Client = App<profiles::Constrained, CaptureIo, { coaptic::app::DEFAULT_ROUTES }, true>;

struct RequestSpec<'a> {
    code: Code,
    path: &'static str,
    payload: &'a [u8],
}

fn query(
    client: &mut Client,
    state: &mut State<'_, FileStore>,
    clock: &Instant,
    peer: Endpoint,
    request: RequestSpec<'_>,
    output: &mut [u8],
) -> Result<(Code, usize)> {
    let RequestSpec {
        code,
        path,
        payload,
    } = request;
    let now = clock.elapsed().as_millis() as u64;
    let call = (if code == Code::GET {
        client.get(path)
    } else {
        client.post(path)
    })
    .payload(payload)
    .to(peer)
    .send(now)
    .map_err(|_| "send")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        client
            .poll(clock.elapsed().as_millis() as u64)
            .map_err(|_| "poll")?;
        // Client-response state is persisted before exposing a completed result.
        state
            .checkpoint(
                client
                    .oscore()
                    .ok_or("context missing")?
                    .replay_checkpoint(),
            )
            .map_err(|_| "checkpoint")?;
        if let Some(reply) = client
            .take_response_into(call, output)
            .map_err(|_| "response buffer")?
        {
            let reply = reply.map_err(|_| "exchange failed")?;
            return Ok((reply.code(), reply.payload().len()));
        }
        if Instant::now() >= deadline {
            return Err("deadline");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn no_response(socket: &UdpSocket, peer: SocketAddr, bytes: &[u8]) -> Result<()> {
    socket.send_to(bytes, peer).map_err(|_| "probe send")?;
    let mut out = [0; 1153];
    match socket.recv_from(&mut out) {
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(())
        }
        _ => Err("refused probe received a datagram"),
    }
}
fn raw_request(context: &mut SecurityContext, mid: u16) -> Result<([u8; 1152], usize)> {
    let options = [Opt::uri_path("test")];
    let plain = Message::new(Type::Confirmable, Code::GET, MessageId::new(mid))
        .with_token(Token::new(b"probe").unwrap())
        .with_options(&options);
    let mut wire = [0; 1152];
    let n = context
        .protect_request(&plain, &mut wire)
        .map_err(|_| "probe protect")?;
    Ok((wire, n))
}

fn verify_saved_identity(c: &Credentials, bytes: &[u8]) -> Result<()> {
    // Authenticate locally before using silence as evidence. This does not send
    // a fresh request, which would advance (and could mask loss of) device state.
    let mirror = Credentials {
        secret: c.secret,
        salt: c.salt,
        context: c.context,
        sender: c.recipient,
        recipient: c.sender,
    };
    let mut verifier =
        SecurityContext::derive(mirror.parameters()).map_err(|_| "saved request context")?;
    let mut opened = [0; 1152];
    let (request, _) = verifier
        .unprotect_request(
            &decode(bytes).map_err(|_| "saved request decode")?,
            &mut opened,
        )
        .map_err(|_| "saved request authentication")?;
    let mut path = request.uri_path();
    if request.code() != Code::GET || path.next() != Some(Ok("identity")) || path.next().is_some() {
        return Err("saved request identity");
    }
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 {
        return Err(
            "usage: waveshare-peer provision|check|replay ADDRESS CREDENTIALS STATE SAVED_WIRE RUN_ID",
        );
    }
    let c = credentials(Path::new(&args[3]))?;
    if args[1] == "provision" {
        let mut store = FileStore::open(Path::new(&args[4]), true)?;
        provision(&mut store, &c).map_err(|_| "explicit provisioning refused")?;
        println!("{{\"passed\":true,\"case\":\"offline_host_state_provisioning\"}}");
        return Ok(());
    }
    let peer: SocketAddr = args[2].parse().map_err(|_| "peer address")?;
    if !peer.is_ipv4() {
        return Err("this finite driver requires IPv4");
    }
    let probe = UdpSocket::bind("0.0.0.0:0").map_err(|_| "probe bind")?;
    probe
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|_| "probe timeout")?;
    if !["check", "replay"].contains(&args[1].as_str())
        || args[6].len() != 32
        || !args[6].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("network mode/run identity");
    }
    let store = FileStore::open(Path::new(&args[4]), false)?;
    let (mut state, context) = State::recover(store, &c).map_err(|_| "host security recovery")?;
    let start = context.sender_seq();
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| "bind")?;
    socket.set_nonblocking(true).map_err(|_| "nonblocking")?;
    let mut client = App::profile::<profiles::Constrained>()
        .block_wise::<true>()
        .full_responses()
        .randomness(|b| getrandom::fill(b).is_ok())
        .oscore(context)
        .bind(CaptureIo {
            io: UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "scratch")?,
            first: [0; 1152],
            length: 0,
        })
        .map_err(|_| "app bind")?;
    let clock = Instant::now();
    let mut output = [0; 4096];
    if args[1] == "replay" {
        let mut f = File::open(&args[5]).map_err(|_| "saved wire unavailable")?;
        let len = f.metadata().map_err(|_| "wire metadata")?.len() as usize;
        if len == 0 || len > 1152 {
            return Err("saved wire length");
        }
        let mut bytes = [0; 1152];
        f.read_exact(&mut bytes[..len]).map_err(|_| "wire read")?;
        verify_saved_identity(&c, &bytes[..len])?;
        // These must be the first protected packets after the observed restart.
        // Establish fresh authenticated liveness only after testing the old wire.
        for _ in 0..3 {
            no_response(&probe, peer, &bytes[..len])?;
        }
        let (code, n) = query(
            &mut client,
            &mut state,
            &clock,
            peer.into(),
            RequestSpec {
                code: Code::GET,
                path: "identity",
                payload: &[],
            },
            &mut output,
        )?;
        if code != Code::CONTENT || &output[..n] != args[6].as_bytes() {
            return Err("firmware liveness after replay refusal");
        }
        println!(
            "{{\"passed\":true,\"case\":\"replay_first_then_authenticated_identity\",\"refusal_attempts\":3,\"sender_start\":{start},\"scope\":\"requires independently observed device restart and no intervening protected traffic\"}}"
        );
        return Ok(());
    }
    let (code, n) = query(
        &mut client,
        &mut state,
        &clock,
        peer.into(),
        RequestSpec {
            code: Code::GET,
            path: "identity",
            payload: &[],
        },
        &mut output,
    )?;
    if code != Code::CONTENT || &output[..n] != args[6].as_bytes() {
        return Err("firmware run identity mismatch");
    }
    let captured = client.transport_mut();
    let mut f = File::create_new(&args[5]).map_err(|_| "saved wire already exists")?;
    f.write_all(&captured.first[..captured.length])
        .map_err(|_| "wire save")?;
    f.sync_all().map_err(|_| "wire sync")?;
    let (code, n) = query(
        &mut client,
        &mut state,
        &clock,
        peer.into(),
        RequestSpec {
            code: Code::GET,
            path: "large",
            payload: &[],
        },
        &mut output,
    )?;
    if code != Code::CONTENT || n != 2000 || output[..n].iter().any(|b| *b != 0x5a) {
        return Err("complete blockwise body mismatch");
    }
    let (code, n) = query(
        &mut client,
        &mut state,
        &clock,
        peer.into(),
        RequestSpec {
            code: Code::POST,
            path: "echo",
            payload: &[0x5a; 128],
        },
        &mut output,
    )?;
    if code != Code::CONTENT || n != 128 || output[..n] != [0x5a; 128] {
        return Err("echo exact-bound mismatch");
    }
    let (code, n) = query(
        &mut client,
        &mut state,
        &clock,
        peer.into(),
        RequestSpec {
            code: Code::POST,
            path: "echo",
            payload: &[0x5a; 129],
        },
        &mut output,
    )?;
    if code != Code::REQUEST_ENTITY_TOO_LARGE || n != 0 {
        return Err("echo overflow not refused");
    }
    let options = [Opt::uri_path("test")];
    let plain = Message::new(Type::Confirmable, Code::GET, MessageId::new(0x7000))
        .with_token(Token::new(b"plain").unwrap())
        .with_options(&options);
    let mut bytes = [0; 1152];
    let n = plain.encode(&mut bytes).map_err(|_| "plain encode")?;
    probe
        .send_to(&bytes[..n], peer)
        .map_err(|_| "plain probe send")?;
    let (n, from) = probe
        .recv_from(&mut bytes)
        .map_err(|_| "plaintext refusal response")?;
    let refusal = decode(&bytes[..n]).map_err(|_| "plaintext refusal decode")?;
    if from != peer || refusal.code() != Code::UNAUTHORIZED {
        return Err("plaintext accepted");
    }
    let mut wrong = Credentials {
        secret: c.secret,
        salt: c.salt,
        context: c.context,
        sender: c.sender,
        recipient: c.recipient,
    };
    wrong.secret[0] ^= 1;
    let mut wrong_context =
        SecurityContext::derive(wrong.parameters()).map_err(|_| "wrong-key fixture")?;
    wrong_context
        .set_sender_seq(1 << 20)
        .map_err(|_| "wrong-key counter")?;
    let (bytes, n) = raw_request(&mut wrong_context, 0x7001)?;
    no_response(&probe, peer, &bytes[..n])?;
    let (mut bytes, n) = raw_request(client.oscore_mut().ok_or("context missing")?, 0x7002)?;
    bytes[n - 1] ^= 1;
    no_response(&probe, peer, &bytes[..n])?;
    let capture = client.transport_mut();
    no_response(&probe, peer, &capture.first[..capture.length])?;
    let (code, n) = query(
        &mut client,
        &mut state,
        &clock,
        peer.into(),
        RequestSpec {
            code: Code::GET,
            path: "test",
            payload: &[],
        },
        &mut output,
    )?;
    if code != Code::CONTENT || &output[..n] != b"coaptic" {
        return Err("valid recovery request failed");
    }
    println!(
        "{{\"passed\":true,\"cases\":[\"protected_firmware_identity\",\"protected_complete_block2_2000\",\"echo_128\",\"echo_129_refusal\",\"plaintext_refusal\",\"wrong_key_refusal\",\"tamper_refusal\",\"replay_refusal\",\"valid_after_refusals\"],\"sender_start\":{start},\"sender_end\":{},\"state_generation\":{},\"scope\":\"finite Coaptic-to-Coaptic IPv4; no enrollment/effects/power-loss proof\"}}",
        client.oscore().unwrap().sender_reservation_end().unwrap(),
        state.generation()
    );
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification refused: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saved_identity_requires_authentication_and_exact_path() {
        let c = Credentials {
            secret: [0x31; 32],
            salt: [0x52; 16],
            context: [0x73; 16],
            sender: 1,
            recipient: 2,
        };
        let mut context = SecurityContext::derive(c.parameters()).unwrap();
        let options = [Opt::uri_path("identity")];
        let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(7))
            .with_token(Token::new(b"old").unwrap())
            .with_options(&options);
        let mut bytes = [0; 1152];
        let n = context.protect_request(&request, &mut bytes).unwrap();
        assert!(verify_saved_identity(&c, &bytes[..n]).is_ok());
        bytes[n - 1] ^= 1;
        assert!(verify_saved_identity(&c, &bytes[..n]).is_err());
        bytes[n - 1] ^= 1;
        let mut foreign = Credentials {
            secret: c.secret,
            salt: c.salt,
            context: c.context,
            sender: c.sender,
            recipient: c.recipient,
        };
        foreign.secret[0] ^= 1;
        assert!(verify_saved_identity(&foreign, &bytes[..n]).is_err());
        assert!(verify_saved_identity(&c, &[]).is_err());
        let options = [Opt::uri_path("identity"), Opt::uri_path("extra")];
        let request =
            Message::new(Type::Confirmable, Code::GET, MessageId::new(8)).with_options(&options);
        let n = context.protect_request(&request, &mut bytes).unwrap();
        assert_eq!(
            verify_saved_identity(&c, &bytes[..n]),
            Err("saved request identity")
        );
    }

    #[test]
    fn replay_response_is_failure_even_before_fresh_liveness() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let responder = std::thread::spawn(move || {
            let mut bytes = [0; 32];
            let (_, peer) = server.recv_from(&mut bytes).unwrap();
            server.send_to(b"accepted stale request", peer).unwrap();
        });
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(
            no_response(&probe, address, b"saved protected request"),
            Err("refused probe received a datagram")
        );
        responder.join().unwrap();
    }

    #[test]
    fn file_store_refuses_concurrent_owner_truncation_and_implicit_creation() {
        let root = std::env::temp_dir().join(format!("coaptic-state-proof-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("state");
        assert!(FileStore::open(&path, false).is_err());
        let mut first = FileStore::open(&path, true).unwrap();
        assert!(FileStore::open(&path, false).is_err());
        assert!(first.read().unwrap().is_none());
        first.commit(&[0x39; RECORD_BYTES]).unwrap();
        assert_eq!(first.read().unwrap(), Some([0x39; RECORD_BYTES]));
        assert!(FileStore::open(&path, true).is_err());
        first.file.set_len(99).unwrap();
        assert_eq!(first.read(), Err(Error::Corrupt));
        drop(first);
        let mut reopened = FileStore::open(&path, false).unwrap();
        assert_eq!(reopened.read(), Err(Error::Corrupt));
        drop(reopened);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
