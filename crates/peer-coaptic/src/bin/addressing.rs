//! Host-only direct UDP addressing fixture. Local bind and remote identity differ.
#![forbid(unsafe_code)]
use coaptic::storage::{DatagramIo, DatagramTransport, Endpoint, UdpSocketIo, profiles};
use coaptic::{App, Code, Response, get};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

type Error = Box<dyn std::error::Error + Send + Sync>;
const BODY: &[u8] = b"coaptic-scoped-addressing";
// Constrained has 1152-byte RX datagrams. The adapter needs one extra byte
// to distinguish a complete packet from an oversized/truncated receive.
const RECEIVE_SCRATCH: usize = 1153;
const TRACE_LIMIT: usize = 64;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn address(value: &str, remote: bool) -> Result<SocketAddr, Error> {
    let parsed: SocketAddr = value.parse()?;
    if remote && parsed.port() == 0 {
        return Err("remote port must be nonzero".into());
    }
    if let SocketAddr::V6(v6) = parsed {
        if v6.ip().is_unicast_link_local() && v6.scope_id() == 0 {
            return Err("link-local address requires a nonzero numeric scope ID".into());
        }
        if v6.flowinfo() != 0 {
            return Err("fixture flow label must be zero".into());
        }
    }
    Ok(parsed)
}

struct TraceIo {
    inner: UdpSocketIo<[u8; RECEIVE_SCRATCH]>,
    events: usize,
}
impl TraceIo {
    fn emit(&mut self, value: serde_json::Value) -> io::Result<()> {
        if self.events == TRACE_LIMIT {
            return Err(io::Error::other("fixture trace limit"));
        }
        self.events += 1;
        println!("{value}");
        Ok(())
    }
    fn error(&mut self, operation: &str, error: &io::Error) {
        let _ = self.emit(
            serde_json::json!({"event":"io-error", "operation":operation,
            "kind":format!("{:?}",error.kind()), "raw_os_error":error.raw_os_error()}),
        );
    }
}
impl DatagramTransport for TraceIo {
    type Error = io::Error;
}
impl DatagramIo for TraceIo {
    fn recv(&mut self, bytes: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
        match self.inner.recv(bytes) {
            Ok(Some((length, peer))) => {
                self.emit(
                    serde_json::json!({"event":"receive", "peer":SocketAddr::from(peer).to_string(),
                    "scope_id":peer.scope_id(), "hex":hex(&bytes[..length])}),
                )?;
                Ok(Some((length, peer)))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                self.error("receive", &error);
                Err(error)
            }
        }
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
        self.emit(
            serde_json::json!({"event":"send-attempt", "peer":SocketAddr::from(peer).to_string(),
            "scope_id":peer.scope_id(), "hex":hex(bytes)}),
        )?;
        match self.inner.send(peer, bytes) {
            Ok(length) => {
                self.emit(serde_json::json!({"event":"sent", "bytes":length}))?;
                Ok(length)
            }
            Err(error) => {
                self.error("send", &error);
                Err(error)
            }
        }
    }
}

fn run(args: &[String]) -> Result<(), Error> {
    let server = args.first().is_some_and(|value| value == "server");
    if !(server && args.len() == 3
        || args.first().is_some_and(|v| v == "client") && args.len() == 4)
    {
        return Err("addressing server BIND DURATION_MS | client BIND REMOTE TIMEOUT_MS".into());
    }
    let bind = address(&args[1], false)?;
    let remote = if server {
        None
    } else {
        Some(address(&args[2], true)?)
    };
    if remote.is_some_and(|peer| peer.is_ipv6() != bind.is_ipv6()) {
        return Err("bind and remote address families differ".into());
    }
    let deadline = args.last().expect("validated arguments").parse::<u64>()?;
    if !(100..=30000).contains(&deadline) {
        return Err("deadline must be 100..30000 ms".into());
    }
    let socket = UdpSocket::bind(bind)?;
    socket.set_nonblocking(true)?;
    let local = socket.local_addr()?;
    let transport = TraceIo {
        inner: UdpSocketIo::new(socket, [0; RECEIVE_SCRATCH])?,
        events: 0,
    };
    let mut app = App::profile::<profiles::Constrained>()
        .block_wise::<false>()
        .routes::<1>()
        .allow_unprotected()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("/test", get(|_| Response::content(BODY)))
        .bind(transport)
        .map_err(|error| format!("bind: {error}"))?;
    println!(
        "{}",
        serde_json::json!({"event":"ready", "local":local.to_string(),
        "remote":remote.map(|peer|peer.to_string()), "security":"unprotected",
        "profile":"Constrained; blockwise=false; routes=1", "calls":4, "deferred":0,
        "requests":4, "association_slots":1, "udp_receive_scratch":RECEIVE_SCRATCH,
        "trace_limit":TRACE_LIMIT})
    );
    let start = Instant::now();
    let call = remote
        .map(|peer| app.get("/test").to(peer.into()).send(1))
        .transpose()
        .map_err(|error| format!("send: {error}"))?;
    while start.elapsed() < Duration::from_millis(deadline) {
        let now = start.elapsed().as_millis() as u64 + 1;
        app.poll(now).map_err(|error| format!("poll: {error}"))?;
        if let Some(call) = call
            && let Some(result) = app.take_response(call)
        {
            let response = result.map_err(|error| format!("call: {error}"))?;
            if response.code() != Code::CONTENT || response.payload() != BODY {
                return Err("wrong application bytes/code".into());
            }
            println!(
                "{}",
                serde_json::json!({"event":"complete", "code":69,"hex":hex(response.payload())})
            );
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if let Some(call) = call {
        app.cancel(call);
        return Err("bounded fixture deadline without matching response".into());
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            println!(
                "{}",
                serde_json::json!({"event":"error","message":error.to_string()})
            );
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unprotected_server_starts_and_exits_at_its_deadline() {
        run(&["server".into(), "127.0.0.1:0".into(), "100".into()]).unwrap();
    }

    #[test]
    fn explicit_local_and_remote_scope_survive_endpoint_conversion() {
        let bind = address("[fe80::10%7]:0", false).unwrap();
        let peer = address("[fe80::20%7]:5683", true).unwrap();
        assert_ne!(bind.ip(), peer.ip());
        assert_eq!(SocketAddr::from(Endpoint::from(peer)), peer);
        assert_eq!(Endpoint::from(peer).scope_id(), 7);
        assert_ne!(
            Endpoint::from(peer),
            Endpoint::from(address("[fe80::20%8]:5683", true).unwrap())
        );
    }
    #[test]
    fn missing_zone_and_zero_remote_port_refused() {
        assert!(address("[fe80::20]:5683", true).is_err());
        assert!(address("[fe80::20%0]:5683", true).is_err());
        assert!(address("[::1]:0", true).is_err());
        assert!(address("[::1]:0", false).is_ok());
    }
}
