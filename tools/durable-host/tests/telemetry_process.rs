use coaptic::provisioning::{OperationId, Receipt, TelemetryOperation};
use coaptic::storage::UdpSocketIo;
use coaptic::{App, Code, ContentFormat, profiles};
use coaptic_esphome_probe::{host_state::FileStore, security_state as security};
use std::{
    io::{BufRead, Read},
    net::UdpSocket,
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
mod support;
const RUN: &str = "0123456789abcdef0123456789abcdef";
struct Process {
    child: Child,
    output: mpsc::Receiver<String>,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Process {
    fn finish(mut self) -> String {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "host service did not stop within its finite budget"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        self.output.recv_timeout(Duration::from_secs(2)).unwrap()
    }
}
fn args(root: &Path, mode: &str, address: &str, peer: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_telemetry-service"));
    command
        .arg(mode)
        .arg(address)
        .arg(peer)
        .arg(root.join("credentials"))
        .arg(root.join("security"))
        .arg(root.join("journal"))
        .arg(root.join("binding"))
        .args(["400", "600", RUN]);
    command
}
fn start(root: &Path, address: &str, peer: &str, drop_reply: bool) -> Process {
    let mut command = args(root, "serve", address, peer);
    if drop_reply {
        command.arg("drop-first-receipt");
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        tx.send(line).unwrap();
        let mut rest = String::new();
        reader.read_to_string(&mut rest).unwrap();
        let _ = tx.send(rest);
    });
    let process = Process { child, output: rx };
    let ready = process.output.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(ready.contains("\"ready\":true"), "{ready}");
    process
}
fn credentials() -> security::Credentials {
    security::Credentials {
        secret: [0x91; 32],
        salt: [0x83; 16],
        context: [0x72; 16],
        sender: 1,
        recipient: 2,
    }
}
fn request(
    root: &Path,
    socket: UdpSocket,
    peer: std::net::SocketAddr,
    expect_reply: bool,
) -> Option<Receipt> {
    let c = credentials();
    let store = FileStore::open(&root.join("client-security"), false).unwrap();
    let (mut security, context) = security::State::recover(store, &c).unwrap();
    socket.set_nonblocking(true).unwrap();
    let io = UdpSocketIo::new(socket, [0; 1153]).unwrap();
    let mut client = App::profile::<profiles::Constrained>()
        .block_wise::<false>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .oscore(context)
        .require_oscore_checkpoint()
        .bind(io)
        .unwrap();
    let mut wire = [0x37; 16 + 1024];
    wire[..16].fill(0x29);
    let call = client
        .post("telemetry")
        .to(peer.into())
        .content_format(ContentFormat::new(42))
        .payload(&wire)
        .deadline(300)
        .send(0)
        .unwrap();
    let clock = Instant::now();
    let mut bytes = [0; 56];
    loop {
        let now = clock.elapsed().as_millis() as u64;
        if now >= 250 {
            assert!(!expect_reply, "protected receipt missing");
            return None;
        }
        client
            .poll_with_oscore_checkpoint(now, |c| security.checkpoint(c).is_ok())
            .unwrap();
        if let Some(response) = client.take_response_into(call, &mut bytes).unwrap() {
            let response = response.unwrap();
            assert!(expect_reply);
            assert_eq!(response.code(), Code::CHANGED);
            return Some(Receipt::decode(response.payload()).unwrap());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[test]
fn child_service_lost_reply_then_restart_recovers_exact_durable_receipt() {
    let root = std::env::temp_dir().join(format!(
        "coaptic-host-service-process-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let c = credentials();
    let mut bytes = Vec::new();
    bytes.extend(c.secret);
    bytes.extend(c.salt);
    bytes.extend(c.context);
    bytes.extend([2, 1]);
    std::fs::write(root.join("credentials"), bytes).unwrap();
    let policy = support::policy(1);
    let (store, generation, digest) = policy.anchor.parts();
    let mut binding = Vec::new();
    binding.extend(store);
    binding.extend(generation.to_be_bytes());
    binding.extend(digest);
    binding.extend([
        0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96,
    ]);
    binding.push(1);
    binding.extend(policy.resource);
    binding.extend(42_u16.to_be_bytes());
    std::fs::write(root.join("binding"), binding).unwrap();
    let mut client_store = FileStore::open(&root.join("client-security"), true).unwrap();
    security::provision(&mut client_store, &c).unwrap();
    drop(client_store);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = client.local_addr().unwrap();
    let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let provision = args(&root, "provision", &address.to_string(), &peer.to_string())
        .output()
        .unwrap();
    assert!(provision.status.success());
    assert!(
        !args(&root, "provision", &address.to_string(), &peer.to_string())
            .output()
            .unwrap()
            .status
            .success()
    );
    let first = start(&root, &address.to_string(), &peer.to_string(), true);
    assert!(request(&root, client.try_clone().unwrap(), address, false).is_none());
    let report = first.finish();
    assert!(report.contains("\"effects\":1"), "{report}");
    assert!(report.contains("\"dropped_receipts\":1"), "{report}");
    let second = start(&root, &address.to_string(), &peer.to_string(), false);
    let receipt = request(&root, client, address, true).unwrap();
    assert_eq!(receipt.sequence(), 1);
    let payload = [0x37; 1024];
    let operation = TelemetryOperation::new(
        OperationId::new([0x29; 16]),
        policy.resource,
        Some(42),
        &payload,
    )
    .unwrap();
    assert_eq!(receipt.id(), operation.id());
    assert_eq!(receipt.digest(), operation.digest());
    let report = second.finish();
    assert!(report.contains("\"effects\":1"), "{report}");
    assert!(report.contains("\"receipts\":1"), "{report}");
    for name in [
        "credentials",
        "security",
        "journal",
        "binding",
        "client-security",
    ] {
        std::fs::remove_file(root.join(name)).unwrap();
    }
    std::fs::remove_dir(root).unwrap();
}
