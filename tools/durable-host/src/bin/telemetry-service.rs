//! Finite host qualification service, never an enrollment authority.
//!
//! Usage: telemetry-service provision|provision-journal|serve BIND PEER CREDENTIALS SECURITY JOURNAL
//! BINDING TIMEOUT_MS MAX_POLLS RUN_ID [drop-first-receipt]
//!
//! The operator-private credential record is the same 66-byte layout used by
//! waveshare-peer. BINDING is a caller-authenticated exact 140-byte fixture:
//! store ID[32], generation u64 big endian, policy digest[32], pinned P-256 public
//! key[33], key ID[1], resource[32], Content-Format u16 big endian (65535 = absent).
//! This explicitly associates the pairwise credentials with that principal; it
//! does not derive the principal from OSCORE or claim enrolled ownership.
//! `provision` creates missing security/journal files offline and refuses existing
//! paths. `provision-journal` creates only the missing journal from BINDING; it
//! never opens credentials/security or sockets and never advances security state.
//! Use it to add telemetry to an already provisioned pairwise context. `serve`
//! authenticates and restores existing security normally. Interrupted provisioning is an
//! operator-reconciliation case; it never falls back to resetting either record.
#![forbid(unsafe_code)]
use coaptic::provisioning::{PinnedPeer, TrustAnchor};
use coaptic::storage::UdpSocketIo;
use coaptic_durable_host::{Authority, Journal, MAX_ROWS, Policy, telemetry};
use coaptic_esphome_probe::{
    host_state::{FileStore, credentials},
    security_state,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, UdpSocket},
    path::Path,
    time::{Duration, Instant},
};

fn binding(path: &Path) -> Result<(Policy, Option<u16>), &'static str> {
    let mut file = std::fs::File::open(path).map_err(|_| "binding unavailable")?;
    if file.metadata().map_err(|_| "binding metadata")?.len() != 140 {
        return Err("binding length");
    }
    let mut bytes = [0; 140];
    file.read_exact(&mut bytes).map_err(|_| "binding read")?;
    let anchor = TrustAnchor::from_parts(
        bytes[..32].try_into().unwrap(),
        u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
        bytes[40..72].try_into().unwrap(),
    )
    .map_err(|_| "binding anchor")?;
    let principal = PinnedPeer::from_public_key(bytes[72..105].try_into().unwrap(), bytes[105])
        .map_err(|_| "binding principal")?
        .principal();
    let format = u16::from_be_bytes(bytes[138..140].try_into().unwrap());
    Ok((
        Policy {
            anchor,
            principal,
            resource: bytes[106..138].try_into().unwrap(),
            enabled: true,
        },
        (format != u16::MAX).then_some(format),
    ))
}
fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().collect();
    if !(11..=12).contains(&args.len()) {
        return Err(
            "usage: telemetry-service provision|provision-journal|serve BIND PEER CREDENTIALS SECURITY JOURNAL BINDING TIMEOUT_MS MAX_POLLS RUN_ID [drop-first-receipt]",
        );
    }
    let drop_first = args
        .get(11)
        .map(|v| v == "drop-first-receipt")
        .unwrap_or(false);
    if args.len() == 12 && !drop_first {
        return Err("unknown fault option");
    }
    let run_id = &args[10];
    if run_id.len() != 32 || !run_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("run ID");
    }
    let (policy, content_format) = binding(Path::new(&args[7]))?;
    let authority = Authority::new(policy);
    if args[1] == "provision-journal" {
        Journal::create(Path::new(&args[6]), authority, MAX_ROWS)
            .map_err(|_| "journal provisioning")?;
        println!("{{\"run_id\":\"{run_id}\",\"journal_provisioned\":true}}");
        return Ok(());
    }
    let credentials = credentials(Path::new(&args[4]))?;
    if args[1] == "provision" {
        let mut security = FileStore::open(Path::new(&args[5]), true)?;
        security_state::provision(&mut security, &credentials)
            .map_err(|_| "security provisioning")?;
        Journal::create(Path::new(&args[6]), authority, MAX_ROWS)
            .map_err(|_| "journal provisioning")?;
        println!("{{\"run_id\":\"{run_id}\",\"provisioned\":true}}");
        return Ok(());
    }
    if args[1] != "serve" {
        return Err("unknown mode");
    }
    let bind: SocketAddr = args[2].parse().map_err(|_| "bind address")?;
    let peer: SocketAddr = args[3].parse().map_err(|_| "peer address")?;
    let timeout_ms: u64 = args[8].parse().map_err(|_| "timeout")?;
    let max_polls: u32 = args[9].parse().map_err(|_| "poll limit")?;
    if timeout_ms == 0 || max_polls == 0 {
        return Err("zero work limit");
    }
    let security = FileStore::open(Path::new(&args[5]), false)?;
    let mut journal =
        Journal::open(Path::new(&args[6]), authority).map_err(|_| "journal recovery")?;
    let socket = UdpSocket::bind(bind).map_err(|_| "bind refused")?;
    socket
        .set_nonblocking(true)
        .map_err(|_| "nonblocking socket")?;
    let io = UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "UDP adapter")?;
    let clock = Instant::now();
    let report = telemetry::run_with_ready(
        io,
        |bytes| getrandom::fill(bytes).is_ok(),
        || {
            std::thread::sleep(Duration::from_millis(1));
            u64::try_from(clock.elapsed().as_millis()).ok()
        },
        telemetry::Binding {
            peer: peer.into(),
            credentials: &credentials,
            policy,
            content_format,
            timeout_ms,
            max_polls,
            drop_first_receipt: drop_first,
        },
        security,
        &mut journal,
        || {
            println!("{{\"ready\":true,\"run_id\":\"{run_id}\"}}");
            std::io::stdout().flush().is_ok()
        },
    )
    .map_err(|_| "service stopped on failure; recover retained records")?;
    println!(
        "{{\"run_id\":\"{run_id}\",\"polls\":{},\"admitted\":{},\"refused\":{},\"poll_errors\":{},\"receipts\":{},\"dropped_receipts\":{},\"effects\":{}}}",
        report.polls,
        report.admitted,
        report.refused,
        report.poll_errors,
        report.receipts,
        report.dropped_receipts,
        report.effects
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
