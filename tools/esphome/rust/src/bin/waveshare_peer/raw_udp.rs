//! Finite raw UDP boundary campaign; device success requires independent counter grading.
use super::{Client, FileStore, RequestSpec, Result, State, query};
use coaptic::Code;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(super) const LENGTHS: [usize; 4] = [1153, 2047, 2048, 4096];
const COUNT: usize = 64;
fn stamp() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock epoch")?
        .as_millis())
}
fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("String write");
    }
    value
}
fn record(out: &mut File, value: &str) -> Result<()> {
    writeln!(out, "{value}")
        .and_then(|()| out.flush())
        .map_err(|_| "report write")
}
fn valid_control(path: &str, code: Code, body: &[u8], run: &str) -> bool {
    code == Code::CONTENT
        && match path {
            "identity" => body == run.as_bytes(),
            "large" => body == [0x5a; 2000],
            "echo" => body == [0x5a; 128],
            "ticks" => body.len() == 4,
            _ => false,
        }
}
fn controls(
    client: &mut Client,
    state: &mut State<'_, FileStore>,
    clock: &Instant,
    peer: SocketAddr,
    run: &str,
    phase: usize,
    out: &mut File,
) -> Result<u32> {
    let mut output = [0; 4096];
    let mut tick = 0;
    for (path, payload) in [
        ("identity", &[][..]),
        ("large", &[][..]),
        ("echo", &[0x5a; 128][..]),
        ("ticks", &[][..]),
    ] {
        let begin = stamp()?;
        let (code, n) = query(
            client,
            state,
            clock,
            peer.into(),
            RequestSpec {
                code: if path == "echo" {
                    Code::POST
                } else {
                    Code::GET
                },
                path,
                payload,
            },
            &mut output,
        )?;
        if !valid_control(path, code, &output[..n], run) {
            return Err("raw UDP protected control mismatch");
        }
        if path == "ticks" {
            tick = u32::from_be_bytes(output[..4].try_into().expect("checked length"));
        }
        record(
            out,
            &format!(
                "{{\"event\":\"control\",\"phase\":{phase},\"path\":\"{path}\",\"start_ms\":{begin},\"end_ms\":{},\"code\":69,\"body_hex\":\"{}\"}}",
                stamp()?,
                hex(&output[..n])
            ),
        )?;
    }
    Ok(tick)
}
pub(super) fn campaign(
    client: &mut Client,
    state: &mut State<'_, FileStore>,
    clock: &Instant,
    probe: &UdpSocket,
    peer: SocketAddr,
    run: &str,
    path: &Path,
) -> Result<()> {
    // create_new preserves original evidence; incomplete reports never contain completion.
    let mut out = File::create_new(path).map_err(|_| "raw report already exists")?;
    let executable = std::env::current_exe().map_err(|_| "tool path")?;
    if executable.metadata().map_err(|_| "tool metadata")?.len() > 16_000_000 {
        return Err("tool byte bound");
    }
    let binary = std::fs::read(executable).map_err(|_| "tool read")?;
    record(
        &mut out,
        &format!(
            "{{\"event\":\"begin\",\"schema\":\"coaptic-raw-udp/1\",\"clock\":\"host_utc\",\"peer\":\"{peer}\",\"run_id\":\"{run}\",\"start_ms\":{},\"binary_sha256\":\"{}\"}}",
            stamp()?,
            hex(&Sha256::digest(binary))
        ),
    )?;
    let begin = Instant::now();
    let mut tick = controls(client, state, clock, peer, run, 0, &mut out)?;
    probe.set_nonblocking(true).map_err(|_| "raw nonblocking")?;
    let packet = [0xa5; 4096];
    for (group, length) in LENGTHS.into_iter().enumerate() {
        std::thread::sleep(Duration::from_millis(300));
        let digest = hex(&Sha256::digest(&packet[..length]));
        for index in 0..COUNT {
            if begin.elapsed() > Duration::from_secs(120) {
                return Err("raw campaign deadline");
            }
            let sent = probe
                .send_to(&packet[..length], peer)
                .map_err(|_| "raw send")?;
            if sent != length {
                return Err("raw short send");
            }
            record(
                &mut out,
                &format!(
                    "{{\"event\":\"packet\",\"group\":{group},\"index\":{index},\"length\":{length},\"at_ms\":{},\"sha256\":\"{digest}\"}}",
                    stamp()?
                ),
            )?;
            std::thread::sleep(Duration::from_millis(2));
        }
        let mut unexpected = [0; 4097];
        match probe.recv_from(&mut unexpected) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            _ => return Err("unexpected raw response or receive error"),
        }
        let next = controls(client, state, clock, peer, run, group + 1, &mut out)?;
        if next <= tick {
            return Err("protected timer did not progress");
        }
        tick = next;
    }
    if begin.elapsed() > Duration::from_secs(120) {
        return Err("raw campaign deadline");
    }
    record(
        &mut out,
        &format!(
            "{{\"event\":\"complete\",\"end_ms\":{},\"packet_count\":256,\"device_qualified\":false}}",
            stamp()?
        ),
    )?;
    out.sync_all().map_err(|_| "report sync")?;
    println!(
        "{{\"passed\":true,\"case\":\"raw_udp_host_campaign\",\"device_qualified\":false,\"scope\":\"requires independently captured source-bound device counters\"}}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_authenticated_controls_refuse_short_wrong_and_error_results() {
        for (path, body) in [
            ("identity", &b"0123456789abcdef0123456789abcdef"[..]),
            ("large", &[0x5a; 2000][..]),
            ("echo", &[0x5a; 128][..]),
            ("ticks", &[0, 0, 0, 1][..]),
        ] {
            let run = "0123456789abcdef0123456789abcdef";
            assert!(valid_control(path, Code::CONTENT, body, run));
            assert!(!valid_control(
                path,
                Code::CONTENT,
                &body[..body.len() - 1],
                run
            ));
            assert!(!valid_control(path, Code::SERVICE_UNAVAILABLE, body, run));
            if path != "ticks" {
                let mut changed = body.to_vec();
                changed[0] ^= 1;
                assert!(!valid_control(path, Code::CONTENT, &changed, run));
            }
        }
        assert!(!valid_control("unknown", Code::CONTENT, &[], ""));
    }
}
