//! Timed coaptic ↔ coap-rs dogfood, plus a coaptic↔coaptic Observe notify collect.
//!
//! ```text
//! cargo run -p coaptic-plugtest --bin dogfood
//! cargo run -p coaptic-plugtest --bin dogfood -- --iterations 2
//! cargo run -p coaptic-plugtest --bin dogfood -- --json dogfood.json
//! cargo run -p coaptic-plugtest --bin dogfood -- --iterations 2 --compare crates/coaptic-plugtest/baselines/dogfood.json
//! cargo run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore
//! cargo run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore --iterations 2 --compare crates/coaptic-plugtest/baselines/dogfood-oscore.json
//! ```
//!
//! Mixed-stack loops (both directions) are GET/PUT/POST, Observe
//! **register/deregister**, and Block1/Block2 against coap-rs under the
//! same timed load as the rest of the bin. The run fails if those
//! [`Metrics`] stay cold (`observe_register` / `observe_cancel` /
//! Block assemble), even without `--compare`. coap-rs is a
//! register/deregister stub: the notify leg is coaptic-server
//! [`App::notify`] collected by a coaptic-client [`App::take_response`]
//! so [`Metrics::observe_notify`] is not left cold.
//!
//! `--oscore` (crate feature `oscore`) adds a coaptic↔coaptic OSCORE
//! GET/PUT/POST loop plus Observe register/notify collect and Inner
//! Block-wise (Block2 GET /large, Block1 PUT /large-update): mirrored
//! caller-owned SecurityContexts, `App::set_oscore` on both sides.
//! The run fails if protect/unprotect, protected notify, or protected
//! Block1/Block2 stays cold, a captured non-empty datagram lacks the
//! OSCORE option, or a token-matching plain 2.xx / plaintext notify
//! completes a Call. The `coap` 0.28 peer has no OSCORE API, so that
//! path stays coaptic↔coaptic.
//!
//! [`App::reset_metrics`] / [`Engine::reset_metrics`] run at the start of
//! each timed window (`progress` counts idle poll ticks). After each
//! window it prints occupancy and [`coaptic::Metrics`] from
//! [`App::metrics`] / [`Engine::metrics`]. Optional `--json PATH` writes
//! the same numbers. Optional `--compare PATH` diffs against a checked-in
//! baseline: **fail** if path-proving counters drop or error counters
//! rise (including mixed-pair `sum(block1_assemble)` / `sum(block2_assemble)`,
//! so a pair-local 0 floor cannot hide a cold assemble path); **print**
//! wall-timing deltas (host/load specific, not a fail). `progress` stays
//! informational. N=2 CI smoke is a lock, not a perf SLA.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use coaptic::app::DEFAULT_ROUTES;
use coaptic::message::{Code, ContentFormat};
use coaptic::storage::{DatagramIo, Engine, Storage};
use coaptic::{App, Call, Endpoint, Metrics, Response, profiles};
use serde::{Deserialize, Serialize};

#[cfg(feature = "oscore")]
use coaptic::message::{Message, Opt, Token, Type, decode, encode, encode_uint};
#[cfg(feature = "oscore")]
use coaptic::oscore::{DeriveParams, SecurityContext};

use crate::coap_rs::CoapRsPeer;
use crate::coaptic::bind_site;
use crate::pcap::bind_loopback;
#[cfg(feature = "oscore")]
use crate::pcap::{Capture, CapturingIo};
use crate::peer::{ClientRequest, ClientResponse, NotifyMailbox, Peer, PeerError};
use crate::runner::harness_lock;
use crate::site;

/// How long and how many times the mixed-stack and notify-collect loops run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Full GET/PUT/POST + Observe-register + block-wise loops per direction,
    /// and Observe notify collects on the coaptic↔coaptic leg.
    pub iterations: usize,
    /// Deadline for a small CON exchange.
    pub timeout: Duration,
    /// Deadline for Block1 / Block2 (large body).
    pub block_timeout: Duration,
    /// Write a JSON report here after a successful run (`None` = stdout only).
    pub json_path: Option<PathBuf>,
    /// Compare this run against a checked-in baseline JSON (`None` = skip).
    pub compare_path: Option<PathBuf>,
    /// OSCORE-protected coaptic↔coaptic GET/PUT/POST + Observe notify.
    pub oscore: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            iterations: 50,
            timeout: Duration::from_millis(1500),
            block_timeout: Duration::from_millis(4000),
            json_path: None,
            compare_path: None,
            oscore: false,
        }
    }
}

impl Config {
    /// Help text for the `dogfood` bin (the one command).
    pub const USAGE: &'static str = "\
cargo run -p coaptic-plugtest --bin dogfood -- [OPTIONS]

Timed dogfood over loopback UDP.

coap-rs peer (both directions, same N as the rest of the bin):
  coap-rs client → coaptic server, and coaptic client → coap-rs server.
  Each iteration is GET/PUT/POST /test, Observe register GET /obs,
  Block2 GET /large, Block1 PUT /large-update, then deregister / DELETE
  /obs. Fails if observe_register / observe_cancel or Block assemble
  stay cold (not only --compare).

Still coaptic-only:
  Observe notify collect (register /obs, App::notify, take_response,
  deregister) — coap-rs is a register/deregister stub.
  OSCORE GET/PUT/POST + notify + Inner Block (--oscore) — coap 0.28 has
  no OSCORE API.

Skip: DTLS dogfood, coap-rs OSCORE, full ETSI plugtest matrix.

--oscore (requires --features oscore) adds a coaptic↔coaptic OSCORE
GET/PUT/POST loop plus Observe register/notify collect and Inner
Block-wise (Block2 GET /large, Block1 PUT /large-update). Mirrored
caller-owned SecurityContexts; App::set_oscore on both sides. Fails if
protect/unprotect, protected notify, or protected Block stays cold, a
non-empty captured datagram is plaintext, or a token-matching plain
2.xx / plaintext notify completes a Call.

Prints wall min/mean/p50/p99/max (and Engine clock deltas on the coaptic
client). Resets `app.metrics()` around each timed window, then prints the
snapshot and a coverage section (mixed vs still coaptic-only).

--json PATH writes schema coaptic-dogfood/1 (Metrics + series timings).
--compare PATH diffs this run against that file: fail if observe_notify /
block1_assemble / block2_assemble (or other path-proving floors) drop, or
if error counters rise. Mixed-pair sum(block1_assemble) and
sum(block2_assemble) are also floors (pair-local 0 on one direction
cannot hide a cold assemble type if the other pair carries the count).
Wall timings print as delta only — host/load specific, not a fail.
progress is informational. CI smokes --iterations 2 against the
checked-in baselines (a lock, not a perf SLA). Refresh (same flags as CI):

  cargo run -p coaptic-plugtest --bin dogfood -- --iterations 2 \\
    --json crates/coaptic-plugtest/baselines/dogfood.json
  cargo run -p coaptic-plugtest --features oscore --bin dogfood -- \\
    --oscore --iterations 2 \\
    --json crates/coaptic-plugtest/baselines/dogfood-oscore.json

Default is 50 iterations (mixed coap-rs + notify; OSCORE too when --oscore).
CI smoke: --iterations 2, and --oscore --iterations 2.

Options:
  --iterations N          loops per direction + notify collects (default 50)
  --timeout-ms N          small-exchange deadline (default 1500)
  --block-timeout-ms N    Block1/Block2 deadline (default 4000)
  --json PATH             write Metrics + timings as JSON
  --compare PATH          fail on metric regression vs baseline JSON
  --oscore                OSCORE-protected coaptic↔coaptic GET/PUT/POST
                          + Observe notify + Block1/Block2
                          (requires: --features oscore)
  -h, --help              print this message
";

    /// Parse `dogfood` CLI args (`--iterations`, timeouts). Not `--help`.
    pub fn from_args<I, S>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut cfg = Self::default();
        let mut it = args.into_iter();
        while let Some(raw) = it.next() {
            let a = raw.as_ref();
            let (flag, inline) = split_flag(a);
            match flag {
                "--iterations" => {
                    cfg.iterations = parse_usize(flag, inline, &mut it)?;
                }
                "--timeout-ms" => {
                    cfg.timeout = Duration::from_millis(parse_u64(flag, inline, &mut it)?);
                }
                "--block-timeout-ms" => {
                    cfg.block_timeout = Duration::from_millis(parse_u64(flag, inline, &mut it)?);
                }
                "--json" => {
                    cfg.json_path = Some(PathBuf::from(parse_string(flag, inline, &mut it)?));
                }
                "--compare" => {
                    cfg.compare_path = Some(PathBuf::from(parse_string(flag, inline, &mut it)?));
                }
                "--oscore" => {
                    if inline.is_some() {
                        return Err("--oscore does not take a value".into());
                    }
                    cfg.oscore = true;
                }
                other => {
                    return Err(format!(
                        "unknown argument {other:?}\n{}",
                        Self::USAGE.trim_end()
                    ));
                }
            }
        }
        if cfg.iterations == 0 {
            return Err("--iterations must be >= 1".into());
        }
        if cfg.oscore && !cfg!(feature = "oscore") {
            return Err(
                "--oscore requires: cargo run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore"
                    .into(),
            );
        }
        Ok(cfg)
    }
}

fn split_flag(a: &str) -> (&str, Option<&str>) {
    match a.split_once('=') {
        Some((flag, val)) => (flag, Some(val)),
        None => (a, None),
    }
}

fn parse_usize(
    flag: &str,
    inline: Option<&str>,
    it: &mut impl Iterator<Item = impl AsRef<str>>,
) -> Result<usize, String> {
    parse_u64(flag, inline, it)?
        .try_into()
        .map_err(|_| format!("{flag} is too large"))
}

fn parse_u64(
    flag: &str,
    inline: Option<&str>,
    it: &mut impl Iterator<Item = impl AsRef<str>>,
) -> Result<u64, String> {
    let raw = parse_string(flag, inline, it)?;
    raw.parse::<u64>()
        .map_err(|_| format!("{flag}: expected a number, got {raw:?}"))
}

fn parse_string(
    flag: &str,
    inline: Option<&str>,
    it: &mut impl Iterator<Item = impl AsRef<str>>,
) -> Result<String, String> {
    match inline {
        Some(v) if !v.is_empty() => Ok(v.to_owned()),
        Some(_) => Err(format!("{flag} needs a value")),
        None => it
            .next()
            .map(|s| s.as_ref().to_owned())
            .ok_or_else(|| format!("{flag} needs a value")),
    }
}

/// Run mixed-stack directions, the notify collect, and write timing + metrics.
pub fn run(cfg: Config, mut out: impl Write) -> Result<(), PeerError> {
    let _guard = harness_lock();
    let t0 = Instant::now();
    writeln!(
        out,
        "dogfood  coaptic ↔ coap-rs + notify collect{}  iterations={}  timeout={}ms  block={}ms",
        if cfg.oscore { " + OSCORE" } else { "" },
        cfg.iterations,
        cfg.timeout.as_millis(),
        cfg.block_timeout.as_millis()
    )
    .map_err(io_err)?;

    site::reset();
    let server = spawn_coaptic_server()?;
    let dest = server.addr;
    writeln!(out, "\n== coap-rs → coaptic  server={dest}").map_err(io_err)?;
    server.reset_metrics()?;
    let a = run_coap_rs_client(&cfg, dest)?;
    a.write("  ", &mut out).map_err(io_err)?;
    let rs_to_coaptic = server.snapshot();
    drop(server);
    writeln!(
        out,
        "  engine    {}  now_ms={}  (coaptic server)",
        rs_to_coaptic.occupancy, rs_to_coaptic.now_ms
    )
    .map_err(io_err)?;
    writeln!(out, "  app.metrics()  {}", rs_to_coaptic.metrics).map_err(io_err)?;

    site::reset();
    let mut rs_server = CoapRsPeer::new();
    let dest = rs_server.start_server()?;
    writeln!(out, "\n== coaptic → coap-rs  server={dest}").map_err(io_err)?;
    let (b, client_occ, client_metrics, client_now, caps) = run_coaptic_client(&cfg, dest)?;
    b.write("  ", &mut out).map_err(io_err)?;
    writeln!(
        out,
        "  engine    {client_occ}  now_ms={client_now}  (coaptic client)"
    )
    .map_err(io_err)?;
    writeln!(out, "  app.metrics()  {client_metrics}").map_err(io_err)?;
    writeln!(out, "  capacities  {caps}").map_err(io_err)?;
    rs_server.stop_server();
    prove_mixed_stack(cfg.iterations, &rs_to_coaptic.metrics, &client_metrics)?;

    site::reset();
    let server = spawn_coaptic_server()?;
    let dest = server.addr;
    writeln!(out, "\n== coaptic ↔ coaptic  observe notify  server={dest}").map_err(io_err)?;
    server.reset_metrics()?;
    let notify = run_coaptic_observe_notify(&cfg, dest, &server)?;
    notify.write("  ", &mut out).map_err(io_err)?;
    let notify_server = server.snapshot();
    drop(server);
    writeln!(
        out,
        "  engine    {}  now_ms={}  (coaptic server)",
        notify_server.occupancy, notify_server.now_ms
    )
    .map_err(io_err)?;
    writeln!(out, "  app.metrics()  {}", notify_server.metrics).map_err(io_err)?;
    writeln!(
        out,
        "  client    {}  now_ms={}  (coaptic client)",
        notify.client_occupancy, notify.client_now_ms
    )
    .map_err(io_err)?;
    writeln!(out, "  client app.metrics()  {}", notify.client_metrics).map_err(io_err)?;
    if notify_server.metrics.observe_notify == 0 || notify.collected == 0 {
        return Err(PeerError(format!(
            "observe_notify stayed cold: collected={} server observe_notify={}",
            notify.collected, notify_server.metrics.observe_notify
        )));
    }
    if notify.collected != cfg.iterations {
        return Err(PeerError(format!(
            "observe notify collected {} of {} iterations",
            notify.collected, cfg.iterations
        )));
    }

    #[cfg(feature = "oscore")]
    let oscore = if cfg.oscore {
        Some(run_oscore_section(&cfg, &mut out)?)
    } else {
        None
    };
    #[cfg(not(feature = "oscore"))]
    let oscore: Option<OscoreReport> = None;

    let wall = t0.elapsed();
    let oscore_wall = if cfg.oscore {
        format!(
            " + {} OSCORE GET/PUT/POST + {} OSCORE observe notify",
            cfg.iterations, cfg.iterations
        )
    } else {
        String::new()
    };
    writeln!(out, "\n== integration").map_err(io_err)?;
    writeln!(
        out,
        "  wall     {:.3}s  (bind + {} loops × 2 mixed + {} notify collects{oscore_wall})",
        wall.as_secs_f64(),
        cfg.iterations,
        cfg.iterations,
    )
    .map_err(io_err)?;
    writeln!(
        out,
        "  observe  collected={}  server observe_notify={}",
        notify.collected, notify_server.metrics.observe_notify
    )
    .map_err(io_err)?;
    writeln!(
        out,
        "  mixed    coap-rs→coaptic  observe_register={}  observe_cancel={}  block1_assemble={}  (server)",
        rs_to_coaptic.metrics.observe_register,
        rs_to_coaptic.metrics.observe_cancel,
        rs_to_coaptic.metrics.block1_assemble
    )
    .map_err(io_err)?;
    writeln!(
        out,
        "  mixed    coaptic→coap-rs  observe_register={}  observe_cancel={}  block2_assemble={}  (client)",
        client_metrics.observe_register, client_metrics.observe_cancel, client_metrics.block2_assemble
    )
    .map_err(io_err)?;
    if let Some(oscore) = oscore.as_ref() {
        writeln!(
            out,
            "  oscore   protected_on_wire={}  client sender_seq={}  observe_collected={}  fail-closed plain GET={}  inject dropped",
            oscore.protected_on_wire, oscore.client_sender_seq, oscore.observe_collected, oscore.plain_get_code
        )
        .map_err(io_err)?;
    }
    writeln!(
        out,
        "  metrics  app.metrics() after timed window (reset_metrics around it)"
    )
    .map_err(io_err)?;
    writeln!(
        out,
        "  caveat   wall timings print as delta; Metrics floors fail on regression"
    )
    .map_err(io_err)?;
    write_coverage(cfg.oscore, &mut out).map_err(io_err)?;
    writeln!(out, "dogfood  ok").map_err(io_err)?;

    let report = build_json_report(
        &cfg,
        wall,
        &a,
        &rs_to_coaptic,
        &b,
        &client_occ,
        &client_metrics,
        client_now,
        &caps,
        &notify,
        &notify_server,
        oscore.as_ref(),
    );
    if let Some(path) = cfg.json_path.as_ref() {
        write_json_report(path, &report)?;
        writeln!(out, "dogfood  json  {}", path.display()).map_err(io_err)?;
    }
    if let Some(path) = cfg.compare_path.as_ref() {
        compare_against_baseline(path, &report, &mut out)?;
    }
    Ok(())
}

fn io_err(e: io::Error) -> PeerError {
    PeerError(e.to_string())
}

/// Fail-closed: mixed-stack Metrics must prove the coap-rs peer actually ran.
///
/// `--compare` floors the same counters vs a baseline; this check runs even
/// without `--compare` so a stub peer cannot hide behind response codes alone.
/// Block assemble is floored per expected direction **and** as
/// `sum(block1_assemble)` / `sum(block2_assemble)` across the pair so a
/// silent swap onto the other direction's 0-floor cannot hide a cold type.
fn prove_mixed_stack(
    iterations: usize,
    rs_to_coaptic: &Metrics,
    coaptic_to_rs: &Metrics,
) -> Result<(), PeerError> {
    let n = u32::try_from(iterations).unwrap_or(u32::MAX);
    prove_floor(
        "coap-rs → coaptic observe_register",
        rs_to_coaptic.observe_register,
        n,
    )?;
    prove_floor(
        "coap-rs → coaptic observe_cancel",
        rs_to_coaptic.observe_cancel,
        n,
    )?;
    prove_floor(
        "coap-rs → coaptic block1_assemble",
        rs_to_coaptic.block1_assemble,
        n,
    )?;
    if rs_to_coaptic.rx_accepted == 0 || rs_to_coaptic.tx_ok == 0 {
        return Err(PeerError(format!(
            "mixed-stack path stayed cold: coap-rs → coaptic rx_accepted={} tx_ok={}",
            rs_to_coaptic.rx_accepted, rs_to_coaptic.tx_ok
        )));
    }
    prove_floor(
        "coaptic → coap-rs observe_register",
        coaptic_to_rs.observe_register,
        n,
    )?;
    prove_floor(
        "coaptic → coap-rs observe_cancel",
        coaptic_to_rs.observe_cancel,
        n,
    )?;
    prove_floor(
        "coaptic → coap-rs block2_assemble",
        coaptic_to_rs.block2_assemble,
        n,
    )?;
    if coaptic_to_rs.rx_accepted == 0 || coaptic_to_rs.tx_ok == 0 {
        return Err(PeerError(format!(
            "mixed-stack path stayed cold: coaptic → coap-rs rx_accepted={} tx_ok={}",
            coaptic_to_rs.rx_accepted, coaptic_to_rs.tx_ok
        )));
    }
    let block1 = rs_to_coaptic
        .block1_assemble
        .saturating_add(coaptic_to_rs.block1_assemble);
    let block2 = rs_to_coaptic
        .block2_assemble
        .saturating_add(coaptic_to_rs.block2_assemble);
    prove_floor("mixed sum(block1_assemble)", block1, n)?;
    prove_floor("mixed sum(block2_assemble)", block2, n)?;
    prove_floor(
        "mixed sum(block1_assemble)+sum(block2_assemble)",
        block1.saturating_add(block2),
        n.saturating_mul(2),
    )?;
    Ok(())
}

fn prove_floor(label: &str, got: u32, want: u32) -> Result<(), PeerError> {
    if got < want {
        Err(PeerError(format!(
            "mixed-stack path stayed cold: {label}={got} want >= {want}"
        )))
    } else {
        Ok(())
    }
}

fn write_coverage(oscore: bool, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "\n== coverage")?;
    writeln!(
        out,
        "  peer      coap-rs  GET/PUT/POST /test, OBS register/deregister /obs, Block1/Block2 (both directions)"
    )?;
    writeln!(
        out,
        "  same      Observe notify collect  (coap-rs is register/deregister only)"
    )?;
    if oscore {
        writeln!(
            out,
            "  same      OSCORE GET/PUT/POST + notify + Inner Block  (coap-rs has no OSCORE)"
        )?;
    } else {
        writeln!(out, "  same      OSCORE  (--oscore; coap-rs has no OSCORE)")?;
    }
    writeln!(
        out,
        "  skip      DTLS dogfood, coap-rs OSCORE, full ETSI plugtest matrix"
    )
}

fn occupancy_line<S: Storage>(engine: &mut Engine<S>) -> String {
    let rx = engine.rx_occupied();
    let tx = engine.tx_occupied();
    format!("occupancy rx={rx} tx={tx}")
}

fn format_capacities<S: Storage>(engine: &Engine<S>) -> String {
    let c = engine.capacities();
    format!(
        "rx_dgram={}/{} tx_dgram={}/{} dedup={} observe={} rx_body={:?}x{:?} tx_body={:?}x{:?}",
        c.rx_datagram_slots,
        c.rx_datagram_bytes,
        c.tx_datagram_slots,
        c.tx_datagram_bytes,
        c.dedup_entries,
        c.observe_entries,
        c.rx_body_slots,
        c.rx_body_bytes,
        c.tx_body_slots,
        c.tx_body_bytes
    )
}

type ClientApp<T> = App<profiles::Default, T, DEFAULT_ROUTES, true>;

struct CoapticServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    reset: Arc<AtomicBool>,
    reset_done: Arc<AtomicBool>,
    notify: NotifyMailbox,
    snapshot: Arc<Mutex<ServerSnap>>,
    join: Option<JoinHandle<()>>,
}

#[derive(Clone)]
struct ServerSnap {
    occupancy: String,
    metrics: Metrics,
    now_ms: u64,
    #[cfg(feature = "oscore")]
    oscore_sender_seq: Option<u64>,
    #[cfg(feature = "oscore")]
    oscore_replay_zero_fresh: Option<bool>,
}

impl CoapticServer {
    fn reset_metrics(&self) -> Result<(), PeerError> {
        self.reset_done.store(false, Ordering::SeqCst);
        self.reset.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_millis(200);
        while Instant::now() < deadline {
            if self.reset_done.load(Ordering::SeqCst) {
                return Ok(());
            }
            thread::yield_now();
        }
        Err(PeerError("coaptic server did not ack reset_metrics".into()))
    }

    fn snapshot(&self) -> ServerSnap {
        self.snapshot.lock().expect("snap").clone()
    }

    fn notify(&self, path: &[&str], payload: &[u8]) -> Result<(), PeerError> {
        *self.notify.lock().expect("notify") = Some((
            path.iter().map(|s| (*s).to_owned()).collect(),
            payload.to_vec(),
        ));
        Ok(())
    }
}

impl Drop for CoapticServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn spawn_coaptic_server() -> Result<CoapticServer, PeerError> {
    spawn_coaptic_server_cfg(false)
}

#[cfg(feature = "oscore")]
fn spawn_oscore_server() -> Result<CoapticServer, PeerError> {
    spawn_coaptic_server_cfg(true)
}

fn spawn_coaptic_server_cfg(attach_oscore: bool) -> Result<CoapticServer, PeerError> {
    let (sock, addr) = bind_loopback().map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let reset = Arc::new(AtomicBool::new(false));
    let reset_done = Arc::new(AtomicBool::new(false));
    let notify: NotifyMailbox = Arc::new(Mutex::new(None));
    let snapshot = Arc::new(Mutex::new(ServerSnap {
        occupancy: String::from("occupancy rx=? tx=?"),
        metrics: Metrics::ZERO,
        now_ms: 0,
        #[cfg(feature = "oscore")]
        oscore_sender_seq: None,
        #[cfg(feature = "oscore")]
        oscore_replay_zero_fresh: None,
    }));
    let stop_t = Arc::clone(&stop);
    let reset_t = Arc::clone(&reset);
    let reset_done_t = Arc::clone(&reset_done);
    let notify_t = Arc::clone(&notify);
    let snap_t = Arc::clone(&snapshot);
    let join = thread::Builder::new()
        .name("coaptic-dogfood-server".into())
        .spawn(move || {
            let mut app = bind_site(sock);
            #[cfg(feature = "oscore")]
            if attach_oscore {
                app.set_oscore(oscore_server_ctx());
            }
            #[cfg(not(feature = "oscore"))]
            let _ = attach_oscore;
            let origin = Instant::now();
            let mut pending: Option<(Vec<String>, Vec<u8>)> = None;
            while !stop_t.load(Ordering::SeqCst) {
                if reset_t.swap(false, Ordering::SeqCst) {
                    app.reset_metrics();
                    reset_done_t.store(true, Ordering::SeqCst);
                }
                let now = elapsed_ms(origin);
                let _ = app.poll(now);
                if let Some(job) = notify_t.lock().expect("n").take() {
                    pending = Some(job);
                }
                if let Some((path, payload)) = pending.take() {
                    let segs: Vec<&str> = path.iter().map(String::as_str).collect();
                    let body: &'static [u8] = if payload == site::OBS_BODY_2 {
                        site::OBS_BODY_2
                    } else if payload == site::OBS_BODY {
                        site::OBS_BODY
                    } else {
                        site::OBS_BODY_2
                    };
                    if let Ok(0) = app.notify(
                        now,
                        &segs,
                        Response::content(body).content_format(ContentFormat::TEXT_PLAIN),
                    ) {
                        pending = Some((path, payload));
                    }
                }
                let occupancy = occupancy_line(app.engine_mut());
                let metrics = app.metrics();
                #[cfg(feature = "oscore")]
                let (oscore_sender_seq, oscore_replay_zero_fresh) = match app.oscore() {
                    Some(ctx) => (Some(ctx.sender_seq()), Some(ctx.replay_fresh(0))),
                    None => (None, None),
                };
                *snap_t.lock().expect("snap") = ServerSnap {
                    occupancy,
                    metrics,
                    now_ms: now,
                    #[cfg(feature = "oscore")]
                    oscore_sender_seq,
                    #[cfg(feature = "oscore")]
                    oscore_replay_zero_fresh,
                };
                thread::yield_now();
            }
        })
        .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(5));
    Ok(CoapticServer {
        addr,
        stop,
        reset,
        reset_done,
        notify,
        snapshot,
        join: Some(join),
    })
}

fn elapsed_ms(origin: Instant) -> u64 {
    u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug)]
struct Got {
    code: Code,
    payload: Vec<u8>,
    body: Option<Vec<u8>>,
    observe: Option<u32>,
}

impl From<ClientResponse> for Got {
    fn from(r: ClientResponse) -> Self {
        Self {
            code: r.code,
            payload: r.payload,
            body: r.body,
            observe: r.observe,
        }
    }
}

impl Got {
    fn assembled_len(&self) -> usize {
        self.body.as_ref().map_or(self.payload.len(), Vec::len)
    }
}

struct Series {
    label: &'static str,
    wall_us: Vec<u64>,
    engine_ms: Vec<u64>,
}

impl Series {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            wall_us: Vec::new(),
            engine_ms: Vec::new(),
        }
    }

    fn record(&mut self, wall: Duration, engine_ms: Option<u64>) {
        self.wall_us
            .push(u64::try_from(wall.as_micros()).unwrap_or(u64::MAX));
        if let Some(ms) = engine_ms {
            self.engine_ms.push(ms);
        }
    }

    fn write(&self, indent: &str, out: &mut impl Write) -> io::Result<()> {
        let wall = summarize(&self.wall_us);
        write!(
            out,
            "{indent}{:<28} n={:<3}  wall ms  min={:.3} mean={:.3} p50={:.3} p99={:.3} max={:.3}",
            self.label,
            self.wall_us.len(),
            us_ms(wall.min),
            wall.mean / 1000.0,
            us_ms(wall.p50),
            us_ms(wall.p99),
            us_ms(wall.max)
        )?;
        if !self.engine_ms.is_empty() {
            let eng = summarize(&self.engine_ms);
            if eng.max == 0 {
                write!(out, "  engineΔ ms  all <1")?;
            } else {
                write!(
                    out,
                    "  engineΔ ms  min={} mean={:.1} max={}",
                    eng.min, eng.mean, eng.max
                )?;
            }
        }
        writeln!(out)
    }

    fn stats(&self) -> SeriesStats {
        let wall = summarize(&self.wall_us);
        let engine = if self.engine_ms.is_empty() {
            None
        } else {
            Some(summarize(&self.engine_ms))
        };
        SeriesStats {
            label: self.label.to_owned(),
            n: self.wall_us.len(),
            wall_ms: WallStats::from_us(&wall),
            engine_delta_ms: engine.as_ref().map(EngineStats::from_ms),
        }
    }
}

struct PairReport {
    get: Series,
    put: Series,
    post: Series,
    obs: Series,
    block2: Series,
    block1: Series,
    loop_: Series,
}

impl PairReport {
    fn new() -> Self {
        Self {
            get: Series::new("GET /test"),
            put: Series::new("PUT /test"),
            post: Series::new("POST /test"),
            obs: Series::new("OBS GET /obs"),
            block2: Series::new("BLOCK2 GET /large"),
            block1: Series::new("BLOCK1 PUT /large-update"),
            loop_: Series::new("LOOP (all verbs)"),
        }
    }

    fn write(&self, indent: &str, out: &mut impl Write) -> io::Result<()> {
        self.get.write(indent, out)?;
        self.put.write(indent, out)?;
        self.post.write(indent, out)?;
        self.obs.write(indent, out)?;
        self.block2.write(indent, out)?;
        self.block1.write(indent, out)?;
        self.loop_.write(indent, out)
    }

    fn series(&self) -> Vec<SeriesStats> {
        [
            &self.get,
            &self.put,
            &self.post,
            &self.obs,
            &self.block2,
            &self.block1,
            &self.loop_,
        ]
        .into_iter()
        .map(Series::stats)
        .collect()
    }
}

struct NotifyReport {
    register: Series,
    notify: Series,
    loop_: Series,
    client_occupancy: String,
    client_metrics: Metrics,
    client_now_ms: u64,
    collected: usize,
}

impl NotifyReport {
    fn write(&self, indent: &str, out: &mut impl Write) -> io::Result<()> {
        self.register.write(indent, out)?;
        self.notify.write(indent, out)?;
        self.loop_.write(indent, out)
    }

    fn series(&self) -> Vec<SeriesStats> {
        [&self.register, &self.notify, &self.loop_]
            .into_iter()
            .map(Series::stats)
            .collect()
    }
}

struct Summary {
    min: u64,
    mean: f64,
    max: u64,
    p50: u64,
    p99: u64,
}

fn summarize(samples: &[u64]) -> Summary {
    if samples.is_empty() {
        return Summary {
            min: 0,
            mean: 0.0,
            max: 0,
            p50: 0,
            p99: 0,
        };
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let sum: u128 = sorted.iter().copied().map(u128::from).sum();
    let mean = sum as f64 / sorted.len() as f64;
    Summary {
        min: *sorted.first().unwrap_or(&0),
        mean,
        max: *sorted.last().unwrap_or(&0),
        p50: percentile(&sorted, 50),
        p99: percentile(&sorted, 99),
    }
}

/// Nearest-rank: p99 on a short run is the last sample.
fn percentile(sorted: &[u64], p: u8) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len();
    let rank = (usize::from(p) * n).div_ceil(100).max(1);
    sorted[rank - 1]
}

fn us_ms(us: u64) -> f64 {
    us as f64 / 1000.0
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SeriesStats {
    label: String,
    n: usize,
    wall_ms: WallStats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    engine_delta_ms: Option<EngineStats>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WallStats {
    min: f64,
    mean: f64,
    p50: f64,
    p99: f64,
    max: f64,
}

impl WallStats {
    fn from_us(s: &Summary) -> Self {
        Self {
            min: us_ms(s.min),
            mean: s.mean / 1000.0,
            p50: us_ms(s.p50),
            p99: us_ms(s.p99),
            max: us_ms(s.max),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EngineStats {
    min: u64,
    mean: f64,
    max: u64,
}

impl EngineStats {
    fn from_ms(s: &Summary) -> Self {
        Self {
            min: s.min,
            mean: s.mean,
            max: s.max,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct MetricsDto {
    rx_accepted: u32,
    rx_error: u32,
    tx_ok: u32,
    tx_fail: u32,
    con_retransmit: u32,
    give_up: u32,
    observe_notify: u32,
    observe_register: u32,
    observe_cancel: u32,
    block1_assemble: u32,
    block2_assemble: u32,
    progress: u32,
    saturated: u32,
    nstart_reject: u32,
    empty_ack: u32,
    empty_rst: u32,
}

impl From<Metrics> for MetricsDto {
    fn from(m: Metrics) -> Self {
        Self {
            rx_accepted: m.rx_accepted,
            rx_error: m.rx_error,
            tx_ok: m.tx_ok,
            tx_fail: m.tx_fail,
            con_retransmit: m.con_retransmit,
            give_up: m.give_up,
            observe_notify: m.observe_notify,
            observe_register: m.observe_register,
            observe_cancel: m.observe_cancel,
            block1_assemble: m.block1_assemble,
            block2_assemble: m.block2_assemble,
            progress: m.progress,
            saturated: m.saturated,
            nstart_reject: m.nstart_reject,
            empty_ack: m.empty_ack,
            empty_rst: m.empty_rst,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonPair {
    name: String,
    series: Vec<SeriesStats>,
    occupancy: String,
    now_ms: u64,
    metrics: MetricsDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capacities: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collected: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oscore: Option<OscoreDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OscoreDto {
    client_sender_seq: u64,
    server_sender_seq: u64,
    protected_on_wire: usize,
    observe_collected: usize,
    fail_closed_plain_get: String,
    inject_dropped: bool,
    #[serde(default)]
    server_metrics: MetricsDto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonReport {
    schema: String,
    caveat: String,
    host: Option<String>,
    iterations: usize,
    timeout_ms: u64,
    block_timeout_ms: u64,
    wall_s: f64,
    observe_collected: usize,
    observe_notify: u32,
    oscore: bool,
    pairs: Vec<JsonPair>,
}

struct OscoreReport {
    get: Series,
    put: Series,
    post: Series,
    obs_register: Series,
    obs_notify: Series,
    block2: Series,
    block1: Series,
    loop_: Series,
    client_occupancy: String,
    client_metrics: Metrics,
    client_now_ms: u64,
    client_sender_seq: u64,
    server_sender_seq: u64,
    server_metrics: Metrics,
    protected_on_wire: usize,
    observe_collected: usize,
    plain_get_code: Code,
    injected_plain: bool,
}

impl OscoreReport {
    #[cfg(feature = "oscore")]
    fn write(&self, indent: &str, out: &mut impl Write) -> io::Result<()> {
        self.get.write(indent, out)?;
        self.put.write(indent, out)?;
        self.post.write(indent, out)?;
        self.obs_register.write(indent, out)?;
        self.obs_notify.write(indent, out)?;
        self.block2.write(indent, out)?;
        self.block1.write(indent, out)?;
        self.loop_.write(indent, out)
    }

    fn series(&self) -> Vec<SeriesStats> {
        [
            &self.get,
            &self.put,
            &self.post,
            &self.obs_register,
            &self.obs_notify,
            &self.block2,
            &self.block1,
            &self.loop_,
        ]
        .into_iter()
        .map(Series::stats)
        .collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_json_report(
    cfg: &Config,
    wall: Duration,
    rs_to_coaptic: &PairReport,
    rs_to_coaptic_snap: &ServerSnap,
    coaptic_to_rs: &PairReport,
    client_occ: &str,
    client_metrics: &Metrics,
    client_now: u64,
    caps: &str,
    notify: &NotifyReport,
    notify_server: &ServerSnap,
    oscore: Option<&OscoreReport>,
) -> JsonReport {
    let host = std::env::var("HOST")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok();
    let mut pairs = vec![
        JsonPair {
            name: MIXED_RS_TO_COAPTIC.into(),
            series: rs_to_coaptic.series(),
            occupancy: rs_to_coaptic_snap.occupancy.clone(),
            now_ms: rs_to_coaptic_snap.now_ms,
            metrics: MetricsDto::from(rs_to_coaptic_snap.metrics),
            capacities: None,
            collected: None,
            oscore: None,
        },
        JsonPair {
            name: MIXED_COAPTIC_TO_RS.into(),
            series: coaptic_to_rs.series(),
            occupancy: client_occ.to_owned(),
            now_ms: client_now,
            metrics: MetricsDto::from(*client_metrics),
            capacities: Some(caps.to_owned()),
            collected: None,
            oscore: None,
        },
        JsonPair {
            name: "coaptic ↔ coaptic observe notify".into(),
            series: notify.series(),
            occupancy: notify_server.occupancy.clone(),
            now_ms: notify_server.now_ms,
            metrics: MetricsDto::from(notify_server.metrics),
            capacities: None,
            collected: Some(notify.collected),
            oscore: None,
        },
    ];
    if let Some(oscore) = oscore {
        pairs.push(JsonPair {
            name: "coaptic ↔ coaptic OSCORE".into(),
            series: oscore.series(),
            occupancy: oscore.client_occupancy.clone(),
            now_ms: oscore.client_now_ms,
            metrics: MetricsDto::from(oscore.client_metrics),
            capacities: None,
            collected: None,
            oscore: Some(OscoreDto {
                client_sender_seq: oscore.client_sender_seq,
                server_sender_seq: oscore.server_sender_seq,
                protected_on_wire: oscore.protected_on_wire,
                observe_collected: oscore.observe_collected,
                fail_closed_plain_get: oscore.plain_get_code.to_string(),
                inject_dropped: oscore.injected_plain,
                server_metrics: MetricsDto::from(oscore.server_metrics),
            }),
        });
    }
    JsonReport {
        schema: "coaptic-dogfood/1".into(),
        caveat: "Wall timings are host/load specific (printed as delta, not a fail). Path-proving Metrics floors fail the run on regression. Mixed-pair sum(block1_assemble)+sum(block2_assemble) is a floor (N=2 smoke lock, not a perf SLA). progress is informational.".into(),
        host,
        iterations: cfg.iterations,
        timeout_ms: u64::try_from(cfg.timeout.as_millis()).unwrap_or(u64::MAX),
        block_timeout_ms: u64::try_from(cfg.block_timeout.as_millis()).unwrap_or(u64::MAX),
        wall_s: wall.as_secs_f64(),
        observe_collected: notify.collected,
        observe_notify: notify_server.metrics.observe_notify,
        oscore: cfg.oscore,
        pairs,
    }
}

fn write_json_report(path: &std::path::Path, report: &JsonReport) -> Result<(), PeerError> {
    let file = std::fs::File::create(path).map_err(|e| format!("json create {path:?}: {e}"))?;
    serde_json::to_writer_pretty(file, report).map_err(|e| format!("json write: {e}"))?;
    Ok(())
}

fn load_json_report(path: &std::path::Path) -> Result<JsonReport, PeerError> {
    let bytes = std::fs::read(path).map_err(|e| format!("compare read {path:?}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("compare parse {path:?}: {e}").into())
}

type MetricField = (&'static str, fn(&MetricsDto) -> u32);

const MIXED_RS_TO_COAPTIC: &str = "coap-rs → coaptic";
const MIXED_COAPTIC_TO_RS: &str = "coaptic → coap-rs";

fn is_mixed_pair(name: &str) -> bool {
    name == MIXED_RS_TO_COAPTIC || name == MIXED_COAPTIC_TO_RS
}

/// Block assemble totals across mixed coap-rs pairs (name-independent).
///
/// Pair-local floors of 0 on one direction are expected (server Block1 vs
/// client Block2). Flooring the sums means a silent swap onto that 0-floor
/// cannot hide a cold assemble type.
fn mixed_block_sums(pairs: &[JsonPair]) -> (u32, u32) {
    let mut block1: u32 = 0;
    let mut block2: u32 = 0;
    for p in pairs.iter().filter(|p| is_mixed_pair(&p.name)) {
        block1 = block1.saturating_add(p.metrics.block1_assemble);
        block2 = block2.saturating_add(p.metrics.block2_assemble);
    }
    (block1, block2)
}

/// Path-proving counters: a drop below the baseline is a regression.
///
/// `rx_accepted` / `tx_ok` are informational — a CON retransmit can raise
/// them on a loaded runner without meaning the path got colder.
const METRIC_FLOORS: &[MetricField] = &[
    ("observe_notify", |m| m.observe_notify),
    ("observe_register", |m| m.observe_register),
    ("observe_cancel", |m| m.observe_cancel),
    ("block1_assemble", |m| m.block1_assemble),
    ("block2_assemble", |m| m.block2_assemble),
];

/// Error / saturation counters: a rise above the baseline is a regression.
const METRIC_CEILS: &[MetricField] = &[
    ("rx_error", |m| m.rx_error),
    ("tx_fail", |m| m.tx_fail),
    ("give_up", |m| m.give_up),
    ("saturated", |m| m.saturated),
    ("nstart_reject", |m| m.nstart_reject),
];

/// Informational only (`progress` is idle poll ticks; retransmit/ACK vary with load).
const METRIC_INFO: &[MetricField] = &[
    ("rx_accepted", |m| m.rx_accepted),
    ("tx_ok", |m| m.tx_ok),
    ("progress", |m| m.progress),
    ("con_retransmit", |m| m.con_retransmit),
    ("empty_ack", |m| m.empty_ack),
    ("empty_rst", |m| m.empty_rst),
];

#[derive(Debug)]
struct CompareOutcome {
    lines: Vec<String>,
    regressions: Vec<String>,
}

impl CompareOutcome {
    fn line(&mut self, s: impl Into<String>) {
        self.lines.push(s.into());
    }

    fn floor_u32(&mut self, label: &str, got: u32, want: u32) {
        self.line(format!("  {label:<28} {want} → {got}"));
        if got < want {
            self.regressions
                .push(format!("{label} dropped {want} → {got}"));
        }
    }

    fn floor_usize(&mut self, label: &str, got: usize, want: usize) {
        self.line(format!("  {label:<28} {want} → {got}"));
        if got < want {
            self.regressions
                .push(format!("{label} dropped {want} → {got}"));
        }
    }

    fn ceil_u32(&mut self, label: &str, got: u32, want: u32) {
        self.line(format!("  {label:<28} {want} → {got}"));
        if got > want {
            self.regressions
                .push(format!("{label} rose {want} → {got}"));
        }
    }

    fn info_u32(&mut self, label: &str, got: u32, want: u32) {
        self.line(format!("  {label:<28} {want} → {got}  (informational)"));
    }
}

fn compare_reports(run: &JsonReport, baseline: &JsonReport) -> CompareOutcome {
    let mut out = CompareOutcome {
        lines: Vec::new(),
        regressions: Vec::new(),
    };
    if run.schema != baseline.schema {
        out.regressions.push(format!(
            "schema {} != baseline {}",
            run.schema, baseline.schema
        ));
    }
    if run.iterations != baseline.iterations {
        out.regressions.push(format!(
            "iterations {} != baseline {} (refresh the baseline or pass the same --iterations)",
            run.iterations, baseline.iterations
        ));
        return out;
    }
    if run.oscore != baseline.oscore {
        out.regressions.push(format!(
            "oscore {} != baseline {} (use --oscore only against the OSCORE baseline)",
            run.oscore, baseline.oscore
        ));
        return out;
    }

    out.line(format!(
        "  {:<28} {:.3}s → {:.3}s  (informational)",
        "wall_s", baseline.wall_s, run.wall_s
    ));
    out.floor_usize(
        "observe_collected",
        run.observe_collected,
        baseline.observe_collected,
    );
    out.floor_u32(
        "observe_notify",
        run.observe_notify,
        baseline.observe_notify,
    );

    let (run_b1, run_b2) = mixed_block_sums(&run.pairs);
    let (base_b1, base_b2) = mixed_block_sums(&baseline.pairs);
    out.floor_u32("sum(block1_assemble)", run_b1, base_b1);
    out.floor_u32("sum(block2_assemble)", run_b2, base_b2);
    out.floor_u32(
        "sum(block1)+sum(block2)",
        run_b1.saturating_add(run_b2),
        base_b1.saturating_add(base_b2),
    );

    for base_pair in &baseline.pairs {
        let Some(run_pair) = run.pairs.iter().find(|p| p.name == base_pair.name) else {
            out.regressions
                .push(format!("missing pair {:?}", base_pair.name));
            continue;
        };
        out.line(format!("  pair {}", base_pair.name));
        compare_metrics(&mut out, "    ", &run_pair.metrics, &base_pair.metrics);
        if let (Some(got), Some(want)) = (run_pair.collected, base_pair.collected) {
            out.floor_usize("    collected", got, want);
        }
        compare_series(&mut out, &run_pair.series, &base_pair.series);
        match (run_pair.oscore.as_ref(), base_pair.oscore.as_ref()) {
            (Some(got), Some(want)) => compare_oscore(&mut out, got, want),
            (None, Some(_)) => out.regressions.push(format!(
                "pair {:?}: OSCORE block missing from this run",
                base_pair.name
            )),
            _ => {}
        }
    }
    for run_pair in &run.pairs {
        if !baseline.pairs.iter().any(|p| p.name == run_pair.name) {
            out.line(format!(
                "  pair {}  (new vs baseline; not compared)",
                run_pair.name
            ));
        }
    }
    out
}

fn compare_metrics(out: &mut CompareOutcome, indent: &str, got: &MetricsDto, want: &MetricsDto) {
    for (name, get) in METRIC_FLOORS {
        out.floor_u32(&format!("{indent}{name}"), get(got), get(want));
    }
    for (name, get) in METRIC_CEILS {
        out.ceil_u32(&format!("{indent}{name}"), get(got), get(want));
    }
    for (name, get) in METRIC_INFO {
        out.info_u32(&format!("{indent}{name}"), get(got), get(want));
    }
}

fn compare_series(out: &mut CompareOutcome, got: &[SeriesStats], want: &[SeriesStats]) {
    for base in want {
        let Some(run) = got.iter().find(|s| s.label == base.label) else {
            out.regressions
                .push(format!("missing series {:?}", base.label));
            continue;
        };
        out.floor_usize(&format!("    series {} n", base.label), run.n, base.n);
        out.line(format!(
            "    series {:<22} p50 {:.3} → {:.3} ms  mean {:.3} → {:.3}  (informational)",
            base.label, base.wall_ms.p50, run.wall_ms.p50, base.wall_ms.mean, run.wall_ms.mean
        ));
    }
}

fn compare_oscore(out: &mut CompareOutcome, got: &OscoreDto, want: &OscoreDto) {
    out.floor_usize(
        "    oscore.observe_collected",
        got.observe_collected,
        want.observe_collected,
    );
    out.floor_usize(
        "    oscore.protected_on_wire",
        got.protected_on_wire,
        want.protected_on_wire,
    );
    if got.client_sender_seq < want.client_sender_seq {
        out.regressions.push(format!(
            "oscore.client_sender_seq dropped {} → {}",
            want.client_sender_seq, got.client_sender_seq
        ));
    }
    out.line(format!(
        "  {:<28} {} → {}",
        "oscore.client_sender_seq", want.client_sender_seq, got.client_sender_seq
    ));
    if got.server_sender_seq < want.server_sender_seq {
        out.regressions.push(format!(
            "oscore.server_sender_seq dropped {} → {}",
            want.server_sender_seq, got.server_sender_seq
        ));
    }
    out.line(format!(
        "  {:<28} {} → {}",
        "oscore.server_sender_seq", want.server_sender_seq, got.server_sender_seq
    ));
    if want.inject_dropped && !got.inject_dropped {
        out.regressions
            .push("oscore.inject_dropped became false".into());
    }
    out.line(format!(
        "  {:<28} {} → {}",
        "oscore.inject_dropped", want.inject_dropped, got.inject_dropped
    ));
    out.line("    oscore.server_metrics");
    compare_metrics(out, "      ", &got.server_metrics, &want.server_metrics);
}

fn compare_against_baseline(
    path: &std::path::Path,
    run: &JsonReport,
    out: &mut impl Write,
) -> Result<(), PeerError> {
    let baseline = load_json_report(path)?;
    let outcome = compare_reports(run, &baseline);
    writeln!(out, "\n== compare  {}", path.display()).map_err(io_err)?;
    for line in &outcome.lines {
        writeln!(out, "{line}").map_err(io_err)?;
    }
    if outcome.regressions.is_empty() {
        writeln!(
            out,
            "  compare  ok  (Metrics floors held; wall timings informational)"
        )
        .map_err(io_err)?;
        Ok(())
    } else {
        for r in &outcome.regressions {
            writeln!(out, "  REGRESSION  {r}").map_err(io_err)?;
        }
        Err(PeerError(format!(
            "baseline regression vs {} ({} issue{})",
            path.display(),
            outcome.regressions.len(),
            if outcome.regressions.len() == 1 {
                ""
            } else {
                "s"
            }
        )))
    }
}

fn run_coap_rs_client(cfg: &Config, dest: SocketAddr) -> Result<PairReport, PeerError> {
    let mut client = CoapRsPeer::new();
    let mut report = PairReport::new();
    let large = site::large_body();
    for i in 0..cfg.iterations {
        let loop_t0 = Instant::now();
        one_rs(
            &mut client,
            dest,
            &mut report.get,
            get_test(),
            cfg.timeout,
            &[Code::CONTENT],
            None,
            i,
            "GET /test",
        )?;
        one_rs(
            &mut client,
            dest,
            &mut report.put,
            put_test(),
            cfg.timeout,
            &[Code::CHANGED],
            None,
            i,
            "PUT /test",
        )?;
        one_rs(
            &mut client,
            dest,
            &mut report.post,
            post_test(),
            cfg.timeout,
            &[Code::CREATED, Code::CHANGED],
            None,
            i,
            "POST /test",
        )?;
        one_rs(
            &mut client,
            dest,
            &mut report.obs,
            get_obs(),
            cfg.timeout,
            &[Code::CONTENT],
            Some(true),
            i,
            "OBS GET /obs",
        )?;
        // Fresh UDP client per send_request: Observe=1 cannot match the
        // registration Token. DELETE /obs drops the resource's observers
        // so high-N does not fill the 4-row table.
        let mut del = ClientRequest::request(Code::DELETE, &["obs"]);
        del.timeout = cfg.timeout;
        let got = client.send_request(dest, &del)?;
        expect_codes("DELETE /obs", i, got.code, &[Code::DELETED])?;
        one_rs(
            &mut client,
            dest,
            &mut report.block2,
            get_large(cfg.block_timeout),
            cfg.block_timeout,
            &[Code::CONTENT],
            Some(false),
            i,
            "BLOCK2 GET /large",
        )?;
        let mut put_large = ClientRequest::request(Code::PUT, &["large-update"]);
        put_large.payload = large.clone();
        put_large.content_format = Some(0);
        put_large.timeout = cfg.block_timeout;
        one_rs(
            &mut client,
            dest,
            &mut report.block1,
            put_large,
            cfg.block_timeout,
            &[Code::CHANGED],
            None,
            i,
            "BLOCK1 PUT /large-update",
        )?;
        report.loop_.record(loop_t0.elapsed(), None);
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn one_rs(
    client: &mut CoapRsPeer,
    dest: SocketAddr,
    series: &mut Series,
    mut req: ClientRequest,
    timeout: Duration,
    want: &[Code],
    observe_or_block2: Option<bool>,
    iter: usize,
    label: &str,
) -> Result<(), PeerError> {
    req.timeout = timeout;
    let t0 = Instant::now();
    let got = Got::from(client.send_request(dest, &req)?);
    series.record(t0.elapsed(), None);
    expect_codes(label, iter, got.code, want)?;
    match observe_or_block2 {
        Some(true) => {
            if got.observe.is_none() {
                return Err(PeerError(format!(
                    "iteration {iter} {label}: missing Observe on {code}",
                    code = got.code
                )));
            }
        }
        Some(false) => {
            let n = got.assembled_len();
            if n < 64 {
                return Err(PeerError(format!(
                    "iteration {iter} {label}: assembled only {n} bytes"
                )));
            }
        }
        None => {}
    }
    Ok(())
}

fn get_test() -> ClientRequest {
    ClientRequest::get(&["test"])
}

fn put_test() -> ClientRequest {
    let mut r = ClientRequest::request(Code::PUT, &["test"]);
    r.payload = site::TEST_BODY.to_vec();
    r.content_format = Some(0);
    r
}

fn post_test() -> ClientRequest {
    let mut r = ClientRequest::request(Code::POST, &["test"]);
    r.payload = site::TEST_BODY.to_vec();
    r.content_format = Some(0);
    r
}

fn get_obs() -> ClientRequest {
    let mut r = ClientRequest::get(&["obs"]);
    r.observe = Some(0);
    r
}

fn get_large(timeout: Duration) -> ClientRequest {
    let mut r = ClientRequest::get(&["large"]);
    r.timeout = timeout;
    r
}

fn run_coaptic_client(
    cfg: &Config,
    dest: SocketAddr,
) -> Result<(PairReport, String, Metrics, u64, String), PeerError> {
    let (sock, _) = bind_loopback().map_err(|e| e.to_string())?;
    let mut app = App::profile::<profiles::Default>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .allow_plaintext()
        .bind(sock)
        .map_err(|e| format!("bind: {e}"))?;
    app.reset_metrics();
    let origin = Instant::now();
    let peer = Endpoint::from(dest);
    let caps = format_capacities(app.engine());
    let mut report = PairReport::new();
    let large = site::large_body();

    for i in 0..cfg.iterations {
        let loop_t0 = Instant::now();
        let loop_e0 = elapsed_ms(origin);

        timed_call(
            &mut app,
            origin,
            cfg.timeout,
            &mut report.get,
            |app, now| {
                app.get("test")
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send GET /test: {e}").into())
            },
            |got| {
                expect_codes("GET /test", i, got.code, &[Code::CONTENT])?;
                if got.payload != site::TEST_BODY {
                    return Err(PeerError(format!(
                        "iteration {i} GET /test: payload {} bytes, expected {}",
                        got.payload.len(),
                        site::TEST_BODY.len()
                    )));
                }
                Ok(())
            },
        )?;

        timed_call(
            &mut app,
            origin,
            cfg.timeout,
            &mut report.put,
            |app, now| {
                app.put("test")
                    .payload(site::TEST_BODY)
                    .content_format(ContentFormat::TEXT_PLAIN)
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send PUT /test: {e}").into())
            },
            |got| expect_codes("PUT /test", i, got.code, &[Code::CHANGED]),
        )?;

        timed_call(
            &mut app,
            origin,
            cfg.timeout,
            &mut report.post,
            |app, now| {
                app.post("test")
                    .payload(site::TEST_BODY)
                    .content_format(ContentFormat::TEXT_PLAIN)
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send POST /test: {e}").into())
            },
            |got| expect_codes("POST /test", i, got.code, &[Code::CREATED, Code::CHANGED]),
        )?;

        timed_call(
            &mut app,
            origin,
            cfg.timeout,
            &mut report.obs,
            |app, now| {
                app.get("obs")
                    .observe()
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send OBS GET /obs: {e}").into())
            },
            |got| {
                expect_codes("OBS GET /obs", i, got.code, &[Code::CONTENT])?;
                if got.observe.is_none() {
                    return Err(PeerError(format!(
                        "iteration {i} OBS GET /obs: missing Observe"
                    )));
                }
                Ok(())
            },
        )?;
        // Drop the registration so the next loop does not fill Observe slots.
        let now = elapsed_ms(origin).saturating_add(1);
        let off = app
            .get("obs")
            .deregister()
            .to(peer)
            .send(now)
            .map_err(|e| format!("send OBS deregister: {e}"))?;
        wait_call(&mut app, off, origin, cfg.timeout)?;

        timed_call(
            &mut app,
            origin,
            cfg.block_timeout,
            &mut report.block2,
            |app, now| {
                app.get("large")
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send GET /large: {e}").into())
            },
            |got| {
                expect_codes("BLOCK2 GET /large", i, got.code, &[Code::CONTENT])?;
                let n = got.assembled_len();
                if n != site::LARGE_LEN {
                    return Err(PeerError(format!(
                        "iteration {i} BLOCK2 GET /large: assembled {n}, expected {}",
                        site::LARGE_LEN
                    )));
                }
                Ok(())
            },
        )?;

        timed_call(
            &mut app,
            origin,
            cfg.block_timeout,
            &mut report.block1,
            |app, now| {
                app.put("large-update")
                    .payload(&large)
                    .content_format(ContentFormat::TEXT_PLAIN)
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send PUT /large-update: {e}").into())
            },
            |got| expect_codes("BLOCK1 PUT /large-update", i, got.code, &[Code::CHANGED]),
        )?;

        report.loop_.record(
            loop_t0.elapsed(),
            Some(elapsed_ms(origin).saturating_sub(loop_e0)),
        );
    }

    let now = elapsed_ms(origin);
    let occupancy = occupancy_line(app.engine_mut());
    let counters = app.metrics();
    Ok((report, occupancy, counters, now, caps))
}

fn run_coaptic_observe_notify(
    cfg: &Config,
    dest: SocketAddr,
    server: &CoapticServer,
) -> Result<NotifyReport, PeerError> {
    let (sock, _) = bind_loopback().map_err(|e| e.to_string())?;
    let mut app = App::profile::<profiles::Default>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .allow_plaintext()
        .bind(sock)
        .map_err(|e| format!("bind: {e}"))?;
    app.reset_metrics();
    let origin = Instant::now();
    let peer = Endpoint::from(dest);
    let mut register = Series::new("OBS register /obs");
    let mut notify = Series::new("OBS notify /obs");
    let mut loop_ = Series::new("OBS collect (reg+notify)");
    let mut collected = 0usize;

    for i in 0..cfg.iterations {
        let loop_t0 = Instant::now();
        let loop_e0 = elapsed_ms(origin);

        let e0 = elapsed_ms(origin);
        let t0 = Instant::now();
        let now = e0.saturating_add(1);
        let call = app
            .get("obs")
            .observe()
            .to(peer)
            .send(now)
            .map_err(|e| format!("send OBS GET /obs: {e}"))?;
        let initial = wait_call(&mut app, call, origin, cfg.timeout)?;
        let e1 = elapsed_ms(origin);
        register.record(t0.elapsed(), Some(e1.saturating_sub(e0)));
        expect_codes("OBS register /obs", i, initial.code, &[Code::CONTENT])?;
        if initial.observe.is_none() {
            return Err(PeerError(format!(
                "iteration {i} OBS register /obs: missing Observe"
            )));
        }

        let e0 = elapsed_ms(origin);
        let t0 = Instant::now();
        server.notify(&["obs"], site::OBS_BODY_2)?;
        let note = wait_call(&mut app, call, origin, cfg.timeout)?;
        let e1 = elapsed_ms(origin);
        notify.record(t0.elapsed(), Some(e1.saturating_sub(e0)));
        expect_codes("OBS notify /obs", i, note.code, &[Code::CONTENT])?;
        if note.observe.is_none() {
            return Err(PeerError(format!(
                "iteration {i} OBS notify /obs: missing Observe"
            )));
        }
        if note.payload != site::OBS_BODY_2 {
            return Err(PeerError(format!(
                "iteration {i} OBS notify /obs: payload {:?} expected {:?}",
                note.payload,
                site::OBS_BODY_2
            )));
        }
        collected += 1;

        let now = elapsed_ms(origin).saturating_add(1);
        let off = app
            .get("obs")
            .deregister()
            .to(peer)
            .send(now)
            .map_err(|e| format!("send OBS deregister: {e}"))?;
        wait_call(&mut app, off, origin, cfg.timeout)?;

        loop_.record(
            loop_t0.elapsed(),
            Some(elapsed_ms(origin).saturating_sub(loop_e0)),
        );
    }

    let now = elapsed_ms(origin);
    Ok(NotifyReport {
        register,
        notify,
        loop_,
        client_occupancy: occupancy_line(app.engine_mut()),
        client_metrics: app.metrics(),
        client_now_ms: now,
        collected,
    })
}

fn timed_call<T, F, C>(
    app: &mut ClientApp<T>,
    origin: Instant,
    timeout: Duration,
    series: &mut Series,
    send: F,
    check: C,
) -> Result<(), PeerError>
where
    T: DatagramIo<Error = std::io::Error>,
    F: FnOnce(&mut ClientApp<T>, u64) -> Result<Call, PeerError>,
    C: FnOnce(&Got) -> Result<(), PeerError>,
{
    let e0 = elapsed_ms(origin);
    let t0 = Instant::now();
    let now = e0.saturating_add(1);
    let call = send(app, now)?;
    let got = wait_call(app, call, origin, timeout)?;
    let e1 = elapsed_ms(origin);
    series.record(t0.elapsed(), Some(e1.saturating_sub(e0)));
    check(&got)
}

fn wait_call<T: DatagramIo<Error = std::io::Error>>(
    app: &mut ClientApp<T>,
    call: Call,
    origin: Instant,
    timeout: Duration,
) -> Result<Got, PeerError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let now = elapsed_ms(origin).saturating_add(1);
        app.poll(now).map_err(|e| format!("poll: {e}"))?;
        if let Some(resp) = app.take_response(call) {
            let resp = resp.map_err(|e| PeerError(e.to_string()))?;
            return Ok(Got {
                code: resp.code(),
                payload: resp.payload().to_vec(),
                body: resp.body().map(ToOwned::to_owned),
                observe: resp.observe_seq(),
            });
        }
        thread::yield_now();
    }
    Err(PeerError(format!(
        "timeout waiting for App take_response (metrics {})",
        app.metrics()
    )))
}

fn expect_codes(label: &str, iter: usize, got: Code, want: &[Code]) -> Result<(), PeerError> {
    if want.contains(&got) {
        Ok(())
    } else {
        Err(PeerError(format!(
            "iteration {iter} {label}: got {got}, expected one of {want:?}"
        )))
    }
}

/// RFC 8613 Appendix C.1 Master Secret (test-only; not for production).
#[cfg(feature = "oscore")]
const OSCORE_MASTER_SECRET: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
#[cfg(feature = "oscore")]
const OSCORE_MASTER_SALT: [u8; 8] = [0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40];

#[cfg(feature = "oscore")]
fn oscore_client_ctx() -> SecurityContext {
    SecurityContext::derive(DeriveParams {
        master_secret: &OSCORE_MASTER_SECRET,
        master_salt: &OSCORE_MASTER_SALT,
        sender_id: &[],
        recipient_id: &[0x01],
        id_context: &[],
    })
    .expect("dogfood OSCORE client derive")
}

#[cfg(feature = "oscore")]
fn oscore_server_ctx() -> SecurityContext {
    SecurityContext::derive(DeriveParams {
        master_secret: &OSCORE_MASTER_SECRET,
        master_salt: &OSCORE_MASTER_SALT,
        sender_id: &[0x01],
        recipient_id: &[],
        id_context: &[],
    })
    .expect("dogfood OSCORE server derive")
}

/// Inject one token-matching plaintext 2.xx before the real datagram.
///
/// Fail-closed must drop it so [`Call`] does not complete on "pwned".
#[cfg(feature = "oscore")]
struct InjectPlainOnce<T> {
    inner: T,
    pending: Option<(Endpoint, Vec<u8>)>,
    injected: Arc<AtomicBool>,
}

#[cfg(feature = "oscore")]
impl<T> InjectPlainOnce<T> {
    fn new(inner: T, injected: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            pending: None,
            injected,
        }
    }
}

#[cfg(feature = "oscore")]
impl<T: DatagramIo> DatagramIo for InjectPlainOnce<T> {
    type Error = T::Error;

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        if let Some((ep, bytes)) = self.pending.take() {
            self.injected.store(true, Ordering::SeqCst);
            buf[..bytes.len()].copy_from_slice(&bytes);
            return Ok(Some((bytes.len(), ep)));
        }
        self.inner.recv(buf)
    }

    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if self.pending.is_none()
            && !self.injected.load(Ordering::SeqCst)
            && let Ok(parsed) = decode(bytes)
            && parsed.oscore().is_some()
            && parsed.code().is_request()
        {
            let plain = Message::new(Type::Acknowledgement, Code::CONTENT, parsed.message_id())
                .with_token(parsed.token())
                .with_payload(b"pwned");
            let mut wire = [0u8; 256];
            if let Ok(n) = encode(&plain, &mut wire) {
                self.pending = Some((dest, wire[..n].to_vec()));
            }
        }
        self.inner.send(dest, bytes)
    }
}

#[cfg(feature = "oscore")]
fn run_oscore_section(cfg: &Config, out: &mut impl Write) -> Result<OscoreReport, PeerError> {
    site::reset();
    let server = spawn_oscore_server()?;
    let dest = server.addr;
    writeln!(out, "\n== coaptic ↔ coaptic  OSCORE  server={dest}").map_err(io_err)?;

    let plain_get_code = oscore_plain_get(dest, cfg.timeout)?;
    if plain_get_code != Code::UNAUTHORIZED {
        return Err(PeerError(format!(
            "OSCORE fail-closed: plain GET /test got {plain_get_code}, expected {}",
            Code::UNAUTHORIZED
        )));
    }

    server.reset_metrics()?;
    let report = run_oscore_client(cfg, dest, &server)?;
    report.write("  ", out).map_err(io_err)?;
    let snap = server.snapshot();
    drop(server);

    writeln!(
        out,
        "  engine    {}  now_ms={}  (coaptic server)",
        snap.occupancy, snap.now_ms
    )
    .map_err(io_err)?;
    writeln!(out, "  app.metrics()  {}", snap.metrics).map_err(io_err)?;
    writeln!(
        out,
        "  client    {}  now_ms={}  (coaptic client)",
        report.client_occupancy, report.client_now_ms
    )
    .map_err(io_err)?;
    writeln!(out, "  client app.metrics()  {}", report.client_metrics).map_err(io_err)?;
    writeln!(
        out,
        "  oscore    client sender_seq={}  server sender_seq={}  protected_on_wire={}  observe_collected={}  server observe_notify={}  plain GET={}  inject={}",
        report.client_sender_seq,
        snap.oscore_sender_seq.unwrap_or(0),
        report.protected_on_wire,
        report.observe_collected,
        snap.metrics.observe_notify,
        plain_get_code,
        if report.injected_plain {
            "dropped"
        } else {
            "missing"
        }
    )
    .map_err(io_err)?;

    // GET/PUT/POST + OBS register/deregister + Block2 (2) + Block1 (2).
    let want = u64::try_from(cfg.iterations.saturating_mul(9)).unwrap_or(u64::MAX);
    if report.client_sender_seq < want {
        return Err(PeerError(format!(
            "OSCORE path stayed cold: client sender_seq={} want >= {want} (GET/PUT/POST/OBS/BLOCK × {})",
            report.client_sender_seq, cfg.iterations
        )));
    }
    let want_wire = cfg.iterations.saturating_mul(19);
    if report.protected_on_wire < want_wire {
        return Err(PeerError(format!(
            "OSCORE path stayed cold: protected_on_wire={} want >= {want_wire}",
            report.protected_on_wire
        )));
    }
    if report.client_metrics.block2_assemble == 0 {
        return Err(PeerError(format!(
            "OSCORE Block2 stayed cold: client block2_assemble={}",
            report.client_metrics.block2_assemble
        )));
    }
    if snap.metrics.block1_assemble == 0 {
        return Err(PeerError(format!(
            "OSCORE Block1 stayed cold: server block1_assemble={}",
            snap.metrics.block1_assemble
        )));
    }
    if report.observe_collected != cfg.iterations {
        return Err(PeerError(format!(
            "OSCORE observe_notify stayed cold: collected={} want {}",
            report.observe_collected, cfg.iterations
        )));
    }
    if snap.metrics.observe_notify == 0 {
        return Err(PeerError(format!(
            "OSCORE observe_notify stayed cold: server observe_notify={}",
            snap.metrics.observe_notify
        )));
    }
    if !report.injected_plain {
        return Err(PeerError(
            "OSCORE fail-closed: never injected a plain 2.xx (protect path cold?)".into(),
        ));
    }
    if snap.oscore_sender_seq.is_none() {
        return Err(PeerError(
            "OSCORE server had no SecurityContext after the timed window".into(),
        ));
    }
    let want_server = u64::try_from(cfg.iterations).unwrap_or(u64::MAX);
    if snap.oscore_sender_seq.unwrap_or(0) < want_server {
        return Err(PeerError(format!(
            "OSCORE notify PIV stayed cold: server sender_seq={:?} want >= {want_server}",
            snap.oscore_sender_seq
        )));
    }
    if snap.oscore_replay_zero_fresh != Some(false) {
        return Err(PeerError(format!(
            "OSCORE unprotect stayed cold: server replay_fresh(0)={:?}",
            snap.oscore_replay_zero_fresh
        )));
    }
    if snap.metrics.rx_accepted == 0 || snap.metrics.tx_ok == 0 {
        return Err(PeerError(format!(
            "OSCORE server metrics stayed cold: {}",
            snap.metrics
        )));
    }
    if report.client_metrics.rx_accepted == 0 || report.client_metrics.tx_ok == 0 {
        return Err(PeerError(format!(
            "OSCORE client metrics stayed cold: {}",
            report.client_metrics
        )));
    }

    Ok(OscoreReport {
        plain_get_code,
        server_sender_seq: snap.oscore_sender_seq.unwrap_or(0),
        server_metrics: snap.metrics,
        ..report
    })
}

#[cfg(feature = "oscore")]
fn oscore_plain_get(dest: SocketAddr, timeout: Duration) -> Result<Code, PeerError> {
    let (sock, _) = bind_loopback().map_err(|e| e.to_string())?;
    let mut app = App::profile::<profiles::Default>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .allow_plaintext()
        .bind(sock)
        .map_err(|e| format!("bind plain GET: {e}"))?;
    let origin = Instant::now();
    let peer = Endpoint::from(dest);
    let now = elapsed_ms(origin).saturating_add(1);
    let call = app
        .get("test")
        .to(peer)
        .send(now)
        .map_err(|e| format!("send plain GET /test: {e}"))?;
    let got = wait_call(&mut app, call, origin, timeout)?;
    Ok(got.code)
}

#[cfg(feature = "oscore")]
fn run_oscore_client(
    cfg: &Config,
    dest: SocketAddr,
    server: &CoapticServer,
) -> Result<OscoreReport, PeerError> {
    let (sock, local) = bind_loopback().map_err(|e| e.to_string())?;
    let capture = Capture::new();
    let injected = Arc::new(AtomicBool::new(false));
    let io = InjectPlainOnce::new(
        CapturingIo::new(sock, local, capture.clone()),
        Arc::clone(&injected),
    );
    let mut app = App::profile::<profiles::Default>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .block_wise::<true>()
        .oscore(oscore_client_ctx())
        .bind(io)
        .map_err(|e| format!("bind OSCORE client: {e}"))?;
    app.reset_metrics();
    let origin = Instant::now();
    let peer = Endpoint::from(dest);
    let mut get = Series::new("OSCORE GET /test");
    let mut put = Series::new("OSCORE PUT /test");
    let mut post = Series::new("OSCORE POST /test");
    let mut obs_register = Series::new("OSCORE OBS register /obs");
    let mut obs_notify = Series::new("OSCORE OBS notify /obs");
    let mut block2 = Series::new("OSCORE BLOCK2 GET /large");
    let mut block1 = Series::new("OSCORE BLOCK1 PUT /large-update");
    let mut loop_ = Series::new("OSCORE LOOP (GET/PUT/POST/OBS/BLOCK)");
    let mut observe_collected = 0usize;
    let large = site::large_body();

    for i in 0..cfg.iterations {
        let loop_t0 = Instant::now();
        let loop_e0 = elapsed_ms(origin);

        timed_call(
            &mut app,
            origin,
            cfg.timeout,
            &mut get,
            |app, now| {
                app.get("test")
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send OSCORE GET /test: {e}").into())
            },
            |got| {
                expect_codes("OSCORE GET /test", i, got.code, &[Code::CONTENT])?;
                if got.payload == b"pwned" {
                    return Err(PeerError(format!(
                        "iteration {i} OSCORE GET /test: plain 2.xx completed the Call"
                    )));
                }
                if got.payload != site::TEST_BODY {
                    return Err(PeerError(format!(
                        "iteration {i} OSCORE GET /test: payload {} bytes, expected {}",
                        got.payload.len(),
                        site::TEST_BODY.len()
                    )));
                }
                Ok(())
            },
        )?;

        timed_call(
            &mut app,
            origin,
            cfg.timeout,
            &mut put,
            |app, now| {
                app.put("test")
                    .payload(site::TEST_BODY)
                    .content_format(ContentFormat::TEXT_PLAIN)
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send OSCORE PUT /test: {e}").into())
            },
            |got| expect_codes("OSCORE PUT /test", i, got.code, &[Code::CHANGED]),
        )?;

        timed_call(
            &mut app,
            origin,
            cfg.timeout,
            &mut post,
            |app, now| {
                app.post("test")
                    .payload(site::TEST_BODY)
                    .content_format(ContentFormat::TEXT_PLAIN)
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send OSCORE POST /test: {e}").into())
            },
            |got| {
                expect_codes(
                    "OSCORE POST /test",
                    i,
                    got.code,
                    &[Code::CREATED, Code::CHANGED],
                )
            },
        )?;

        let e0 = elapsed_ms(origin);
        let t0 = Instant::now();
        let now = e0.saturating_add(1);
        let call = app
            .get("obs")
            .observe()
            .to(peer)
            .send(now)
            .map_err(|e| format!("send OSCORE OBS GET /obs: {e}"))?;
        let initial = wait_call(&mut app, call, origin, cfg.timeout)?;
        let e1 = elapsed_ms(origin);
        obs_register.record(t0.elapsed(), Some(e1.saturating_sub(e0)));
        expect_codes(
            "OSCORE OBS register /obs",
            i,
            initial.code,
            &[Code::CONTENT],
        )?;
        if initial.observe.is_none() {
            return Err(PeerError(format!(
                "iteration {i} OSCORE OBS register /obs: missing Observe"
            )));
        }

        if i == 0 {
            inject_plain_oscore_notify(local, call.token())?;
            let now = elapsed_ms(origin).saturating_add(1);
            app.poll(now)
                .map_err(|e| format!("poll after plain notify: {e}"))?;
            if let Some(got) = app.take_response(call) {
                let got = got.map_err(|e| PeerError(e.to_string()))?;
                if got.payload() == b"pwned" {
                    return Err(PeerError(
                        "OSCORE fail-closed: plaintext notify completed the Call".into(),
                    ));
                }
                return Err(PeerError(
                    "OSCORE fail-closed: unexpected take_response after plaintext notify".into(),
                ));
            }
        }

        let e0 = elapsed_ms(origin);
        let t0 = Instant::now();
        server.notify(&["obs"], site::OBS_BODY_2)?;
        let note = wait_call(&mut app, call, origin, cfg.timeout)?;
        let e1 = elapsed_ms(origin);
        obs_notify.record(t0.elapsed(), Some(e1.saturating_sub(e0)));
        expect_codes("OSCORE OBS notify /obs", i, note.code, &[Code::CONTENT])?;
        if note.observe.is_none() {
            return Err(PeerError(format!(
                "iteration {i} OSCORE OBS notify /obs: missing Observe"
            )));
        }
        if note.payload == b"pwned" {
            return Err(PeerError(format!(
                "iteration {i} OSCORE OBS notify /obs: plain 2.xx completed the Call"
            )));
        }
        if note.payload != site::OBS_BODY_2 {
            return Err(PeerError(format!(
                "iteration {i} OSCORE OBS notify /obs: payload {:?} expected {:?}",
                note.payload,
                site::OBS_BODY_2
            )));
        }
        observe_collected += 1;

        let now = elapsed_ms(origin).saturating_add(1);
        let off = app
            .get("obs")
            .deregister()
            .to(peer)
            .send(now)
            .map_err(|e| format!("send OSCORE OBS deregister: {e}"))?;
        wait_call(&mut app, off, origin, cfg.timeout)?;

        timed_call(
            &mut app,
            origin,
            cfg.block_timeout,
            &mut block2,
            |app, now| {
                app.get("large")
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send OSCORE GET /large: {e}").into())
            },
            |got| {
                expect_codes("OSCORE BLOCK2 GET /large", i, got.code, &[Code::CONTENT])?;
                if got.payload == b"pwned" {
                    return Err(PeerError(
                        "OSCORE fail-closed: plain 2.xx completed Block2".into(),
                    ));
                }
                let n = got.assembled_len();
                if n != site::LARGE_LEN {
                    return Err(PeerError(format!(
                        "iteration {i} OSCORE BLOCK2 GET /large: assembled {n}, expected {}",
                        site::LARGE_LEN
                    )));
                }
                Ok(())
            },
        )?;

        timed_call(
            &mut app,
            origin,
            cfg.block_timeout,
            &mut block1,
            |app, now| {
                app.put("large-update")
                    .payload(&large)
                    .content_format(ContentFormat::TEXT_PLAIN)
                    .to(peer)
                    .send(now)
                    .map_err(|e| format!("send OSCORE PUT /large-update: {e}").into())
            },
            |got| {
                expect_codes(
                    "OSCORE BLOCK1 PUT /large-update",
                    i,
                    got.code,
                    &[Code::CHANGED],
                )?;
                if got.payload == b"pwned" {
                    return Err(PeerError(
                        "OSCORE fail-closed: plain 2.xx completed Block1".into(),
                    ));
                }
                Ok(())
            },
        )?;

        loop_.record(
            loop_t0.elapsed(),
            Some(elapsed_ms(origin).saturating_sub(loop_e0)),
        );
    }

    let client_sender_seq = app
        .oscore()
        .ok_or("OSCORE client dropped SecurityContext")?
        .sender_seq();
    let protected_on_wire = count_protected_on_wire(&capture)?;
    let now = elapsed_ms(origin);
    Ok(OscoreReport {
        get,
        put,
        post,
        obs_register,
        obs_notify,
        block2,
        block1,
        loop_,
        client_occupancy: occupancy_line(app.engine_mut()),
        client_metrics: app.metrics(),
        client_now_ms: now,
        client_sender_seq,
        server_sender_seq: 0,
        server_metrics: Metrics::ZERO,
        protected_on_wire,
        observe_collected,
        plain_get_code: Code::EMPTY,
        injected_plain: injected.load(Ordering::SeqCst),
    })
}

#[cfg(feature = "oscore")]
fn inject_plain_oscore_notify(dest: SocketAddr, token: Token) -> Result<(), PeerError> {
    let seq = encode_uint(1);
    let opts = [Opt::observe(&seq)];
    let plain = Message::new(
        Type::NonConfirmable,
        Code::CONTENT,
        coaptic::message::MessageId::new(0x0ead),
    )
    .with_token(token)
    .with_options(&opts)
    .with_payload(b"pwned");
    let mut wire = [0u8; 256];
    let n = encode(&plain, &mut wire).map_err(|e| format!("encode plain notify: {e}"))?;
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    sock.send_to(&wire[..n], dest)
        .map_err(|e| format!("send plain notify: {e}"))?;
    Ok(())
}

#[cfg(feature = "oscore")]
fn count_protected_on_wire(capture: &Capture) -> Result<usize, PeerError> {
    let mut protected = 0usize;
    for pkt in capture.snapshot() {
        let Ok(parsed) = decode(&pkt.bytes) else {
            return Err(PeerError("OSCORE capture: undecodable datagram".into()));
        };
        if parsed.is_empty() {
            continue;
        }
        if parsed.oscore().is_some() {
            protected += 1;
        } else if parsed.payload() == b"pwned" {
            // Intentional fail-closed inject (plain 2.xx / notify).
            continue;
        } else {
            return Err(PeerError(format!(
                "OSCORE capture: non-empty {} without OSCORE option (plain completion?)",
                parsed.code()
            )));
        }
    }
    Ok(protected)
}

#[cfg(test)]
mod tests {
    use super::{
        CompareOutcome, Config, JsonPair, JsonReport, Metrics, MetricsDto, OscoreDto, SeriesStats,
        WallStats, compare_reports, percentile, prove_mixed_stack, run,
    };

    fn empty_wall() -> WallStats {
        WallStats {
            min: 1.0,
            mean: 2.0,
            p50: 1.5,
            p99: 3.0,
            max: 4.0,
        }
    }

    fn series(label: &str, n: usize) -> SeriesStats {
        SeriesStats {
            label: label.into(),
            n,
            wall_ms: empty_wall(),
            engine_delta_ms: None,
        }
    }

    fn pair(name: &str, metrics: MetricsDto) -> JsonPair {
        JsonPair {
            name: name.into(),
            series: vec![
                series("GET /test", 2),
                series("BLOCK1 PUT /large-update", 2),
            ],
            occupancy: "occupancy rx=0 tx=0".into(),
            now_ms: 10,
            metrics,
            capacities: None,
            collected: None,
            oscore: None,
        }
    }

    fn report(metrics: MetricsDto) -> JsonReport {
        JsonReport {
            schema: "coaptic-dogfood/1".into(),
            caveat: "test".into(),
            host: None,
            iterations: 2,
            timeout_ms: 1500,
            block_timeout_ms: 4000,
            wall_s: 0.4,
            observe_collected: 2,
            observe_notify: metrics.observe_notify,
            oscore: false,
            pairs: vec![
                pair(super::MIXED_RS_TO_COAPTIC, metrics.clone()),
                pair(
                    "coaptic ↔ coaptic observe notify",
                    MetricsDto {
                        observe_notify: metrics.observe_notify,
                        ..MetricsDto::default()
                    },
                ),
            ],
        }
    }

    /// Complementary mixed-pair Block floors, matching checked-in baselines:
    /// server Block1=4 / Block2=0, client Block1=0 / Block2=4.
    fn mixed_baseline() -> JsonReport {
        let mut base = report(MetricsDto {
            rx_accepted: 18,
            tx_ok: 18,
            observe_register: 2,
            observe_cancel: 2,
            block1_assemble: 4,
            block2_assemble: 0,
            ..MetricsDto::default()
        });
        base.pairs.insert(
            1,
            pair(
                super::MIXED_COAPTIC_TO_RS,
                MetricsDto {
                    rx_accepted: 18,
                    tx_ok: 18,
                    observe_register: 2,
                    observe_cancel: 2,
                    block1_assemble: 0,
                    block2_assemble: 4,
                    ..MetricsDto::default()
                },
            ),
        );
        base
    }

    fn assert_ok(out: CompareOutcome) {
        assert!(
            out.regressions.is_empty(),
            "unexpected regressions: {:?}",
            out.regressions
        );
    }

    #[test]
    fn percentile_ranks() {
        let s = [1u64, 2, 3, 4];
        assert_eq!(percentile(&s, 0), 1);
        assert_eq!(percentile(&s, 50), 2);
        assert_eq!(percentile(&s, 99), 4);
        assert_eq!(percentile(&[], 50), 0);
    }

    #[test]
    fn config_parses_flags() {
        let cfg = Config::from_args([
            "--iterations",
            "3",
            "--timeout-ms=200",
            "--json",
            "/tmp/dogfood.json",
            "--compare",
            "/tmp/baseline.json",
        ])
        .unwrap();
        assert_eq!(cfg.iterations, 3);
        assert_eq!(cfg.timeout.as_millis(), 200);
        assert_eq!(
            cfg.json_path.as_deref(),
            Some(std::path::Path::new("/tmp/dogfood.json"))
        );
        assert_eq!(
            cfg.compare_path.as_deref(),
            Some(std::path::Path::new("/tmp/baseline.json"))
        );
    }

    #[test]
    fn config_default_is_high_n() {
        let cfg = Config::default();
        assert!(cfg.iterations > 2, "default must be above CI smoke");
        assert_eq!(cfg.iterations, 50);
        assert!(cfg.json_path.is_none());
        assert!(cfg.compare_path.is_none());
        assert!(!cfg.oscore);
    }

    #[test]
    fn compare_identity_is_ok() {
        let base = report(MetricsDto {
            rx_accepted: 10,
            tx_ok: 10,
            observe_notify: 2,
            observe_register: 2,
            block1_assemble: 4,
            block2_assemble: 4,
            ..MetricsDto::default()
        });
        let mut run = base.clone();
        run.wall_s = 0.9;
        run.pairs[0].metrics.progress = 999;
        run.pairs[0].series[0].wall_ms.p50 = 9.9;
        assert_ok(compare_reports(&run, &base));
    }

    #[test]
    fn compare_observe_notify_drop_fails() {
        let base = report(MetricsDto {
            observe_notify: 2,
            ..MetricsDto::default()
        });
        let mut run = base.clone();
        run.observe_notify = 0;
        run.pairs[1].metrics.observe_notify = 0;
        let out = compare_reports(&run, &base);
        assert!(
            out.regressions.iter().any(|r| r.contains("observe_notify")),
            "{:?}",
            out.regressions
        );
    }

    #[test]
    fn compare_block_assemble_drop_fails() {
        let base = report(MetricsDto {
            block1_assemble: 4,
            block2_assemble: 4,
            ..MetricsDto::default()
        });
        let mut run = base.clone();
        run.pairs[0].metrics.block1_assemble = 1;
        let out = compare_reports(&run, &base);
        assert!(
            out.regressions
                .iter()
                .any(|r| r.contains("block1_assemble")),
            "{:?}",
            out.regressions
        );
    }

    #[test]
    fn compare_mixed_block_sums_identity_ok() {
        let base = mixed_baseline();
        let mut run = base.clone();
        run.wall_s = 0.9;
        run.pairs[0].metrics.progress = 999;
        run.pairs[1].metrics.progress = 999;
        assert_ok(compare_reports(&run, &base));
    }

    #[test]
    fn compare_mixed_block1_cold_fails_sum() {
        // Pair-local Block2 floor on the server pair is 0, so stuffing
        // Block1 counts into Block2 would pass that field. The cross-pair
        // sum(block1_assemble) must still fail.
        let base = mixed_baseline();
        let mut run = base.clone();
        run.pairs[0].metrics.block1_assemble = 0;
        run.pairs[0].metrics.block2_assemble = 4;
        let out = compare_reports(&run, &base);
        assert!(
            out.regressions
                .iter()
                .any(|r| r.contains("sum(block1_assemble)")),
            "{:?}",
            out.regressions
        );
        // Combined total can stay 8 (4+4 → 0+8); that must not hide Block1 cold.
        assert!(
            out.regressions
                .iter()
                .any(|r| r.contains("sum(block1_assemble) dropped 4 → 0")),
            "{:?}",
            out.regressions
        );
    }

    #[test]
    fn compare_mixed_block_swap_onto_zero_floor_fails() {
        // Silent direction swap: each type is still warm, but on the
        // pair whose pair-local floor was 0. Per-pair non-zero floors
        // and the expected-direction fail-closed checks catch this;
        // the sums stay 4+4 (not a total-cold hide).
        let base = mixed_baseline();
        let mut run = base.clone();
        run.pairs[0].metrics.block1_assemble = 0;
        run.pairs[0].metrics.block2_assemble = 4;
        run.pairs[1].metrics.block1_assemble = 4;
        run.pairs[1].metrics.block2_assemble = 0;
        let out = compare_reports(&run, &base);
        assert!(
            out.regressions
                .iter()
                .any(|r| r.contains("block1_assemble") && r.contains("dropped 4 → 0")),
            "{:?}",
            out.regressions
        );
        assert!(
            out.regressions
                .iter()
                .any(|r| r.contains("block2_assemble") && r.contains("dropped 4 → 0")),
            "{:?}",
            out.regressions
        );
        assert!(
            !out.regressions
                .iter()
                .any(|r| r.contains("sum(block1_assemble)") || r.contains("sum(block2_assemble)")),
            "type totals still warm: {:?}",
            out.regressions
        );
    }

    #[test]
    fn compare_missing_mixed_pair_fails() {
        let base = report(MetricsDto {
            observe_register: 2,
            block1_assemble: 4,
            ..MetricsDto::default()
        });
        let mut run = base.clone();
        run.pairs.retain(|p| p.name != super::MIXED_RS_TO_COAPTIC);
        let out = compare_reports(&run, &base);
        assert!(
            out.regressions
                .iter()
                .any(|r| r.contains("missing pair") && r.contains(super::MIXED_RS_TO_COAPTIC)),
            "{:?}",
            out.regressions
        );
    }

    #[test]
    fn mixed_stack_cold_metrics_fail() {
        let err = prove_mixed_stack(2, &Metrics::ZERO, &Metrics::ZERO).unwrap_err();
        assert!(
            err.0.contains("stayed cold") && err.0.contains("coap-rs"),
            "{err}"
        );
    }

    #[test]
    fn mixed_stack_warm_metrics_ok() {
        let server = Metrics {
            rx_accepted: 10,
            tx_ok: 10,
            observe_register: 2,
            observe_cancel: 2,
            block1_assemble: 2,
            ..Metrics::ZERO
        };
        let client = Metrics {
            rx_accepted: 10,
            tx_ok: 10,
            observe_register: 2,
            observe_cancel: 2,
            block2_assemble: 2,
            ..Metrics::ZERO
        };
        prove_mixed_stack(2, &server, &client).expect("warm mixed-stack");
    }

    #[test]
    fn mixed_stack_block_sum_swap_fails() {
        // Block1 counts land on the client (0-floor direction); server Block1 cold.
        let server = Metrics {
            rx_accepted: 10,
            tx_ok: 10,
            observe_register: 2,
            observe_cancel: 2,
            block1_assemble: 0,
            block2_assemble: 2,
            ..Metrics::ZERO
        };
        let client = Metrics {
            rx_accepted: 10,
            tx_ok: 10,
            observe_register: 2,
            observe_cancel: 2,
            block1_assemble: 2,
            block2_assemble: 0,
            ..Metrics::ZERO
        };
        let err = prove_mixed_stack(2, &server, &client).unwrap_err();
        assert!(
            err.0.contains("stayed cold") && err.0.contains("block1_assemble"),
            "{err}"
        );
    }

    #[test]
    fn mixed_stack_block1_absorbed_as_block2_fails() {
        // Total assemble still 4, but Block1 went cold (all counted as Block2).
        let server = Metrics {
            rx_accepted: 10,
            tx_ok: 10,
            observe_register: 2,
            observe_cancel: 2,
            block1_assemble: 0,
            block2_assemble: 2,
            ..Metrics::ZERO
        };
        let client = Metrics {
            rx_accepted: 10,
            tx_ok: 10,
            observe_register: 2,
            observe_cancel: 2,
            block2_assemble: 2,
            ..Metrics::ZERO
        };
        let err = prove_mixed_stack(2, &server, &client).unwrap_err();
        assert!(
            err.0.contains("stayed cold")
                && (err.0.contains("block1_assemble") || err.0.contains("sum(block1")),
            "{err}"
        );
    }

    #[test]
    fn compare_error_counter_rise_fails() {
        let base = report(MetricsDto::default());
        let mut run = base.clone();
        run.pairs[0].metrics.rx_error = 3;
        let out = compare_reports(&run, &base);
        assert!(
            out.regressions.iter().any(|r| r.contains("rx_error")),
            "{:?}",
            out.regressions
        );
    }

    #[test]
    fn compare_iterations_mismatch_fails() {
        let base = report(MetricsDto::default());
        let mut run = base.clone();
        run.iterations = 50;
        let out = compare_reports(&run, &base);
        assert!(
            out.regressions.iter().any(|r| r.contains("iterations")),
            "{:?}",
            out.regressions
        );
    }

    #[test]
    fn compare_oscore_server_observe_and_block() {
        let mut base = report(MetricsDto {
            observe_notify: 2,
            block2_assemble: 4,
            ..MetricsDto::default()
        });
        base.oscore = true;
        base.pairs.push(JsonPair {
            name: "coaptic ↔ coaptic OSCORE".into(),
            series: vec![
                series("OSCORE OBS notify /obs", 2),
                series("OSCORE BLOCK1 PUT /large-update", 2),
            ],
            occupancy: "occupancy rx=0 tx=0".into(),
            now_ms: 10,
            metrics: MetricsDto {
                block2_assemble: 4,
                ..MetricsDto::default()
            },
            capacities: None,
            collected: None,
            oscore: Some(OscoreDto {
                client_sender_seq: 10,
                server_sender_seq: 2,
                protected_on_wire: 22,
                observe_collected: 2,
                fail_closed_plain_get: "4.01 Unauthorized".into(),
                inject_dropped: true,
                server_metrics: MetricsDto {
                    observe_notify: 2,
                    block1_assemble: 8,
                    ..MetricsDto::default()
                },
            }),
        });
        let mut run = base.clone();
        run.wall_s = 1.2;
        assert_ok(compare_reports(&run, &base));

        run.pairs[2]
            .oscore
            .as_mut()
            .unwrap()
            .server_metrics
            .observe_notify = 0;
        run.pairs[2]
            .oscore
            .as_mut()
            .unwrap()
            .server_metrics
            .block1_assemble = 0;
        let out = compare_reports(&run, &base);
        assert!(
            out.regressions.iter().any(|r| r.contains("observe_notify")),
            "{:?}",
            out.regressions
        );
        assert!(
            out.regressions
                .iter()
                .any(|r| r.contains("block1_assemble")),
            "{:?}",
            out.regressions
        );
    }

    #[test]
    fn config_oscore_flag() {
        let parsed = Config::from_args(["--oscore"]);
        #[cfg(feature = "oscore")]
        {
            assert!(parsed.unwrap().oscore);
        }
        #[cfg(not(feature = "oscore"))]
        {
            let err = parsed.unwrap_err();
            assert!(err.contains("--features oscore"), "{err}");
        }
    }

    #[test]
    fn timed_dogfood_smoke() {
        let mut buf = Vec::new();
        let json_path =
            std::env::temp_dir().join(format!("coaptic-dogfood-smoke-{}.json", std::process::id()));
        // 5 > Default observe table (4) so a missing deregister fails the run.
        let cfg = Config {
            iterations: 5,
            json_path: Some(json_path.clone()),
            ..Config::default()
        };
        run(cfg, &mut buf).expect("dogfood smoke");
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("coap-rs → coaptic"), "{s}");
        assert!(s.contains("coaptic → coap-rs"), "{s}");
        assert!(s.contains("coaptic ↔ coaptic  observe notify"), "{s}");
        assert!(s.contains("OBS notify /obs"), "{s}");
        assert!(s.contains("LOOP (all verbs)"), "{s}");
        assert!(s.contains("app.metrics()"), "{s}");
        assert!(s.contains("rx_accepted="), "{s}");
        assert!(s.contains("observe  collected=5"), "{s}");
        assert!(s.contains("mixed    coap-rs→coaptic"), "{s}");
        assert!(s.contains("== coverage"), "{s}");
        assert!(s.contains("peer      coap-rs"), "{s}");
        assert!(s.contains("same      Observe notify collect"), "{s}");
        assert!(s.contains("coap-rs has no OSCORE"), "{s}");
        assert!(s.contains("dogfood  ok"), "{s}");
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&json_path).expect("json file")).expect("json");
        let _ = std::fs::remove_file(&json_path);
        assert_eq!(report["schema"], "coaptic-dogfood/1");
        assert_eq!(report["iterations"], 5);
        assert_eq!(report["observe_collected"], 5);
        assert_eq!(report["oscore"], false);
        assert!(
            report["observe_notify"].as_u64().unwrap_or(0) >= 5,
            "{report}"
        );
        let pairs = report["pairs"].as_array().expect("pairs");
        let rs_to = pairs
            .iter()
            .find(|p| p["name"] == "coap-rs → coaptic")
            .expect("coap-rs → coaptic pair");
        assert!(
            rs_to["metrics"]["observe_register"].as_u64().unwrap_or(0) >= 5,
            "{report}"
        );
        assert!(
            rs_to["metrics"]["block1_assemble"].as_u64().unwrap_or(0) >= 5,
            "{report}"
        );
        let to_rs = pairs
            .iter()
            .find(|p| p["name"] == "coaptic → coap-rs")
            .expect("coaptic → coap-rs pair");
        assert!(
            to_rs["metrics"]["observe_register"].as_u64().unwrap_or(0) >= 5,
            "{report}"
        );
        assert!(
            to_rs["metrics"]["block2_assemble"].as_u64().unwrap_or(0) >= 5,
            "{report}"
        );
        eprintln!("{s}");
    }

    #[cfg(feature = "oscore")]
    #[test]
    fn oscore_plain_get_is_unauthorized() {
        let _guard = crate::runner::harness_lock();
        let server = super::spawn_oscore_server().expect("oscore server");
        let code = super::oscore_plain_get(server.addr, std::time::Duration::from_millis(1500))
            .expect("plain GET");
        assert_eq!(code, super::Code::UNAUTHORIZED, "fail-closed 4.01");
    }

    #[cfg(feature = "oscore")]
    #[test]
    fn timed_dogfood_oscore_smoke() {
        let mut buf = Vec::new();
        let json_path = std::env::temp_dir().join(format!(
            "coaptic-dogfood-oscore-smoke-{}.json",
            std::process::id()
        ));
        let cfg = Config {
            iterations: 2,
            json_path: Some(json_path.clone()),
            oscore: true,
            ..Config::default()
        };
        run(cfg, &mut buf).expect("oscore dogfood smoke");
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("coaptic ↔ coaptic  OSCORE"), "{s}");
        assert!(s.contains("OSCORE GET /test"), "{s}");
        assert!(s.contains("OSCORE PUT /test"), "{s}");
        assert!(s.contains("OSCORE POST /test"), "{s}");
        assert!(s.contains("OSCORE OBS notify /obs"), "{s}");
        assert!(s.contains("OSCORE BLOCK2 GET /large"), "{s}");
        assert!(s.contains("OSCORE BLOCK1 PUT /large-update"), "{s}");
        assert!(s.contains("protected_on_wire="), "{s}");
        assert!(s.contains("fail-closed plain GET="), "{s}");
        assert!(s.contains("inject dropped"), "{s}");
        assert!(s.contains("== coverage"), "{s}");
        assert!(
            s.contains("OSCORE GET/PUT/POST + notify + Inner Block"),
            "{s}"
        );
        assert!(s.contains("dogfood  ok"), "{s}");
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&json_path).expect("json file")).expect("json");
        let _ = std::fs::remove_file(&json_path);
        assert_eq!(report["oscore"], true);
        let pair = report["pairs"]
            .as_array()
            .and_then(|ps| ps.iter().find(|p| p["name"] == "coaptic ↔ coaptic OSCORE"))
            .expect("oscore pair");
        let oscore = &pair["oscore"];
        assert!(
            oscore["client_sender_seq"].as_u64().unwrap_or(0) >= 10,
            "{report}"
        );
        assert!(
            oscore["protected_on_wire"].as_u64().unwrap_or(0) >= 22,
            "{report}"
        );
        assert_eq!(oscore["observe_collected"], 2);
        assert_eq!(oscore["inject_dropped"], true);
        assert!(
            oscore["fail_closed_plain_get"]
                .as_str()
                .is_some_and(|c| c.contains("4.01") || c.contains("UNAUTHORIZED")),
            "{report}"
        );
        eprintln!("{s}");
    }
}
