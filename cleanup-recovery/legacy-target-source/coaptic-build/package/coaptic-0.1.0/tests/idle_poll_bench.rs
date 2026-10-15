//! Manual `--release --ignored` timings for idle `progress` / `App::poll` (#157).
//!
//! ```text
//! cargo test --release --test idle_poll_bench -- --ignored --nocapture
//! ```

use std::hint::black_box;
use std::time::Instant;

use coaptic::app::App;
use coaptic::profiles;
use coaptic::storage::{
    DatagramIo, Endpoint, Engine, EngineBuilder, Memory, WithBodies, profiles as storage_profiles,
};
use coaptic::{Request, Response, get};

const N: u32 = 50_000;
const WARMUP: u32 = 2_000;

struct NullIo;

impl DatagramIo for NullIo {
    type Error = &'static str;

    fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        Ok(None)
    }

    fn send(&mut self, _: Endpoint, _: &[u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }
}

fn ns_per_op(iters: u32, elapsed: std::time::Duration) -> f64 {
    elapsed.as_secs_f64() * 1e9 / f64::from(iters)
}

fn get_temp(_req: Request<'_>) -> Response<'static> {
    Response::content(b"21.5")
}

type DefaultEngine =
    Engine<Memory<storage_profiles::Default, WithBodies<storage_profiles::Default>>>;

fn empty_engine() -> DefaultEngine {
    EngineBuilder::new()
        .profile::<storage_profiles::Default>()
        .block_wise(true)
        .build(Memory::<storage_profiles::Default>::with_block_wise())
        .expect("build")
}

fn pending_engine() -> DefaultEngine {
    use coaptic::message::MessageId;
    let mut engine = empty_engine();
    let ep = Endpoint::v4([192, 0, 2, 81], 5683);
    let tx = engine.acquire_tx().expect("tx");
    engine
        .record_pending_con(tx, ep, MessageId::new(21), 0, 0)
        .expect("pending");
    engine
}

#[test]
#[ignore]
fn bench_idle_progress_and_poll() {
    let mut engine = empty_engine();
    for _ in 0..WARMUP {
        black_box(engine.progress(0));
    }
    let t = Instant::now();
    for _ in 0..N {
        black_box(engine.progress(0));
    }
    let idle_progress = ns_per_op(N, t.elapsed());

    let mut pending = pending_engine();
    for _ in 0..WARMUP {
        black_box(pending.progress(0));
    }
    let t = Instant::now();
    for _ in 0..N {
        black_box(pending.progress(0));
    }
    let pending_progress = ns_per_op(N, t.elapsed());

    let mut app = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route("sensors/temp", get(get_temp))
        .bind(NullIo)
        .expect("bind");
    for _ in 0..WARMUP {
        app.poll(0).expect("poll");
    }
    let t = Instant::now();
    for _ in 0..N {
        app.poll(0).expect("poll");
    }
    let idle_poll = ns_per_op(N, t.elapsed());

    println!("idle Engine::progress  {idle_progress:.1} ns/op  N={N}");
    println!("pending CON progress   {pending_progress:.1} ns/op  (RTO not due)");
    println!("idle App::poll         {idle_poll:.1} ns/op");
    assert!(idle_progress > 0.0);
    assert!(pending_progress > 0.0);
    assert!(idle_poll > 0.0);
}
