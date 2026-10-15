use coaptic::oscore::{ReplayCheckpoint, SecurityContext};
use coaptic_esphome_probe::security_state::{self, Credentials, Error, RECORD_BYTES, State, Store};
use std::{hint::black_box, time::Instant};

#[derive(Default)]
struct Memory { bytes: Option<[u8; RECORD_BYTES]>, reads: u64, writes: u64 }
impl Store for &mut Memory {
    fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, Error> { self.reads += 1; Ok(black_box(self.bytes)) }
    fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> Result<(), Error> { self.writes += 1; self.bytes = Some(black_box(*bytes)); Ok(()) }
}
fn main() {
    let c = Credentials {secret:[0x39;32],salt:[0x42;16],context:[0x27;16],sender:1,recipient:2};
    let iterations = 20000;
    for session in 0..7 {
        let mut memory=Memory::default();
        security_state::provision(&mut &mut memory,&c).unwrap();
        let (mut state, context)=State::recover(&mut memory,&c).unwrap();
        let state_bytes=std::mem::size_of_val(&state);
        black_box(context);
        let begin=Instant::now();
        for index in 1..=iterations { state.checkpoint(black_box(ReplayCheckpoint::from_parts(index,1).unwrap())).unwrap(); }
        let checkpoint_ns=begin.elapsed().as_nanos();
        drop(state);
        assert_eq!(memory.writes, iterations+2);
        let begin=Instant::now();
        for _ in 0..iterations { black_box(SecurityContext::derive(black_box(c.parameters())).unwrap()); }
        let derive_ns=begin.elapsed().as_nanos();
        println!("{{\"session\":{session},\"iterations\":{iterations},\"checkpoint_ns\":{checkpoint_ns},\"derive_ns\":{derive_ns},\"state_bytes\":{state_bytes},\"reads\":{},\"writes\":{},\"method\":\"host release CPU/wall diagnostic; volatile fixed-record store; black_box results; setup separate; no durable I/O or MCU claim; derive span is independent, not additive\"}}",memory.reads,memory.writes);
    }
}
