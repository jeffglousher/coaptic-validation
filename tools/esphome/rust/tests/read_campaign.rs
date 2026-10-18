#![cfg(all(feature = "network", feature = "oscore", feature = "host"))]

use coaptic::Endpoint;
use coaptic::storage::{DatagramIo, UdpSocketIo};
use coaptic_esphome_probe::{
    network,
    read_campaign::{self, Observation},
    security_state::{self, Credentials, Error, RECORD_BYTES, Store},
};
use std::{
    net::UdpSocket,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
struct Memory(Arc<Mutex<Option<[u8; RECORD_BYTES]>>>);
impl Store for Memory {
    fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, Error> {
        Ok(*self.0.lock().unwrap())
    }
    fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> Result<(), Error> {
        *self.0.lock().unwrap() = Some(*bytes);
        Ok(())
    }
}
struct Missing;
impl Store for Missing {
    fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, Error> {
        Err(Error::Unavailable)
    }
    fn commit(&mut self, _: &[u8; RECORD_BYTES]) -> Result<(), Error> {
        panic!("must not initialize failed storage")
    }
}
struct BrokenIo;
impl coaptic::storage::DatagramTransport for BrokenIo {
    type Error = ();
}
impl DatagramIo for BrokenIo {
    fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
        Err(())
    }
    fn send(&mut self, _: Endpoint, _: &[u8]) -> Result<usize, ()> {
        Err(())
    }
}
fn credentials(sender: u8, recipient: u8) -> Credentials {
    Credentials {
        secret: [0x61; 32],
        salt: [0x62; 16],
        context: [0x63; 16],
        sender,
        recipient,
    }
}
fn random(bytes: &mut [u8]) -> bool {
    getrandom::fill(bytes).is_ok()
}
fn client_io() -> UdpSocketIo<[u8; 1153]> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    UdpSocketIo::new(socket, [0; 1153]).unwrap()
}

// This is a correctness/refusal test, not a durable-filesystem or performance
// measurement. Only the isolated test stores below use volatile memory.
#[test]
fn matched_complete_reads_refuse_failures_then_recover() {
    let server_credentials = credentials(2, 1);
    let client_credentials = credentials(1, 2);
    let mut server_state = Memory::default();
    let mut client_state = Memory::default();
    security_state::provision(&mut server_state, &server_credentials).unwrap();
    security_state::provision(&mut client_state, &client_credentials).unwrap();
    let identity = *b"0123456789abcdef0123456789abcdef";
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer: Endpoint = socket.local_addr().unwrap().into();
    socket.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let worker = std::thread::spawn(move || {
        let clock = Instant::now();
        network::run_protected(
            UdpSocketIo::new(socket, [0; 1153]).unwrap(),
            random,
            || {
                if stopped.load(Ordering::Acquire) || clock.elapsed() >= Duration::from_secs(15) {
                    None
                } else {
                    std::thread::yield_now();
                    Some(clock.elapsed().as_millis() as u64)
                }
            },
            &identity,
            &server_credentials,
            server_state,
        )
    });
    let mut results = Vec::new();
    let clock = Instant::now();
    read_campaign::run(
        client_io(),
        random,
        || Some(clock.elapsed().as_nanos() as u64),
        || std::thread::sleep(Duration::from_millis(1)),
        &client_credentials,
        client_state.clone(),
        peer,
        &identity,
        |o| {
            results.push(o);
            Ok(())
        },
    )
    .unwrap();
    let operations: Vec<_> = results
        .iter()
        .filter_map(|r| match r {
            Observation::Operation(op) => Some(op),
            _ => None,
        })
        .collect();
    assert_eq!(operations.len(), 24);
    for (index, operation) in operations.iter().enumerate() {
        assert_eq!(operation.iteration, index as u32 / 3);
        assert_eq!(
            (operation.path, operation.bytes),
            [("identity", 32), ("test", 7), ("large", 2000)][index % 3]
        );
        assert!(operation.elapsed_ns > 0);
        assert!(operation.polls > 0);
        assert!(
            operation.elapsed_ns
                >= operation.prepare_ns
                    + operation.poll_ns
                    + operation.checkpoint_ns
                    + operation.take_ns
                    + operation.verify_ns
                    + operation.wait_ns
        );
    }
    // A valid protected response from the wrong expected source identity refuses
    // before any complete-operation observation, rather than becoming a sample.
    let mut completed = 0;
    let clock = Instant::now();
    assert_eq!(
        read_campaign::run(
            client_io(),
            random,
            || Some(clock.elapsed().as_nanos() as u64),
            || std::thread::sleep(Duration::from_millis(1)),
            &client_credentials,
            client_state.clone(),
            peer,
            b"ffffffffffffffffffffffffffffffff",
            |o| {
                if matches!(o, Observation::Operation(_)) {
                    completed += 1;
                }
                Ok(())
            }
        ),
        Err("campaign representation/identity")
    );
    assert_eq!(completed, 0);
    // The durable sender ranges are retained across failed/successful runs.
    let clock = Instant::now();
    read_campaign::run(
        client_io(),
        random,
        || Some(clock.elapsed().as_nanos() as u64),
        || std::thread::sleep(Duration::from_millis(1)),
        &client_credentials,
        client_state.clone(),
        peer,
        &identity,
        |_| Ok(()),
    )
    .unwrap();
    stop.store(true, Ordering::Release);
    assert_eq!(worker.join().unwrap(), Ok(()));

    assert_eq!(
        read_campaign::run(
            BrokenIo,
            random,
            || Some(0),
            || {},
            &client_credentials,
            Missing,
            peer,
            &identity,
            |_| panic!("no observations after storage failure")
        ),
        Err("campaign security recovery")
    );
    assert!(
        read_campaign::run(
            BrokenIo,
            random,
            || Some(0),
            || {},
            &client_credentials,
            client_state.clone(),
            peer,
            &identity,
            |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(
        read_campaign::run(
            client_io(),
            random,
            || Some(0),
            || {},
            &client_credentials,
            client_state.clone(),
            peer,
            &identity,
            |_| Err("report unavailable")
        ),
        Err("report unavailable")
    );
    // No response: advancing time reaches the deadline without a false sample.
    let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut now = 0;
    assert_eq!(
        read_campaign::run(
            client_io(),
            random,
            || {
                now += 1_000_000_000;
                Some(now)
            },
            || {},
            &client_credentials,
            client_state.clone(),
            blackhole.local_addr().unwrap().into(),
            &identity,
            |o| {
                assert!(!matches!(o, Observation::Operation(_)));
                Ok(())
            }
        ),
        Err("campaign deadline/poll bound")
    );
    // Frozen time also terminates through a finite resource bound.
    assert_eq!(
        read_campaign::run(
            client_io(),
            random,
            || Some(0),
            || {},
            &client_credentials,
            client_state,
            blackhole.local_addr().unwrap().into(),
            &identity,
            |o| {
                assert!(!matches!(o, Observation::Operation(_)));
                Ok(())
            }
        ),
        Err("campaign deadline/poll bound")
    );
}
