#![cfg(all(feature = "network", feature = "oscore", feature = "host"))]

use coaptic::Endpoint;
use coaptic::storage::{DatagramIo, UdpSocketIo};
use coaptic_esphome_probe::{
    network,
    read_campaign::{self, Observation},
    read_campaign_device::{self, Selection},
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
    // Streaming refuses an unavailable output sink after a verified response;
    // the terminal row never turns that partial campaign into a success.
    let mut refused_operations = 0;
    let mut refused_terminal = 0;
    let clock = Instant::now();
    assert_eq!(
        read_campaign_device::run(
            client_io(),
            random,
            &client_credentials,
            client_state.clone(),
            Selection {
                peer,
                expected_identity: &identity,
                async_network: false,
            },
            || Some(clock.elapsed().as_nanos() as u64),
            || std::thread::sleep(Duration::from_millis(1)),
            |record| {
                match record.words[0] {
                    2 => {
                        refused_operations += 1;
                        return false;
                    }
                    3 => {
                        refused_terminal += 1;
                        assert_eq!(&record.words[1..3], &[0, 0]);
                    }
                    _ => {}
                }
                true
            }
        ),
        Err(read_campaign_device::Error::Output)
    );
    assert_eq!((refused_operations, refused_terminal), (1, 1));

    // A fresh campaign reuses the same authenticated state after refusal. Every
    // record borrows one reused 128-byte owner, and all 24 bodies are verified.
    let mut prepared = 0;
    let mut reservations = 0;
    let mut completed = 0;
    let mut terminal = 0;
    let mut accepted = 0;
    let mut record_address: *const read_campaign_device::Record = core::ptr::null();
    let clock = Instant::now();
    read_campaign_device::run(
        client_io(),
        random,
        &client_credentials,
        client_state.clone(),
        Selection {
            peer,
            expected_identity: &identity,
            async_network: false,
        },
        || Some(clock.elapsed().as_nanos() as u64),
        || std::thread::sleep(Duration::from_millis(1)),
        |record| {
            let address = core::ptr::from_ref(record);
            if record_address.is_null() {
                record_address = address;
            }
            assert_eq!(address, record_address);
            match record.words[0] {
                0 => {
                    assert_eq!(accepted, 0);
                    prepared += 1;
                    assert!(record.words[2] <= read_campaign_device::APP_BYTE_CEILING as u64);
                    assert_eq!(record.words[3], 4096);
                    assert_eq!(record.words[4], 128);
                    assert!(record.words[5] <= read_campaign_device::STATE_BYTE_CEILING as u64);
                    assert!(record.words[10..].iter().all(|&word| word == 0));
                }
                1 => {
                    reservations += 1;
                    assert!(record.words[2..].iter().all(|&word| word == 0));
                }
                2 => {
                    assert_eq!(prepared, 1);
                    assert_eq!(terminal, 0);
                    assert_eq!(record.words[1], completed / 3);
                    assert_eq!(record.words[2], completed % 3);
                    assert_eq!(record.words[3], [32, 7, 2000][completed as usize % 3]);
                    assert!(record.words[5] > 0);
                    assert!(record.words[12] > 0);
                    assert!(record.words[13..].iter().all(|&word| word == 0));
                    completed += 1;
                }
                3 => {
                    terminal += 1;
                    assert_eq!(&record.words[1..4], &[1, 24, accepted]);
                    assert!(record.words[4..].iter().all(|&word| word == 0));
                }
                _ => panic!("unknown stream record"),
            }
            accepted += 1;
            true
        },
    )
    .unwrap();
    assert_eq!((prepared, completed, terminal), (1, 24, 1));
    assert_eq!(accepted, 26 + reservations);
    assert!(accepted <= read_campaign_device::MAX_RECORDS as u64);
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

    unprotected_reads_use_the_same_workload_and_deadline();
}

fn unprotected_reads_use_the_same_workload_and_deadline() {
    let identity = *b"0123456789abcdef0123456789abcdef";
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer: Endpoint = socket.local_addr().unwrap().into();
    socket.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let worker = std::thread::spawn(move || {
        let clock = Instant::now();
        network::run(
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
        )
    });
    let mut completed = 0;
    let clock = Instant::now();
    let result = read_campaign::run_unprotected(
        client_io(),
        random,
        || Some(clock.elapsed().as_nanos() as u64),
        || std::thread::sleep(Duration::from_millis(1)),
        peer,
        &identity,
        |observation| {
            match observation {
                Observation::Preparation { recovery_ns, .. } => assert_eq!(recovery_ns, 0),
                Observation::Reservation { .. } => panic!("unprotected sender reservation"),
                Observation::Operation(op) => {
                    assert_eq!(op.iteration, completed / 3);
                    assert_eq!(
                        (op.path, op.bytes),
                        [("identity", 32), ("test", 7), ("large", 2000)][completed as usize % 3]
                    );
                    assert!(op.elapsed_ns > 0 && op.polls > 0);
                    completed += 1;
                }
            }
            Ok(())
        },
    );
    stop.store(true, Ordering::Release);
    assert_eq!(worker.join().unwrap(), Ok(()));
    assert_eq!(result, Ok(()));
    assert_eq!(completed, read_campaign::OPERATIONS);

    let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut now = 0;
    assert_eq!(
        read_campaign::run_unprotected(
            client_io(),
            random,
            || {
                now += 1_000_000_000;
                Some(now)
            },
            || {},
            blackhole.local_addr().unwrap().into(),
            &identity,
            |observation| {
                assert!(!matches!(observation, Observation::Operation(_)));
                Ok(())
            },
        ),
        Err("campaign deadline/poll bound")
    );
}
