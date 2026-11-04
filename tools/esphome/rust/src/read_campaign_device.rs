//! Selected synchronous or native async device binding for the existing matched GET workload.
//!
//! The platform owns the socket, clock, bounded wait and protected runs
//! additionally own durable security storage. The platform also owns the
//! output sink. Observations stream after each complete operation; no trace,
//! packet buffer or sample array is retained here. This is the body-enabled
//! Constrained configuration, not the SmallDevice preset or Service profile.
#![forbid(unsafe_code)]

use crate::read_campaign::{self, Observation};
#[cfg(feature = "oscore")]
use crate::security_state::{Credentials, State, Store};
use coaptic::app::AppStore;
use coaptic::storage::{DatagramIo, DatagramTransport};
use coaptic::{App, Endpoint, profiles};

/// Whole App ceiling, including its caller-selected transport; not peak stack.
pub const APP_BYTE_CEILING: usize = 48 * 1024;
/// Durable state plus caller-owned store metadata; independent of the App.
pub const STATE_BYTE_CEILING: usize = 1024;
pub const OUTPUT_BYTES: usize = 4096;
/// One preparation, at most one reservation per operation, and one terminal row.
pub const MAX_RECORDS: usize = 2 * read_campaign::OPERATIONS as usize + 2;

type CampaignApp<T> = App<profiles::Constrained, T, 8, true, AppStore<profiles::Constrained, true>>;

/// Explicit qualification selection. Identity borrows the existing run ID.
#[derive(Clone, Copy)]
pub struct Selection<'a> {
    pub peer: Endpoint,
    pub expected_identity: &'a [u8; 32],
    pub async_network: bool,
}

/// Fixed metadata-only platform record, borrowed only during the output callback.
///
/// Word 0 is the kind: preparation 0, sender reservation 1, complete operation 2,
/// terminal 3. Preparation words 1..9 are recovery ns, whole App bytes, existing
/// output bytes, this record bytes, security owner bytes, selected App ceiling,
/// Selection bytes, state ceiling and shared Observation bytes. Preparation word
/// 10 identifies the actual driving API: synchronous 0, native async 1. Reservation
/// word 1 is elapsed ns. Operation words 1..12
/// are iteration, path (identity 0/test 1/large 2), bytes, start ns, elapsed ns,
/// preparation ns, poll ns, checkpoint ns, collection ns, verification ns,
/// wait ns and poll count. Terminal words 1..3 are success, completed operations
/// and preceding accepted record count. Unused words are zero.
///
/// No word contains payloads, credentials, pointers or persistent record bytes.
/// App/State/record/output sizes are components, not an additive stack peak.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub words: [u64; 16],
}

const _: () = {
    assert!(core::mem::size_of::<Record>() == 128);
    assert!(core::mem::size_of::<Selection<'_>>() <= 48);
    assert!(core::mem::size_of::<Observation>() <= 128);
    assert!(MAX_RECORDS <= 50);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AsyncSelection,
    Peer,
    Identity,
    Layout,
    Output,
    Campaign(&'static str),
}

/// Run exactly the shared 24-operation protected workload, preserving its store.
///
/// Eight route slots (none installed on the initiator), four Calls, no deferred
/// slots, one association and four request bindings; two RX and two TX datagrams
/// of 1152 bytes, one 4096-byte body per direction, four dedup entries and two
/// Observe entries. Only one Call is used concurrently. Existing
/// 4096-byte collection output and App body storage remain inside the shared
/// algorithm. This wrapper adds one 128-byte record and scalar counters only.
///
/// Async selection, bad identity/peer and oversized App layout refuse before
/// any platform callback, entropy, durable-state access or network I/O. The
/// caller must supply a nonblocking synchronous transport and a bounded wait.
/// `clock_ns` reads monotonic time without waiting. `emit` runs outside measured
/// operation intervals and must accept each record or return false. A false or
/// missing terminal record leaves qualification incomplete. No state is reset.
#[cfg(feature = "oscore")]
#[allow(clippy::too_many_arguments)]
pub fn run<T: DatagramIo, S: Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    credentials: &Credentials,
    store: S,
    selection: Selection<'_>,
    clock_ns: impl FnMut() -> Option<u64>,
    wait: impl FnMut(),
    emit: impl FnMut(&Record) -> bool,
) -> Result<(), Error> {
    stream::<T>(
        &selection,
        core::mem::size_of::<State<S>>(),
        |observe| {
            read_campaign::run(
                io,
                random,
                clock_ns,
                wait,
                credentials,
                store,
                selection.peer,
                selection.expected_identity,
                observe,
            )
        },
        emit,
    )
}

/// Stream the same 24 reads without credentials, a store or security recovery.
/// The fixed Record is reused; preparation reports zero security-owner bytes.
/// Identity checking in this mode provides attribution, not authentication.
#[allow(clippy::too_many_arguments)]
pub fn run_unprotected<T: DatagramIo>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    selection: Selection<'_>,
    clock_ns: impl FnMut() -> Option<u64>,
    wait: impl FnMut(),
    emit: impl FnMut(&Record) -> bool,
) -> Result<(), Error> {
    stream::<T>(
        &selection,
        0,
        |observe| {
            read_campaign::run_unprotected(
                io,
                random,
                clock_ns,
                wait,
                selection.peer,
                selection.expected_identity,
                observe,
            )
        },
        emit,
    )
}

/// Native async binding of the same unprotected reads and record stream.
/// A synchronous selection refuses before any platform callback is invoked.
#[cfg(feature = "async-network")]
#[allow(clippy::too_many_arguments)]
pub async fn run_unprotected_async<T: coaptic::storage::AsyncDatagramIo>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    selection: Selection<'_>,
    clock_ns: impl FnMut() -> Option<u64>,
    timers: (
        &mut impl coaptic::platform::AsyncTimer,
        &mut impl coaptic::platform::AsyncTimer,
    ),
    emit: impl FnMut(&Record) -> bool,
) -> Result<(), Error> {
    let mut records = Records::new::<T>(&selection, 0, true, emit)?;
    let result = read_campaign::run_unprotected_async(
        io,
        random,
        clock_ns,
        timers,
        selection.peer,
        selection.expected_identity,
        |observation| records.observe(observation),
    )
    .await;
    records.finish(result)
}

/// Native async protected binding. Durable state is recovered and preserved;
/// selecting this API never provisions or resets credentials or replay history.
#[cfg(all(feature = "async-network", feature = "oscore"))]
#[allow(clippy::too_many_arguments)]
pub async fn run_async<T: coaptic::storage::AsyncDatagramIo, S: Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    credentials: &Credentials,
    store: S,
    selection: Selection<'_>,
    clock_ns: impl FnMut() -> Option<u64>,
    timers: (
        &mut impl coaptic::platform::AsyncTimer,
        &mut impl coaptic::platform::AsyncTimer,
    ),
    emit: impl FnMut(&Record) -> bool,
) -> Result<(), Error> {
    let mut records = Records::new::<T>(&selection, core::mem::size_of::<State<S>>(), true, emit)?;
    let result = read_campaign::run_async(
        io,
        random,
        clock_ns,
        timers,
        credentials,
        store,
        selection.peer,
        selection.expected_identity,
        |observation| records.observe(observation),
    )
    .await;
    records.finish(result)
}

fn stream<T: DatagramIo>(
    selection: &Selection<'_>,
    state_bytes: usize,
    execute: impl FnOnce(
        &mut dyn FnMut(Observation) -> Result<(), &'static str>,
    ) -> Result<(), &'static str>,
    emit: impl FnMut(&Record) -> bool,
) -> Result<(), Error> {
    let mut records = Records::new::<T>(selection, state_bytes, false, emit)?;
    let result = execute(&mut |observation| records.observe(observation));
    records.finish(result)
}

struct Records<E> {
    record: Record,
    emitted: usize,
    completed: usize,
    output_failed: bool,
    app_bytes: usize,
    state_bytes: usize,
    asynchronous: bool,
    emit: E,
}
impl<E: FnMut(&Record) -> bool> Records<E> {
    fn new<T: DatagramTransport>(
        selection: &Selection<'_>,
        state_bytes: usize,
        asynchronous: bool,
        emit: E,
    ) -> Result<Self, Error> {
        if selection.async_network != asynchronous {
            return Err(Error::AsyncSelection);
        }
        let (address, port) = selection.peer.as_ipv4().ok_or(Error::Peer)?;
        if address == [0; 4] || address[0] >= 224 || port == 0 {
            return Err(Error::Peer);
        }
        if !selection
            .expected_identity
            .iter()
            .all(u8::is_ascii_hexdigit)
        {
            return Err(Error::Identity);
        }
        let app_bytes = core::mem::size_of::<CampaignApp<T>>();
        if app_bytes > APP_BYTE_CEILING || state_bytes > STATE_BYTE_CEILING {
            return Err(Error::Layout);
        }
        Ok(Self {
            record: Record { words: [0; 16] },
            emitted: 0,
            completed: 0,
            output_failed: false,
            app_bytes,
            state_bytes,
            asynchronous,
            emit,
        })
    }
    fn observe(&mut self, observation: Observation) -> Result<(), &'static str> {
        if self.emitted >= MAX_RECORDS - 1 {
            return Err("campaign device record bound");
        }
        self.record.words.fill(0);
        match observation {
            Observation::Preparation {
                recovery_ns,
                app_bytes: actual,
            } => {
                if actual != self.app_bytes {
                    return Err("campaign device profile changed");
                }
                self.record.words[1] = recovery_ns;
                self.record.words[2] = actual as u64;
                self.record.words[3] = OUTPUT_BYTES as u64;
                self.record.words[4] = core::mem::size_of::<Record>() as u64;
                self.record.words[5] = self.state_bytes as u64;
                self.record.words[6] = APP_BYTE_CEILING as u64;
                self.record.words[7] = core::mem::size_of::<Selection<'_>>() as u64;
                self.record.words[8] = STATE_BYTE_CEILING as u64;
                self.record.words[9] = core::mem::size_of::<Observation>() as u64;
                self.record.words[10] = u64::from(self.asynchronous);
            }
            Observation::Reservation { elapsed_ns } => {
                self.record.words[0] = 1;
                self.record.words[1] = elapsed_ns;
            }
            Observation::Operation(op) => {
                let path = match op.path {
                    "identity" => 0,
                    "test" => 1,
                    "large" => 2,
                    _ => return Err("campaign device profile changed"),
                };
                self.record.words[0] = 2;
                self.record.words[1] = u64::from(op.iteration);
                self.record.words[2] = path;
                self.record.words[3] = op.bytes as u64;
                self.record.words[4] = op.start_ns;
                self.record.words[5] = op.elapsed_ns;
                self.record.words[6] = op.prepare_ns;
                self.record.words[7] = op.poll_ns;
                self.record.words[8] = op.checkpoint_ns;
                self.record.words[9] = op.take_ns;
                self.record.words[10] = op.verify_ns;
                self.record.words[11] = op.wait_ns;
                self.record.words[12] = u64::from(op.polls);
            }
        }
        if !(self.emit)(&self.record) {
            self.output_failed = true;
            return Err("campaign device output");
        }
        self.emitted += 1;
        self.completed += usize::from(self.record.words[0] == 2);
        Ok(())
    }
    fn finish(&mut self, result: Result<(), &'static str>) -> Result<(), Error> {
        let result = result.and(if self.completed == read_campaign::OPERATIONS as usize {
            Ok(())
        } else {
            Err("campaign device completion count")
        });
        self.record.words.fill(0);
        self.record.words[0] = 3;
        self.record.words[1] = u64::from(result.is_ok());
        self.record.words[2] = self.completed as u64;
        self.record.words[3] = self.emitted as u64;
        if !(self.emit)(&self.record) || self.output_failed {
            return Err(Error::Output);
        }
        result.map_err(Error::Campaign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "oscore")]
    use crate::security_state::{Error as StoreError, RECORD_BYTES};
    use coaptic::storage::DatagramTransport;

    struct NoIo;
    impl DatagramTransport for NoIo {
        type Error = ();
    }
    impl DatagramIo for NoIo {
        fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
            panic!("configuration refusal must precede receive")
        }
        fn send(&mut self, _: Endpoint, _: &[u8]) -> Result<usize, ()> {
            panic!("configuration refusal must precede send")
        }
    }
    #[cfg(feature = "oscore")]
    struct NoStore;
    #[cfg(feature = "oscore")]
    impl Store for NoStore {
        fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, StoreError> {
            panic!("configuration refusal must precede durable read")
        }
        fn commit(&mut self, _: &[u8; RECORD_BYTES]) -> Result<(), StoreError> {
            panic!("configuration refusal must precede durable commit")
        }
    }
    fn no_random(_: &mut [u8]) -> bool {
        panic!("configuration refusal must precede entropy")
    }
    #[cfg(feature = "oscore")]
    fn refuse(selection: Selection<'_>) -> Result<(), Error> {
        run(
            NoIo,
            no_random,
            &Credentials {
                secret: [0; 32],
                salt: [0; 16],
                context: [0; 16],
                sender: 1,
                recipient: 2,
            },
            NoStore,
            selection,
            || panic!("configuration refusal must precede clock"),
            || panic!("configuration refusal must precede wait"),
            |_| panic!("configuration refusal must precede output"),
        )
    }

    fn refuse_unprotected(selection: Selection<'_>) -> Result<(), Error> {
        run_unprotected(
            NoIo,
            no_random,
            selection,
            || panic!("configuration refusal must precede clock"),
            || panic!("configuration refusal must precede wait"),
            |_| panic!("configuration refusal must precede output"),
        )
    }

    #[test]
    fn selection_refuses_async_bad_identity_and_nonunicast_before_any_callback() {
        selection_refusals(refuse_unprotected);
        #[cfg(feature = "oscore")]
        selection_refusals(refuse);
    }

    fn selection_refusals(refuse: for<'a> fn(Selection<'a>) -> Result<(), Error>) {
        let identity = *b"0123456789abcdef0123456789abcdef";
        let valid = || Selection {
            peer: Endpoint::v4([192, 168, 1, 1], 5683),
            expected_identity: &identity,
            async_network: false,
        };
        assert_eq!(
            refuse(Selection {
                async_network: true,
                ..valid()
            }),
            Err(Error::AsyncSelection)
        );
        assert_eq!(
            refuse(Selection {
                expected_identity: &[b'x'; 32],
                ..valid()
            }),
            Err(Error::Identity)
        );
        for peer in [
            Endpoint::v4([0; 4], 5683),
            Endpoint::v4([224, 0, 0, 1], 5683),
            Endpoint::v4([192, 168, 1, 1], 0),
        ] {
            assert_eq!(refuse(Selection { peer, ..valid() }), Err(Error::Peer));
        }
    }

    #[cfg(feature = "async-network")]
    mod asynchronous {
        use super::*;
        use coaptic::storage::AsyncDatagramIo;
        use core::future::Future;
        use core::task::{Context, Poll, Waker};
        use std::{
            cell::{Cell, RefCell},
            collections::VecDeque,
            rc::Rc,
        };

        type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;
        struct Io {
            incoming: Queue,
            outgoing: Queue,
        }
        impl DatagramTransport for Io {
            type Error = ();
        }
        impl DatagramIo for Io {
            fn recv(&mut self, out: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
                Ok(self.incoming.borrow_mut().pop_front().map(|bytes| {
                    out[..bytes.len()].copy_from_slice(&bytes);
                    (bytes.len(), Endpoint::v4([127, 0, 0, 1], 5683))
                }))
            }
            fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
                self.outgoing.borrow_mut().push_back(bytes.to_vec());
                Ok(bytes.len())
            }
        }
        impl AsyncDatagramIo for Io {
            async fn recv(&mut self, out: &mut [u8]) -> Result<(usize, Endpoint), ()> {
                core::future::poll_fn(|_| match DatagramIo::recv(self, out) {
                    Ok(Some(packet)) => Poll::Ready(Ok(packet)),
                    Ok(None) => Poll::Pending,
                    Err(error) => Poll::Ready(Err(error)),
                })
                .await
            }
            async fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
                DatagramIo::send(self, peer, bytes)
            }
        }
        struct Timer;
        impl coaptic::platform::AsyncTimer for Timer {
            async fn wait_until(&mut self, _: u64) {
                core::future::pending().await
            }
        }
        fn random(bytes: &mut [u8]) -> bool {
            bytes.fill(0x42);
            true
        }
        fn identity(_: coaptic::Request<'_>) -> coaptic::Response<'static> {
            coaptic::Response::content(b"0123456789abcdef0123456789abcdef")
        }
        fn test(_: coaptic::Request<'_>) -> coaptic::Response<'static> {
            coaptic::Response::content(b"coaptic")
        }
        fn large(_: coaptic::Request<'_>) -> coaptic::Response<'static> {
            coaptic::Response::content(&[0x5a; 2000])
        }

        #[test]
        fn native_async_stream_verifies_all_reads_and_identifies_its_mode() {
            let inbound: Queue = Default::default();
            let outbound: Queue = Default::default();
            let mut server = App::profile::<profiles::Constrained>()
                .block_wise::<true>()
                .allow_unprotected()
                .randomness(random)
                .route("identity", coaptic::get(identity))
                .route("test", coaptic::get(test))
                .route("large", coaptic::get(large))
                .bind(Io {
                    incoming: outbound.clone(),
                    outgoing: inbound.clone(),
                })
                .unwrap();
            let now = Cell::new(0u64);
            let mut rows = Vec::new();
            let mut protocol = Timer;
            let mut local = Timer;
            let result = {
                let mut future = core::pin::pin!(run_unprotected_async(
                    Io {
                        incoming: inbound,
                        outgoing: outbound
                    },
                    random,
                    Selection {
                        peer: Endpoint::v4([127, 0, 0, 1], 5683),
                        expected_identity: b"0123456789abcdef0123456789abcdef",
                        async_network: true
                    },
                    || {
                        now.set(now.get() + 1000);
                        Some(now.get())
                    },
                    (&mut protocol, &mut local),
                    |record| {
                        rows.push(*record);
                        true
                    }
                ));
                let mut context = Context::from_waker(Waker::noop());
                (0..2000).find_map(|_| {
                    server.poll(now.get() / 1_000_000).unwrap();
                    match future.as_mut().poll(&mut context) {
                        Poll::Ready(result) => Some(result),
                        Poll::Pending => None,
                    }
                })
            };
            assert_eq!(result, Some(Ok(())));
            assert_eq!(rows.len(), 26);
            assert_eq!(rows[0].words[0], 0);
            assert_eq!(rows[0].words[10], 1);
            assert_eq!(rows.iter().filter(|row| row.words[0] == 2).count(), 24);
            assert_eq!(&rows.last().unwrap().words[..4], &[3, 1, 24, 25]);
        }

        #[test]
        fn async_selection_mismatch_refuses_before_any_callback() {
            let selection = Selection {
                peer: Endpoint::v4([127, 0, 0, 1], 5683),
                expected_identity: b"0123456789abcdef0123456789abcdef",
                async_network: false,
            };
            let result = Records::new::<NoIo>(&selection, 0, true, |_| panic!("output"));
            assert!(matches!(result, Err(Error::AsyncSelection)));
        }
    }
}
