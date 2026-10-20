//! Selected synchronous device binding for the existing matched GET workload.
//!
//! The platform owns the socket, durable security store, clock, bounded wait and
//! output sink. Observations stream after each complete operation; no trace,
//! packet buffer or sample array is retained here. This is the body-enabled
//! Constrained configuration, not the SmallDevice preset or Service profile.
#![forbid(unsafe_code)]

use crate::read_campaign::{self, Observation};
use crate::security_state::{Credentials, State, Store};
use coaptic::app::AppStore;
use coaptic::storage::DatagramIo;
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
/// Selection bytes, state ceiling and shared Observation bytes. Reservation
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
#[allow(clippy::too_many_arguments)]
pub fn run<T: DatagramIo, S: Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    credentials: &Credentials,
    store: S,
    selection: Selection<'_>,
    clock_ns: impl FnMut() -> Option<u64>,
    wait: impl FnMut(),
    mut emit: impl FnMut(&Record) -> bool,
) -> Result<(), Error> {
    if selection.async_network {
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
    if app_bytes > APP_BYTE_CEILING || core::mem::size_of::<State<S>>() > STATE_BYTE_CEILING {
        return Err(Error::Layout);
    }
    let mut record = Record { words: [0; 16] };
    let mut emitted = 0;
    let mut completed = 0;
    let mut output_failed = false;
    let result = read_campaign::run(
        io,
        random,
        clock_ns,
        wait,
        credentials,
        store,
        selection.peer,
        selection.expected_identity,
        |observation| {
            if emitted >= MAX_RECORDS - 1 {
                return Err("campaign device record bound");
            }
            record.words.fill(0);
            match observation {
                Observation::Preparation {
                    recovery_ns,
                    app_bytes: actual,
                } => {
                    if actual != app_bytes {
                        return Err("campaign device profile changed");
                    }
                    record.words[1] = recovery_ns;
                    record.words[2] = actual as u64;
                    record.words[3] = OUTPUT_BYTES as u64;
                    record.words[4] = core::mem::size_of::<Record>() as u64;
                    record.words[5] = core::mem::size_of::<State<S>>() as u64;
                    record.words[6] = APP_BYTE_CEILING as u64;
                    record.words[7] = core::mem::size_of::<Selection<'_>>() as u64;
                    record.words[8] = STATE_BYTE_CEILING as u64;
                    record.words[9] = core::mem::size_of::<Observation>() as u64;
                }
                Observation::Reservation { elapsed_ns } => {
                    record.words[0] = 1;
                    record.words[1] = elapsed_ns;
                }
                Observation::Operation(op) => {
                    let path = match op.path {
                        "identity" => 0,
                        "test" => 1,
                        "large" => 2,
                        _ => return Err("campaign device profile changed"),
                    };
                    record.words[0] = 2;
                    record.words[1] = u64::from(op.iteration);
                    record.words[2] = path;
                    record.words[3] = op.bytes as u64;
                    record.words[4] = op.start_ns;
                    record.words[5] = op.elapsed_ns;
                    record.words[6] = op.prepare_ns;
                    record.words[7] = op.poll_ns;
                    record.words[8] = op.checkpoint_ns;
                    record.words[9] = op.take_ns;
                    record.words[10] = op.verify_ns;
                    record.words[11] = op.wait_ns;
                    record.words[12] = u64::from(op.polls);
                }
            }
            if !emit(&record) {
                output_failed = true;
                return Err("campaign device output");
            }
            emitted += 1;
            completed += usize::from(record.words[0] == 2);
            Ok(())
        },
    )
    .and({
        if completed == read_campaign::OPERATIONS as usize {
            Ok(())
        } else {
            Err("campaign device completion count")
        }
    });
    record.words.fill(0);
    record.words[0] = 3;
    record.words[1] = u64::from(result.is_ok());
    record.words[2] = completed as u64;
    record.words[3] = emitted as u64;
    if !emit(&record) || output_failed {
        return Err(Error::Output);
    }
    result.map_err(Error::Campaign)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    struct NoStore;
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

    #[test]
    fn selection_refuses_async_bad_identity_and_nonunicast_before_any_callback() {
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
}
