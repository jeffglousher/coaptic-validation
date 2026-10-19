use super::*;
use coaptic::provisioning::{
    EnrollmentPolicy, OperationId, ReceiptStore, TelemetryOperation, TrustAnchor,
};
use coaptic::storage::{DatagramTransport, UdpSocketIo};
use coaptic_receipts::{Authority, Journal, Policy};
use std::{cell::Cell, net::UdpSocket};

#[test]
fn enrolled_pending_owner_has_an_independent_memory_ceiling() {
    assert!(core::mem::size_of::<Device>() <= 1344);
    std::eprintln!(
        "Pairing owner bytes: record={} state={} device={} pending={}",
        core::mem::size_of::<PairingRecord>(),
        core::mem::size_of::<LocalPairing>(),
        core::mem::size_of::<Device>(),
        core::mem::size_of::<crate::pending_telemetry::Pending<'_, PendingStore<'_, Memory>>>()
    );
    // One retained record plus its custody reference/metadata, never another
    // application payload array. Persistent bytes and transmission prefix are
    // separately bounded; target stack peaks still require the final firmware.
    assert!(
        core::mem::size_of::<crate::pending_telemetry::Pending<'_, PendingStore<'_, Memory>>>()
            <= 1280
    );
    assert_eq!(crate::pending_telemetry::RECORD_BYTES, 1214);
}

struct DropReply {
    inner: UdpSocketIo<[u8; 1473]>,
    drop_next: Rc<Cell<bool>>,
}
impl DatagramTransport for DropReply {
    type Error = std::io::Error;
}
impl DatagramIo for DropReply {
    fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        self.inner.recv(bytes)
    }
    fn send(&mut self, to: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if self.drop_next.replace(false) {
            Ok(bytes.len())
        } else {
            self.inner.send(to, bytes)
        }
    }
}
struct QuietConsole(Rc<Cell<bool>>, Rc<Cell<usize>>);
impl Console for QuietConsole {
    fn read(&mut self, _: &mut [u8]) -> Result<usize, Error> {
        Ok(0)
    }
    fn write(&mut self, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
    fn restart(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn event(&mut self, event: u32) {
        if event == 4 {
            self.0.set(true);
        }
    }
    fn diagnostics(&mut self, snapshot: &coaptic::app::diagnostics::Snapshot) {
        assert!(snapshot.at_ms > 0);
        assert!(snapshot.usage.storage.tx_datagram.capacity > 0);
        self.1.set(self.1.get() + 1);
    }
}

#[test]
fn enrolled_udp_restart_recovers_one_effect_after_lost_receipt() {
    let device_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let host_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    device_socket.set_nonblocking(true).unwrap();
    host_socket.set_nonblocking(true).unwrap();
    let device_endpoint = Endpoint::from(device_socket.local_addr().unwrap());
    let host_endpoint = Endpoint::from(host_socket.local_addr().unwrap());
    let store = Rc::new(RefCell::new(Memory::default()));
    let mut shared = Shared(store.clone());
    let mut device = Device::initialize(&mut shared, 17, random).unwrap();
    let host = Identity::from_private_key([2; 32], 18).unwrap();
    let challenge = device.pairing.begin(&device.identity, 0, random).unwrap();
    let policy = EnrollmentPolicy::new(host.peer(), [7; 32], permissions(true)).unwrap();
    device
        .pairing
        .pair(&challenge, policy, 1, |old, next| {
            prepare_pending(&mut shared, &device.private, &device.identity, old, next)?;
            let mut bytes = [0; STORE_BYTES];
            let len = encode_store(&device.private, 17, next, Some(host_endpoint), &mut bytes)?;
            shared.commit(&device.stored[..device.stored_len], &bytes[..len])
        })
        .unwrap();
    let mut host_pairing =
        LocalPairing::restore(&host, PairingRecord::unpaired(&host, [9; 32]).unwrap()).unwrap();
    let challenge = host_pairing.begin(&host, 0, random).unwrap();
    host_pairing
        .pair(
            &challenge,
            EnrollmentPolicy::new(device.identity.peer(), [7; 32], permissions(true)).unwrap(),
            1,
            |_, _| Ok::<_, ()>(()),
        )
        .unwrap();
    let record = host_pairing.checkpoint();
    let anchor =
        TrustAnchor::from_parts(*record.store(), record.revision(), record.commitment()).unwrap();
    let authority = Authority::new(Policy {
        anchor,
        principal: device.identity.peer().principal(),
        resource: telemetry_resource(),
        enabled: true,
    });
    let path = std::env::temp_dir().join(format!(
        "coaptic-enrolled-receipts-{}-{}",
        std::process::id(),
        host_socket.local_addr().unwrap().port()
    ));
    let mut journal = Journal::create(&path, authority.clone(), 2).unwrap();
    for phase in 0..2 {
        let diagnostic_samples = Rc::new(Cell::new(0));
        let drop_next = Rc::new(Cell::new(false));
        let mut connection = ManagedConnection::<_, profiles::Constrained>::from_local_pairing(
            &host,
            &host_pairing,
            device_endpoint,
            DropReply {
                inner: UdpSocketIo::new(host_socket.try_clone().unwrap(), [0; 1473]).unwrap(),
                drop_next: drop_next.clone(),
            },
            random,
            0,
        )
        .unwrap();
        if host.peer().principal().fingerprint() > device.identity.peer().principal().fingerprint()
        {
            connection.connect(0).unwrap();
        }
        let completed = Rc::new(Cell::new(false));
        let mut now = 0;
        let mut committed = false;
        let mut io = Some(UdpSocketIo::new(device_socket.try_clone().unwrap(), [0; 1473]).unwrap());
        let result = run(
            || io.take().unwrap(),
            random,
            || {
                now += 1;
                connection
                    .poll_with(now, |principal, request, _| {
                        if request.path() == ["identity"] {
                            return Response::content_copy(host.peer().principal().fingerprint());
                        }
                        assert_eq!(request.path(), ["telemetry"]);
                        assert_eq!(request.content_format(), Some(Ok(ContentFormat::CBOR)));
                        let payload = request.payload();
                        let operation = TelemetryOperation::new(
                            OperationId::new(payload[..16].try_into().unwrap()),
                            telemetry_resource(),
                            Some(60),
                            &payload[16..],
                        )
                        .unwrap();
                        let receipt = journal.commit(&anchor, principal, &operation).unwrap();
                        committed = true;
                        if phase == 0 {
                            drop_next.set(true);
                        }
                        Response::new(Code::CHANGED).payload_copy(&receipt.encode())
                    })
                    .unwrap();
                if (phase == 0 && committed) || completed.get() || now > 20_000 {
                    None
                } else {
                    Some(now)
                }
            },
            Shared(store.clone()),
            QuietConsole(completed.clone(), diagnostic_samples.clone()),
        );
        assert_eq!(result, Ok(()));
        assert!(diagnostic_samples.get() > 0);
        assert!(now <= 20_000, "enrolled service did not complete");
        assert_eq!(journal.effects().unwrap(), 1);
        let recovered = Device::recover(&mut Shared(store.clone()))
            .unwrap()
            .unwrap();
        let mut backend = Shared(store.clone());
        let pending = recover_pending(&recovered, &mut backend, true)
            .unwrap()
            .unwrap();
        if phase == 0 {
            assert!(!completed.get());
            assert!(pending.pending().unwrap().is_some());
            assert!(pending.completion().unwrap().is_none());
        } else {
            assert!(completed.get());
            assert!(pending.pending().unwrap().is_none());
            assert_eq!(pending.completion().unwrap().unwrap().sequence(), 1);
        }
        drop(pending);
        drop(journal);
        journal = Journal::open(&path, authority.clone()).unwrap();
    }
    drop(journal);
    std::fs::remove_file(path).unwrap();
}
