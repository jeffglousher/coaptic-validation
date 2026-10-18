use super::*;
use coaptic::{platform::AsyncTimer, storage::AsyncDatagramIo};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};

pub(super) struct NativeOnly(pub(super) Scripted);
impl coaptic::storage::DatagramTransport for NativeOnly {
    type Error = ();
}
impl AsyncDatagramIo for NativeOnly {
    async fn recv(&mut self, bytes: &mut [u8]) -> Result<(usize, Endpoint), ()> {
        crate::cooperate().await;
        if core::mem::take(&mut self.0.fail) {
            return Err(());
        }
        if let Some(packet) = self.0.incoming.pop_front() {
            bytes[..packet.len()].copy_from_slice(&packet);
            Ok((packet.len(), Endpoint::v4([192, 0, 2, 1], 5683)))
        } else {
            core::future::pending().await
        }
    }
    async fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
        crate::cooperate().await;
        self.0.outgoing.borrow_mut().push(bytes.to_vec());
        Ok(bytes.len())
    }
}

pub(super) struct Timer(pub(super) Rc<Cell<u64>>);
impl AsyncTimer for Timer {
    async fn wait_until(&mut self, deadline: u64) {
        core::future::poll_fn(|_| {
            if self.0.get() >= deadline {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

// Simulated external clock interrupts advance both independent timer sources.
// The finite driver also catches a service that never returns to its executor.
pub(super) fn drive<F: Future>(future: F, now: &Cell<u64>) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for tick in 0..1000 {
        now.set(tick);
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return result;
        }
    }
    panic!("service failed to stop within finite timer schedule")
}

#[test]
fn native_only_service_echoes_after_pending_io_and_releases_ownership() {
    let _lock = TEST_LOCK.lock().unwrap();
    for _ in 0..2 {
        let now = Rc::new(Cell::new(0));
        let out = Rc::new(RefCell::new(Vec::new()));
        let io = NativeOnly(Scripted {
            incoming: [request(9, coaptic::Code::POST, "echo", b"native async")].into(),
            outgoing: out.clone(),
            fail: true,
        });
        let mut protocol = Timer(now.clone());
        let mut local = Timer(now.clone());
        assert_eq!(
            drive(
                run_async(
                    io,
                    |b| {
                        b.fill(42);
                        true
                    },
                    || (now.get() < 500).then_some(now.get()),
                    &[1; 32],
                    (&mut protocol, &mut local)
                ),
                &now
            ),
            Ok(())
        );
        let packets = out.borrow();
        assert_eq!(packets.len(), 1);
        let reply = decode(&packets[0]).unwrap();
        assert_eq!(reply.code(), coaptic::Code::CONTENT);
        assert_eq!(reply.payload(), b"native async");
        assert_eq!(reply.message_id(), MessageId::new(9));
    }
}
