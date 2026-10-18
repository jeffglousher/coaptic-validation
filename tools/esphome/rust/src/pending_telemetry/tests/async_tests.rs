use super::*;
use crate::{protected_telemetry as runner, security_state as security};
use coaptic::{Endpoint, platform::AsyncTimer, storage::AsyncDatagramIo};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use std::cell::Cell;

#[derive(Default)]
struct Security(Option<[u8; security::RECORD_BYTES]>);
impl security::Store for Security {
    fn read(&mut self) -> Result<Option<[u8; security::RECORD_BYTES]>, security::Error> {
        Ok(self.0)
    }
    fn commit(&mut self, bytes: &[u8; security::RECORD_BYTES]) -> Result<(), security::Error> {
        self.0 = Some(*bytes);
        Ok(())
    }
}
struct Socket {
    accept: bool,
    accepted: Rc<Cell<bool>>,
}
impl coaptic::storage::DatagramTransport for Socket {
    type Error = ();
}
impl AsyncDatagramIo for Socket {
    async fn recv(&mut self, _: &mut [u8]) -> Result<(usize, Endpoint), ()> {
        core::future::pending().await
    }
    async fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
        if !self.accept {
            core::future::pending::<()>().await;
        }
        self.accepted.set(true);
        Ok(bytes.len())
    }
}
struct Timer(Rc<Cell<u64>>);
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

#[test]
fn pending_send_deadline_and_post_accept_clock_failure_preserve_exact_operation() {
    for accept in [false, true] {
        let credentials = credentials();
        let backend = initialized(&credentials);
        let mut pending = Pending::recover(backend.clone(), &credentials, principal(1)).unwrap();
        pending
            .begin(OperationId::new([7; 16]), [3; 32], Some(42), b"retained")
            .unwrap();
        drop(pending);
        let original = backend.0.borrow().record;
        let mut security = Security::default();
        security::provision(&mut security, &credentials).unwrap();
        let now = Rc::new(Cell::new(0));
        let accepted = Rc::new(Cell::new(false));
        let mut protocol = Timer(now.clone());
        let mut local = Timer(now.clone());
        let result = {
            let mut future = core::pin::pin!(runner::run_async(
                Socket {
                    accept,
                    accepted: accepted.clone()
                },
                |b| {
                    b.fill(42);
                    true
                },
                || (!accepted.get()).then_some(now.get()),
                runner::Service {
                    endpoint: Endpoint::v4([192, 0, 2, 1], 5683),
                    principal: principal(1),
                    resource: [3; 32],
                    credentials: &credentials,
                    timeout_ms: 20
                },
                security,
                backend.clone(),
                (&mut protocol, &mut local),
            ));
            let mut cx = Context::from_waker(Waker::noop());
            let mut result = None;
            for tick in 0..=20 {
                now.set(tick);
                if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                    result = Some(value);
                    break;
                }
            }
            result.expect("deadline must interrupt Pending initial send")
        };
        assert_eq!(
            result,
            Err(if accept {
                runner::Error::AfterSend
            } else {
                runner::Error::Deadline
            })
        );
        assert_eq!(backend.0.borrow().record, original);
        let recovered = Pending::recover(backend, &credentials, principal(1)).unwrap();
        let operation = recovered.pending().unwrap().unwrap();
        assert_eq!(operation.id(), OperationId::new([7; 16]));
        assert_eq!(operation.payload(), b"retained");
        assert!(recovered.completion().unwrap().is_none());
    }
}
