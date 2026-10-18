//! Optional single-task ESP-IDF readiness driver.
//!
//! Socket calls borrow packet slots only for the duration of a nonblocking
//! syscall. Pending futures retain no native pointer, so cancellation and even
//! forgetting a future cannot leave DMA accessing a released slot. The driver
//! uses the existing FreeRTOS task, one process-lifetime eventfd, socket/optional
//! console interests and two timer deadlines. There is no packet queue or boxed future.
//! ESP-IDF itself allocates its eventfd/select bookkeeping; this is not a claim
//! that the platform socket stack or task startup uses no allocator.
//!
//! This boundary is not a complete App service: the caller still owns App,
//! durable commits, recovery and the root future. The synchronous service is
//! independent. Only one driver may exist; unrelated external executors must
//! not poll these transport futures because readiness wakes this driver's root.
use coaptic::storage::{AsyncDatagramIo, DatagramTransport};
use coaptic::{Endpoint, platform::AsyncTimer};
use core::cell::{Cell, RefCell};
use core::ffi::c_void;
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

unsafe extern "C" {
    fn coaptic_async_init() -> bool;
    fn coaptic_async_wake();
    fn coaptic_async_now(context: *mut c_void) -> u64;
    fn coaptic_async_wait(context: *mut c_void, interests: u32, deadline: u64) -> i32;
    fn coaptic_async_yield();
    fn coaptic_async_storage(metadata: u32, future: u32);
    #[cfg(feature = "pairing")]
    fn coaptic_async_console_ready() -> i32;
    fn coaptic_socket_recv(
        context: *mut c_void,
        bytes: *mut u8,
        capacity: u32,
        peer: *mut u64,
    ) -> i32;
    fn coaptic_socket_send(context: *mut c_void, bytes: *const u8, length: u32, peer: u64) -> i32;
    fn coaptic_socket_random(bytes: *mut u8, length: u32) -> bool;
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
const READ: u32 = 1;
const WRITE: u32 = 2;
#[cfg(feature = "pairing")]
const CONSOLE: u32 = 4;
const WAKER_SLOTS: usize = if cfg!(feature = "pairing") { 5 } else { 4 };

/// Refusal from the platform; a send failure can have ambiguous delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Another driver owns the bounded readiness state.
    Busy,
    /// Eventfd or socket operation failed.
    Io,
    /// The platform requested orderly termination.
    Stopped,
}

/// Scoped ownership of one live ESPHome socket context.
pub struct Runtime {
    context: *mut c_void,
    interests: Cell<u32>,
    deadlines: [Cell<Option<u64>>; 2],
    wakers: [RefCell<Option<Waker>>; WAKER_SLOTS],
}

// Whole metadata ceiling, including alignment and protocol/local/console wakers.
const _: () =
    assert!(core::mem::size_of::<Runtime>() <= if cfg!(feature = "pairing") { 168 } else { 144 });

impl Runtime {
    /// Claim one live ESPHome component without starting a task or polling it.
    ///
    /// # Safety
    /// `context` must refer to a live `CoapticNetwork` with an open socket for
    /// the entire runtime lifetime. Its socket must have no other reader or
    /// writer. Call from its owning task. Dropping the runtime must precede
    /// socket/component destruction. The retained eventfd contains no context
    /// pointer, so previously cloned wakers remain safe after this lifetime.
    pub unsafe fn new(context: *mut c_void) -> Result<Self, Error> {
        if ACTIVE.swap(true, Ordering::AcqRel) {
            return Err(Error::Busy);
        }
        if context.is_null() || !unsafe { coaptic_async_init() } {
            ACTIVE.store(false, Ordering::Release);
            return Err(Error::Io);
        }
        Ok(Self {
            context,
            interests: Cell::new(0),
            deadlines: core::array::from_fn(|_| Cell::new(None)),
            wakers: core::array::from_fn(|_| RefCell::new(None)),
        })
    }

    /// Split one socket, protocol/local timers and its task driver. Their borrows prevent
    /// another split or runtime destruction while any operation remains live.
    pub fn split(&mut self) -> (Socket<'_>, Timer<'_>, Timer<'_>, Driver<'_>) {
        (Socket(self), Timer(self, 0), Timer(self, 1), Driver(self))
    }

    /// Include the reserved device's exclusive USB console readiness source.
    #[cfg(feature = "pairing")]
    pub fn split_with_console(
        &mut self,
    ) -> (
        Socket<'_>,
        Timer<'_>,
        Timer<'_>,
        ConsoleReady<'_>,
        Driver<'_>,
    ) {
        (
            Socket(self),
            Timer(self, 0),
            Timer(self, 1),
            ConsoleReady(self),
            Driver(self),
        )
    }

    fn now(&self) -> Result<u64, Error> {
        match unsafe { coaptic_async_now(self.context) } {
            u64::MAX => Err(Error::Stopped),
            now => Ok(now),
        }
    }

    fn register(&self, index: usize, waker: &Waker) {
        let mut slot = self.wakers[index].borrow_mut();
        match slot.as_mut() {
            Some(previous) => previous.clone_from(waker),
            None => *slot = Some(waker.clone()),
        }
    }

    fn wake_ready(&self, ready: u32) {
        for index in 0..WAKER_SLOTS {
            let due = if index < 2 {
                ready & (1 << index) != 0
            } else if index == 4 {
                ready & 8 != 0
            } else {
                ready & 4 != 0
                    && self.deadlines[index - 2]
                        .get()
                        .is_some_and(|deadline| self.now().is_ok_and(|now| now >= deadline))
            };
            if due {
                let waker = self.wakers[index].borrow_mut().take();
                if let Some(waker) = waker {
                    waker.wake();
                }
            }
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Release);
    }
}

// No borrowed data lives behind this waker. ESP-IDF owns the retained eventfd
// until process termination. An old waker can at worst spuriously wake a later
// driver; it can never access an old Runtime or a reused native descriptor.
unsafe fn clone_waker(_: *const ()) -> RawWaker {
    raw_waker()
}
unsafe fn wake(_: *const ()) {
    unsafe { coaptic_async_wake() }
}
unsafe fn drop_waker(_: *const ()) {}
static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, wake, wake, drop_waker);
fn raw_waker() -> RawWaker {
    RawWaker::new(core::ptr::null(), &VTABLE)
}

/// Runs the root future on the caller's existing FreeRTOS task.
pub struct Driver<'a>(&'a Runtime);
impl Driver<'_> {
    /// Sleep in select until socket readiness, deadline, external wake or stop.
    /// Ready/self-waking traffic yields to FreeRTOS after 32 root polls.
    /// The caller pins and owns the root future; returning releases its borrow.
    /// Borrowing avoids moving the large root through another task stack frame.
    #[inline(never)]
    pub fn run<F: Future>(&mut self, mut future: Pin<&mut F>) -> Result<F::Output, Error> {
        // Leave at least 32 KiB of the existing 96 KiB task stack outside the
        // retained root future. Native high-water qualification remains needed
        // for construction peaks and nested synchronous crypto/storage frames.
        const {
            assert!(core::mem::size_of::<F>() <= 65_536);
        }
        unsafe {
            coaptic_async_storage(
                core::mem::size_of::<Runtime>() as u32,
                core::mem::size_of::<F>() as u32,
            )
        };
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut context = Context::from_waker(&waker);
        let mut burst = 0;
        loop {
            self.0.now()?;
            if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
                return Ok(result);
            }
            burst += 1;
            if burst == 32 {
                unsafe { coaptic_async_yield() };
                burst = 0;
            }
            match unsafe {
                coaptic_async_wait(
                    self.0.context,
                    self.0.interests.get(),
                    self.0
                        .deadlines
                        .iter()
                        .filter_map(Cell::get)
                        .min()
                        .unwrap_or(u64::MAX),
                )
            } {
                -2 => return Err(Error::Stopped),
                ready if ready >= 0 => self.0.wake_ready(ready as u32),
                _ => return Err(Error::Io),
            }
        }
    }
}

/// Async-only transport borrowing this driver's one socket.
pub struct Socket<'a>(&'a Runtime);
struct Interest<'a> {
    runtime: &'a Runtime,
    bit: u32,
}
impl Drop for Interest<'_> {
    fn drop(&mut self) {
        self.runtime
            .interests
            .set(self.runtime.interests.get() & !self.bit);
        self.runtime.wakers[match self.bit {
            READ => 0,
            WRITE => 1,
            _ => 4,
        }]
        .borrow_mut()
        .take();
    }
}

/// Readiness only: commissioning bytes remain in the existing native USB ring.
#[cfg(feature = "pairing")]
pub struct ConsoleReady<'a>(&'a Runtime);
#[cfg(feature = "pairing")]
impl ConsoleReady<'_> {
    /// Wait without reading ahead or staging a commissioning frame.
    pub async fn wait(&mut self) -> Result<(), Error> {
        let interest = Interest {
            runtime: self.0,
            bit: CONSOLE,
        };
        poll_fn(|context| match unsafe { coaptic_async_console_ready() } {
            0 => {
                interest.runtime.register(4, context.waker());
                interest
                    .runtime
                    .interests
                    .set(interest.runtime.interests.get() | CONSOLE);
                Poll::Pending
            }
            1 => Poll::Ready(Ok(())),
            _ => Poll::Ready(Err(Error::Io)),
        })
        .await
    }
}
impl DatagramTransport for Socket<'_> {
    type Error = Error;
    fn fill_random(&mut self, bytes: &mut [u8]) -> bool {
        let Ok(length) = u32::try_from(bytes.len()) else {
            return false;
        };
        unsafe { coaptic_socket_random(bytes.as_mut_ptr(), length) }
    }
}
impl AsyncDatagramIo for Socket<'_> {
    async fn recv(&mut self, bytes: &mut [u8]) -> Result<(usize, Endpoint), Error> {
        let capacity = u32::try_from(bytes.len()).map_err(|_| Error::Io)?;
        let interest = Interest {
            runtime: self.0,
            bit: READ,
        };
        poll_fn(|context| {
            let mut peer = 0;
            let size = unsafe {
                coaptic_socket_recv(
                    interest.runtime.context,
                    bytes.as_mut_ptr(),
                    capacity,
                    &mut peer,
                )
            };
            if size == -1 {
                interest.runtime.register(0, context.waker());
                interest
                    .runtime
                    .interests
                    .set(interest.runtime.interests.get() | READ);
                return Poll::Pending;
            }
            Poll::Ready(
                if size < 0 || size as usize > bytes.len() || peer >> 48 != 0 {
                    Err(Error::Io)
                } else {
                    Ok((
                        size as usize,
                        Endpoint::v4(((peer >> 16) as u32).to_be_bytes(), peer as u16),
                    ))
                },
            )
        })
        .await
    }
    async fn send(&mut self, destination: Endpoint, bytes: &[u8]) -> Result<usize, Error> {
        let length = u32::try_from(bytes.len()).map_err(|_| Error::Io)?;
        let (address, port) = destination.as_ipv4().ok_or(Error::Io)?;
        let peer = (u64::from(u32::from_be_bytes(address)) << 16) | u64::from(port);
        let interest = Interest {
            runtime: self.0,
            bit: WRITE,
        };
        poll_fn(|context| {
            let size = unsafe {
                coaptic_socket_send(interest.runtime.context, bytes.as_ptr(), length, peer)
            };
            if size == -3 {
                interest.runtime.register(1, context.waker());
                interest
                    .runtime
                    .interests
                    .set(interest.runtime.interests.get() | WRITE);
                return Poll::Pending;
            }
            Poll::Ready(if size < 0 || size as usize != bytes.len() {
                Err(Error::Io)
            } else {
                Ok(size as usize)
            })
        })
        .await
    }
}

/// One of two cancel-safe absolute timers in ESP-IDF's monotonic millisecond domain.
pub struct Timer<'a>(&'a Runtime, usize);
struct Deadline<'a>(&'a Runtime, usize);
impl Drop for Deadline<'_> {
    fn drop(&mut self) {
        self.0.deadlines[self.1].set(None);
        self.0.wakers[2 + self.1].borrow_mut().take();
    }
}
impl AsyncTimer for Timer<'_> {
    async fn wait_until(&mut self, deadline: u64) {
        let registration = Deadline(self.0, self.1);
        poll_fn(|context| match registration.0.now() {
            Ok(now) if now < deadline => {
                registration.0.register(2 + registration.1, context.waker());
                registration.0.deadlines[registration.1].set(Some(deadline));
                Poll::Pending
            }
            _ => Poll::Ready(()),
        })
        .await
    }
}

#[cfg(test)]
mod tests;
