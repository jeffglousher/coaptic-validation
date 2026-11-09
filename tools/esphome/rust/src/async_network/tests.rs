use super::*;
use core::pin::pin;
use std::sync::{Arc, Condvar, Mutex};
use std::task::Wake;

static SERIAL: Mutex<()> = Mutex::new(());
static STATE: Mutex<State> = Mutex::new(State::new());
static EXTERNAL_WAKE: Condvar = Condvar::new();
struct State {
    now: u64,
    waits: u32,
    attempts: u32,
    ready: bool,
    stopped: bool,
    expected_interest: u32,
    wakes: u32,
    yields: u32,
    wake_in_wait: bool,
    stop_in_wait: bool,
    await_external_wake: bool,
    bytes: [u8; 4],
}
impl State {
    const fn new() -> Self {
        Self {
            now: 10,
            waits: 0,
            attempts: 0,
            ready: false,
            stopped: false,
            expected_interest: 0,
            wakes: 0,
            yields: 0,
            wake_in_wait: false,
            stop_in_wait: false,
            await_external_wake: false,
            bytes: [0; 4],
        }
    }
}
#[unsafe(no_mangle)]
extern "C" fn coaptic_async_init() -> bool {
    true
}
#[unsafe(no_mangle)]
extern "C" fn coaptic_async_wake() {
    STATE.lock().unwrap().wakes += 1;
    EXTERNAL_WAKE.notify_all();
}
#[unsafe(no_mangle)]
extern "C" fn coaptic_async_now(_: *mut c_void) -> u64 {
    let state = STATE.lock().unwrap();
    if state.stopped { u64::MAX } else { state.now }
}
#[unsafe(no_mangle)]
extern "C" fn coaptic_async_wait(_: *mut c_void, interests: u32, deadline: u64) -> i32 {
    let mut state = STATE.lock().unwrap();
    assert_eq!(interests, state.expected_interest);
    state.waits += 1;
    if state.stop_in_wait {
        state.stopped = true;
        return -2;
    }
    if state.await_external_wake {
        let (awakened, timeout) = EXTERNAL_WAKE
            .wait_timeout_while(state, std::time::Duration::from_millis(500), |s| {
                s.wakes == 0
            })
            .unwrap();
        state = awakened;
        if timeout.timed_out() && state.wakes == 0 {
            return -1;
        }
    }
    state.ready = true;
    if deadline != u64::MAX {
        state.now = deadline;
    }
    let ready = (interests as i32 & 3)
        | if interests & 4 != 0 { 8 } else { 0 }
        | if deadline != u64::MAX { 4 } else { 0 };
    let wake_in_wait = state.wake_in_wait;
    drop(state);
    if wake_in_wait {
        // Publication after parking must interrupt the native wait even when
        // it occurs before the platform actually enters its blocking syscall.
        assert_ne!(WAKE_STATE.load(Ordering::Acquire) & PARKED, 0);
        unsafe { super::wake(core::ptr::null()) };
    }
    ready
}
#[unsafe(no_mangle)]
extern "C" fn coaptic_async_yield() {
    STATE.lock().unwrap().yields += 1;
}
#[unsafe(no_mangle)]
extern "C" fn coaptic_async_storage(_: u32, _: u32) {}
#[cfg(feature = "pairing")]
#[unsafe(no_mangle)]
extern "C" fn coaptic_async_console_ready() -> i32 {
    i32::from(STATE.lock().unwrap().ready)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn coaptic_socket_recv(
    _: *mut c_void,
    bytes: *mut u8,
    capacity: u32,
    peer: *mut u64,
) -> i32 {
    let mut state = STATE.lock().unwrap();
    state.attempts += 1;
    if !state.ready {
        return -1;
    }
    assert!(capacity >= 4);
    unsafe {
        core::ptr::copy_nonoverlapping(b"recv".as_ptr(), bytes, 4);
        *peer = (0x7f000001_u64 << 16) | 5683;
    }
    4
}
#[unsafe(no_mangle)]
unsafe extern "C" fn coaptic_socket_send(
    _: *mut c_void,
    bytes: *const u8,
    length: u32,
    _: u64,
) -> i32 {
    let mut state = STATE.lock().unwrap();
    state.attempts += 1;
    if !state.ready {
        return -3;
    }
    assert_eq!(length, 4);
    state
        .bytes
        .copy_from_slice(unsafe { core::slice::from_raw_parts(bytes, 4) });
    4
}
#[unsafe(no_mangle)]
extern "C" fn coaptic_socket_random(_: *mut u8, _: u32) -> bool {
    false
}

fn runtime() -> Runtime {
    *STATE.lock().unwrap() = State::new();
    assert_eq!(WAKE_STATE.load(Ordering::Acquire) & PARKED, 0);
    unsafe { Runtime::new(core::ptr::dangling_mut()).unwrap() }
}

#[test]
fn receive_and_send_wait_for_readiness_without_staging() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (mut socket, _, _, mut driver) = runtime.split();
    STATE.lock().unwrap().expected_interest = READ;
    let mut bytes = [0; 4];
    assert_eq!(
        driver.run(core::pin::pin!(socket.recv(&mut bytes))),
        Ok(Ok((4, Endpoint::v4([127, 0, 0, 1], 5683))))
    );
    assert_eq!(&bytes, b"recv");
    assert_eq!(driver.0.interests.get(), 0);
    {
        let mut state = STATE.lock().unwrap();
        assert_eq!((state.attempts, state.waits), (2, 1));
        state.ready = false;
        state.expected_interest = WRITE;
    }
    assert_eq!(
        driver.run(core::pin::pin!(
            socket.send(Endpoint::v4([127, 0, 0, 1], 5683), b"send")
        )),
        Ok(Ok(4))
    );
    assert_eq!(STATE.lock().unwrap().bytes, *b"send");
    assert_eq!(driver.0.interests.get(), 0);
}

#[test]
fn cancelled_waits_remove_socket_and_timer_interests() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (mut socket, mut timer, _, driver) = runtime.split();
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    let mut bytes = [0; 4];
    {
        let mut future = pin!(socket.recv(&mut bytes));
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert_eq!(driver.0.interests.get(), READ);
    }
    assert_eq!(driver.0.interests.get(), 0);
    {
        let mut future = pin!(timer.wait_until(25));
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert_eq!(driver.0.deadlines[0].get(), Some(25));
    }
    assert_eq!(driver.0.deadlines[0].get(), None);
    // Drop before first poll never installs a readiness interest.
    drop(socket.recv(&mut bytes));
    assert_eq!(driver.0.interests.get(), 0);
}

#[test]
fn absolute_timer_and_stop_are_bounded() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (_, mut timer, _, mut driver) = runtime.split();
    assert_eq!(driver.run(core::pin::pin!(timer.wait_until(25))), Ok(()));
    assert_eq!(STATE.lock().unwrap().waits, 1);
    assert_eq!(driver.0.deadlines[0].get(), None);
    STATE.lock().unwrap().stopped = true;
    assert_eq!(
        driver.run(core::pin::pin!(core::future::pending::<()>())),
        Err(Error::Stopped)
    );
}

#[test]
fn local_deadline_wakes_before_protocol_timer_and_cancels_both() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (_, mut protocol, mut local, mut driver) = runtime.split();
    let selected = driver.run(core::pin::pin!(async {
        let mut protocol = pin!(protocol.wait_until(100));
        let mut local = pin!(local.wait_until(25));
        poll_fn(|context| {
            if local.as_mut().poll(context).is_ready() {
                return Poll::Ready(1);
            }
            if protocol.as_mut().poll(context).is_ready() {
                return Poll::Ready(2);
            }
            Poll::Pending
        })
        .await
    }));
    assert_eq!(selected, Ok(1));
    assert_eq!(STATE.lock().unwrap().now, 25);
    assert_eq!(STATE.lock().unwrap().waits, 1);
    assert!(driver.0.deadlines.iter().all(|slot| slot.get().is_none()));
    assert!(driver.0.wakers.iter().all(|slot| slot.borrow().is_none()));
}

#[cfg(feature = "pairing")]
#[test]
fn console_readiness_never_consumes_a_byte_and_cancellation_removes_its_waker() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (_, _, _, mut console, mut driver) = runtime.split_with_console();
    STATE.lock().unwrap().expected_interest = CONSOLE;
    assert_eq!(driver.run(core::pin::pin!(console.wait())), Ok(Ok(())));
    assert_eq!(STATE.lock().unwrap().attempts, 0);
    assert_eq!(driver.0.interests.get(), 0);
    assert!(driver.0.wakers[4].borrow().is_none());
    STATE.lock().unwrap().ready = false;
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    {
        let mut future = pin!(console.wait());
        assert!(future.as_mut().poll(&mut context).is_pending());
    }
    assert_eq!(driver.0.interests.get(), 0);
    assert!(driver.0.wakers[4].borrow().is_none());
}

#[test]
fn retained_waker_has_no_runtime_pointer_and_owner_is_exclusive() {
    let _serial = SERIAL.lock().unwrap();
    let runtime = runtime();
    assert!(matches!(
        unsafe { Runtime::new(core::ptr::dangling_mut()) },
        Err(Error::Busy)
    ));
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    drop(runtime);
    waker.wake_by_ref();
    assert_eq!(STATE.lock().unwrap().wakes, 0);
    let _runtime = unsafe { Runtime::new(core::ptr::dangling_mut()).unwrap() };
    println!(
        "async runtime metadata: {} bytes",
        core::mem::size_of::<Runtime>()
    );
}

#[test]
fn self_wakes_repoll_without_native_round_trips_and_keep_fairness() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (_, _, _, mut driver) = runtime.split();
    let mut polls = 0;
    assert_eq!(
        driver.run(pin!(poll_fn(|cx| {
            polls += 1;
            if polls <= 65 {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(polls)
            }
        }))),
        Ok(66)
    );
    let state = STATE.lock().unwrap();
    assert_eq!((state.waits, state.wakes, state.yields), (0, 0, 2));
    assert_eq!(WAKE_STATE.load(Ordering::Acquire) & PARKED, 0);
}

#[test]
fn wake_after_parking_interrupts_wait_without_an_extra_readiness_wake() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (mut socket, _, _, mut driver) = runtime.split();
    {
        let mut state = STATE.lock().unwrap();
        state.expected_interest = READ;
        state.wake_in_wait = true;
    }
    let mut bytes = [0; 4];
    assert_eq!(
        driver.run(pin!(socket.recv(&mut bytes))),
        Ok(Ok((4, Endpoint::v4([127, 0, 0, 1], 5683))))
    );
    let state = STATE.lock().unwrap();
    assert_eq!((state.waits, state.wakes), (1, 1));
    assert_eq!(&bytes, b"recv");
    assert_eq!(WAKE_STATE.load(Ordering::Acquire) & PARKED, 0);
}

#[test]
fn stopped_wait_clears_parking_before_returning() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (mut socket, _, _, mut driver) = runtime.split();
    {
        let mut state = STATE.lock().unwrap();
        state.expected_interest = READ;
        state.stop_in_wait = true;
    }
    let mut bytes = [0; 4];
    assert_eq!(
        driver.run(pin!(socket.recv(&mut bytes))),
        Err(Error::Stopped)
    );
    assert_eq!(WAKE_STATE.load(Ordering::Acquire) & PARKED, 0);
    assert_eq!(driver.0.interests.get(), 0);
}

struct QueuedWake {
    ready: Arc<AtomicBool>,
    parent: Waker,
}
impl Wake for QueuedWake {
    fn wake(self: Arc<Self>) {
        self.ready.store(true, Ordering::Release);
        self.parent.wake_by_ref();
    }
}

#[test]
fn local_work_does_not_starve_wake_gated_socket_or_timer_children() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (mut socket, mut timer, _, mut driver) = runtime.split();
    STATE.lock().unwrap().expected_interest = READ;
    let mut bytes = [0; 4];
    let mut receive = pin!(socket.recv(&mut bytes));
    let mut timeout = pin!(timer.wait_until(25));
    let receive_ready = Arc::new(AtomicBool::new(true));
    let timer_ready = Arc::new(AtomicBool::new(true));
    let mut received = false;
    let mut timed_out = false;
    let mut polls = 0;
    let result = driver.run(pin!(poll_fn(|cx| {
        polls += 1;
        if polls > 4 {
            return Poll::Ready(Err("child readiness starved"));
        }
        if receive_ready.swap(false, Ordering::AcqRel) {
            let waker = Waker::from(Arc::new(QueuedWake {
                ready: receive_ready.clone(),
                parent: cx.waker().clone(),
            }));
            received = receive
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready();
        }
        if timer_ready.swap(false, Ordering::AcqRel) {
            let waker = Waker::from(Arc::new(QueuedWake {
                ready: timer_ready.clone(),
                parent: cx.waker().clone(),
            }));
            timed_out = timeout
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready();
        }
        if received && timed_out {
            return Poll::Ready(Ok(()));
        }
        // The other child stays runnable, while the I/O children are polled
        // only when their stored child wakers publish them to the root queue.
        STATE.lock().unwrap().now = 25;
        cx.waker().wake_by_ref();
        Poll::Pending
    })));
    assert_eq!(result, Ok(Ok(())));
    assert_eq!(polls, 2);
    let state = STATE.lock().unwrap();
    assert_eq!((state.waits, state.wakes), (1, 0));
    assert_eq!(WAKE_STATE.load(Ordering::Acquire) & PARKED, 0);
}

#[test]
fn external_notification_racing_parking_is_not_lost() {
    let _serial = SERIAL.lock().unwrap();
    for iteration in 0..32 {
        let mut runtime = runtime();
        STATE.lock().unwrap().await_external_wake = true;
        let (_, _, _, mut driver) = runtime.split();
        let ready = Arc::new(AtomicBool::new(false));
        let publish = ready.clone();
        let (send, recv) = std::sync::mpsc::sync_channel::<Waker>(1);
        let worker = std::thread::spawn(move || {
            let waker = recv.recv().unwrap();
            if iteration % 2 == 0 {
                std::thread::yield_now();
            }
            publish.store(true, Ordering::Release);
            waker.wake();
        });
        let mut first = Some(send);
        let result = driver.run(pin!(poll_fn(|cx| {
            if ready.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            if let Some(send) = first.take() {
                send.send(cx.waker().clone()).unwrap();
            }
            Poll::Pending
        })));
        worker.join().unwrap();
        assert_eq!(result, Ok(()), "park race iteration {iteration}");
        assert_eq!(WAKE_STATE.load(Ordering::Acquire) & PARKED, 0);
    }
}
