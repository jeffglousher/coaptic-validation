use super::*;
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());
static STATE: Mutex<State> = Mutex::new(State::new());
struct State {
    now: u64,
    waits: u32,
    attempts: u32,
    ready: bool,
    stopped: bool,
    expected_interest: u32,
    wakes: u32,
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
    state.ready = true;
    if deadline != u64::MAX {
        state.now = deadline;
    }
    interests as i32 | if deadline != u64::MAX { 4 } else { 0 }
}
#[unsafe(no_mangle)]
extern "C" fn coaptic_async_yield() {}
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
    unsafe { Runtime::new(core::ptr::dangling_mut()).unwrap() }
}

#[test]
fn receive_and_send_wait_for_readiness_without_staging() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (mut socket, _, mut driver) = runtime.split();
    STATE.lock().unwrap().expected_interest = READ;
    let mut bytes = [0; 4];
    assert_eq!(
        driver.run(socket.recv(&mut bytes)),
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
        driver.run(socket.send(Endpoint::v4([127, 0, 0, 1], 5683), b"send")),
        Ok(Ok(4))
    );
    assert_eq!(STATE.lock().unwrap().bytes, *b"send");
    assert_eq!(driver.0.interests.get(), 0);
}

#[test]
fn cancelled_waits_remove_socket_and_timer_interests() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (mut socket, mut timer, driver) = runtime.split();
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
        assert_eq!(driver.0.deadline.get(), Some(25));
    }
    assert_eq!(driver.0.deadline.get(), None);
    // Drop before first poll never installs a readiness interest.
    drop(socket.recv(&mut bytes));
    assert_eq!(driver.0.interests.get(), 0);
}

#[test]
fn absolute_timer_and_stop_are_bounded() {
    let _serial = SERIAL.lock().unwrap();
    let mut runtime = runtime();
    let (_, mut timer, mut driver) = runtime.split();
    assert_eq!(driver.run(timer.wait_until(25)), Ok(()));
    assert_eq!(STATE.lock().unwrap().waits, 1);
    assert_eq!(driver.0.deadline.get(), None);
    STATE.lock().unwrap().stopped = true;
    assert_eq!(
        driver.run(core::future::pending::<()>()),
        Err(Error::Stopped)
    );
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
    assert_eq!(STATE.lock().unwrap().wakes, 1);
    let _runtime = unsafe { Runtime::new(core::ptr::dangling_mut()).unwrap() };
    println!(
        "async runtime metadata: {} bytes",
        core::mem::size_of::<Runtime>()
    );
}
