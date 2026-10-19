//! Synchronous borrowed-buffer boundary to ESPHome's owned lwIP socket.
#[cfg(not(feature = "async-network"))]
use coaptic::Endpoint;
#[cfg(not(feature = "async-network"))]
use coaptic::storage::DatagramIo;
use core::ffi::c_void;

unsafe extern "C" {
    #[cfg(not(feature = "async-network"))]
    fn coaptic_socket_recv(
        context: *mut c_void,
        bytes: *mut u8,
        capacity: u32,
        peer: *mut u64,
    ) -> i32;
    #[cfg(not(feature = "async-network"))]
    fn coaptic_socket_send(context: *mut c_void, bytes: *const u8, length: u32, peer: u64) -> i32;
    #[cfg(not(feature = "async-network"))]
    fn coaptic_socket_clock(context: *mut c_void) -> u64;
    #[cfg(feature = "async-network")]
    fn coaptic_async_now(context: *mut c_void) -> u64;
    fn coaptic_security_mode(context: *mut c_void) -> u32;
    #[cfg(feature = "oscore")]
    fn coaptic_security_config(context: *mut c_void, bytes: *mut u8, length: u32) -> bool;
    #[cfg(feature = "oscore")]
    fn coaptic_security_read(context: *mut c_void, bytes: *mut u8, length: u32) -> i32;
    #[cfg(feature = "oscore")]
    fn coaptic_security_commit(context: *mut c_void, bytes: *const u8, length: u32) -> bool;
    #[cfg(feature = "telemetry")]
    fn coaptic_telemetry_config(context: *mut c_void, bytes: *mut u8, capacity: u32) -> i32;
    #[cfg(feature = "telemetry")]
    fn coaptic_pending_read(context: *mut c_void, bytes: *mut u8, length: u32) -> i32;
    #[cfg(feature = "telemetry")]
    fn coaptic_pending_commit(context: *mut c_void, bytes: *const u8, length: u32) -> bool;
    fn coaptic_socket_random(bytes: *mut u8, length: u32) -> bool;
    fn coaptic_enter_critical();
    fn coaptic_leave_critical();
}

struct EspHomeCriticalSection;
critical_section::set_impl!(EspHomeCriticalSection);

/// ESP-IDF's portMUX serializes all cores and nests on the owning task.
/// Acquire/release callbacks must use the same process-lifetime mutex, restore
/// interrupt state on exit, and never unwind across this boundary.
unsafe impl critical_section::Impl for EspHomeCriticalSection {
    unsafe fn acquire() -> critical_section::RawRestoreState {
        unsafe { coaptic_enter_critical() }
    }
    unsafe fn release(_: critical_section::RawRestoreState) {
        unsafe { coaptic_leave_critical() }
    }
}

#[cfg(not(feature = "async-network"))]
struct Socket(*mut c_void);
#[cfg(not(feature = "async-network"))]
impl coaptic::storage::DatagramTransport for Socket {
    type Error = ();
}
#[cfg(not(feature = "async-network"))]
impl DatagramIo for Socket {
    fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
        let mut peer = 0;
        let size = unsafe {
            coaptic_socket_recv(self.0, bytes.as_mut_ptr(), bytes.len() as u32, &mut peer)
        };
        if size == -1 {
            return Ok(None);
        }
        if size < 0 || size as usize > bytes.len() || peer >> 48 != 0 {
            return Err(());
        }
        let address = (peer >> 16) as u32;
        Ok(Some((
            size as usize,
            Endpoint::v4(address.to_be_bytes(), peer as u16),
        )))
    }
    fn send(&mut self, to: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
        let (address, port) = to.as_ipv4().ok_or(())?;
        let peer = (u64::from(u32::from_be_bytes(address)) << 16) | u64::from(port);
        let size = unsafe { coaptic_socket_send(self.0, bytes.as_ptr(), bytes.len() as u32, peer) };
        if size < 0 || size as usize != bytes.len() {
            return Err(());
        }
        Ok(size as usize)
    }
}

#[cfg(feature = "oscore")]
struct Nvs(*mut c_void);
#[cfg(feature = "oscore")]
impl super::security_state::Store for Nvs {
    fn read(
        &mut self,
    ) -> Result<Option<[u8; super::security_state::RECORD_BYTES]>, super::security_state::Error>
    {
        let mut bytes = [0; super::security_state::RECORD_BYTES];
        match unsafe { coaptic_security_read(self.0, bytes.as_mut_ptr(), bytes.len() as u32) } {
            0 => Ok(None),
            1 => Ok(Some(bytes)),
            _ => Err(super::security_state::Error::Unavailable),
        }
    }
    fn commit(
        &mut self,
        bytes: &[u8; super::security_state::RECORD_BYTES],
    ) -> Result<(), super::security_state::Error> {
        if unsafe { coaptic_security_commit(self.0, bytes.as_ptr(), bytes.len() as u32) } {
            Ok(())
        } else {
            Err(super::security_state::Error::Unavailable)
        }
    }
}

#[cfg(feature = "telemetry")]
struct PendingNvs(*mut c_void);
#[cfg(feature = "telemetry")]
impl super::pending_telemetry::Store for PendingNvs {
    fn read(
        &mut self,
    ) -> Result<Option<[u8; super::pending_telemetry::RECORD_BYTES]>, super::pending_telemetry::Error>
    {
        let mut bytes = [0; super::pending_telemetry::RECORD_BYTES];
        match unsafe { coaptic_pending_read(self.0, bytes.as_mut_ptr(), bytes.len() as u32) } {
            0 => Ok(None),
            1 => Ok(Some(bytes)),
            _ => Err(super::pending_telemetry::Error::Storage),
        }
    }
    fn commit(
        &mut self,
        bytes: &[u8; super::pending_telemetry::RECORD_BYTES],
    ) -> Result<(), super::pending_telemetry::Error> {
        if unsafe { coaptic_pending_commit(self.0, bytes.as_ptr(), bytes.len() as u32) } {
            Ok(())
        } else {
            Err(super::pending_telemetry::Error::Storage)
        }
    }
}

#[cfg(feature = "telemetry")]
fn telemetry(
    context: *mut c_void,
    mode: u32,
    credentials: &super::security_state::Credentials,
    random: fn(&mut [u8]) -> bool,
    clock: impl FnMut() -> Option<u64>,
) -> Result<(), &'static str> {
    let mut bytes = [0; super::telemetry_config::MAX_BYTES];
    let length =
        unsafe { coaptic_telemetry_config(context, bytes.as_mut_ptr(), bytes.len() as u32) };
    if length < 0 || length as usize > bytes.len() {
        return Err("telemetry config");
    }
    let config = super::telemetry_config::Config::parse(&bytes[..length as usize], mode == 4)
        .ok_or("telemetry config")?;
    if mode == 4 {
        // Verify existing security ownership; offline provisioning opens no socket.
        // If a commit fails, stop without resetting or replacing either record.
        super::security_state::verify_record(&mut Nvs(context), credentials)
            .map_err(|_| "security recovery")?;
        let mut store = PendingNvs(context);
        let operation = config.operation.ok_or("telemetry config")?;
        super::pending_telemetry::provision_operation(
            &mut store,
            credentials,
            config.principal,
            &operation,
        )
        .map_err(|_| "pending provisioning")
    } else {
        let service = super::protected_telemetry::Service {
            endpoint: config.endpoint,
            principal: config.principal,
            resource: config.resource,
            credentials,
            timeout_ms: config.timeout_ms,
        };
        #[cfg(feature = "async-network")]
        {
            run_telemetry_async(context, random, clock, service)
        }
        #[cfg(not(feature = "async-network"))]
        {
            super::protected_telemetry::run(
                Socket(context),
                random,
                clock,
                service,
                Nvs(context),
                PendingNvs(context),
            )
            .map(|_| ())
            .map_err(|_| "telemetry stopped")
        }
    }
}

/// Runs the IPv4 qualification service with ESPHome-owned task and socket state.
///
/// # Safety
/// `context` must point to a live ESPHome `CoapticNetwork` for the entire call.
/// `id` must reference 32 readable bytes, valid for the initial copy. Call only
/// once per firmware boot, from the socket's sole task. C callbacks must not
/// retain buffers, unwind, alias mutable buffers, or report unwritten bytes.
/// The clock callback must periodically yield within a bounded poll budget,
/// bound idle waits for timer progress, remain monotonic, and return u64::MAX
/// to stop. It may return immediately during a bounded ready burst.
/// Entropy must be supplied while the Wi-Fi hardware RNG source is enabled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn coaptic_network_run(context: *mut c_void, id: *const u8) -> i32 {
    if context.is_null() || id.is_null() {
        return -1;
    }
    let mode = unsafe { coaptic_security_mode(context) };
    #[cfg(feature = "pairing")]
    if mode == 5 {
        return if pairing_ffi::run(context).is_ok() {
            0
        } else {
            -11
        };
    }
    unsafe { run_legacy(context, id, mode) }
}

// Keep the legacy App's large construction frame off the paired worker's stack.
// Both profiles fit individually; reserving both frames on a dispatch path does not.
#[inline(never)]
unsafe fn run_legacy(context: *mut c_void, id: *const u8, mode: u32) -> i32 {
    let mut run_id = [0; 32];
    run_id.copy_from_slice(unsafe { core::slice::from_raw_parts(id, 32) });
    let random =
        |bytes: &mut [u8]| unsafe { coaptic_socket_random(bytes.as_mut_ptr(), bytes.len() as u32) };
    #[cfg(not(feature = "async-network"))]
    let clock = || {
        let now = unsafe { coaptic_socket_clock(context) };
        (now != u64::MAX).then_some(now)
    };
    #[cfg(all(feature = "async-network", feature = "telemetry"))]
    let clock = || async_clock(context);
    let result = match mode {
        0 => {
            #[cfg(feature = "async-network")]
            {
                run_unprotected_async(context, random, &run_id)
            }
            #[cfg(not(feature = "async-network"))]
            {
                super::network::run(Socket(context), random, clock, &run_id)
            }
        }
        #[cfg(feature = "oscore")]
        1..=4 => {
            let mut bytes = [0; 66];
            if !unsafe { coaptic_security_config(context, bytes.as_mut_ptr(), bytes.len() as u32) }
            {
                return -1;
            }
            let credentials = super::security_state::Credentials {
                secret: bytes[..32].try_into().unwrap(),
                salt: bytes[32..48].try_into().unwrap(),
                context: bytes[48..64].try_into().unwrap(),
                sender: bytes[64],
                recipient: bytes[65],
            };
            bytes.fill(0);
            if mode == 2 {
                // Explicit offline mode: no socket read/send or network service.
                super::security_state::provision(&mut Nvs(context), &credentials)
                    .map_err(|_| "provisioning")
            } else if mode == 1 {
                #[cfg(feature = "async-network")]
                {
                    run_protected_async(context, random, &run_id, &credentials)
                }
                #[cfg(not(feature = "async-network"))]
                {
                    super::network::run_protected(
                        Socket(context),
                        random,
                        clock,
                        &run_id,
                        &credentials,
                        Nvs(context),
                    )
                }
            } else {
                #[cfg(feature = "telemetry")]
                {
                    telemetry(context, mode, &credentials, random, clock)
                }
                #[cfg(not(feature = "telemetry"))]
                {
                    Err("unsupported security mode")
                }
            }
        }
        _ => Err("unsupported security mode"),
    };
    match result {
        Ok(()) => 0,
        Err("security recovery") => -2,
        Err("security checkpoint") => -3,
        Err("sender reservation") => -4,
        Err("provisioning") => -5,
        Err("unsupported security mode") => -6,
        Err("clock regression") => -7,
        Err("telemetry config") => -8,
        Err("pending provisioning") => -9,
        Err("telemetry stopped") => -10,
        Err(_) => -1,
    }
}

#[cfg(feature = "async-network")]
fn async_clock(context: *mut c_void) -> Option<u64> {
    let now = unsafe { coaptic_async_now(context) };
    (now != u64::MAX).then_some(now)
}

#[cfg(feature = "async-network")]
#[inline(never)]
fn run_unprotected_async(
    context: *mut c_void,
    random: fn(&mut [u8]) -> bool,
    id: &[u8; 32],
) -> Result<(), &'static str> {
    let mut runtime =
        unsafe { crate::async_network::Runtime::new(context) }.map_err(|_| "async driver")?;
    let (socket, mut protocol, mut local, mut driver) = runtime.split();
    match driver.run(core::pin::pin!(crate::network::run_async(
        socket,
        random,
        || async_clock(context),
        id,
        (&mut protocol, &mut local),
    ))) {
        Ok(result) => result,
        Err(crate::async_network::Error::Stopped) => Ok(()),
        Err(_) => Err("async driver"),
    }
}

#[cfg(all(feature = "async-network", feature = "telemetry"))]
#[inline(never)]
fn run_telemetry_async(
    context: *mut c_void,
    random: fn(&mut [u8]) -> bool,
    clock: impl FnMut() -> Option<u64>,
    service: crate::protected_telemetry::Service<'_>,
) -> Result<(), &'static str> {
    let mut runtime =
        unsafe { crate::async_network::Runtime::new(context) }.map_err(|_| "async driver")?;
    let (socket, mut protocol, mut local, mut driver) = runtime.split();
    driver
        .run(core::pin::pin!(crate::protected_telemetry::run_async(
            socket,
            random,
            clock,
            service,
            Nvs(context),
            PendingNvs(context),
            (&mut protocol, &mut local),
        )))
        .map_err(|_| "telemetry stopped")?
        .map(|_| ())
        .map_err(|_| "telemetry stopped")
}

#[cfg(all(feature = "async-network", feature = "oscore"))]
#[inline(never)]
fn run_protected_async(
    context: *mut c_void,
    random: fn(&mut [u8]) -> bool,
    id: &[u8; 32],
    credentials: &crate::security_state::Credentials,
) -> Result<(), &'static str> {
    let mut runtime =
        unsafe { crate::async_network::Runtime::new(context) }.map_err(|_| "async driver")?;
    let (socket, mut protocol, mut local, mut driver) = runtime.split();
    match driver.run(core::pin::pin!(crate::network::run_protected_async(
        socket,
        random,
        || async_clock(context),
        id,
        (&mut protocol, &mut local),
        credentials,
        Nvs(context),
    ))) {
        Ok(result) => result,
        Err(crate::async_network::Error::Stopped) => Ok(()),
        Err(_) => Err("async driver"),
    }
}

#[cfg(feature = "pairing")]
mod pairing_ffi {
    use super::*;
    use crate::pairing::{Console, Error, Store};

    unsafe extern "C" {
        fn coaptic_pairing_read(context: *mut c_void, bytes: *mut u8, capacity: u32) -> i32;
        fn coaptic_pairing_commit(context: *mut c_void, bytes: *const u8, length: u32) -> bool;
        fn coaptic_pairing_console_read(context: *mut c_void, bytes: *mut u8, capacity: u32)
        -> i32;
        fn coaptic_pairing_console_write(
            context: *mut c_void,
            bytes: *const u8,
            length: u32,
        ) -> bool;
        fn coaptic_pairing_restart(context: *mut c_void);
        fn coaptic_pairing_event(context: *mut c_void, event: u32);
        fn coaptic_pairing_owner_sizes(context: *mut c_void, managed: u32, worker: u32);
        fn coaptic_pairing_diagnostics(
            context: *mut c_void,
            at_ms: u64,
            token_refused: u32,
            rx_refused: u32,
            tx_refused: u32,
            refusal_sent: u32,
            refusal_unsent: u32,
            hard_rx: u32,
            hard_tx: u32,
            rx_accepted: u32,
            progress: u32,
        );
    }

    struct Nvs(*mut c_void);
    impl Store for Nvs {
        fn pending_read(
            &mut self,
        ) -> Result<Option<[u8; crate::pending_telemetry::RECORD_BYTES]>, Error> {
            crate::pending_telemetry::Store::read(&mut PendingNvs(self.0))
                .map_err(|_| Error::Storage)
        }
        fn pending_commit(
            &mut self,
            bytes: &[u8; crate::pending_telemetry::RECORD_BYTES],
        ) -> Result<(), Error> {
            crate::pending_telemetry::Store::commit(&mut PendingNvs(self.0), bytes)
                .map_err(|_| Error::Storage)
        }
        fn read(&mut self, output: &mut [u8; crate::pairing::STORE_BYTES]) -> Result<usize, Error> {
            let length =
                unsafe { coaptic_pairing_read(self.0, output.as_mut_ptr(), output.len() as u32) };
            if length < 0 || length as usize > output.len() {
                return Err(Error::Storage);
            }
            Ok(length as usize)
        }
        fn commit(&mut self, expected: &[u8], next: &[u8]) -> Result<(), Error> {
            use zeroize::Zeroizing;
            let mut current = Zeroizing::new([0; crate::pairing::STORE_BYTES]);
            let len = self.read(&mut current)?;
            if &current[..len] != expected {
                return Err(Error::Storage);
            }
            if !unsafe { coaptic_pairing_commit(self.0, next.as_ptr(), next.len() as u32) } {
                return Err(Error::Storage);
            }
            current.fill(0);
            let len = self.read(&mut current)?;
            if &current[..len] != next {
                return Err(Error::Storage);
            }
            Ok(())
        }
    }

    struct Usb(*mut c_void);
    impl Console for Usb {
        fn read(&mut self, bytes: &mut [u8]) -> Result<usize, Error> {
            let len = unsafe {
                coaptic_pairing_console_read(self.0, bytes.as_mut_ptr(), bytes.len() as u32)
            };
            if len < 0 || len as usize > bytes.len() {
                return Err(Error::Console);
            }
            Ok(len as usize)
        }
        fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
            if unsafe { coaptic_pairing_console_write(self.0, bytes.as_ptr(), bytes.len() as u32) }
            {
                Ok(())
            } else {
                Err(Error::Console)
            }
        }
        fn restart(&mut self) -> Result<(), Error> {
            unsafe { coaptic_pairing_restart(self.0) };
            Ok(())
        }
        fn event(&mut self, event: u32) {
            unsafe { coaptic_pairing_event(self.0, event) };
        }
        fn diagnostics(&mut self, snapshot: &coaptic::app::diagnostics::Snapshot) {
            let metrics = &snapshot.metrics;
            unsafe {
                coaptic_pairing_diagnostics(
                    self.0,
                    snapshot.at_ms,
                    metrics.token_capacity_refused,
                    metrics.admission_rx_refused,
                    metrics.admission_tx_refused,
                    metrics.admission_refusal_sent,
                    metrics.admission_refusal_unsent,
                    metrics.hard_rx_exhausted,
                    metrics.hard_tx_exhausted,
                    metrics.rx_accepted,
                    metrics.progress,
                )
            };
        }
    }

    #[cfg(feature = "async-network")]
    impl crate::pairing::ConsoleWait for crate::async_network::ConsoleReady<'_> {
        async fn wait(&mut self) -> Result<(), Error> {
            crate::async_network::ConsoleReady::wait(self)
                .await
                .map_err(|_| Error::Console)
        }
    }

    #[cfg(feature = "async-network")]
    #[inline(never)]
    pub(super) fn run(context: *mut c_void) -> Result<(), &'static str> {
        let mut runtime =
            unsafe { crate::async_network::Runtime::new(context) }.map_err(|_| "async driver")?;
        let (socket, mut protocol, mut local, console_ready, mut driver) =
            runtime.split_with_console();
        let worker = core::pin::pin!(crate::pairing::run_async(
            socket,
            |bytes| unsafe { coaptic_socket_random(bytes.as_mut_ptr(), bytes.len() as u32) },
            || async_clock(context),
            Nvs(context),
            Usb(context),
            (&mut protocol, &mut local),
            console_ready,
        ));
        fn worker_bytes<F>(_: &F) -> usize {
            // Leave 32 KiB of the 192 KiB task reservation for active call frames.
            const { assert!(core::mem::size_of::<F>() <= 160 * 1024) };
            core::mem::size_of::<F>()
        }
        unsafe {
            coaptic_pairing_owner_sizes(
                context,
                crate::pairing::managed_owner_bytes::<crate::async_network::Socket<'_>>() as u32,
                worker_bytes(worker.as_ref().get_ref()) as u32,
            );
        }
        match driver.run(worker) {
            Ok(result) => result.map_err(|_| "pairing stopped"),
            Err(crate::async_network::Error::Stopped) => Ok(()),
            Err(_) => Err("async driver"),
        }
    }

    #[cfg(not(feature = "async-network"))]
    #[inline(never)]
    pub(super) fn run(context: *mut c_void) -> Result<(), &'static str> {
        crate::pairing::run(
            || Socket(context),
            |bytes| unsafe { coaptic_socket_random(bytes.as_mut_ptr(), bytes.len() as u32) },
            || {
                let now = unsafe { coaptic_socket_clock(context) };
                (now != u64::MAX).then_some(now)
            },
            Nvs(context),
            Usb(context),
        )
        .map_err(|_| "pairing stopped")
    }
}
