//! Synchronous borrowed-buffer boundary to ESPHome's owned lwIP socket.
use coaptic::Endpoint;
use coaptic::storage::DatagramIo;
use core::ffi::c_void;

unsafe extern "C" {
    fn coaptic_socket_recv(
        context: *mut c_void,
        bytes: *mut u8,
        capacity: u32,
        peer: *mut u64,
    ) -> i32;
    fn coaptic_socket_send(context: *mut c_void, bytes: *const u8, length: u32, peer: u64) -> i32;
    fn coaptic_socket_clock(context: *mut c_void) -> u64;
    fn coaptic_security_mode(context: *mut c_void) -> u32;
    #[cfg(feature = "oscore")]
    fn coaptic_security_config(context: *mut c_void, bytes: *mut u8, length: u32) -> bool;
    #[cfg(feature = "oscore")]
    fn coaptic_security_read(context: *mut c_void, bytes: *mut u8, length: u32) -> i32;
    #[cfg(feature = "oscore")]
    fn coaptic_security_commit(context: *mut c_void, bytes: *const u8, length: u32) -> bool;
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

struct Socket(*mut c_void);
impl DatagramIo for Socket {
    type Error = ();
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
    let mut run_id = [0; 32];
    run_id.copy_from_slice(unsafe { core::slice::from_raw_parts(id, 32) });
    let mode = unsafe { coaptic_security_mode(context) };
    let random =
        |bytes: &mut [u8]| unsafe { coaptic_socket_random(bytes.as_mut_ptr(), bytes.len() as u32) };
    let clock = || {
        let now = unsafe { coaptic_socket_clock(context) };
        (now != u64::MAX).then_some(now)
    };
    let result = match mode {
        0 => super::network::run(Socket(context), random, clock, &run_id),
        #[cfg(feature = "oscore")]
        1 | 2 => {
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
            } else {
                super::network::run_protected(
                    Socket(context),
                    random,
                    clock,
                    &run_id,
                    &credentials,
                    Nvs(context),
                )
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
        Err(_) => -1,
    }
}
