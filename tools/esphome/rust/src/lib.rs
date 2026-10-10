//! Scalar C ABI for running the bounded Coaptic probe inside ESPHome/ESP-IDF.
//!
//! This adapter exercises real App loopback and optional OSCORE through a Rust
//! static library. Feature `network` also supplies a live IPv4 UDP qualification
//! service. ESPHome owns sockets, tasks, console and stack accounting. This is
//! not yet a device driver, Home Assistant entity integration or Taldra gateway.
//!
//! Generate a pinned ESPHome configuration with `tools/qualification/esphome_probe.py`.
//! The component links this crate using Rust 1.97.1 for C3/C6 or Espressif Rust
//! 1.97.0.0 for S3. Network callbacks borrow buffers synchronously; no Rust-owned
//! pointers escape. The loopback ABI uses only scalar values.
//! A panic terminates through ESP-IDF's `abort`, so missing captures cannot pass.
//!
//! ESP32-S3 builders may use a locally generated archive with
//! `coaptic_network.rust_runtime: bundled`. Generate it with
//! `tools/esphome/build_archive.py --expected-library-revision LIBRARY_COMMIT_SHA`.
//! Generated archives stay out of git. Bundle configuration requires both
//! `expected_library_revision` and `expected_suite_revision`; the report retains
//! clean revisions, prepared lock hashes, compiler identity and SHA-256.
//! These checks establish build provenance, not authenticated device attestation.
//! The import uses ESP-IDF's
//! local component dependency mechanism and does not replace
//! `EXTRA_COMPONENT_DIRS`, allowing other native components in the same build.
//! The bundled service requires `qualification_only: true` and a fresh 32-digit
//! hexadecimal `run_id`. It remains a private-network test service, not a
//! supported Home Assistant integration.
//!
//! To combine this service with another Rust subsystem, consume this crate as
//! an `rlib` dependency with features `network,library-only`, produce one
//! enclosing `staticlib`, and configure `coaptic_network.rust_runtime: external`.
//! The enclosing crate owns the single panic handler and must retain this
//! crate's exported C ABI. Do not link the standalone archive beside another
//! Rust static library: their panic runtimes can conflict. `library-only` is
//! intended for dependency builds, not a standalone `no_std` staticlib build.
//! Source and archive tooling explicitly enables `standalone` and requests
//! `--crate-type staticlib`; normal dependency builds produce only an `rlib`.
//! Qualify the final link, stack and simultaneous transports; separate firmware
//! tests alone do not establish combined HID reliability.
#![cfg_attr(target_os = "none", no_std)]

#[cfg(feature = "network")]
pub mod network;

#[cfg(all(feature = "network", feature = "oscore"))]
pub mod security_state;

#[cfg(feature = "telemetry")]
pub mod pending_telemetry;

#[cfg(all(feature = "network", target_os = "none"))]
mod network_ffi;

#[cfg(all(feature = "network", target_os = "none"))]
pub use network_ffi::coaptic_network_run;

/// ABI revision required by the ESPHome qualification component.
#[unsafe(no_mangle)]
pub extern "C" fn coaptic_probe_version() -> u32 {
    1
}

/// Returns one when the linked Rust probe includes OSCORE, otherwise zero.
#[unsafe(no_mangle)]
pub extern "C" fn coaptic_probe_oscore() -> u32 {
    u32::from(cfg!(feature = "oscore"))
}

/// Executes the finite loopback campaign; zero means pass and minus one refusal.
///
/// Call once from the owned qualification task. The caller supplies sufficient
/// stack and records its high-water mark. Success does not establish networking,
/// radio, platform entropy, allocator stress or durable storage integration.
#[unsafe(no_mangle)]
pub extern "C" fn coaptic_probe_run() -> i32 {
    if qualification_no_std::protocol_runtime_probe().is_ok() {
        0
    } else {
        -1
    }
}

#[cfg(all(
    target_os = "none",
    feature = "standalone",
    not(feature = "library-only")
))]
unsafe extern "C" {
    fn abort() -> !;
}

#[cfg(all(
    target_os = "none",
    feature = "standalone",
    not(feature = "library-only")
))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { abort() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn scalar_abi_executes_the_protocol_probe() {
        assert_eq!(super::coaptic_probe_version(), 1);
        assert_eq!(
            super::coaptic_probe_oscore(),
            u32::from(cfg!(feature = "oscore"))
        );
        assert_eq!(super::coaptic_probe_run(), 0);
    }
}
