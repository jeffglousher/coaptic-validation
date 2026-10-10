//! Host execution of the same no-allocator campaign used by the ESP32 launcher.
fn main() {
    qualification_no_std::protocol_runtime_probe().expect("runtime probe");
    println!("COAPTIC_RUNTIME_PASS oscore={}", cfg!(feature = "oscore"));
}
