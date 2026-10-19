use coaptic::storage::{AllocMemory, DatagramIo, Endpoint};
struct Io;
impl coaptic::storage::DatagramTransport for Io {
    type Error = ();
}
impl DatagramIo for Io {
    fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
        Ok(None)
    }
    fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
        Ok(bytes.len())
    }
}
fn main() {
    println!(
        "{{\"alloc_memory_inline_bytes\":{},\"allocated_app_inline_bytes\":{},\"fixed_app_inline_bytes\":{}}}",
        core::mem::size_of::<AllocMemory>(),
        core::mem::size_of::<coaptic::App<coaptic::profiles::Default, Io, 1, true, AllocMemory>>(),
        core::mem::size_of::<coaptic::App<coaptic::profiles::Default, Io, 1, true>>()
    );
}
