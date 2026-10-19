#![no_std]
#![no_main]
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use coaptic_ingress_classifier::{COUNTERS, Class, MAX_FRAME, TOTAL, classify};
#[map]
static COUNTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(COUNTERS, 0);

#[inline(always)]
fn count(index: u32) {
    if let Some(value) = COUNTS.get_ptr_mut(index) {
        // XDP execution uses this CPU's map slot; no shared flow state.
        unsafe {
            *value = (*value).saturating_add(1);
        }
    }
}
#[xdp]
pub fn coaptic_observe(ctx: XdpContext) -> u32 {
    let start = ctx.data();
    let end = ctx.data_end();
    count(TOTAL);
    let class = if end < start || end - start > MAX_FRAME {
        Class::Uninspected
    } else {
        // Bounds cover the complete linear packet; no packet copy or write.
        let frame = unsafe { core::slice::from_raw_parts(start as *const u8, end - start) };
        classify(frame)
    };
    count(class as u32);
    xdp_action::XDP_PASS
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Any surviving panic edge must fail verifier acceptance, not silently classify.
    loop {}
}
