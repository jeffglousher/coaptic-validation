#![no_std]
#![no_main]
use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_xdp_load_bytes,
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
    let class = if end < start || end - start < 14 || end - start > MAX_FRAME {
        Class::Uninspected
    } else {
        let len = end - start;
        // LLVM's scalar slice checks do not establish verifier packet ranges.
        // One bounded stack copy lets the unchanged shared decoder read ordinary
        // memory. This scratch is per invocation; no map or packet is modified.
        let mut frame = [0u8; MAX_FRAME];
        let loaded =
            unsafe { bpf_xdp_load_bytes(ctx.ctx, 0, frame.as_mut_ptr().cast(), len as u32) };
        if loaded == 0 {
            classify(&frame[..len])
        } else {
            Class::Uninspected
        }
    };
    count(class as u32);
    xdp_action::XDP_PASS
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Any surviving panic edge must fail verifier acceptance, not silently classify.
    loop {}
}
