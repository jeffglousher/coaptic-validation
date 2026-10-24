#![no_std]
#![no_main]
//! Separate opt-in ELF: the existing ingress object/maps remain unchanged.
#[path = "../../../syscall_contract.rs"]
#[allow(dead_code)] // Shared host/kernel contract; each binary uses a subset.
mod contract;
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::{Array, PerCpuArray},
    programs::TracePointContext,
};

// Slot 0 contains (TGID << 32 | TID), or zero while disabled. One map update
// changes both selection and gate; no flow state, syscall pairing or timestamps.
#[map]
static SC_CTL: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static SC_COUNTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(contract::COUNTERS, 0);

#[inline(always)]
fn selected() -> bool {
    let Some(target) = SC_CTL.get(0).copied().filter(|n| *n != 0) else {
        return false;
    };
    let current = bpf_get_current_pid_tgid();
    if current >> 32 == target >> 32 && current != target {
        count(contract::FOREIGN_THREAD);
    }
    current == target
}
#[inline(always)]
fn count(index: u32) {
    if let Some(value) = SC_COUNTS.get_ptr_mut(index) {
        // These non-sleeping tracepoint callbacks on one CPU cannot run the
        // selected single userspace thread concurrently with itself.
        unsafe {
            *value = (*value).saturating_add(1);
        }
    }
}
#[tracepoint]
pub fn sc_enter(ctx: TracePointContext) -> u32 {
    if selected() {
        // Loader requires the exact raw_syscalls format before attachment.
        match unsafe { ctx.read_at::<i64>(8) } {
            Ok(number) => count(contract::bin(number) * contract::FIELDS),
            Err(_) => count(contract::READ_ERROR),
        }
    }
    0
}
#[tracepoint]
pub fn sc_exit(ctx: TracePointContext) -> u32 {
    if selected() {
        match unsafe { (ctx.read_at::<i64>(8), ctx.read_at::<i64>(16)) } {
            (Ok(number), Ok(result)) => {
                count(contract::bin(number) * contract::FIELDS + contract::exit_class(result))
            }
            _ => count(contract::READ_ERROR),
        }
    }
    0
}
#[unsafe(link_section = "license")]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
