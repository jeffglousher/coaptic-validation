//! ESP32-C3/C6 runtime and stack-paint launcher for the bounded protocol probe.
//!
//! Build with `cargo +1.97.1 build --release --target riscv32imc-unknown-none-elf`
//! from this directory for C3. For C6, use `--no-default-features --features
//! esp32c6 --target riscv32imac-unknown-none-elf`. Add `oscore` to the features
//! for the protected-message checks. Never select the chip from its ISA alone.
//! Flash and retain console output with `espflash flash --monitor PATH_TO_ELF`.
//! Output uses native USB Serial/JTAG when connected, otherwise UART0. A board
//! exposing native USB also supports the built-in JTAG debugger without a probe.
//! The report covers loopback execution and stack use after HAL initialization.
//! Radio, allocator, entropy and flash durability remain separate campaigns.
#![no_std]
#![no_main]

use esp_println::println;

#[cfg(all(feature = "esp32c3", feature = "esp32c6"))]
compile_error!("select exactly one ESP32 chip");
#[cfg(not(any(feature = "esp32c3", feature = "esp32c6")))]
compile_error!("select an ESP32 chip");

#[cfg(feature = "esp32c3")]
const CHIP: &str = "esp32c3";
#[cfg(all(feature = "esp32c6", not(feature = "esp32c3")))]
const CHIP: &str = "esp32c6";

esp_bootloader_esp_idf::esp_app_desc!();

unsafe extern "C" {
    static _stack_end: u8;
    static _stack_start: u8;
}

struct StackPaint {
    low: usize,
    ceiling: usize,
    top: usize,
}

impl StackPaint {
    /// Paint unused CPU0 stack below the current frame, leaving a 1024-byte gap.
    ///
    /// # Safety
    /// Must run on the selected chip's CPU0 main stack after HAL initialization,
    /// before any other execution context can use this region. Linker stack bounds
    /// must describe writable RAM; the first 256 bytes contain the stack guard.
    unsafe fn initialize() -> Self {
        let pointer: usize;
        unsafe {
            core::arch::asm!("mv {}, sp", out(reg) pointer, options(nomem, nostack));
        }
        let low = core::ptr::addr_of!(_stack_end) as usize + 256;
        let top = core::ptr::addr_of!(_stack_start) as usize;
        let ceiling = pointer.checked_sub(1024).expect("stack pointer bound");
        assert!(low < ceiling && ceiling < top);
        for address in low..ceiling {
            unsafe {
                core::ptr::write_volatile(address as *mut u8, 0xa5);
            }
        }
        Self { low, ceiling, top }
    }

    /// Read the deepest overwritten byte in the painted region.
    ///
    /// # Safety
    /// Uses the same main stack and linker RAM region passed to `initialize`.
    /// No other context may write the painted region while it is scanned.
    unsafe fn high_water(&self) -> usize {
        let first = (self.low..self.ceiling)
            .find(|address| unsafe { core::ptr::read_volatile(*address as *const u8) != 0xa5 })
            .expect("probe did not reach painted stack");
        assert!(first > self.low, "stack exhausted painted range");
        self.top - first
    }
}

#[esp_hal::main]
fn main() -> ! {
    let _peripherals = esp_hal::init(esp_hal::Config::default());
    let paint = unsafe { StackPaint::initialize() };
    let result = qualification_no_std::protocol_runtime_probe();
    let passed = result.is_ok();
    let high_water = unsafe { paint.high_water() };
    println!(
        "COAPTIC_DEVICE {{\"schema\":\"coaptic-device/1\",\"chip\":\"{}\",\"run_id\":\"{}\",\"passed\":{},\"oscore\":{},\"stack_high_water_bytes\":{},\"stack_capacity_bytes\":{}}}",
        CHIP,
        option_env!("COAPTIC_DEVICE_RUN_ID").unwrap_or("manual"),
        passed,
        cfg!(feature = "oscore"),
        high_water,
        paint.top - paint.low
    );
    result.expect("device protocol probe");
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("COAPTIC_DEVICE_FAIL {info}");
    loop {
        core::hint::spin_loop();
    }
}
