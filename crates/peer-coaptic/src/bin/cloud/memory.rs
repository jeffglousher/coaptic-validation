//! Requested Rust layouts and OS process counters are overlapping views.
//! Process counters include more than Coaptic and are never added to App sizes.

use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static REQUESTS: AtomicUsize = AtomicUsize::new(0);
static REALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

pub fn allocated(bytes: usize) {
    REQUESTS.fetch_add(1, Relaxed);
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(live, Relaxed);
}

pub fn deallocated(bytes: usize) {
    LIVE.fetch_sub(bytes, Relaxed);
}

pub fn reallocated(previous: usize, next: usize) {
    REALLOCATIONS.fetch_add(1, Relaxed);
    if next >= previous {
        let live = LIVE.fetch_add(next - previous, Relaxed) + next - previous;
        PEAK.fetch_max(live, Relaxed);
    } else {
        LIVE.fetch_sub(previous - next, Relaxed);
    }
}

#[derive(Clone, Copy, Default)]
pub struct Snapshot {
    requested_live: usize,
    requested_peak: usize,
    allocations: usize,
    reallocations: usize,
    process: Process,
}

impl Snapshot {
    pub const fn requested_live(self) -> usize {
        self.requested_live
    }

    pub fn capture() -> Self {
        // OS sampling uses fixed stack storage, outside the App allocation scope.
        let process = process();
        Self {
            requested_live: LIVE.load(Relaxed),
            requested_peak: PEAK.load(Relaxed),
            allocations: REQUESTS.load(Relaxed),
            reallocations: REALLOCATIONS.load(Relaxed),
            process,
        }
    }

    pub fn json(self, phase: &str) -> serde_json::Value {
        serde_json::json!({
            "phase": phase,
            "rust_requested_live_bytes": self.requested_live,
            "rust_requested_lifetime_peak_bytes": self.requested_peak,
            "successful_rust_allocations": self.allocations,
            "successful_rust_reallocations": self.reallocations,
            "process_resident_bytes": self.process.resident,
            "process_lifetime_peak_resident_bytes": self.process.peak_resident,
            "process_private_commit_bytes": self.process.private_commit,
            "process_lifetime_peak_private_commit_bytes": self.process.peak_private_commit,
            "process_virtual_bytes": self.process.virtual_bytes,
            "process_lifetime_peak_virtual_bytes": self.process.peak_virtual,
            "os_counter_source": self.process.source,
        })
    }
}

#[derive(Clone, Copy, Default)]
struct Process {
    resident: Option<usize>,
    peak_resident: Option<usize>,
    private_commit: Option<usize>,
    peak_private_commit: Option<usize>,
    virtual_bytes: Option<usize>,
    peak_virtual: Option<usize>,
    source: &'static str,
}

#[cfg(windows)]
fn process() -> Process {
    // https://learn.microsoft.com/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex
    #[repr(C)]
    #[derive(Default)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set: usize,
        working_set: usize,
        quota_peak_paged_pool: usize,
        quota_paged_pool: usize,
        quota_peak_nonpaged_pool: usize,
        quota_nonpaged_pool: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
        private_usage: usize,
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(process: isize, counters: *mut Counters, bytes: u32) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
    }
    let mut counters = Counters {
        cb: std::mem::size_of::<Counters>() as u32,
        ..Counters::default()
    };
    // The pseudohandle needs no close; the initialized structure matches cb.
    let bytes = counters.cb;
    if unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, bytes) } == 0 {
        return Process {
            source: "GetProcessMemoryInfo failed",
            ..Process::default()
        };
    }
    Process {
        resident: Some(counters.working_set),
        peak_resident: Some(counters.peak_working_set),
        private_commit: Some(counters.private_usage),
        peak_private_commit: Some(counters.peak_pagefile_usage),
        source: "Windows PROCESS_MEMORY_COUNTERS_EX; commit and resident overlap Rust heap/stack/runtime",
        ..Process::default()
    }
}

#[cfg(target_os = "linux")]
fn process() -> Process {
    use std::io::Read;
    // Kernel proc documentation describes these as approximate asynchronous RSS
    // counters. VmPeak is virtual address space, not physical or committed RAM.
    // https://www.kernel.org/doc/html/latest/filesystems/proc.html
    let mut bytes = [0; 8192];
    let Ok(mut file) = std::fs::File::open("/proc/self/status") else {
        return Process {
            source: "/proc/self/status unavailable",
            ..Process::default()
        };
    };
    let mut length = 0;
    loop {
        match file.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Process::default(),
        }
        if length == bytes.len() {
            return Process {
                source: "/proc/self/status exceeded fixed 8192-byte sample",
                ..Process::default()
            };
        }
    }
    let Ok(status) = std::str::from_utf8(&bytes[..length]) else {
        return Process::default();
    };
    let kib = |field: &str| {
        let value = status.lines().find_map(|line| line.strip_prefix(field))?;
        let mut words = value.split_whitespace();
        let number = words.next()?.parse::<usize>().ok()?;
        (words.next()? == "kB")
            .then_some(number.checked_mul(1024))
            .flatten()
    };
    Process {
        resident: kib("VmRSS:"),
        peak_resident: kib("VmHWM:"),
        virtual_bytes: kib("VmSize:"),
        peak_virtual: kib("VmPeak:"),
        source: "Linux /proc/self/status; approximate RSS, virtual memory is not a RAM requirement",
        ..Process::default()
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn process() -> Process {
    Process {
        source: "OS process counters unavailable on this platform",
        ..Process::default()
    }
}
