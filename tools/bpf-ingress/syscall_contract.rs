//! Linux x86_64 LP64 diagnostic contract. Counts are independent boundary events.
pub const MAX_CPUS: usize = 64;
pub const BINS: u32 = 16;
pub const FIELDS: u32 = 5;
pub const READ_ERROR: u32 = BINS * FIELDS;
pub const FOREIGN_THREAD: u32 = READ_ERROR + 1;
pub const COUNTERS: u32 = FOREIGN_THREAD + 1;
pub const NAMES: [&str; BINS as usize] = [
    "read",
    "write",
    "poll",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "epoll_wait",
    "epoll_pwait",
    "recvmmsg",
    "sendmmsg",
    "pselect6",
    "ppoll",
    "clock_gettime",
    "epoll_pwait2",
    "other",
];
pub const CLASSES: [&str; FIELDS as usize] = [
    "enter",
    "exit_ok",
    "exit_eagain",
    "exit_eintr",
    "exit_other_error",
];

#[inline(always)]
pub const fn bin(number: i64) -> u32 {
    match number {
        0 => 0,
        1 => 1,
        7 => 2,
        44 => 3,
        45 => 4,
        46 => 5,
        47 => 6,
        232 => 7,
        281 => 8,
        299 => 9,
        307 => 10,
        270 => 11,
        271 => 12,
        228 => 13,
        441 => 14,
        _ => 15,
    }
}

#[inline(always)]
pub const fn exit_class(result: i64) -> u32 {
    match result {
        -11 => 2,
        -4 => 3,
        -4095..=-1 => 4,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_linux_errors() {
        for n in [
            -1, 0, 1, 7, 44, 45, 46, 47, 228, 232, 270, 271, 281, 299, 307, 441, 999,
        ] {
            assert!(bin(n) < BINS);
        }
        assert_eq!(bin(45), 4);
        assert_eq!(bin(999), 15);
        assert_eq!(exit_class(-11), 2);
        assert_eq!(exit_class(-4), 3);
        assert_eq!(exit_class(-512), 4); // Visible restart codes are errors, never balanced away.
        assert_eq!(exit_class(0), 1);
        assert_eq!(exit_class(100), 1);
        assert_eq!(COUNTERS, 82);
    }
}
