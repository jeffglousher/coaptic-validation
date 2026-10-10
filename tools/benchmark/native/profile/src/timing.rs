//! Fixed-size diagnostic distributions. Recording never allocates or logs.

use std::fmt;

/// Inclusive upper bounds, from one microsecond through about one second.
pub const BIN_UPPER_BOUNDS_NS: [u128; 21] = [
    1_000,
    2_000,
    4_000,
    8_000,
    16_000,
    32_000,
    64_000,
    128_000,
    256_000,
    512_000,
    1_024_000,
    2_048_000,
    4_096_000,
    8_192_000,
    16_384_000,
    32_768_000,
    65_536_000,
    131_072_000,
    262_144_000,
    524_288_000,
    1_048_576_000,
];

#[derive(Clone, Copy, Default)]
pub struct Distribution {
    samples: u64,
    total_ns: u128,
    max_ns: u128,
    bins: [u64; BIN_UPPER_BOUNDS_NS.len()],
    overflow: u64,
    counter_saturated: bool,
}

impl Distribution {
    pub fn record(&mut self, elapsed_ns: u128) {
        self.counter_saturated |=
            self.samples == u64::MAX || self.total_ns > u128::MAX - elapsed_ns;
        self.samples = self.samples.saturating_add(1);
        self.total_ns = self.total_ns.saturating_add(elapsed_ns);
        self.max_ns = self.max_ns.max(elapsed_ns);
        let bucket = match BIN_UPPER_BOUNDS_NS
            .iter()
            .position(|&upper| elapsed_ns <= upper)
        {
            Some(index) => &mut self.bins[index],
            None => &mut self.overflow,
        };
        self.counter_saturated |= *bucket == u64::MAX;
        *bucket = bucket.saturating_add(1);
    }
}

impl fmt::Display for Distribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{{\"samples\":{},\"total_ns\":{},\"max_ns\":{},\"bins\":{:?},\"overflow\":{},\"counter_saturated\":{}}}",
            self.samples,
            self.total_ns,
            self.max_ns,
            self.bins,
            self.overflow,
            self.counter_saturated
        )
    }
}

#[derive(Clone, Copy, Default)]
pub struct SendTimings {
    pub complete: Distribution,
    pub failed: Distribution,
}

impl SendTimings {
    /// Only a complete write is successful; errors and short/overlong writes fail.
    pub fn record<E>(&mut self, expected: usize, outcome: &Result<usize, E>, elapsed_ns: u128) {
        match outcome {
            Ok(written) if *written == expected => self.complete.record(elapsed_ns),
            _ => self.failed.record(elapsed_ns),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_distribution_has_no_samples_or_tail() {
        let timing = Distribution::default();
        assert_eq!(timing.samples, 0);
        assert_eq!(timing.total_ns, 0);
        assert_eq!(timing.max_ns, 0);
        assert_eq!(timing.bins, [0; 21]);
        assert_eq!(timing.overflow, 0);
        assert!(!timing.counter_saturated);
    }

    #[test]
    fn every_inclusive_boundary_and_adjacent_sample_is_accounted_once() {
        let mut timing = Distribution::default();
        let mut expected_total = 0;
        for upper in BIN_UPPER_BOUNDS_NS {
            for sample in [upper - 1, upper, upper + 1] {
                timing.record(sample);
                expected_total += sample;
            }
        }
        assert_eq!(timing.bins[0], 2);
        assert_eq!(timing.bins[1..], [3; 20]);
        assert_eq!(timing.overflow, 1);
        assert_eq!(timing.samples, 63);
        assert_eq!(timing.bins.iter().sum::<u64>() + timing.overflow, 63);
        assert_eq!(timing.total_ns, expected_total);
        assert_eq!(timing.max_ns, 1_048_576_001);
        assert!(!timing.counter_saturated);
    }

    #[test]
    fn zero_and_large_outlier_are_retained_without_clamping() {
        let mut timing = Distribution::default();
        for sample in [0, 1_000, 1_001, 1_048_576_000, 9_000_000_000] {
            timing.record(sample);
        }
        assert_eq!(timing.samples, 5);
        assert_eq!(timing.total_ns, 10_048_578_001);
        assert_eq!(timing.max_ns, 9_000_000_000);
        assert_eq!(timing.bins[0], 2);
        assert_eq!(timing.bins[1], 1);
        assert_eq!(timing.bins[20], 1);
        assert_eq!(timing.overflow, 1);
    }

    #[test]
    fn send_errors_and_partial_writes_are_separate_from_complete_writes() {
        let mut timing = SendTimings::default();
        timing.record(8, &Ok::<_, ()>(8), 3);
        timing.record(8, &Err::<usize, _>(()), 7);
        timing.record(8, &Ok::<_, ()>(7), 11);
        timing.record(8, &Ok::<_, ()>(9), 13);
        timing.record(0, &Ok::<_, ()>(0), 17);
        assert_eq!(timing.complete.samples, 2);
        assert_eq!(timing.failed.samples, 3);
        assert_eq!(timing.complete.total_ns, 20);
        assert_eq!(timing.failed.total_ns, 31);
        assert_eq!(timing.complete.max_ns, 17);
        assert_eq!(timing.failed.max_ns, 13);
        assert_eq!(timing.complete.total_ns + timing.failed.total_ns, 51);
    }

    #[test]
    fn arithmetic_limits_are_reported_without_wrapping() {
        let mut timing = Distribution {
            samples: u64::MAX,
            total_ns: u128::MAX,
            bins: [u64::MAX; 21],
            ..Distribution::default()
        };
        timing.record(1);
        assert_eq!(timing.samples, u64::MAX);
        assert_eq!(timing.total_ns, u128::MAX);
        assert_eq!(timing.bins[0], u64::MAX);
        assert_eq!(timing.max_ns, 1);
        assert!(timing.counter_saturated);
        let mut tail = Distribution {
            overflow: u64::MAX,
            ..Distribution::default()
        };
        tail.record(u128::MAX);
        assert_eq!(tail.overflow, u64::MAX);
        assert_eq!(tail.max_ns, u128::MAX);
        assert!(tail.counter_saturated);
    }
}
