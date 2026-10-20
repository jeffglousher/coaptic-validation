//! One worker-owned, bounded ChaCha20 generator seeded by the platform owner.
//!
//! Seeding requires 32 unpredictable hardware bytes obtained while the main
//! platform owner excludes RF lifecycle changes. Generation never samples RF,
//! allocates, reseeds, clones the stream or falls back to another source.
#![forbid(unsafe_code)]

use chacha20::{
    ChaCha20Rng,
    rand_core::{Rng, SeedableRng},
};
use zeroize::{Zeroize, Zeroizing};

pub const SEED_BYTES: usize = 32;
pub const MAX_REQUEST_BYTES: usize = 256;
/// Four GiB per boot: 536 million eight-byte token draws. Requests charge whole
/// four-byte words, including discarded tail bytes, so buffered generation also
/// stays within this block-aligned limit. Exhaustion refuses;
/// it does not restart, repeat a seed or silently request more hardware entropy.
pub const MAX_GENERATED_BYTES: u64 = 1_u64 << 32;
/// Independent whole owner ceiling, including the crate's buffered blocks.
pub const OWNER_BYTE_CEILING: usize = 512;

/// Exclusive generator owner. Deliberately has no Clone or state serialization.
/// RustCrypto zeroizes its key and buffered output on drop.
pub struct Entropy {
    rng: Option<ChaCha20Rng>,
    remaining: u64,
}

const _: () = {
    assert!(core::mem::size_of::<Entropy>() <= OWNER_BYTE_CEILING);
    assert!(core::mem::size_of::<Zeroizing<[u8; SEED_BYTES]>>() == SEED_BYTES);
};

impl Entropy {
    /// Consume and wipe the platform handoff. An all-zero seed refuses as a
    /// platform failure check, not an entropy-health certification.
    pub fn from_seed(seed: &mut [u8; SEED_BYTES]) -> Option<Self> {
        let material = Zeroizing::new(core::mem::take(seed));
        seed.zeroize();
        if material.iter().all(|&byte| byte == 0) {
            return None;
        }
        Some(Self {
            rng: Some(ChaCha20Rng::from_seed(*material)),
            remaining: MAX_GENERATED_BYTES,
        })
    }

    /// Fill one bounded request. Oversized requests refuse unchanged, before
    /// generation. Exhaustion wipes a valid-sized output and permanently drops
    /// the generator. Every false result forbids using the output as entropy.
    pub fn fill(&mut self, output: &mut [u8]) -> bool {
        if output.len() > MAX_REQUEST_BYTES {
            return false;
        }
        if output.is_empty() {
            return true;
        }
        let charged = (output.len() as u64 + 3) & !3;
        if charged > self.remaining || self.rng.is_none() {
            output.zeroize();
            self.rng = None;
            self.remaining = 0;
            return false;
        }
        self.rng.as_mut().unwrap().fill_bytes(output);
        self.remaining -= charged;
        if self.remaining == 0 {
            self.rng = None;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_consumed_and_output_matches_rustcrypto_reference_vector() {
        let mut seed = core::array::from_fn(|i| (i + 1) as u8);
        let mut owner = Entropy::from_seed(&mut seed).unwrap();
        assert_eq!(seed, [0; SEED_BYTES]);
        let mut bytes = [0; 13];
        assert!(owner.fill(&mut bytes));
        // RustCrypto chacha20 0.10.2 tests/rng.rs test_rng_output.
        assert_eq!(
            bytes,
            [
                0xb1, 0x69, 0x7e, 0x9f, 0xc6, 0x46, 0x1e, 0x19, 0x83, 0xd1, 0x31, 0xcf, 0x69
            ]
        );
        assert!(owner.fill(&mut bytes));
        assert_eq!(
            bytes,
            [
                0xa7, 0xa3, 0xfc, 0x13, 0x4f, 0x14, 0x98, 0x80, 0xe8, 0xbb, 0x2b, 0x5d, 0x23
            ]
        );
        assert_eq!(owner.remaining, MAX_GENERATED_BYTES - 32);
        assert!(Entropy::from_seed(&mut [0; SEED_BYTES]).is_none());
    }

    #[test]
    fn request_refusal_preserves_stream_and_total_exhaustion_is_permanent() {
        let mut owner = Entropy::from_seed(&mut [7; SEED_BYTES]).unwrap();
        let mut control = Entropy::from_seed(&mut [7; SEED_BYTES]).unwrap();
        let mut too_large = [0x55; MAX_REQUEST_BYTES + 1];
        assert!(!owner.fill(&mut too_large));
        assert_eq!(too_large, [0x55; MAX_REQUEST_BYTES + 1]);
        let mut bytes = [0; MAX_REQUEST_BYTES];
        let mut expected = [0; MAX_REQUEST_BYTES];
        assert!(owner.fill(&mut bytes));
        assert!(control.fill(&mut expected));
        assert_eq!(bytes, expected);
        owner.remaining = 3;
        assert!(!owner.fill(&mut bytes[..4]));
        assert_eq!(&bytes[..4], &[0; 4]);
        assert_eq!(owner.remaining, 0);
        assert!(owner.rng.is_none());
        bytes[0] = 1;
        assert!(!owner.fill(&mut bytes[..1]));
        assert_eq!(bytes[0], 0);
    }

    #[test]
    fn independent_owners_do_not_share_state() {
        let mut first = Entropy::from_seed(&mut [1; SEED_BYTES]).unwrap();
        let mut second = Entropy::from_seed(&mut [2; SEED_BYTES]).unwrap();
        let mut a = [0; 32];
        let mut b = [0; 32];
        assert!(first.fill(&mut a));
        assert!(second.fill(&mut b));
        assert_ne!(a, b);
        assert_eq!(first.remaining, MAX_GENERATED_BYTES - 32);
        assert_eq!(second.remaining, MAX_GENERATED_BYTES - 32);
    }
}
