//! Bounded deterministic campaigns. No fuzz-coverage percentage is implied.
//! Reproduce with `cargo test --test seeded_qualification --all-features -- --nocapture`.
use coaptic::message::{MissingBlocks, ProblemDetails, decode};

const SEED: u64 = 0x9177_8613_7959_7252;
const CASES: usize = 50_000;

struct Generator(u64);
impl Generator {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn seeded_datagram_mutations_preserve_views_and_reject_invalid_headers() {
    // Hand-written datagrams, independent of the encoder: empty ACK, GET,
    // token + Uri-Path, and response payload. RFC 7252 sections 3/3.1/4.1.
    let corpus: &[&[u8]] = &[
        &[0x60, 0, 0x12, 0x34],
        &[0x40, 1, 0x12, 0x34],
        &[0x41, 1, 0x12, 0x34, 0xab, 0xb1, b'x'],
        &[0x61, 69, 0x12, 0x34, 0xab, 0xff, b'x'],
    ];
    for packet in corpus {
        assert!(decode(packet).is_ok());
    }
    let mut random = Generator(SEED);
    let (mut accepted, mut refused) = (0, 0);
    for case in 0..CASES {
        let mut bytes = [0u8; 512];
        let n = if case % 2 == 0 {
            let base = corpus[(random.next() as usize) % corpus.len()];
            bytes[..base.len()].copy_from_slice(base);
            let at = (random.next() as usize) % base.len();
            bytes[at] ^= 1 << ((random.next() % 8) as u8);
            base.len()
        } else {
            let n = (random.next() as usize) % 513;
            for byte in &mut bytes[..n] {
                *byte = random.next() as u8;
            }
            n
        };
        match decode(&bytes[..n]) {
            Ok(parsed) => {
                accepted += 1;
                let mut canonical = [0u8; 1024];
                let len = parsed.encode(&mut canonical).unwrap();
                let reopened = decode(&canonical[..len]).unwrap();
                assert_eq!(
                    parsed.header(),
                    reopened.header(),
                    "seed={SEED:x} case={case}"
                );
                assert_eq!(parsed.payload(), reopened.payload());
                assert_eq!(parsed.token(), reopened.token());
                assert!(parsed.options().eq(reopened.options()));
                let mut short = [0u8; 1024];
                assert!(parsed.encode(&mut short[..len - 1]).is_err());
                let _ = parsed.check_rfc7252_formats();
                let _ = parsed.unknown_critical();
            }
            Err(_) => refused += 1,
        }
        // Guaranteed-invalid version and Token lengths, regardless of payload.
        if n >= 4 {
            bytes[0] &= 0x3f;
            assert!(decode(&bytes[..n]).is_err());
            bytes[0] = 0x40 | (9 + ((random.next() % 7) as u8));
            assert!(decode(&bytes[..n]).is_err());
        }
    }
    assert!(accepted > 1000 && refused > 1000);
    println!("datagram seed={SEED:x} cases={CASES} accepted={accepted} refused={refused}");
}

#[test]
fn seeded_cbor_mutations_keep_bounds_and_known_values() {
    // {-1: "a"}, with an unknown nested extension in the second map.
    let corpus: &[&[u8]] = &[
        &[0xa1, 0x20, 0x61, b'a'],
        &[0xa2, 0x20, 0x61, b'a', 0x28, 0x82, 1, 2],
    ];
    for bytes in corpus {
        assert_eq!(
            ProblemDetails::decode(bytes).unwrap().title_text(),
            Some("a")
        );
    }
    let mut random = Generator(SEED ^ 0x9290);
    let mut accepted = 0;
    for case in 0..CASES {
        let mut bytes = [0u8; 256];
        let base = corpus[case % corpus.len()];
        let n = if case % 3 == 0 {
            bytes[..base.len()].copy_from_slice(base);
            let at = random.next() as usize % base.len();
            bytes[at] ^= random.next() as u8;
            base.len()
        } else {
            let n = random.next() as usize % 257;
            for byte in &mut bytes[..n] {
                *byte = random.next() as u8;
            }
            n
        };
        if let Ok(problem) = ProblemDetails::decode(&bytes[..n]) {
            accepted += 1;
            let mut canonical = [0u8; 512];
            let len = problem.encode(&mut canonical).unwrap();
            assert_eq!(&canonical[..len], &bytes[..n]);
            assert_eq!(ProblemDetails::decode(&canonical[..len]).unwrap(), problem);
            let mut short = [0u8; 512];
            assert!(problem.encode(&mut short[..len - 1]).is_err());
        }
        let mut numbers = [0u32; 256];
        if let Ok(count) = MissingBlocks::decode(&bytes[..n], &mut numbers) {
            assert!(count > 0 && count <= n);
            assert!(numbers[..count].windows(2).all(|pair| pair[0] < pair[1]));
            let mut wire = [0u8; 1280];
            let len = MissingBlocks::encode(numbers[..count].iter().copied(), &mut wire).unwrap();
            let mut decoded = [0u32; 256];
            assert_eq!(
                MissingBlocks::decode(&wire[..len], &mut decoded).unwrap(),
                count
            );
            assert_eq!(&decoded[..count], &numbers[..count]);
            let mut short = [0u32; 256];
            assert!(MissingBlocks::decode(&wire[..len], &mut short[..count - 1]).is_err());
        }
    }
    assert!(accepted > 0);
    println!(
        "cbor seed={:x} cases={CASES} problem_accepted={accepted}",
        SEED ^ 0x9290
    );
}
