#![no_main]

use coaptic::message::{MissingBlocks, ProblemDetails};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4096 {
        return;
    }
    if let Ok(problem) = ProblemDetails::decode(bytes) {
        let mut canonical = vec![0; bytes.len() + 64];
        let size = problem.encode(&mut canonical).unwrap();
        assert_eq!(&canonical[..size], bytes);
        assert_eq!(ProblemDetails::decode(&canonical[..size]).unwrap(), problem);
        assert!(problem.encode(&mut canonical[..size - 1]).is_err());
    }
    let mut numbers = vec![0; bytes.len()];
    if let Ok(count) = MissingBlocks::decode(bytes, &mut numbers) {
        assert!(count > 0 && count <= bytes.len());
        assert!(numbers[..count].windows(2).all(|pair| pair[0] < pair[1]));
        let mut canonical = vec![0; count * 5];
        let size = MissingBlocks::encode(numbers[..count].iter().copied(), &mut canonical).unwrap();
        let mut restored = vec![0; count];
        assert_eq!(
            MissingBlocks::decode(&canonical[..size], &mut restored).unwrap(),
            count
        );
        assert_eq!(restored, numbers[..count]);
        assert!(MissingBlocks::decode(&canonical[..size], &mut restored[..count - 1]).is_err());
    }
});
