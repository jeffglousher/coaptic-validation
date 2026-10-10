#![no_main]

use coaptic::message::decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4096 {
        return;
    }
    if let Ok(parsed) = decode(bytes) {
        let mut canonical = vec![0; bytes.len() + 64];
        let size = parsed.encode(&mut canonical).unwrap();
        let reopened = decode(&canonical[..size]).unwrap();
        assert_eq!(parsed.header(), reopened.header());
        assert_eq!(parsed.token(), reopened.token());
        assert_eq!(parsed.payload(), reopened.payload());
        assert!(parsed.options().eq(reopened.options()));
        assert!(parsed.encode(&mut canonical[..size - 1]).is_err());
        let _ = parsed.check_rfc7252_formats();
        let _ = parsed.unknown_critical();
    }
});
