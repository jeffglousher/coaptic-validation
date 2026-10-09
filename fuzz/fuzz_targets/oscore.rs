#![no_main]

use coaptic::message::{Code, Message, MessageId, Token, Type, decode};
use coaptic::oscore::{DeriveParams, Error, SecurityContext};
use libfuzzer_sys::fuzz_target;

fn context(server: bool) -> SecurityContext {
    SecurityContext::derive(DeriveParams {
        master_secret: b"fuzz qualification fixture secret",
        master_salt: &[],
        sender_id: if server { &[2] } else { &[1] },
        recipient_id: if server { &[1] } else { &[2] },
        id_context: &[],
    })
    .unwrap()
}

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() < 5 || bytes.len() > 512 {
        return;
    }
    let sequence = bytes[..5]
        .iter()
        .fold(0u64, |n, byte| (n << 8) | u64::from(*byte));
    let mut client = context(false);
    let mut server = context(true);
    client.set_sender_seq(sequence).unwrap();
    let plain = Message::new(Type::Confirmable, Code::POST, MessageId::new(1))
        .with_token(Token::new(&[1]).unwrap())
        .with_payload(&bytes[5..]);
    let mut wire = [0u8; 1280];
    let size = client.protect_request(&plain, &mut wire).unwrap();
    let initial = server.replay_checkpoint();
    let mut scratch = [0u8; 1280];
    wire[size - 1] ^= 1;
    assert!(
        server
            .unprotect_request(&decode(&wire[..size]).unwrap(), &mut scratch)
            .is_err()
    );
    assert_eq!(server.replay_checkpoint(), initial);
    wire[size - 1] ^= 1;
    let (opened, _) = server
        .unprotect_request(&decode(&wire[..size]).unwrap(), &mut scratch)
        .unwrap();
    assert_eq!(opened.payload(), &bytes[5..]);
    assert!(!server.replay_fresh(sequence));
    assert!(matches!(
        server.unprotect_request(&decode(&wire[..size]).unwrap(), &mut scratch),
        Err(Error::Replay)
    ));
    let checkpoint = server.replay_checkpoint();
    let mut restarted = context(true);
    restarted.restore_replay(checkpoint).unwrap();
    assert!(matches!(
        restarted.unprotect_request(&decode(&wire[..size]).unwrap(), &mut scratch),
        Err(Error::Replay)
    ));
    for candidate in bytes.chunks_exact(5) {
        let sequence = candidate
            .iter()
            .fold(0u64, |n, byte| (n << 8) | u64::from(*byte));
        let before = restarted.replay_checkpoint();
        let fresh = restarted.replay_fresh(sequence);
        restarted.replay_accept(sequence);
        if fresh {
            assert!(!restarted.replay_fresh(sequence));
        } else {
            assert_eq!(restarted.replay_checkpoint(), before);
        }
    }
});
