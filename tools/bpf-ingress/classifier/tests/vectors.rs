use coaptic_ingress_classifier::{Class, MAX_COAP, classify};
#[path = "../../vectors.rs"]
mod vectors;
use vectors::{packet, seeds};
#[test]
fn differential_full_token_syntax_and_all_truncations() {
    let vectors = seeds();
    for bytes in vectors {
        for len in 0..=bytes.len() {
            let payload = &bytes[..len];
            let expected = if coaptic::message::extended::decode(payload).is_ok() {
                Class::CoapSyntax
            } else {
                Class::MalformedCoap
            };
            for ipv6 in [false, true] {
                let frame = packet(payload, ipv6);
                let before = frame.clone();
                assert_eq!(classify(&frame), expected);
                assert_eq!(frame, before);
                for truncated in 0..frame.len() {
                    assert_eq!(classify(&frame[..truncated]), Class::Uninspected);
                }
            }
        }
    }
}
#[test]
fn bounds_fragments_extensions_and_noncoap_pass_uninspected() {
    for ipv6 in [false, true] {
        let mut payload = vec![0; MAX_COAP];
        payload[..5].copy_from_slice(&[0x40, 1, 0, 1, 0xff]);
        assert_eq!(classify(&packet(&payload, ipv6)), Class::CoapSyntax);
        payload.push(0);
        assert_eq!(classify(&packet(&payload, ipv6)), Class::Oversized);
        let mut frame = packet(&[0x40, 1, 0, 1], ipv6);
        let udp = if ipv6 { 54 } else { 34 };
        frame[udp..udp + 4].fill(0);
        assert_eq!(classify(&frame), Class::Uninspected);
    }
    let mut fragmented = packet(&[0x40, 1, 0, 1], false);
    fragmented[20] = 0x20;
    assert_eq!(classify(&fragmented), Class::Uninspected);
    let mut extension = packet(&[0x40, 1, 0, 1], true);
    extension[20] = 44;
    assert_eq!(classify(&extension), Class::Uninspected);
}

#[test]
fn kernel_corpus_is_the_portable_classifier_corpus() {
    for frame in vectors::corpus() {
        let before = frame.clone();
        let _ = classify(&frame);
        assert_eq!(frame, before);
    }
}
