use coaptic_ingress_classifier::{Class, MAX_COAP, classify};
fn packet(payload: &[u8], ipv6: bool) -> Vec<u8> {
    let header = if ipv6 { 54 } else { 34 };
    let mut f = vec![0; header + 8 + payload.len()];
    if ipv6 {
        f[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        f[14] = 0x60;
        f[18..20].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        f[20] = 17;
    } else {
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((payload.len() + 28) as u16).to_be_bytes());
        f[23] = 17;
    }
    f[header..header + 2].copy_from_slice(&5683u16.to_be_bytes());
    f[header + 2..header + 4].copy_from_slice(&5683u16.to_be_bytes());
    f[header + 4..header + 6].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    f[header + 8..].copy_from_slice(payload);
    f
}
#[test]
fn differential_full_token_syntax_and_all_truncations() {
    let mut extended = vec![0x4d, 1, 0, 1, 0];
    extended.extend_from_slice(&[7; 13]);
    let vectors = [
        vec![0x40, 1, 0, 1],
        vec![0x60, 0, 0, 1],
        vec![0x40, 1, 0, 1, 0x90], // opaque OSCORE option, never authentication
        vec![0x40, 1, 0, 1, 0xff],
        vec![0x4f, 1, 0, 1],
        vec![0x40, 1, 0, 1, 0xf0],
        extended,
    ];
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
