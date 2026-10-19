use coaptic_ingress_classifier::MAX_COAP;
pub fn packet(payload: &[u8], ipv6: bool) -> Vec<u8> {
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
pub fn seeds() -> Vec<Vec<u8>> {
    let mut extended = vec![0x4d, 1, 0, 1, 0];
    extended.extend_from_slice(&[7; 13]);
    let vectors = vec![
        vec![0x40, 1, 0, 1],
        vec![0x60, 0, 0, 1],
        vec![0x40, 1, 0, 1, 0x90], // opaque OSCORE option, never authentication
        vec![0x40, 1, 0, 1, 0xff],
        vec![0x4f, 1, 0, 1],
        vec![0x40, 1, 0, 1, 0xf0],
        extended,
    ];
    vectors
}
pub fn corpus() -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for bytes in seeds() {
        for len in 0..=bytes.len() {
            for ipv6 in [false, true] {
                let frame = packet(&bytes[..len], ipv6);
                for truncated in 0..frame.len() {
                    frames.push(frame[..truncated].to_vec());
                }
                frames.push(frame);
            }
        }
    }
    for ipv6 in [false, true] {
        let mut payload = vec![0; MAX_COAP];
        payload[..5].copy_from_slice(&[0x40, 1, 0, 1, 0xff]);
        frames.push(packet(&payload, ipv6));
        payload.push(0);
        frames.push(packet(&payload, ipv6));
        let mut wrong_port = packet(&[0x40, 1, 0, 1], ipv6);
        let udp = if ipv6 { 54 } else { 34 };
        wrong_port[udp..udp + 4].fill(0);
        frames.push(wrong_port);
    }
    let mut fragmented = packet(&[0x40, 1, 0, 1], false);
    fragmented[20] = 0x20;
    frames.push(fragmented);
    let mut extension = packet(&[0x40, 1, 0, 1], true);
    extension[20] = 44;
    frames.push(extension);
    frames
}
