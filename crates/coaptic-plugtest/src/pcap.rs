//! UDP datagram capture, PCAP writer, and a [`DatagramIo`] tap.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// How many CoAP requests the next captures should accept and then not deliver.
static REQUEST_DROPS: AtomicUsize = AtomicUsize::new(0);

/// Drops the next `n` CoAP requests seen by a [`CapturingIo`] (logged, not delivered).
///
/// The guard clears the counter on drop so a failed TD cannot leak loss into the next one.
pub struct RequestLoss;

impl RequestLoss {
    /// Arm `n` request drops. One drop is one lost request, which forces a retransmission.
    #[must_use]
    pub fn arm(n: usize) -> Self {
        REQUEST_DROPS.store(n, Ordering::SeqCst);
        Self
    }
}

impl Drop for RequestLoss {
    fn drop(&mut self) {
        REQUEST_DROPS.store(0, Ordering::SeqCst);
    }
}

fn take_request_drop(bytes: &[u8]) -> bool {
    if !is_coap_request(bytes) {
        return false;
    }
    // `try_update` is Rust 1.95. This crate's rust-version is 1.85, where `fetch_update` is that operation.
    #[allow(deprecated)]
    let updated =
        REQUEST_DROPS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
    updated.is_ok()
}

/// CON/NON request (class 0, not empty). Responses and empty ACKs are never dropped.
fn is_coap_request(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || bytes[0] >> 6 != 1 {
        return false;
    }
    let ty = (bytes[0] >> 4) & 0b11;
    let code = bytes[1];
    ty <= 1 && code >> 5 == 0 && code != 0
}

use coaptic::storage::{DatagramIo, Endpoint};

/// One captured UDP payload (the CoAP datagram, or a DTLS record).
#[derive(Clone, Debug)]
pub struct Packet {
    /// Sender (ephemeral ports are wild-carded by the grader).
    pub src: SocketAddr,
    /// Destination.
    pub dst: SocketAddr,
    /// UDP payload bytes.
    pub bytes: Vec<u8>,
    /// Capture clock (nanoseconds since UNIX epoch). Not graded.
    pub t_ns: u128,
    /// `true` when these bytes are plaintext CoAP after DTLS unwrap.
    pub decrypted: bool,
}

/// Ordered packet log (shared with a background server thread).
#[derive(Clone, Debug, Default)]
pub struct Capture {
    packets: Arc<Mutex<Vec<Packet>>>,
}

impl Capture {
    /// Empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one datagram.
    pub fn push(&self, src: SocketAddr, dst: SocketAddr, bytes: &[u8], decrypted: bool) {
        let t_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        self.packets.lock().expect("capture").push(Packet {
            src,
            dst,
            bytes: bytes.to_vec(),
            t_ns,
            decrypted,
        });
    }

    /// Snapshot (does not clear).
    #[must_use]
    pub fn snapshot(&self) -> Vec<Packet> {
        self.packets.lock().expect("capture").clone()
    }

    /// Take and clear.
    #[must_use]
    pub fn take(&self) -> Vec<Packet> {
        let mut g = self.packets.lock().expect("capture");
        std::mem::take(&mut *g)
    }

    /// Append packets from `other`.
    pub fn extend_from(&self, other: &Capture) {
        let extra = other.snapshot();
        self.packets.lock().expect("capture").extend(extra);
    }

    /// Write a classic PCAP (microsecond, LINKTYPE_RAW = IPv4).
    ///
    /// Ephemeral ports stay in the file; the grader wildcards them. Message
    /// ID / Token live in the CoAP payload and are not rewritten.
    pub fn write_pcap(&self, mut w: impl std::io::Write) -> std::io::Result<()> {
        let packets = self.snapshot();
        if packets
            .iter()
            .filter(|p| !p.decrypted)
            .any(|p| !p.src.is_ipv4() || !p.dst.is_ipv4() || p.bytes.len() > 65_507)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IPv4 capture requires IPv4 endpoints and a legal UDP payload length",
            ));
        }
        // magic, v2.4, thiszone, sigfigs, snaplen, LINKTYPE_RAW
        w.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&0xffffu32.to_le_bytes())?;
        w.write_all(&101u32.to_le_bytes())?;
        for pkt in packets {
            if pkt.decrypted {
                continue;
            }
            let frame = ipv4_udp_frame(pkt.src, pkt.dst, &pkt.bytes);
            let sec = u32::try_from(pkt.t_ns / 1_000_000_000).unwrap_or(0);
            let usec = u32::try_from((pkt.t_ns / 1000) % 1_000_000).unwrap_or(0);
            let n = u32::try_from(frame.len()).unwrap_or(u32::MAX);
            w.write_all(&sec.to_le_bytes())?;
            w.write_all(&usec.to_le_bytes())?;
            w.write_all(&n.to_le_bytes())?;
            w.write_all(&n.to_le_bytes())?;
            w.write_all(&frame)?;
        }
        Ok(())
    }
}

fn ipv4_udp_frame(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (saddr, sport) = v4_parts(src);
    let (daddr, dport) = v4_parts(dst);
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut out = Vec::with_capacity(ip_len);
    out.extend_from_slice(&[0x45, 0]);
    out.extend_from_slice(&(u16::try_from(ip_len).unwrap_or(u16::MAX)).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    out.extend_from_slice(&saddr.octets());
    out.extend_from_slice(&daddr.octets());
    let sum = inet_checksum(&out);
    out[10..12].copy_from_slice(&sum.to_be_bytes());
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&(u16::try_from(udp_len).unwrap_or(u16::MAX)).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

fn v4_parts(addr: SocketAddr) -> (Ipv4Addr, u16) {
    match addr.ip() {
        IpAddr::V4(v4) => (v4, addr.port()),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4() {
                (v4, addr.port())
            } else {
                (Ipv4Addr::LOCALHOST, addr.port())
            }
        }
    }
}

fn inet_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = header.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += u32::from(b) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// [`DatagramIo`] that logs every send/recv against a known local address.
pub struct CapturingIo<T> {
    inner: T,
    local: SocketAddr,
    capture: Capture,
    decrypted: bool,
}

impl<T> CapturingIo<T> {
    /// Wrap `inner`. `local` is this socket's address (pcap src on send).
    pub fn new(inner: T, local: SocketAddr, capture: Capture) -> Self {
        Self {
            inner,
            local,
            capture,
            decrypted: false,
        }
    }

    /// Mark logged payloads as plaintext after DTLS unwrap.
    #[must_use]
    pub fn decrypted(mut self) -> Self {
        self.decrypted = true;
        self
    }

    /// Shared capture log.
    #[must_use]
    pub fn capture(&self) -> &Capture {
        &self.capture
    }

    /// Underlying transport.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: DatagramIo> DatagramIo for CapturingIo<T> {
    type Error = T::Error;

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        match self.inner.recv(buf) {
            Ok(Some((n, ep))) => {
                let src = SocketAddr::from(ep);
                self.capture
                    .push(src, self.local, &buf[..n], self.decrypted);
                if take_request_drop(&buf[..n]) {
                    return Ok(None);
                }
                Ok(Some((n, ep)))
            }
            other => other,
        }
    }

    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        // Log before the syscall. A localhost peer can recv and the runner
        // can `take_capture` between `send_to` and `push` (CI flake:
        // request in the pcap, response missing, client already succeeded).
        self.capture
            .push(self.local, SocketAddr::from(dest), bytes, self.decrypted);
        if take_request_drop(bytes) {
            return Ok(bytes.len());
        }
        self.inner.send(dest, bytes)
    }
}

/// Bind `127.0.0.1:0`, non-blocking, short read timeout.
pub fn bind_loopback() -> std::io::Result<(UdpSocket, SocketAddr)> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.set_nonblocking(true)?;
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(5)));
    let addr = sock.local_addr()?;
    Ok((sock, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_refuses_ipv6_and_oversize_instead_of_fabricating_ipv4_evidence() {
        for (src, body) in [
            ("[fe80::1%2]:5683", vec![0; 4]),
            ("127.0.0.1:5683", vec![0; 65_508]),
        ] {
            let cap = Capture::new();
            cap.push(
                src.parse().unwrap(),
                "127.0.0.1:5684".parse().unwrap(),
                &body,
                false,
            );
            let mut bytes = Vec::new();
            assert_eq!(
                cap.write_pcap(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
            assert!(bytes.is_empty());
        }
    }

    #[test]
    fn pcap_records_have_consistent_endian_and_valid_ipv4_udp_layout() {
        let cap = Capture::new();
        let src = "192.0.2.1:12345".parse().unwrap();
        let dst = "192.0.2.2:5683".parse().unwrap();
        cap.push(src, dst, &[0x40, 1, 0, 42], false);
        cap.push(dst, src, &[0x60, 0x45, 0, 42], false);
        cap.push(dst, src, b"excluded decrypted data", true);
        let mut bytes = Vec::new();
        cap.write_pcap(&mut bytes).unwrap();
        assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), 2);
        assert_eq!(u16::from_le_bytes(bytes[6..8].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 101);
        let mut offset = 24;
        for (from, to, payload) in [
            (src, dst, [0x40, 1, 0, 42]),
            (dst, src, [0x60, 0x45, 0, 42]),
        ] {
            let len =
                u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
            assert_eq!(len, 32);
            assert_eq!(
                &bytes[offset + 8..offset + 12],
                &bytes[offset + 12..offset + 16]
            );
            let frame = &bytes[offset + 16..offset + 16 + len];
            assert_eq!(frame[0], 0x45);
            assert_eq!(u16::from_be_bytes(frame[2..4].try_into().unwrap()), 32);
            assert_eq!(inet_checksum(&frame[..20]), 0);
            assert_eq!(frame[9], 17);
            assert_eq!(&frame[12..16], &v4_parts(from).0.octets());
            assert_eq!(&frame[16..20], &v4_parts(to).0.octets());
            assert_eq!(
                u16::from_be_bytes(frame[20..22].try_into().unwrap()),
                from.port()
            );
            assert_eq!(
                u16::from_be_bytes(frame[22..24].try_into().unwrap()),
                to.port()
            );
            assert_eq!(u16::from_be_bytes(frame[24..26].try_into().unwrap()), 12);
            assert_eq!(&frame[28..], &payload);
            offset += 16 + len;
        }
        assert_eq!(offset, bytes.len());
    }
}
