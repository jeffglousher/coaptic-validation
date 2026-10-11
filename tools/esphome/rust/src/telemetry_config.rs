//! Fixed-buffer configuration boundary for the qualification C adapter.
#![forbid(unsafe_code)]

use coaptic::Endpoint;
use coaptic::provisioning::{OperationId, PinnedPeer, Principal, TelemetryOperation};

/// Maximum configuration size: service header, operation header, bounded payload.
pub const MAX_BYTES: usize = 97 + TelemetryOperation::MAX_PAYLOAD;

pub struct Config<'a> {
    pub principal: Principal,
    pub resource: [u8; 32],
    pub endpoint: Endpoint,
    pub timeout_ms: u64,
    pub operation: Option<TelemetryOperation<'a>>,
}

impl<'a> Config<'a> {
    /// The 76-byte header contains compressed P-256 public key (33), KID (1),
    /// resource (32), IPv4 address (4), port (2), and timeout milliseconds (4).
    /// Integers are big-endian. Provisioning appends operation ID (16), format
    /// presence (1), format (2), payload length (2), and exactly that payload.
    /// Normal operation accepts only the service header; it cannot create work.
    pub fn parse(bytes: &'a [u8], provisioning: bool) -> Option<Self> {
        if bytes.len() < 76 || bytes.len() > MAX_BYTES {
            return None;
        }
        let principal = PinnedPeer::from_public_key(bytes[..33].try_into().ok()?, bytes[33])
            .ok()?
            .principal();
        let resource = bytes[34..66].try_into().ok()?;
        let address: [u8; 4] = bytes[66..70].try_into().ok()?;
        let port = u16::from_be_bytes(bytes[70..72].try_into().ok()?);
        let timeout_ms = u32::from_be_bytes(bytes[72..76].try_into().ok()?) as u64;
        // This one-peer qualification flow does not support unspecified,
        // multicast or limited-broadcast destinations.
        if address == [0; 4]
            || address[0] >= 224
            || port == 0
            || !(1..=300_000).contains(&timeout_ms)
        {
            return None;
        }
        let operation = if provisioning {
            if bytes.len() < 97 {
                return None;
            }
            let id = OperationId::new(bytes[76..92].try_into().ok()?);
            let format = match bytes[92] {
                0 if bytes[93..95] == [0, 0] => None,
                1 => Some(u16::from_be_bytes(bytes[93..95].try_into().ok()?)),
                _ => return None,
            };
            let length = u16::from_be_bytes(bytes[95..97].try_into().ok()?) as usize;
            if bytes.len() != 97 + length {
                return None;
            }
            Some(TelemetryOperation::new(id, resource, format, &bytes[97..]).ok()?)
        } else {
            if bytes.len() != 76 {
                return None;
            }
            None
        };
        Some(Self {
            principal,
            resource,
            endpoint: Endpoint::v4(address, port),
            timeout_ms,
            operation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> [u8; MAX_BYTES] {
        let mut bytes = [0; MAX_BYTES];
        bytes[..33].copy_from_slice(&[
            2, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ]);
        bytes[33] = 1;
        bytes[34..66].fill(5);
        bytes[66..70].copy_from_slice(&[192, 0, 2, 2]);
        bytes[70..72].copy_from_slice(&5683u16.to_be_bytes());
        bytes[72..76].copy_from_slice(&30_000u32.to_be_bytes());
        bytes[76..92].fill(9);
        bytes[92] = 1;
        bytes[94] = 42;
        bytes[95..97].copy_from_slice(&1024u16.to_be_bytes());
        bytes[97..].fill(0x67);
        bytes
    }

    #[test]
    fn complete_config_and_pending_operation_have_exact_bounds() {
        let bytes = header();
        let normal = Config::parse(&bytes[..76], false).unwrap();
        assert_eq!(normal.endpoint, Endpoint::v4([192, 0, 2, 2], 5683));
        assert_eq!(normal.timeout_ms, 30_000);
        assert!(normal.operation.is_none());
        let provision = Config::parse(&bytes, true).unwrap();
        assert_eq!(provision.principal, normal.principal);
        let operation = provision.operation.unwrap();
        assert_eq!(operation.id(), OperationId::new([9; 16]));
        assert_eq!(operation.resource(), &[5; 32]);
        assert_eq!(operation.content_format(), Some(42));
        assert_eq!(operation.payload(), &[0x67; 1024]);
        for length in 0..76 {
            assert!(Config::parse(&bytes[..length], false).is_none());
        }
        for length in 76..MAX_BYTES {
            assert!(Config::parse(&bytes[..length], true).is_none());
        }
        assert!(Config::parse(&bytes, false).is_none());
        for (index, value) in [(0, 0), (66, 224), (92, 2), (95, 5)] {
            let mut invalid = bytes;
            invalid[index] = value;
            assert!(Config::parse(&invalid, true).is_none());
        }
        for range in [66..70, 70..72, 72..76] {
            let mut invalid = bytes;
            invalid[range].fill(0);
            assert!(Config::parse(&invalid, true).is_none());
        }
        let mut absent_format = bytes;
        absent_format[92] = 0;
        assert!(Config::parse(&absent_format, true).is_none());
        absent_format[93..95].fill(0);
        assert!(
            Config::parse(&absent_format, true)
                .unwrap()
                .operation
                .unwrap()
                .content_format()
                .is_none()
        );
        assert!(Config::parse(&bytes, true).is_some());
    }
}
