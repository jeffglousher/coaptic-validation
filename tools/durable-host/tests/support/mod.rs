use coaptic::provisioning::{PinnedPeer, TrustAnchor};
use coaptic_durable_host::Policy;

// Public P-256 generator point. No private key or deployed credential is present.
pub fn policy(kid: u8) -> Policy {
    let public = [
        0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96,
    ];
    Policy {
        anchor: TrustAnchor::from_parts([3; 32], 1, [4; 32]).unwrap(),
        principal: PinnedPeer::from_public_key(&public, kid)
            .unwrap()
            .principal(),
        resource: [5; 32],
        enabled: true,
    }
}
