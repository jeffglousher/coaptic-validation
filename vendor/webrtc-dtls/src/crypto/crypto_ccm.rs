// AES-CCM (Counter with CBC-MAC)
// Alternative to GCM mode.
// Available in OpenSSL as of TLS 1.3 (2018), but disabled by default.
// Two AES computations per block, thus expected to be somewhat slower than AES-GCM.
// RFC 6655 year 2012 https://tools.ietf.org/html/rfc6655
// Much lower adoption, probably because it came after GCM and offer no significant benefit.

// https://github.com/RustCrypto/AEADs
// https://docs.rs/ccm/0.3.0/ccm/ Or https://crates.io/crates/aes-ccm?

use std::io::Cursor;

use aes::Aes128;
use ccm::aead::generic_array::GenericArray;
use ccm::aead::AeadInPlace;
use ccm::consts::{U12, U16, U8};
use ccm::Ccm;
use ccm::KeyInit;
use rand::Rng;

use super::*;
use crate::content::*;
use crate::error::*;
use crate::record_layer::record_layer_header::*;

const CRYPTO_CCM_8_TAG_LENGTH: usize = 8;
const CRYPTO_CCM_TAG_LENGTH: usize = 16;
const CRYPTO_CCM_NONCE_LENGTH: usize = 12;

type AesCcm8 = Ccm<Aes128, U8, U12>;
type AesCcm = Ccm<Aes128, U16, U12>;

#[derive(Clone)]
pub enum CryptoCcmTagLen {
    CryptoCcm8TagLength,
    CryptoCcmTagLength,
}

enum CryptoCcmType {
    CryptoCcm8(AesCcm8),
    CryptoCcm(AesCcm),
}

// State needed to handle encrypted input/output
pub struct CryptoCcm {
    local_ccm: CryptoCcmType,
    remote_ccm: CryptoCcmType,
    local_write_iv: Vec<u8>,
    remote_write_iv: Vec<u8>,
    // used by clone()
    local_write_key: Vec<u8>,
    remote_write_key: Vec<u8>,
}

impl Clone for CryptoCcm {
    fn clone(&self) -> Self {
        match self.local_ccm {
            CryptoCcmType::CryptoCcm(_) => Self::new(
                &CryptoCcmTagLen::CryptoCcmTagLength,
                &self.local_write_key,
                &self.local_write_iv,
                &self.remote_write_key,
                &self.remote_write_iv,
            ),
            CryptoCcmType::CryptoCcm8(_) => Self::new(
                &CryptoCcmTagLen::CryptoCcm8TagLength,
                &self.local_write_key,
                &self.local_write_iv,
                &self.remote_write_key,
                &self.remote_write_iv,
            ),
        }
    }
}

impl CryptoCcm {
    pub fn new(
        tag_len: &CryptoCcmTagLen,
        local_key: &[u8],
        local_write_iv: &[u8],
        remote_key: &[u8],
        remote_write_iv: &[u8],
    ) -> Self {
        let key = GenericArray::from_slice(local_key);
        let local_ccm = match tag_len {
            CryptoCcmTagLen::CryptoCcmTagLength => CryptoCcmType::CryptoCcm(AesCcm::new(key)),
            CryptoCcmTagLen::CryptoCcm8TagLength => CryptoCcmType::CryptoCcm8(AesCcm8::new(key)),
        };

        let key = GenericArray::from_slice(remote_key);
        let remote_ccm = match tag_len {
            CryptoCcmTagLen::CryptoCcmTagLength => CryptoCcmType::CryptoCcm(AesCcm::new(key)),
            CryptoCcmTagLen::CryptoCcm8TagLength => CryptoCcmType::CryptoCcm8(AesCcm8::new(key)),
        };

        CryptoCcm {
            local_ccm,
            local_write_key: local_key.to_vec(),
            local_write_iv: local_write_iv.to_vec(),
            remote_ccm,
            remote_write_key: remote_key.to_vec(),
            remote_write_iv: remote_write_iv.to_vec(),
        }
    }

    pub fn encrypt(&self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let payload = &raw[RECORD_LAYER_HEADER_SIZE..];
        let raw = &raw[..RECORD_LAYER_HEADER_SIZE];

        let mut nonce = vec![0u8; CRYPTO_CCM_NONCE_LENGTH];
        nonce[..4].copy_from_slice(&self.local_write_iv[..4]);
        rand::thread_rng().fill(&mut nonce[4..]);
        let nonce = GenericArray::from_slice(&nonce);

        let additional_data = generate_aead_additional_data(pkt_rlh, payload.len());

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(payload);

        match &self.local_ccm {
            CryptoCcmType::CryptoCcm(ccm) => {
                ccm.encrypt_in_place(nonce, &additional_data, &mut buffer)
                    .map_err(|e| Error::Other(e.to_string()))?;
            }
            CryptoCcmType::CryptoCcm8(ccm8) => {
                ccm8.encrypt_in_place(nonce, &additional_data, &mut buffer)
                    .map_err(|e| Error::Other(e.to_string()))?;
            }
        }

        let mut r = Vec::with_capacity(raw.len() + nonce.len() + buffer.len());

        r.extend_from_slice(raw);
        r.extend_from_slice(&nonce[4..]);
        r.extend_from_slice(&buffer);

        // Update recordLayer size to include explicit nonce
        let r_len = (r.len() - RECORD_LAYER_HEADER_SIZE) as u16;
        r[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE]
            .copy_from_slice(&r_len.to_be_bytes());

        Ok(r)
    }

    pub fn decrypt(&self, r: &[u8]) -> Result<Vec<u8>> {
        let mut reader = Cursor::new(r);
        let h = RecordLayerHeader::unmarshal(&mut reader)?;
        if h.content_type == ContentType::ChangeCipherSpec {
            // Nothing to encrypt with ChangeCipherSpec
            return Ok(r.to_vec());
        }

        if r.len() <= (RECORD_LAYER_HEADER_SIZE + 8) {
            return Err(Error::ErrNotEnoughRoomForNonce);
        }

        let mut nonce = vec![];
        nonce.extend_from_slice(&self.remote_write_iv[..4]);
        nonce.extend_from_slice(&r[RECORD_LAYER_HEADER_SIZE..RECORD_LAYER_HEADER_SIZE + 8]);
        let nonce = GenericArray::from_slice(&nonce);

        let out = &r[RECORD_LAYER_HEADER_SIZE + 8..];
        let tag_len = match self.remote_ccm {
            CryptoCcmType::CryptoCcm(_) => CRYPTO_CCM_TAG_LENGTH,
            CryptoCcmType::CryptoCcm8(_) => CRYPTO_CCM_8_TAG_LENGTH,
        };
        if out.len() < tag_len {
            return Err(Error::ErrInvalidPacketLength);
        }

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(out);

        match &self.remote_ccm {
            CryptoCcmType::CryptoCcm(ccm) => {
                let additional_data =
                    generate_aead_additional_data(&h, out.len() - CRYPTO_CCM_TAG_LENGTH);
                ccm.decrypt_in_place(nonce, &additional_data, &mut buffer)
                    .map_err(|_| Error::ErrInvalidMac)?;
            }
            CryptoCcmType::CryptoCcm8(ccm8) => {
                let additional_data =
                    generate_aead_additional_data(&h, out.len() - CRYPTO_CCM_8_TAG_LENGTH);
                ccm8.decrypt_in_place(nonce, &additional_data, &mut buffer)
                    .map_err(|_| Error::ErrInvalidMac)?;
            }
        }

        let mut d = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + buffer.len());
        d.extend_from_slice(&r[..RECORD_LAYER_HEADER_SIZE]);
        d.extend_from_slice(&buffer);

        Ok(d)
    }
}

#[cfg(test)]
mod record_policy_tests {
    use super::*;

    fn codec(tag: CryptoCcmTagLen, remote_key: &[u8]) -> CryptoCcm {
        CryptoCcm::new(&tag, &[0x11; 16], &[0x22; 4], remote_key, &[0x22; 4])
    }
    fn header(len: usize) -> RecordLayerHeader {
        RecordLayerHeader {
            content_type: ContentType::ApplicationData,
            protocol_version: PROTOCOL_VERSION1_2,
            epoch: 1,
            sequence_number: 7,
            content_len: len as u16,
        }
    }
    #[test]
    fn ccm_short_record_refuses_without_tag_length_underflow() {
        for (tag, bytes) in [
            (CryptoCcmTagLen::CryptoCcm8TagLength, 8),
            (CryptoCcmTagLen::CryptoCcmTagLength, 16),
        ] {
            let ccm = codec(tag, &[0x11; 16]);
            for length in 0..8 + bytes {
                let mut wire = Vec::new();
                header(length).marshal(&mut wire).unwrap();
                wire.resize(RECORD_LAYER_HEADER_SIZE + length, 0);
                assert!(ccm.decrypt(&wire).is_err(), "short record must refuse");
            }
        }
    }
    #[test]
    fn ccm_authentication_is_typed_and_valid_record_recovers() {
        for tag in [
            CryptoCcmTagLen::CryptoCcm8TagLength,
            CryptoCcmTagLen::CryptoCcmTagLength,
        ] {
            let sender = codec(tag.clone(), &[0x11; 16]);
            let receiver = codec(tag.clone(), &[0x11; 16]);
            let wrong = codec(tag, &[0x33; 16]);
            let mut plain = Vec::new();
            header(4).marshal(&mut plain).unwrap();
            plain.extend_from_slice(b"test");
            let encrypted = sender.encrypt(&header(4), &plain).unwrap();
            assert_eq!(wrong.decrypt(&encrypted).unwrap_err(), Error::ErrInvalidMac);
            let opened = receiver.decrypt(&encrypted).unwrap();
            assert_eq!(&opened[RECORD_LAYER_HEADER_SIZE..], b"test");
        }
    }
}
