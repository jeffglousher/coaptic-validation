// AES-GCM (Galois Counter Mode)
// The most widely used block cipher worldwide.
// Mandatory as of TLS 1.2 (2008) and used by default by most clients.
// RFC 5288 year 2008 https://tools.ietf.org/html/rfc5288

// https://github.com/RustCrypto/AEADs
// https://docs.rs/aes-gcm/0.8.0/aes_gcm/

use std::io::Cursor;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, KeyInit};
use rand::Rng;

use super::*;
use crate::content::*;
use crate::error::*;
use crate::record_layer::record_layer_header::*; // what about Aes256Gcm?

const CRYPTO_GCM_TAG_LENGTH: usize = 16;
const CRYPTO_GCM_NONCE_LENGTH: usize = 12;

// State needed to handle encrypted input/output
#[derive(Clone)]
pub struct CryptoGcm {
    local_gcm: Aes128Gcm,
    remote_gcm: Aes128Gcm,
    local_write_iv: Vec<u8>,
    remote_write_iv: Vec<u8>,
}

impl CryptoGcm {
    pub fn new(
        local_key: &[u8],
        local_write_iv: &[u8],
        remote_key: &[u8],
        remote_write_iv: &[u8],
    ) -> Self {
        let key = GenericArray::from_slice(local_key);
        let local_gcm = Aes128Gcm::new(key);

        let key = GenericArray::from_slice(remote_key);
        let remote_gcm = Aes128Gcm::new(key);

        CryptoGcm {
            local_gcm,
            local_write_iv: local_write_iv.to_vec(),
            remote_gcm,
            remote_write_iv: remote_write_iv.to_vec(),
        }
    }

    pub fn encrypt(&self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let payload = &raw[RECORD_LAYER_HEADER_SIZE..];
        let raw = &raw[..RECORD_LAYER_HEADER_SIZE];

        let mut nonce = vec![0u8; CRYPTO_GCM_NONCE_LENGTH];
        nonce[..4].copy_from_slice(&self.local_write_iv[..4]);
        rand::thread_rng().fill(&mut nonce[4..]);
        let nonce = GenericArray::from_slice(&nonce);

        let additional_data = generate_aead_additional_data(pkt_rlh, payload.len());

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(payload);

        self.local_gcm
            .encrypt_in_place(nonce, &additional_data, &mut buffer)
            .map_err(|e| Error::Other(e.to_string()))?;

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

        let out = &r[RECORD_LAYER_HEADER_SIZE + 8..];
        if out.len() < CRYPTO_GCM_TAG_LENGTH {
            return Err(Error::ErrInvalidPacketLength);
        }

        let mut nonce = vec![];
        nonce.extend_from_slice(&self.remote_write_iv[..4]);
        nonce.extend_from_slice(&r[RECORD_LAYER_HEADER_SIZE..RECORD_LAYER_HEADER_SIZE + 8]);
        let nonce = GenericArray::from_slice(&nonce);


        let additional_data = generate_aead_additional_data(&h, out.len() - CRYPTO_GCM_TAG_LENGTH);

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(out);

        self.remote_gcm
            .decrypt_in_place(nonce, &additional_data, &mut buffer)
            .map_err(|_| Error::ErrInvalidMac)?;

        let mut d = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + buffer.len());
        d.extend_from_slice(&r[..RECORD_LAYER_HEADER_SIZE]);
        d.extend_from_slice(&buffer);

        Ok(d)
    }
}

#[cfg(test)]
mod record_policy_tests {
    use super::*;

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
    fn gcm_short_records_refuse_without_underflow() {
        let gcm = CryptoGcm::new(&[1; 16], &[2; 4], &[1; 16], &[2; 4]);
        for length in 0..8 + CRYPTO_GCM_TAG_LENGTH {
            let mut wire = Vec::new();
            header(length).marshal(&mut wire).unwrap();
            wire.resize(RECORD_LAYER_HEADER_SIZE + length, 0);
            assert!(gcm.decrypt(&wire).is_err());
        }
    }

    #[test]
    fn gcm_authentication_refuses_and_valid_record_recovers() {
        let gcm = CryptoGcm::new(&[1; 16], &[2; 4], &[1; 16], &[2; 4]);
        let wrong = CryptoGcm::new(&[3; 16], &[2; 4], &[3; 16], &[2; 4]);
        for payload in [b"".as_slice(), b"test".as_slice()] {
            let h = header(payload.len());
            let mut plain = Vec::new();
            h.marshal(&mut plain).unwrap();
            plain.extend_from_slice(payload);
            let encrypted = gcm.encrypt(&h, &plain).unwrap();
            assert_eq!(wrong.decrypt(&encrypted).unwrap_err(), Error::ErrInvalidMac);
            let mut tampered = encrypted.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert_eq!(gcm.decrypt(&tampered).unwrap_err(), Error::ErrInvalidMac);
            let opened = gcm.decrypt(&encrypted).unwrap();
            assert_eq!(&opened[RECORD_LAYER_HEADER_SIZE..], payload);
        }
    }
}
