//! HKDF-SHA-256 and AES-CCM-16-64-128. RustCrypto only; no hand-rolled AEAD.

use aes::Aes128;
use ccm::aead::{AeadInOut, KeyInit, Tag};
use ccm::{
    Ccm,
    consts::{U8, U13},
};
use hkdf::Hkdf;
use sha2::Sha256;

use super::cbor;
use super::header::PartialIv;
use super::{Error, KEY_LEN, NONCE_LEN, TAG_LEN};

type Aes128Ccm = Ccm<Aes128, U8, U13>;

pub(crate) fn hkdf_expand(
    master_secret: &[u8],
    master_salt: &[u8],
    id: &[u8],
    id_context: Option<&[u8]>,
    label: &str,
    out: &mut [u8],
) -> Result<(), Error> {
    let mut info = [0u8; 48];
    let n = cbor::encode_info(
        &mut info,
        id,
        id_context,
        label,
        u8::try_from(out.len()).map_err(|_| Error::Derive)?,
    )?;
    let hk = Hkdf::<Sha256>::new(Some(master_salt), master_secret);
    hk.expand(&info[..n], out).map_err(|_| Error::Derive)
}

pub(crate) fn nonce(common_iv: &[u8; NONCE_LEN], id_piv: &[u8], piv: PartialIv) -> [u8; NONCE_LEN] {
    let mut raw = [0u8; NONCE_LEN];
    raw[0] = id_piv.len() as u8;
    let id_pad = NONCE_LEN - 6;
    raw[1 + id_pad - id_piv.len()..1 + id_pad].copy_from_slice(id_piv);
    let piv_bytes = piv.as_bytes();
    raw[NONCE_LEN - piv_bytes.len()..].copy_from_slice(piv_bytes);
    for (r, iv) in raw.iter_mut().zip(common_iv.iter()) {
        *r ^= *iv;
    }
    raw
}

pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(Error::MessageLength)?;
    if out.len() < n {
        return Err(Error::BufferTooSmall);
    }
    out[..plaintext.len()].copy_from_slice(plaintext);
    let cipher = Aes128Ccm::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(nonce.into(), aad, (&mut out[..plaintext.len()]).into())
        .map_err(|_| Error::Encrypt)?;
    out[plaintext.len()..n].copy_from_slice(&tag);
    Ok(n)
}

pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if ciphertext.len() < TAG_LEN {
        return Err(Error::MessageLength);
    }
    let pt_len = ciphertext.len() - TAG_LEN;
    if out.len() < pt_len {
        return Err(Error::BufferTooSmall);
    }
    out[..pt_len].copy_from_slice(&ciphertext[..pt_len]);
    let tag =
        Tag::<Aes128Ccm>::try_from(&ciphertext[pt_len..]).map_err(|_| Error::MessageLength)?;
    let cipher = Aes128Ccm::new(key.into());
    cipher
        .decrypt_inout_detached(nonce.into(), aad, (&mut out[..pt_len]).into(), &tag)
        .map_err(|_| Error::Decrypt)?;
    Ok(pt_len)
}

pub(crate) struct Aad {
    bytes: [u8; 64],
    len: usize,
}

impl Aad {
    pub(crate) fn new(request_kid: &[u8], request_piv: &[u8]) -> Result<Self, Error> {
        let mut bytes = [0u8; 64];
        let len = cbor::encode_aad(&mut bytes, request_kid, request_piv, &[])?;
        Ok(Self { bytes, len })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
