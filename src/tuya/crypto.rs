//! Криптографические примитивы протокола.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::{AeadInPlace, Aes128Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use super::error::{Error, Result};

pub type Key = [u8; 16];

/// AES-128-ECB; при `pad` добавляется дополнение PKCS7
pub fn ecb_encrypt(key: &Key, data: &[u8], pad: bool) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut buf = data.to_vec();
    if pad {
        let n = 16 - (buf.len() % 16);
        buf.extend(std::iter::repeat_n(n as u8, n));
    }
    for block in buf.chunks_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    buf
}

/// AES-128-ECB с мягким снятием PKCS7 (некорректное дополнение не считается
/// ошибкой, как и в tinytuya)
pub fn ecb_decrypt(key: &Key, data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(16) {
        return Err(Error::Crypto(format!("длина {} не кратна 16", data.len())));
    }
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut buf = data.to_vec();
    for block in buf.chunks_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
    if let Some(&n) = buf.last() {
        let n = n as usize;
        if (1..=16).contains(&n) && n <= buf.len() {
            buf.truncate(buf.len() - n);
        }
    }
    Ok(buf)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC принимает ключ любой длины");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// AES-128-GCM; возвращает шифротекст и тег
pub fn gcm_encrypt(key: &Key, iv: &[u8; 12], aad: &[u8], data: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let mut buf = data.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut buf)
        .expect("шифрование GCM не может завершиться ошибкой для таких размеров");
    (buf, tag.into())
}

pub fn gcm_decrypt(key: &Key, iv: &[u8], aad: &[u8], data: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != 12 || tag.len() != 16 {
        return Err(Error::BadFrame("неверная длина IV или тега".into()));
    }
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let mut buf = data.to_vec();
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut buf, GenericArray::from_slice(tag))
        .map_err(|_| Error::BadChecksum)?;
    Ok(buf)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &Key = b"0123456789abcdef";

    #[test]
    fn ecb_roundtrip_with_padding() {
        for len in [0, 1, 15, 16, 17, 100] {
            let data: Vec<u8> = (0..len as u8).collect();
            let enc = ecb_encrypt(KEY, &data, true);
            assert_eq!(enc.len() % 16, 0);
            assert_eq!(ecb_decrypt(KEY, &enc).unwrap(), data);
        }
    }

    #[test]
    fn gcm_roundtrip_and_tamper() {
        let iv = [7u8; 12];
        let (ct, tag) = gcm_encrypt(KEY, &iv, b"aad", b"hello");
        assert_eq!(gcm_decrypt(KEY, &iv, b"aad", &ct, &tag).unwrap(), b"hello");
        assert!(gcm_decrypt(KEY, &iv, b"other", &ct, &tag).is_err());
    }
}
