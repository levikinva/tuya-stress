//! Согласование сеансового ключа (протоколы 3.4 и 3.5).
//!
//! 1. Клиент → `SESS_KEY_NEG_START`: случайный `local_nonce` (16 байт)
//! 2. Устройство → `SESS_KEY_NEG_RESP`: `remote_nonce` (16) + HMAC(local_key, local_nonce) (32)
//! 3. Клиент → `SESS_KEY_NEG_FINISH`: HMAC(local_key, remote_nonce)
//! 4. Обе стороны вычисляют сеансовый ключ из `local_nonce XOR remote_nonce`
//!
//! Все сообщения согласования шифруются исходным local key.

use super::crypto::{self, Key};
use super::error::{Error, Result};
use super::version::Version;

/// Проверяет ответ устройства на шаге 2 и возвращает `remote_nonce`
pub fn verify_response(local_key: &Key, local_nonce: &[u8; 16], payload: &[u8]) -> Result<[u8; 16]> {
    if payload.len() < 48 {
        return Err(Error::Negotiation(format!("короткий ответ ({} байт)", payload.len())));
    }
    if crypto::hmac_sha256(local_key, local_nonce)[..] != payload[16..48] {
        return Err(Error::Negotiation("не сошёлся HMAC (неверный local key?)".into()));
    }
    Ok(payload[..16].try_into().unwrap())
}

/// Данные для шага 3
pub fn finish_payload(local_key: &Key, remote_nonce: &[u8; 16]) -> [u8; 32] {
    crypto::hmac_sha256(local_key, remote_nonce)
}

/// Вычисляет сеансовый ключ
pub fn derive_key(version: Version, local_key: &Key, local_nonce: &[u8; 16], remote_nonce: &[u8; 16]) -> Key {
    let mut xor = [0u8; 16];
    for (i, b) in xor.iter_mut().enumerate() {
        *b = local_nonce[i] ^ remote_nonce[i];
    }
    match version {
        Version::V35 => {
            let iv: [u8; 12] = local_nonce[..12].try_into().unwrap();
            let (ct, _tag) = crypto::gcm_encrypt(local_key, &iv, &[], &xor);
            ct.try_into().unwrap()
        }
        _ => crypto::ecb_encrypt(local_key, &xor, false).try_into().unwrap(),
    }
}

#[cfg(test)]
mod tests {
    //! Эталонные ключи вычислены tinytuya 1.20.
    use super::*;

    const KEY: &Key = b"0123456789abcdef";

    fn nonces() -> ([u8; 16], [u8; 16]) {
        let local: [u8; 16] = core::array::from_fn(|i| i as u8);
        let remote: [u8; 16] = core::array::from_fn(|i| 100 + i as u8);
        (local, remote)
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn session_keys_match_tinytuya() {
        let (l, r) = nonces();
        assert_eq!(hex(&derive_key(Version::V34, KEY, &l, &r)), "66c0d72e3ec70800f70b18898e76c684");
        assert_eq!(hex(&derive_key(Version::V35, KEY, &l, &r)), "995ba0797218575a8c42637ebce7cc51");
    }

    #[test]
    fn verify_response_checks_hmac() {
        let (l, r) = nonces();
        let mut good = r.to_vec();
        good.extend(crypto::hmac_sha256(KEY, &l));
        assert_eq!(verify_response(KEY, &l, &good).unwrap(), r);

        let mut bad = good.clone();
        bad[20] ^= 1;
        assert!(verify_response(KEY, &l, &bad).is_err());
        assert!(verify_response(KEY, &l, &good[..40]).is_err());
    }
}
