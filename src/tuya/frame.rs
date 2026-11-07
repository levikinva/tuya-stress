//! Сборка и разбор пакетов протокола, без сетевого ввода-вывода.
//!
//! Форматы:
//! - 3.3: `55AA | seq | cmd | len | [retcode] | [заголовок] AES-ECB(данные) | CRC32 | AA55`
//! - 3.4: `55AA | seq | cmd | len | [retcode] | AES-ECB([заголовок] данные) | HMAC-SHA256 | AA55`
//! - 3.5: `6699 | 0u16 | seq | cmd | len | IV | AES-GCM([retcode] [заголовок] данные) | тег | 9966`
//!
//! Код возврата (retcode) есть только в пакетах от устройства.

use super::consts::{MAX_PAYLOAD, PREFIX_55AA, PREFIX_6699, SUFFIX_55AA, SUFFIX_6699, needs_version_header};
use super::crypto::{self, Key};
use super::error::{Error, Result};
use super::version::{VERSION_HEADER_LEN, Version};

/// Разобранный пакет
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub seqno: u32,
    pub cmd: u32,
    /// Код возврата (только в пакетах от устройства)
    pub retcode: Option<u32>,
    /// Расшифрованные данные без заголовка версии
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn payload_str(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }
}

/// Собирает пакет от клиента к устройству. `iv` нужен только для 3.5;
/// если не задан, генерируется случайно.
pub fn encode(version: Version, key: &Key, seqno: u32, cmd: u32, payload: &[u8], iv: Option<[u8; 12]>) -> Vec<u8> {
    encode_with_retcode(version, key, seqno, cmd, None, payload, iv)
}

/// Собирает пакет в общем виде, в том числе с кодом возврата, как это делает
/// устройство (пригодится для эмулятора и тестов).
pub fn encode_with_retcode(
    version: Version,
    key: &Key,
    seqno: u32,
    cmd: u32,
    retcode: Option<u32>,
    payload: &[u8],
    iv: Option<[u8; 12]>,
) -> Vec<u8> {
    let header = needs_version_header(cmd).then(|| version.header());
    let retcode_bytes = retcode.map(u32::to_be_bytes);

    match version {
        Version::V33 => {
            let mut body = Vec::new();
            body.extend(retcode_bytes.iter().flatten());
            body.extend(header.iter().flatten());
            body.extend(crypto::ecb_encrypt(key, payload, true));
            let mut f = header_55aa(seqno, cmd, body.len() + 8);
            f.extend(&body);
            let crc = crc32fast::hash(&f);
            f.extend(crc.to_be_bytes());
            f.extend(SUFFIX_55AA.to_be_bytes());
            f
        }
        Version::V34 => {
            let mut plain = Vec::new();
            plain.extend(header.iter().flatten());
            plain.extend_from_slice(payload);
            let mut body = Vec::new();
            body.extend(retcode_bytes.iter().flatten());
            body.extend(crypto::ecb_encrypt(key, &plain, true));
            let mut f = header_55aa(seqno, cmd, body.len() + 36);
            f.extend(&body);
            let mac = crypto::hmac_sha256(key, &f);
            f.extend(mac);
            f.extend(SUFFIX_55AA.to_be_bytes());
            f
        }
        Version::V35 => {
            let mut plain = Vec::new();
            plain.extend(retcode_bytes.iter().flatten());
            plain.extend(header.iter().flatten());
            plain.extend_from_slice(payload);
            let mut f = Vec::with_capacity(18 + 12 + plain.len() + 20);
            f.extend(PREFIX_6699.to_be_bytes());
            f.extend(0u16.to_be_bytes());
            f.extend(seqno.to_be_bytes());
            f.extend(cmd.to_be_bytes());
            f.extend(((plain.len() + 12 + 16) as u32).to_be_bytes());
            let iv = iv.unwrap_or_else(crypto::random_bytes::<12>);
            let (ct, tag) = crypto::gcm_encrypt(key, &iv, &f[4..18], &plain);
            f.extend(iv);
            f.extend(ct);
            f.extend(tag);
            f.extend(SUFFIX_6699.to_be_bytes());
            f
        }
    }
}

fn header_55aa(seqno: u32, cmd: u32, len: usize) -> Vec<u8> {
    let mut f = Vec::with_capacity(16 + len);
    f.extend(PREFIX_55AA.to_be_bytes());
    f.extend(seqno.to_be_bytes());
    f.extend(cmd.to_be_bytes());
    f.extend((len as u32).to_be_bytes());
    f
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

/// Пытается извлечь из начала буфера один полный пакет.
///
/// Возвращает `Ok(None)`, если данных пока недостаточно. Мусор перед началом
/// пакета отбрасывается. `has_retcode` — есть ли в пакете код возврата
/// (`true` для пакетов от устройства).
pub fn decode(version: Version, key: &Key, buf: &mut Vec<u8>, has_retcode: bool) -> Result<Option<Frame>> {
    // синхронизация по маркеру начала пакета
    let start = buf.windows(4).position(|w| {
        let p = be32(w);
        p == PREFIX_55AA || p == PREFIX_6699
    });
    match start {
        Some(0) => {}
        Some(n) => {
            buf.drain(..n);
        }
        None => {
            let keep = buf.len().min(3);
            buf.drain(..buf.len() - keep);
            return Ok(None);
        }
    }

    if be32(buf) == PREFIX_6699 {
        decode_6699(key, buf, has_retcode)
    } else {
        decode_55aa(version, key, buf, has_retcode)
    }
}

fn decode_55aa(version: Version, key: &Key, buf: &mut Vec<u8>, has_retcode: bool) -> Result<Option<Frame>> {
    if buf.len() < 16 {
        return Ok(None);
    }
    let seqno = be32(&buf[4..]);
    let cmd = be32(&buf[8..]);
    let len = be32(&buf[12..]) as usize;
    if len > MAX_PAYLOAD {
        buf.drain(..4);
        return Err(Error::BadFrame(format!("заявленная длина {len} байт")));
    }
    let total = 16 + len;
    if buf.len() < total {
        return Ok(None);
    }
    let raw: Vec<u8> = buf.drain(..total).collect();

    let end_len = if version == Version::V34 { 36 } else { 8 };
    let retcode_len = if has_retcode { 4 } else { 0 };
    if len < retcode_len + end_len {
        return Err(Error::BadFrame("слишком короткий пакет".into()));
    }
    let body_end = total - end_len;

    let checksum_ok = if version == Version::V34 {
        crypto::hmac_sha256(key, &raw[..body_end])[..] == raw[body_end..body_end + 32]
    } else {
        be32(&raw[body_end..]) == crc32fast::hash(&raw[..body_end])
    };
    if !checksum_ok {
        return Err(Error::BadChecksum);
    }

    let retcode = has_retcode.then(|| be32(&raw[16..]));
    let mut payload = raw[16 + retcode_len..body_end].to_vec();
    let vh = version.as_bytes();

    if version == Version::V33 {
        if payload.starts_with(vh) {
            payload.drain(..VERSION_HEADER_LEN.min(payload.len()));
        }
        if !payload.is_empty() {
            payload = crypto::ecb_decrypt(key, &payload)?;
        }
    } else {
        if !payload.is_empty() {
            payload = crypto::ecb_decrypt(key, &payload)?;
        }
        if payload.starts_with(vh) {
            payload.drain(..VERSION_HEADER_LEN.min(payload.len()));
        }
    }

    Ok(Some(Frame { seqno, cmd, retcode, payload }))
}

fn decode_6699(key: &Key, buf: &mut Vec<u8>, has_retcode: bool) -> Result<Option<Frame>> {
    if buf.len() < 18 {
        return Ok(None);
    }
    let seqno = be32(&buf[6..]);
    let cmd = be32(&buf[10..]);
    let len = be32(&buf[14..]) as usize;
    if !(28..=MAX_PAYLOAD).contains(&len) {
        buf.drain(..4);
        return Err(Error::BadFrame(format!("заявленная длина {len} байт")));
    }
    let total = 18 + len + 4;
    if buf.len() < total {
        return Ok(None);
    }
    let raw: Vec<u8> = buf.drain(..total).collect();

    let iv = &raw[18..30];
    let ct = &raw[30..total - 20];
    let tag = &raw[total - 20..total - 4];
    let mut payload = crypto::gcm_decrypt(key, iv, &raw[4..18], ct, tag)?;

    let retcode = if has_retcode && payload.len() >= 4 {
        let r = be32(&payload);
        payload.drain(..4);
        Some(r)
    } else {
        None
    };
    if payload.starts_with(Version::V35.as_bytes()) {
        payload.drain(..VERSION_HEADER_LEN.min(payload.len()));
    }

    Ok(Some(Frame { seqno, cmd, retcode, payload }))
}

#[cfg(test)]
mod tests {
    //! Эталонные пакеты сгенерированы tinytuya 1.20.
    use super::*;
    use crate::tuya::consts::cmd;

    const KEY: &Key = b"0123456789abcdef";
    const SESSION: &Key = b"fedcba9876543210";
    const P33: &str = r#"{"devId":"dev123","uid":"dev123","t":"1700000000","dps":{"114":10}}"#;
    const P: &str = r#"{"protocol":5,"t":1700000000,"data":{"dps":{"114":10}}}"#;

    const V33: &str = "000055aa000000010000000700000067332e33000000000000000000000000d136205043d3aaf4a21fdd2b78ba3af8bcebef0e364fb8ebcd4fb9c2fbbe35c4f9645c25b6fa8a9bfbe41e4dd4d1f3301a0349f812ee0dcee81749df5a0b93022c3671203e114c94a606a2af45c8c0c89687d1fc0000aa55";
    const V34: &str = "000055aa000000020000000d000000746a2f4275da435008b5b5d1f2e19bf95d9fabc506b104548101bafb6638e0886b1e4c9dd4fafe30e6932f5acf9b6f464647b55ad12fb8b4466d2eae063f375fea0d4749fdeeaf86568bcb218b621f2243a8a5312bbadcea71ce8b8f14e4f017f671b6aeed826cf7ae8e07597a72b247d80000aa55";
    const V35: &str = "000066990000000000030000000d00000062000102030405060708090a0b15447ce622319dd4423374fb35ff5864c5ab8c5a0b5c009545758cd60f0e09c4435f4b34606e0087a3d5dc85a5a3a2a30b6242df0b4cee8de82465f9801a9c6678b2694f730781fe590689636e296c4f80761581049e00009966";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    const IV: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    #[test]
    fn encode_matches_tinytuya() {
        assert_eq!(hex(&encode(Version::V33, KEY, 1, cmd::CONTROL, P33.as_bytes(), None)), V33);
        assert_eq!(hex(&encode(Version::V34, SESSION, 2, cmd::CONTROL_NEW, P.as_bytes(), None)), V34);
        assert_eq!(hex(&encode(Version::V35, SESSION, 3, cmd::CONTROL_NEW, P.as_bytes(), Some(IV))), V35);
    }

    #[test]
    fn decode_tinytuya_frames() {
        for (v, key, data, seq, payload) in [
            (Version::V33, KEY, V33, 1, P33),
            (Version::V34, SESSION, V34, 2, P),
            (Version::V35, SESSION, V35, 3, P),
        ] {
            let mut buf = unhex(data);
            let f = decode(v, key, &mut buf, false).unwrap().unwrap();
            assert_eq!(f.seqno, seq);
            assert_eq!(f.payload_str(), payload, "версия {v}");
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn device_frames_with_retcode_roundtrip() {
        for v in [Version::V33, Version::V34, Version::V35] {
            let data = encode_with_retcode(v, KEY, 9, cmd::STATUS, Some(0), br#"{"dps":{"1":true}}"#, None);
            let mut buf = data.clone();
            let f = decode(v, KEY, &mut buf, true).unwrap().unwrap();
            assert_eq!(f.retcode, Some(0));
            assert_eq!(f.cmd, cmd::STATUS);
            assert_eq!(f.payload, br#"{"dps":{"1":true}}"#);

            // пустой ответ на команду
            let mut buf = encode_with_retcode(v, KEY, 10, cmd::CONTROL_NEW, Some(0), b"", None);
            let f = decode(v, KEY, &mut buf, true).unwrap().unwrap();
            assert_eq!(f.retcode, Some(0));
        }
    }

    #[test]
    fn partial_frame_and_resync() {
        let full = unhex(V33);
        let mut buf = vec![0xde, 0xad, 0xbe, 0xef, 0x01];
        buf.extend_from_slice(&full[..20]);
        assert!(decode(Version::V33, KEY, &mut buf, false).unwrap().is_none());
        buf.extend_from_slice(&full[20..]);
        let f = decode(Version::V33, KEY, &mut buf, false).unwrap().unwrap();
        assert_eq!(f.payload_str(), P33);
    }

    #[test]
    fn wrong_key_is_rejected() {
        for (v, data) in [(Version::V34, V34), (Version::V35, V35)] {
            let mut buf = unhex(data);
            assert!(matches!(decode(v, KEY, &mut buf, false), Err(Error::BadChecksum)));
        }
    }
}
