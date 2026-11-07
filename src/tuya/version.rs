use std::fmt;
use std::str::FromStr;

/// Версия локального протокола Tuya
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Version {
    V33,
    V34,
    V35,
}

/// Длина заголовка версии: "3.x" + 12 нулевых байт
pub const VERSION_HEADER_LEN: usize = 15;

impl Version {
    pub fn as_bytes(self) -> &'static [u8; 3] {
        match self {
            Version::V33 => b"3.3",
            Version::V34 => b"3.4",
            Version::V35 => b"3.5",
        }
    }

    /// Заголовок версии, который добавляется к большинству команд
    pub fn header(self) -> [u8; VERSION_HEADER_LEN] {
        let mut h = [0u8; VERSION_HEADER_LEN];
        h[..3].copy_from_slice(self.as_bytes());
        h
    }

    /// Нужно ли согласовывать сеансовый ключ
    pub fn uses_session_key(self) -> bool {
        self != Version::V33
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(std::str::from_utf8(self.as_bytes()).unwrap())
    }
}

impl FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "3.3" => Ok(Version::V33),
            "3.4" => Ok(Version::V34),
            "3.5" => Ok(Version::V35),
            other => Err(format!("неподдерживаемая версия протокола {other:?} (доступны 3.3, 3.4, 3.5)")),
        }
    }
}
