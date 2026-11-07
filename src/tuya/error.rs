use std::fmt;

/// Ошибки работы с устройством.
#[derive(Debug)]
pub enum Error {
    /// Ошибка ввода-вывода (подключение, отправка, чтение)
    Io(std::io::Error),
    /// Устройство не ответило за отведённое время
    Timeout,
    /// Устройство закрыло соединение
    Closed,
    /// Не сошлась CRC, HMAC или тег GCM
    BadChecksum,
    /// Пакет повреждён или имеет неожиданный формат
    BadFrame(String),
    /// Ошибка расшифровки
    Crypto(String),
    /// Не удалось согласовать сеансовый ключ (3.4/3.5)
    Negotiation(String),
    /// Устройство ответило ненулевым кодом возврата
    Device { code: u32, message: String },
    /// Неверные параметры подключения
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "ошибка сети: {e}"),
            Error::Timeout => write!(f, "таймаут ответа"),
            Error::Closed => write!(f, "устройство закрыло соединение"),
            Error::BadChecksum => write!(f, "неверная контрольная сумма пакета (не тот ключ?)"),
            Error::BadFrame(s) => write!(f, "повреждённый пакет: {s}"),
            Error::Crypto(s) => write!(f, "ошибка расшифровки: {s}"),
            Error::Negotiation(s) => write!(f, "согласование ключа: {s}"),
            Error::Device { code, message } if message.is_empty() => {
                write!(f, "устройство вернуло код {code}")
            }
            Error::Device { code, message } => write!(f, "устройство вернуло код {code}: {message}"),
            Error::Config(s) => write!(f, "неверные параметры: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Error::Timeout,
            _ => Error::Io(e),
        }
    }
}
