//! Локальный протокол Tuya.
//!
//! - [`consts`]  — номера команд и маркеры пакетов
//! - [`version`] — версии протокола
//! - [`crypto`]  — AES-ECB, AES-GCM, HMAC-SHA256
//! - [`frame`]   — сборка и разбор пакетов (без сетевого ввода-вывода)
//! - [`session`] — вычисление сеансового ключа для 3.4/3.5
//! - [`conn`]    — TCP-соединение с устройством и команды верхнего уровня
//! - [`error`]   — тип ошибок

pub mod conn;
pub mod consts;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod session;
pub mod version;

pub use conn::{Connection, DeviceConfig};
pub use error::{Error, Result};
pub use frame::Frame;
pub use version::Version;
