//! Вывод: на экран и, если задан `--log`, одновременно в файл.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static LOG_FILE: OnceLock<Mutex<File>> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();

/// Запоминает момент старта и, если задан путь, открывает лог-файл
/// (дописывает в конец, если файл уже есть).
pub fn init(log_path: Option<&Path>) -> io::Result<()> {
    START.get_or_init(Instant::now);
    if let Some(path) = log_path {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let _ = LOG_FILE.set(Mutex::new(file));
    }
    Ok(())
}

/// Печатает строку на экран и в лог-файл
pub fn line(text: &str) {
    println!("{text}");
    if let Some(f) = LOG_FILE.get()
        && let Ok(mut f) = f.lock()
    {
        // сразу сбрасываем на диск: лог должен пережить аварийное завершение
        let _ = writeln!(f, "{text}");
        let _ = f.flush();
    }
}

/// Метка времени: локальное время, unix-время и минуты от старта.
/// Unix-время удобно сравнивать с полем `t` в отчётах устройства.
pub fn stamp() -> String {
    let now = chrono::Local::now();
    let minutes = START.get().map(|s| s.elapsed().as_secs_f64() / 60.0).unwrap_or(0.0);
    format!("[{} t={} +{minutes:.1} мин]", now.format("%Y-%m-%d %H:%M:%S"), now.timestamp())
}

/// `out!(...)` — как `println!`, но и в лог-файл
macro_rules! out {
    () => { $crate::output::line("") };
    ($($arg:tt)*) => { $crate::output::line(&format!($($arg)*)) };
}

/// `event!(...)` — строка с меткой времени в начале
macro_rules! event {
    ($($arg:tt)*) => {
        $crate::output::line(&format!("{} {}", $crate::output::stamp(), format!($($arg)*)))
    };
}

pub(crate) use {event, out};
