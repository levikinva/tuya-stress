//! Параметры командной строки.

use clap::{Parser, ValueEnum};
use serde_json::Value;
use tuya_stress::tuya::Version;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Одно постоянное соединение (как у tuya-local)
    Persist,
    /// Новое соединение на каждую операцию
    Reconnect,
}

/// Стресс-тест Tuya-устройства по локальному протоколу (3.3, 3.4, 3.5)
#[derive(Parser, Debug)]
#[command(version, disable_version_flag = true)]
pub struct Args {
    /// Device ID
    #[arg(long)]
    pub id: String,
    /// IP-адрес или имя устройства
    #[arg(long)]
    pub ip: String,
    /// TCP-порт устройства
    #[arg(long, default_value_t = tuya_stress::tuya::consts::DEFAULT_PORT)]
    pub port: u16,
    /// Local key (16 символов)
    #[arg(long)]
    pub key: String,
    /// Версия протокола (та же, что в tuya-local): 3.3, 3.4 или 3.5
    #[arg(long, default_value = "3.4")]
    pub version: Version,
    /// Режим соединения
    #[arg(long, value_enum, default_value = "persist")]
    pub mode: Mode,
    /// Только запрашивать статус, без команд записи
    #[arg(long)]
    pub read_only: bool,
    /// dp для записи (114 = температура нагрева у Tion Bio X)
    #[arg(long, default_value_t = 114)]
    pub dp: u32,
    /// Значения через запятую, которые будут чередоваться (числа, true/false или строки)
    #[arg(long, default_value = "10,15", value_parser = parse_values)]
    pub values: Values,
    /// Пауза между операциями, секунд
    #[arg(long, default_value_t = 5.0)]
    pub interval: f64,
    /// Сколько ошибок подряд считать зависанием
    #[arg(long, default_value_t = 5)]
    pub fail_limit: u32,
    /// Пауза перед переподключением после ошибки, секунд. По умолчанию
    /// пауза растёт с числом ошибок подряд: 1, 2 … 5 с
    #[arg(long, value_name = "СЕКУНД")]
    pub reconnect_delay: Option<f64>,
    /// Сетевой таймаут, секунд
    #[arg(long, default_value_t = 5.0)]
    pub timeout: f64,
    /// Остановиться после указанного числа успешных операций
    #[arg(long)]
    pub max_ops: Option<u64>,
    /// После подтверждения команды дождаться от устройства отчёта о новом
    /// состоянии и только потом отправлять следующую
    #[arg(long)]
    pub wait_status: bool,
    /// Печатать каждую операцию и ответы устройства
    #[arg(long)]
    pub verbose: bool,
    /// Дублировать вывод в файл (дописывается в конец, если файл уже есть)
    #[arg(long, value_name = "ФАЙЛ")]
    pub log: Option<std::path::PathBuf>,
}

/// Список значений для записи (обёртка, чтобы clap разбирал строку целиком)
#[derive(Debug, Clone)]
pub struct Values(pub Vec<Value>);

fn parse_values(s: &str) -> Result<Values, String> {
    let v: Vec<Value> = s.split(',').map(parse_value).collect();
    if v.is_empty() {
        return Err("нужно хотя бы одно значение".into());
    }
    Ok(Values(v))
}

fn parse_value(s: &str) -> Value {
    let s = s.trim();
    match s {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => s.parse::<i64>().map(Value::from).unwrap_or_else(|_| Value::from(s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }

    #[test]
    fn values_are_typed() {
        let Values(v) = parse_values("10, true,abc,-3").unwrap();
        assert_eq!(v, vec![Value::from(10), Value::Bool(true), Value::from("abc"), Value::from(-3)]);
    }
}
