mod cli;
mod output;
mod stress;

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use output::{event, out};
use tuya_stress::tuya::DeviceConfig;

fn main() -> ExitCode {
    let args = cli::Args::parse();

    let mut cfg = match DeviceConfig::new(&args.id, &args.ip, Some(args.port), &args.key, args.version) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Ошибка: {e}");
            return ExitCode::from(2);
        }
    };
    cfg.timeout = Duration::from_secs_f64(args.timeout);

    if let Err(e) = output::init(args.log.as_deref()) {
        eprintln!("Ошибка: не удалось открыть лог-файл: {e}");
        return ExitCode::from(2);
    }

    event!(
        "старт: устройство={} протокол={} режим={:?} только_чтение={} ожидание_статуса={} интервал={}с пауза_переподключения={} dp={} значения={}",
        args.ip,
        args.version,
        args.mode,
        args.read_only,
        args.wait_status,
        args.interval,
        args.reconnect_delay.map_or("1–5с".to_string(), |d| format!("{d}с")),
        args.dp,
        args.values.0.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")
    );

    let out = stress::run(&args, cfg);
    let minutes = out.elapsed.as_secs_f64() / 60.0;
    let stats = format!(
        "{} успешных операций за {minutes:.1} мин, отказов устройства: {}, подключений: {}",
        out.ok, out.rejected, out.connects
    );

    if out.hung {
        out!();
        event!("Устройство не отвечает: {stats}");
        ExitCode::from(1)
    } else {
        out!();
        event!("Готово: {stats}");
        ExitCode::SUCCESS
    }
}
