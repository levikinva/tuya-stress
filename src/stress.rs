//! Основной цикл стресс-теста.

use std::time::{Duration, Instant};

use tuya_stress::tuya::{Connection, DeviceConfig, Error, Result};

use crate::cli::{Args, Mode};
use crate::output::{event, out};

/// Итог прогона
pub struct Outcome {
    pub ok: u64,
    /// Сколько раз устройство ответило, но отказалось выполнять команду
    pub rejected: u64,
    pub connects: u64,
    pub elapsed: Duration,
    /// true — устройство перестало отвечать, false — достигнут --max-ops
    pub hung: bool,
}

struct Runner<'a> {
    args: &'a Args,
    cfg: DeviceConfig,
    conn: Option<Connection>,
    start: Instant,
    ok: u64,
    rejected: u64,
    fails: u32,
    connects: u64,
    last_report: Instant,
}

/// Как часто печатать прогресс
const PROGRESS_EVERY: Duration = Duration::from_secs(60);

/// Пауза перед переподключением растёт с числом ошибок подряд: 1 с, 2 с … до 5 с
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const RECONNECT_DELAY_MAX_STEPS: u32 = 5;

impl<'a> Runner<'a> {
    fn log_error(&self, e: impl std::fmt::Display) {
        event!("#{} ОШИБКА: {e}", self.ok);
    }

    fn connection(&mut self) -> Option<&mut Connection> {
        if self.conn.is_none() {
            // после ошибок переподключаемся не сразу: шквал подключений сам
            // по себе нагружает устройство и искажает результат
            if self.fails > 0 {
                std::thread::sleep(RECONNECT_DELAY * self.fails.min(RECONNECT_DELAY_MAX_STEPS));
            }
            match Connection::open(&self.cfg) {
                Ok(c) => {
                    self.connects += 1;
                    self.conn = Some(c);
                    // в режиме reconnect подключение на каждой операции, не засоряем вывод
                    if self.args.mode == Mode::Persist || self.args.verbose {
                        event!("подключено (подключений: {})", self.connects);
                    }
                }
                Err(e) => {
                    self.fails += 1;
                    self.log_error(e);
                }
            }
        }
        self.conn.as_mut()
    }

    fn operation(&mut self) -> Option<Result<()>> {
        let args = self.args;
        let value = &args.values.0[(self.ok as usize) % args.values.0.len()];
        let conn = self.connection()?;
        let result = if args.read_only {
            conn.query().map(|s| {
                if args.verbose {
                    out!("  статус: {s}");
                }
            })
        } else {
            conn.set_dp(args.dp, value).and_then(|()| {
                if args.wait_status {
                    let s = conn.wait_status(args.dp, value)?;
                    if args.verbose {
                        out!("  статус: {s}");
                    }
                }
                Ok(())
            })
        };
        // пакеты, которые устройство прислало само (периодические отчёты и т. п.)
        let unclaimed = conn.take_unclaimed();
        if args.verbose {
            for f in unclaimed {
                out!("  прочее (cmd {}): {}", f.cmd, f.payload_str());
            }
        }
        Some(result)
    }

    fn step(&mut self) {
        match self.operation() {
            None => {} // не удалось подключиться, ошибка уже записана
            Some(Ok(())) => {
                self.fails = 0;
                self.ok += 1;
                // первая операция, затем не реже раза в минуту
                let report_due = self.last_report.elapsed() >= PROGRESS_EVERY;
                if self.ok == 1 || report_due || self.args.verbose {
                    event!("успешно: {} (подключений: {})", self.ok, self.connects);
                    self.last_report = Instant::now();
                }
            }
            Some(Err(e @ Error::Device { .. })) => {
                // устройство на связи, просто отказалось выполнять команду:
                // это не зависание и не повод переподключаться
                self.rejected += 1;
                self.fails = 0;
                event!("#{} ОТКАЗ: {e}", self.ok);
            }
            Some(Err(e)) => {
                self.fails += 1;
                self.log_error(e);
                self.conn = None; // следующая попытка — с новым соединением
            }
        }
        if self.args.mode == Mode::Reconnect {
            self.conn = None;
        }
    }
}

pub fn run(args: &Args, cfg: DeviceConfig) -> Outcome {
    let mut r = Runner {
        args,
        cfg,
        conn: None,
        start: Instant::now(),
        ok: 0,
        rejected: 0,
        fails: 0,
        connects: 0,
        last_report: Instant::now(),
    };
    let interval = Duration::from_secs_f64(args.interval);

    loop {
        r.step();

        let hung = r.fails >= args.fail_limit;
        let done = args.max_ops.is_some_and(|m| r.ok >= m);
        if hung || done {
            return Outcome {
                ok: r.ok,
                rejected: r.rejected,
                connects: r.connects,
                elapsed: r.start.elapsed(),
                hung,
            };
        }
        std::thread::sleep(interval);
    }
}
