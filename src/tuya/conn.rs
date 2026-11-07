//! TCP-соединение с устройством.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use super::consts::{DEFAULT_PORT, cmd};
use super::crypto::{self, Key};
use super::error::{Error, Result};
use super::frame::{self, Frame};
use super::session;
use super::version::Version;

/// Параметры подключения к устройству
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub id: String,
    pub addr: SocketAddr,
    pub local_key: Key,
    pub version: Version,
    /// Таймаут подключения и ожидания каждого чтения
    pub timeout: Duration,
}

impl DeviceConfig {
    pub fn new(id: &str, host: &str, port: Option<u16>, local_key: &str, version: Version) -> Result<Self> {
        let local_key: Key = local_key
            .as_bytes()
            .try_into()
            .map_err(|_| Error::Config(format!("local key должен быть ровно 16 символов, сейчас {}", local_key.len())))?;
        let addr = (host, port.unwrap_or(DEFAULT_PORT))
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .ok_or_else(|| Error::Config(format!("не удалось разобрать адрес {host}")))?;
        Ok(DeviceConfig {
            id: id.to_string(),
            addr,
            local_key,
            version,
            timeout: Duration::from_secs(5),
        })
    }
}

/// Открытое соединение (для 3.4/3.5 — с уже согласованным сеансовым ключом)
pub struct Connection {
    cfg: DeviceConfig,
    stream: TcpStream,
    /// Текущий ключ шифрования: local key или сеансовый
    key: Key,
    seqno: u32,
    rx: Vec<u8>,
    /// Пакеты, которые пришли, но пока никому не понадобились (например,
    /// отчёт о состоянии, пришедший раньше подтверждения команды)
    backlog: VecDeque<Frame>,
}

/// Сколько всего ждать нужного ответа, пропуская посторонние пакеты
const REPLY_DEADLINE: Duration = Duration::from_secs(10);

/// Сколько непрочитанных пакетов хранить
const BACKLOG_LIMIT: usize = 64;

impl Connection {
    pub fn open(cfg: &DeviceConfig) -> Result<Self> {
        let stream = TcpStream::connect_timeout(&cfg.addr, cfg.timeout)?;
        stream.set_read_timeout(Some(cfg.timeout))?;
        stream.set_write_timeout(Some(cfg.timeout))?;
        stream.set_nodelay(true)?;

        let mut conn = Connection {
            cfg: cfg.clone(),
            stream,
            key: cfg.local_key,
            seqno: 1,
            rx: Vec::new(),
            backlog: VecDeque::new(),
        };
        if cfg.version.uses_session_key() {
            conn.negotiate()?;
        }
        Ok(conn)
    }

    pub fn version(&self) -> Version {
        self.cfg.version
    }

    fn negotiate(&mut self) -> Result<()> {
        let local_key = self.cfg.local_key;
        self.key = local_key;
        let local_nonce = crypto::random_bytes::<16>();

        self.send(cmd::SESS_KEY_NEG_START, &local_nonce)?;
        let resp = self
            .recv_until(|f| f.cmd == cmd::SESS_KEY_NEG_RESP)
            .map_err(|e| Error::Negotiation(format!("нет ответа на шаге 2: {e}")))?;
        let remote_nonce = session::verify_response(&local_key, &local_nonce, &resp.payload)?;
        self.send(cmd::SESS_KEY_NEG_FINISH, &session::finish_payload(&local_key, &remote_nonce))?;

        self.key = session::derive_key(self.cfg.version, &local_key, &local_nonce, &remote_nonce);
        Ok(())
    }

    /// Отправляет одну команду
    pub fn send(&mut self, cmd: u32, payload: &[u8]) -> Result<()> {
        let data = frame::encode(self.cfg.version, &self.key, self.seqno, cmd, payload, None);
        self.seqno = self.seqno.wrapping_add(1);
        self.stream.write_all(&data)?;
        Ok(())
    }

    /// Читает один пакет от устройства
    pub fn recv(&mut self) -> Result<Frame> {
        let mut tmp = [0u8; 4096];
        loop {
            if let Some(f) = frame::decode(self.cfg.version, &self.key, &mut self.rx, true)? {
                return Ok(f);
            }
            match self.stream.read(&mut tmp)? {
                0 => return Err(Error::Closed),
                n => self.rx.extend_from_slice(&tmp[..n]),
            }
        }
    }

    /// Возвращает первый подходящий пакет: сначала ищет среди уже
    /// полученных, затем читает новые. Неподходящие пакеты откладываются
    /// в очередь, их можно забрать через [`Connection::take_unclaimed`].
    pub fn recv_until(&mut self, pred: impl Fn(&Frame) -> bool) -> Result<Frame> {
        if let Some(i) = self.backlog.iter().position(&pred) {
            return Ok(self.backlog.remove(i).unwrap());
        }
        let deadline = Instant::now() + REPLY_DEADLINE;
        while Instant::now() < deadline {
            let f = self.recv()?;
            if pred(&f) {
                return Ok(f);
            }
            if self.backlog.len() >= BACKLOG_LIMIT {
                self.backlog.pop_front();
            }
            self.backlog.push_back(f);
        }
        Err(Error::Timeout)
    }

    /// Забирает пакеты, которые пришли, но не были ответом ни на одну
    /// команду: обычно это отчёты, которые устройство шлёт само
    pub fn take_unclaimed(&mut self) -> Vec<Frame> {
        self.backlog.drain(..).collect()
    }

    /// Устанавливает значение одного dp и ждёт подтверждения
    pub fn set_dp(&mut self, dp: u32, value: &Value) -> Result<()> {
        let dps = json!({ dp.to_string(): value });
        let (command, body) = match self.cfg.version {
            Version::V33 => (
                cmd::CONTROL,
                json!({"devId": self.cfg.id, "uid": self.cfg.id, "t": unix_time().to_string(), "dps": dps}),
            ),
            _ => (cmd::CONTROL_NEW, json!({"protocol": 5, "t": unix_time(), "data": {"dps": dps}})),
        };
        self.send(command, body.to_string().as_bytes())?;
        let reply = self.recv_until(|f| f.cmd == command)?;
        check_retcode(&reply)
    }

    /// Запрашивает состояние всех dp; возвращает JSON-ответ устройства
    pub fn query(&mut self) -> Result<String> {
        let (command, body) = match self.cfg.version {
            Version::V33 => (
                cmd::DP_QUERY,
                json!({"gwId": self.cfg.id, "devId": self.cfg.id, "uid": self.cfg.id, "t": unix_time().to_string()})
                    .to_string(),
            ),
            _ => (cmd::DP_QUERY_NEW, "{}".to_string()),
        };
        self.send(command, body.as_bytes())?;
        let reply = self.recv_until(|f| f.cmd == command || (f.cmd == cmd::STATUS && !f.payload.is_empty()))?;
        check_retcode(&reply)?;
        Ok(reply.payload_str())
    }

    /// Ждёт от устройства отчёта о состоянии (STATUS), в котором у `dp`
    /// значение `value`, то есть подтверждения, что команда выполнена;
    /// возвращает содержимое отчёта. Отчёты о других dp откладываются.
    pub fn wait_status(&mut self, dp: u32, value: &Value) -> Result<String> {
        let key = dp.to_string();
        let f = self.recv_until(|f| f.cmd == cmd::STATUS && status_value(&f.payload, &key) == Some(value.clone()))?;
        Ok(f.payload_str())
    }

    /// Отправляет heartbeat и ждёт ответа
    pub fn heartbeat(&mut self) -> Result<()> {
        let body = json!({"gwId": self.cfg.id, "devId": self.cfg.id}).to_string();
        self.send(cmd::HEART_BEAT, body.as_bytes())?;
        self.recv_until(|f| f.cmd == cmd::HEART_BEAT).map(|_| ())
    }
}

/// Достаёт значение dp из отчёта о состоянии: `{"dps":{"114":5},...}`
/// (у 3.4/3.5 бывает обёрнуто в `{"data":{"dps":...}}`)
fn status_value(payload: &[u8], dp: &str) -> Option<Value> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    let dps = v.get("dps").or_else(|| v.get("data").and_then(|d| d.get("dps")))?;
    dps.get(dp).cloned()
}

fn check_retcode(f: &Frame) -> Result<()> {
    match f.retcode {
        Some(code) if code != 0 => Err(Error::Device { code, message: f.payload_str() }),
        _ => Ok(()),
    }
}

fn unix_time() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_value_extracts_dp() {
        assert_eq!(status_value(br#"{"dps":{"114":5},"t":1}"#, "114"), Some(json!(5)));
        assert_eq!(status_value(br#"{"data":{"dps":{"101":true}}}"#, "101"), Some(json!(true)));
        assert_eq!(status_value(br#"{"dps":{"101":true}}"#, "114"), None);
        assert_eq!(status_value(b"garbage", "114"), None);
    }
}
