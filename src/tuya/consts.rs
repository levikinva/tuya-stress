//! Константы протокола. Номера команд соответствуют `lan_protocol.h` из
//! Tuya SDK (и `command_types.py` в tinytuya).

pub const PREFIX_55AA: u32 = 0x0000_55AA;
pub const SUFFIX_55AA: u32 = 0x0000_AA55;
pub const PREFIX_6699: u32 = 0x0000_6699;
pub const SUFFIX_6699: u32 = 0x0000_9966;

/// Порт локального протокола по умолчанию
pub const DEFAULT_PORT: u16 = 6668;

/// Максимальный размер полезной нагрузки, больше которого пакет считается повреждённым
pub const MAX_PAYLOAD: usize = 64 * 1024;

pub mod cmd {
    pub const SESS_KEY_NEG_START: u32 = 3;
    pub const SESS_KEY_NEG_RESP: u32 = 4;
    pub const SESS_KEY_NEG_FINISH: u32 = 5;
    pub const CONTROL: u32 = 7;
    pub const STATUS: u32 = 8;
    pub const HEART_BEAT: u32 = 9;
    pub const DP_QUERY: u32 = 10;
    pub const CONTROL_NEW: u32 = 13;
    pub const DP_QUERY_NEW: u32 = 16;
    pub const UPDATEDPS: u32 = 18;
    pub const LAN_EXT_STREAM: u32 = 64;
}

/// Команды, к которым не добавляется заголовок версии протокола
pub const NO_HEADER_CMDS: [u32; 8] = [
    cmd::DP_QUERY,
    cmd::DP_QUERY_NEW,
    cmd::UPDATEDPS,
    cmd::HEART_BEAT,
    cmd::SESS_KEY_NEG_START,
    cmd::SESS_KEY_NEG_RESP,
    cmd::SESS_KEY_NEG_FINISH,
    cmd::LAN_EXT_STREAM,
];

pub fn needs_version_header(cmd: u32) -> bool {
    !NO_HEADER_CMDS.contains(&cmd)
}
