"""Минимальный эмулятор Tuya-устройства (3.3/3.4/3.5) на примитивах tinytuya,
для проверки Rust-клиента.
Аргументы: версия, порт, [после скольких команд "зависнуть"], [отклонять каждую N-ю команду]"""
import hmac, json, os, socket, struct, sys, threading
from hashlib import sha256
from tinytuya.core.message_helper import pack_message, unpack_message, parse_header, TuyaMessage
from tinytuya.core.crypto_helper import AESCipher
from tinytuya.core import header as H

VER = float(sys.argv[1]); PORT = int(sys.argv[2]); HANG_AFTER = int(sys.argv[3]) if len(sys.argv) > 3 else 10**9
REJECT_EVERY = int(sys.argv[4]) if len(sys.argv) > 4 else 0
KEY = b"0123456789abcdef"
VB = str(VER).encode(); VH = VB + b"\x00" * 12
state = {"114": 5, "101": True}
cmd_count = 0

def handle(sock):
    global cmd_count
    key = KEY; seq = 100; buf = b""; local_nonce = remote_nonce = None
    def send(cmd, payload, use_key, add_header=False, retcode=0):
        nonlocal seq
        seq += 1
        if VER == 3.5:
            plain = (VH if add_header else b"") + payload
            data = pack_message(TuyaMessage(seq, cmd, retcode, plain, 0, True, H.PREFIX_6699_VALUE, True), hmac_key=use_key)
        elif VER == 3.4:
            plain = (VH if add_header else b"") + payload
            enc = AESCipher(use_key).encrypt(plain, False) if plain else b""
            data = pack_message(TuyaMessage(seq, cmd, 0, struct.pack(">I", retcode) + enc, 0, True, H.PREFIX_55AA_VALUE, False), hmac_key=use_key)
        else:
            enc = AESCipher(use_key).encrypt(payload, False) if payload else b""
            body = struct.pack(">I", retcode) + ((VH + enc) if add_header else enc)
            data = pack_message(TuyaMessage(seq, cmd, 0, body, 0, True, H.PREFIX_55AA_VALUE, False))
        sock.sendall(data)
    while True:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return
        if not chunk:
            return
        buf += chunk
        while True:
            try:
                hdr = parse_header(buf)
            except Exception:
                break
            if len(buf) < hdr.total_length:
                break
            raw, buf = buf[:hdr.total_length], buf[hdr.total_length:]
            m = unpack_message(raw, hmac_key=(key if VER >= 3.4 else None), header=hdr, no_retcode=True)
            assert m.crc_good, "клиент прислал пакет с неверной CRC/HMAC/тегом"
            p = m.payload
            if VER == 3.3:
                if p.startswith(VB): p = p[15:]
                p = AESCipher(key).decrypt(p, False, decode_text=False) if p else b""
            elif VER == 3.4:
                p = AESCipher(key).decrypt(p, False, decode_text=False) if p else b""
                if p.startswith(VB): p = p[15:]
            else:
                if p.startswith(VB): p = p[15:]
            if m.cmd == 3:
                local_nonce = p; remote_nonce = os.urandom(16)
                send(4, remote_nonce + hmac.new(KEY, local_nonce, sha256).digest(), KEY)
                continue
            if m.cmd == 5:
                assert p == hmac.new(KEY, remote_nonce, sha256).digest(), "неверный HMAC в шаге 3"
                x = bytes(a ^ b for a, b in zip(local_nonce, remote_nonce))
                c = AESCipher(KEY)
                key = c.encrypt(x, False, pad=False) if VER == 3.4 else c.encrypt(x, use_base64=False, pad=False, iv=local_nonce[:12])[12:28]
                continue
            cmd_count += 1
            if cmd_count > HANG_AFTER:
                continue  # "завис": молчим
            js = json.loads(p.decode())
            if m.cmd in (7, 13) and REJECT_EVERY and cmd_count % REJECT_EVERY == 0:
                send(m.cmd, b"data format error", key, retcode=1)
            elif m.cmd in (7, 13):
                dps = js["dps"] if m.cmd == 7 else js["data"]["dps"]
                state.update(dps)
                if cmd_count % 3 == 0:
                    # посторонний отчёт, как периодические отчёты реальных устройств
                    send(8, json.dumps({"dps": {"101": True}, "t": 1}).encode(), key, add_header=True)
                if cmd_count % 5 == 0:
                    # отчёт раньше подтверждения
                    send(8, json.dumps({"dps": dps, "t": 1}).encode(), key, add_header=True)
                    send(m.cmd, b"", key)
                else:
                    send(m.cmd, b"", key)
                    send(8, json.dumps({"dps": dps, "t": 1}).encode(), key, add_header=True)
            elif m.cmd in (10, 16):
                send(m.cmd, json.dumps({"dps": state}).encode(), key)
            print(f"cmd={m.cmd} payload={js}", flush=True)

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT)); srv.listen()
while True:
    s, _ = srv.accept()
    threading.Thread(target=handle, args=(s,), daemon=True).start()
