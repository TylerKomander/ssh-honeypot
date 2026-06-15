import json
import os
import socket
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paramiko

HOST = os.environ.get("HONEYPOT_HOST", "0.0.0.0")
PORT = int(os.environ.get("HONEYPOT_PORT", "2222"))
BANNER = os.environ.get("HONEYPOT_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")
ACCEPT_TIMEOUT = 15

BASE = Path(__file__).resolve().parent
LOG_DIR = Path(os.environ.get("HONEYPOT_LOG_DIR", BASE / "logs"))
LOG_FILE = LOG_DIR / "honeypot.jsonl"
HOST_KEY_FILE = Path(os.environ.get("HONEYPOT_HOST_KEY", BASE / "host.key"))

_log_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat()


def log_event(event):
    line = json.dumps(event, separators=(",", ":"))
    with _log_lock:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line, flush=True)


def load_host_key():
    if HOST_KEY_FILE.exists():
        return paramiko.RSAKey(filename=str(HOST_KEY_FILE))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_FILE))
    return key


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, session_id, src_ip, src_port):
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        log_event({
            "event": "auth_attempt",
            "timestamp": now(),
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "method": "password",
            "username": username,
            "password": password,
        })
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log_event({
            "event": "auth_attempt",
            "timestamp": now(),
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "method": "publickey",
            "username": username,
            "key_type": key.get_name(),
            "key_fingerprint": key.get_fingerprint().hex(),
        })
        return paramiko.AUTH_FAILED


def handle_connection(client, addr, host_key):
    src_ip, src_port = addr
    session_id = uuid.uuid4().hex[:12]
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        transport.start_server(server=HoneypotServer(session_id, src_ip, src_port))
        log_event({
            "event": "connection",
            "timestamp": now(),
            "session_id": session_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "client_banner": transport.remote_version,
        })
        transport.accept(timeout=ACCEPT_TIMEOUT)
    except (paramiko.SSHException, EOFError, ConnectionResetError, OSError) as exc:
        log_event({
            "event": "error",
            "timestamp": now(),
            "session_id": session_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "detail": type(exc).__name__,
        })
    finally:
        if transport is not None:
            transport.close()
        try:
            client.close()
        except OSError:
            pass


def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    host_key = load_host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)
    log_event({"event": "listener_start", "timestamp": now(), "host": HOST, "port": PORT})
    try:
        while True:
            client, addr = sock.accept()
            threading.Thread(
                target=handle_connection,
                args=(client, addr, host_key),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        log_event({"event": "listener_stop", "timestamp": now()})
    finally:
        sock.close()


if __name__ == "__main__":
    main()
