"""
Engine - Log Ingestion
Syslog UDP/TCP aur file watcher se logs collect karta hai.
Har log parse karke DB mein save karta hai.
"""
 
import socket
import threading
from datetime import datetime
from models.database import Event
from extensions import get_session
from engine.parser import parse_raw
from engine.correlator import correlator
import config
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Shared: event save karo + correlator chalao
# ─────────────────────────────────────────────────────────────────────────────
def _save_event(raw_message: str, source_type: str = "syslog"):
    parsed = parse_raw(raw_message, source_type)
    session = get_session()
    try:
        event = Event(
            timestamp    = parsed.get("timestamp", datetime.utcnow()),
            source_ip    = parsed.get("source_ip"),
            dest_ip      = parsed.get("dest_ip"),
            source_port  = parsed.get("source_port"),
            dest_port    = parsed.get("dest_port"),
            source_type  = parsed.get("source_type", source_type),
            category     = parsed.get("category", "unknown"),
            severity     = parsed.get("severity", "INFO"),
            severity_num = parsed.get("severity_num", 1),
            raw_message  = raw_message,
            parsed_data  = parsed.get("parsed_data", {}),
            hostname     = parsed.get("hostname"),
            username     = parsed.get("username"),
            tags         = parsed.get("tags", []),
        )
        session.add(event)
        session.commit()
        # Correlation engine ko bheju
        correlator.process_event(event)
    except Exception as ex:
        session.rollback()
        print(f"[INGEST ERROR] {ex}")
    finally:
        session.close()
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Syslog UDP Listener
# ─────────────────────────────────────────────────────────────────────────────
def start_syslog_udp():
    cfg  = config.LOG_SOURCES.get("syslog_udp", {})
    if not cfg.get("enabled"):
        return
 
    host = cfg.get("host", "0.0.0.0")
    port = cfg.get("port", 514)
 
    def _listen():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((host, port))
            print(f"[SYSLOG UDP] Listening on {host}:{port}")
            while True:
                data, addr = sock.recvfrom(4096)
                msg = data.decode("utf-8", errors="ignore").strip()
                if msg:
                    _save_event(msg, source_type="syslog_udp")
        except PermissionError:
            print(f"[WARN] UDP port {port} needs root. Skipping syslog_udp.")
        finally:
            sock.close()
 
    t = threading.Thread(target=_listen, daemon=True, name="syslog-udp")
    t.start()
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Syslog TCP Listener
# ─────────────────────────────────────────────────────────────────────────────
def start_syslog_tcp():
    cfg = config.LOG_SOURCES.get("syslog_tcp", {})
    if not cfg.get("enabled"):
        return
 
    host = cfg.get("host", "0.0.0.0")
    port = cfg.get("port", 1514)
 
    def _handle_client(conn, addr):
        with conn:
            buf = b""
            while True:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    msg = line.decode("utf-8", errors="ignore").strip()
                    if msg:
                        _save_event(msg, source_type="syslog_tcp")
 
    def _listen():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((host, port))
            srv.listen(10)
            print(f"[SYSLOG TCP] Listening on {host}:{port}")
            while True:
                conn, addr = srv.accept()
                ct = threading.Thread(
                    target=_handle_client, args=(conn, addr), daemon=True
                )
                ct.start()
        except PermissionError:
            print(f"[WARN] TCP port {port} needs root. Skipping syslog_tcp.")
        finally:
            srv.close()
 
    t = threading.Thread(target=_listen, daemon=True, name="syslog-tcp")
    t.start()
 
 
# ─────────────────────────────────────────────────────────────────────────────
# File Watcher
# ─────────────────────────────────────────────────────────────────────────────
def start_file_watcher():
    cfg = config.LOG_SOURCES.get("file_watcher", {})
    if not cfg.get("enabled"):
        return
 
    paths = cfg.get("paths", [])
 
    def _tail(path: str):
        import os
        import time
        if not os.path.exists(path):
            print(f"[WARN] Log file not found: {path}")
            return
        with open(path, "r", errors="ignore") as f:
            f.seek(0, 2)   # dosra end tak jump
            print(f"[FILE WATCHER] Watching: {path}")
            while True:
                line = f.readline()
                if line:
                    _save_event(line.strip(), source_type="file_watcher")
                else:
                    time.sleep(0.5)
 
    for path in paths:
        t = threading.Thread(target=_tail, args=(path,), daemon=True,
                             name=f"watcher-{path.split('/')[-1]}")
        t.start()
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Start All Ingestion Sources
# ─────────────────────────────────────────────────────────────────────────────
def start_all():
    start_syslog_udp()
    start_syslog_tcp()
    start_file_watcher()
    print("[INGEST] All log sources started.")