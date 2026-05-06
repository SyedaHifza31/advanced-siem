import os
from pathlib import Path
from dotenv import load_dotenv
 
load_dotenv()
 
BASE_DIR = Path(__file__).parent
 
# ─── Database ─────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/data/siem.db")
 
# ─── Server ───────────────────────────────────────────────────────────────────
HOST       = os.getenv("SIEM_HOST", "0.0.0.0")
PORT       = int(os.getenv("SIEM_PORT", 5000))
DEBUG      = os.getenv("SIEM_DEBUG", "false").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY", "siem-secret-key-change-in-production")
 
# ─── Log Sources ──────────────────────────────────────────────────────────────
LOG_SOURCES = {
    "syslog_udp": {
        "enabled":  True,
        "host":     "0.0.0.0",
        "port":     514,
        "protocol": "udp",
    },
    "syslog_tcp": {
        "enabled":  True,
        "host":     "0.0.0.0",
        "port":     1514,
        "protocol": "tcp",
    },
    "file_watcher": {
        "enabled": True,
        "paths": [
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
        ],
    },
    "agent_tcp": {
        "enabled": True,
        "host":    "0.0.0.0",
        "port":    5144,
    },
}
 
# ─── Detection Rules ──────────────────────────────────────────────────────────
RULES_DIR = BASE_DIR / "rules"
 
THREAT_INTEL_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
]
THREAT_INTEL_UPDATE_INTERVAL = 3600  # seconds
 
# ─── Alert Channels ───────────────────────────────────────────────────────────
ALERT_CHANNELS = {
    "email": {
        "enabled":   False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username":  "",
        "password":  "",
        "recipients": [],
    },
    "slack": {
        "enabled":     False,
        "webhook_url": "",
    },
    "webhook": {
        "enabled": False,
        "url":     "",
        "headers": {},
    },
}
 
# ─── Data Retention ───────────────────────────────────────────────────────────
EVENT_RETENTION_DAYS  = 90
ALERT_RETENTION_DAYS  = 365
MAX_EVENTS_IN_MEMORY  = 10_000
 
# ─── Severity Levels ──────────────────────────────────────────────────────────
SEVERITY_LEVELS = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
}
 
# ─── Correlation Settings ─────────────────────────────────────────────────────
CORRELATION_WINDOW     = 300   # seconds
BRUTE_FORCE_THRESHOLD  = 5     # failed attempts
PORT_SCAN_THRESHOLD    = 20    # unique ports within window
