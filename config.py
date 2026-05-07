"""
Advanced SIEM System — config.py
Deploy-safe: $PORT env variable support
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent

# ─── Database ─────────────────────────────────────────────────────────────────
# Railway/Render pe /app/data ya local mein data/
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/data/siem.db")

# ─── Server ───────────────────────────────────────────────────────────────────
HOST       = os.getenv("SIEM_HOST", "0.0.0.0")
PORT       = int(os.getenv("PORT", os.getenv("SIEM_PORT", 5000)))  # Railway $PORT support
DEBUG      = os.getenv("SIEM_DEBUG", "false").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production-please")

# ─── Log Sources ──────────────────────────────────────────────────────────────
LOG_SOURCES = {
    "syslog_udp":   {"enabled": False, "host": "0.0.0.0", "port": 514},
    "syslog_tcp":   {"enabled": False, "host": "0.0.0.0", "port": 1514},
    "file_watcher": {"enabled": False, "paths": ["/var/log/auth.log"]},
    "agent_tcp":    {"enabled": True,  "host": "0.0.0.0", "port": 5144},
}

# ─── Threat Intel ─────────────────────────────────────────────────────────────
RULES_DIR = BASE_DIR / "rules"
THREAT_INTEL_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
]
THREAT_INTEL_UPDATE_INTERVAL = 3600

# ─── Alert Channels ───────────────────────────────────────────────────────────
ALERT_CHANNELS = {
    "email": {
        "enabled":   os.getenv("EMAIL_ENABLED", "false").lower() == "true",
        "smtp_host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": int(os.getenv("SMTP_PORT", 587)),
        "username":  os.getenv("SMTP_USER", ""),
        "password":  os.getenv("SMTP_PASS", ""),
        "recipients": os.getenv("ALERT_RECIPIENTS", "").split(",") if os.getenv("ALERT_RECIPIENTS") else [],
    },
    "slack": {
        "enabled":     os.getenv("SLACK_ENABLED", "false").lower() == "true",
        "webhook_url": os.getenv("SLACK_WEBHOOK", ""),
    },
}

# ─── Detection Thresholds ─────────────────────────────────────────────────────
CORRELATION_WINDOW    = int(os.getenv("CORRELATION_WINDOW", 300))
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", 5))
PORT_SCAN_THRESHOLD   = int(os.getenv("PORT_SCAN_THRESHOLD", 20))

# ─── Retention ────────────────────────────────────────────────────────────────
EVENT_RETENTION_DAYS = 90
ALERT_RETENTION_DAYS = 365

SEVERITY_LEVELS = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
}