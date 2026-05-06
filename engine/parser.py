import re
from datetime import datetime
 
 
# ─── Regex Patterns ───────────────────────────────────────────────────────────
_SSH_FAIL    = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
_SSH_ACCEPT  = re.compile(r"Accepted password for (\S+) from ([\d.]+) port (\d+)")
_SUDO        = re.compile(r"sudo:\s+(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.+)")
_NGINX       = re.compile(
    r'([\d.]+) - \S+ \[.+\] "(\w+) (\S+) HTTP/[\d.]+" (\d{3}) (\d+)'
)
 
 
def
    result = {
        "raw_message": raw_message,
        "source_type": source_type,
        "category":    "unknown",
        "severity":    "INFO",
        "severity_num": 1,
        "parsed_data": {},
        "tags":        [],
        "timestamp":   datetime.utcnow(),
    }
 
    msg = raw_message.lower()
 
    # ── SSH Failed login ──────────────────────────────────────────────────────
    m = _SSH_FAIL.search(raw_message)
    if m:
        result.update({
            "category":    "auth",
            "severity":    "MEDIUM",
            "severity_num": 3,
            "username":    m.group(1),
            "source_ip":   m.group(2),
            "source_port": int(m.group(3)),
            "tags":        ["ssh", "failed-login"],
            "parsed_data": {"event": "ssh_fail", "user": m.group(1)},
        })
        return result
 
    # ── SSH Accepted login ────────────────────────────────────────────────────
    m = _SSH_ACCEPT.search(raw_message)
    if m:
        result.update({
            "category":    "auth",
            "severity":    "LOW",
            "severity_num": 2,
            "username":    m.group(1),
            "source_ip":   m.group(2),
            "source_port": int(m.group(3)),
            "tags":        ["ssh", "login-success"],
            "parsed_data": {"event": "ssh_accept", "user": m.group(1)},
        })
        return result
 
    # ── Sudo command ──────────────────────────────────────────────────────────
    m = _SUDO.search(raw_message)
    if m:
        result.update({
            "category":    "auth",
            "severity":    "MEDIUM",
            "severity_num": 3,
            "username":    m.group(1),
            "tags":        ["sudo", "privilege-escalation"],
            "parsed_data": {
                "event":   "sudo",
                "user":    m.group(1),
                "run_as":  m.group(2),
                "command": m.group(3).strip(),
            },
        })
        return result
 
    # ── Nginx access log ──────────────────────────────────────────────────────
    m = _NGINX.search(raw_message)
    if m:
        status_code = int(m.group(4))
        severity    = "LOW"
        if status_code >= 500:
            severity = "HIGH"
        elif status_code >= 400:
            severity = "MEDIUM"
        result.update({
            "category":    "web",
            "severity":    severity,
            "severity_num": {"LOW": 2, "MEDIUM": 3, "HIGH": 4}.get(severity, 1),
            "source_ip":   m.group(1),
            "dest_port":   80,
            "tags":        ["nginx", "http"],
            "parsed_data": {
                "method":  m.group(2),
                "path":    m.group(3),
                "status":  status_code,
                "bytes":   int(m.group(5)),
            },
        })
        return result
 
    # ── Malware keywords ──────────────────────────────────────────────────────
    if any(kw in msg for kw in ["malware", "trojan", "ransomware", "virus"]):
        result.update({
            "category":    "malware",
            "severity":    "CRITICAL",
            "severity_num": 5,
            "tags":        ["malware"],
        })
        return result
 
    return result
 
