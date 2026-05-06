import os
import random
from datetime import datetime, timedelta
from models.database import init_db, Event, Alert, Asset, ThreatIntel
 
os.makedirs("data", exist_ok=True)
engine, Session = init_db("sqlite:///data/siem.db")
session = Session()
 
print("Seeding SIEM database...")
 
# ─── Helper ───────────────────────────────────────────────────────────────────
def rand_time(hours_back=72):
    return datetime.utcnow() - timedelta(
        hours=random.randint(0, hours_back),
        minutes=random.randint(0, 59)
    )
 
ATTACKER_IPS  = ["185.220.101.45", "45.33.32.156", "103.21.244.0",
                  "194.165.16.11", "92.118.160.5",  "109.70.100.22"]
INTERNAL_IPS  = ["192.168.1.10",   "192.168.1.20",  "192.168.1.50",
                  "10.0.0.5",       "10.0.0.12",     "172.16.0.3"]
HOSTNAMES     = ["web-server-01", "db-server-01", "mail-server",
                  "dev-machine-01", "fileserver", "gateway-01"]
USERNAMES     = ["admin", "root", "ubuntu", "john.doe",
                  "jane.smith", "svc_backup", "guest"]
 
# ─── 1. THREAT INTEL ──────────────────────────────────────────────────────────
threat_data = [
    ("185.220.101.45", "ip",     "c2",       "CRITICAL", 95, "Feodo Tracker"),
    ("45.33.32.156",   "ip",     "scanner",  "HIGH",     88, "AbuseIPDB"),
    ("103.21.244.0",   "ip",     "malware",  "HIGH",     82, "MalwareBazaar"),
    ("194.165.16.11",  "ip",     "phishing", "MEDIUM",   75, "OpenPhish"),
    ("evil-corp.xyz",  "domain", "c2",       "CRITICAL", 90, "VirusTotal"),
    ("malware-cdn.ru", "domain", "malware",  "HIGH",     85, "URLhaus"),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash", "ransomware", "CRITICAL", 99, "MalwareBazaar"),
]
 
for ind, ioc_type, threat_type, severity, confidence, source in threat_data:
    exists = session.query(ThreatIntel).filter_by(indicator=ind).first()
    if not exists:
        session.add(ThreatIntel(
            indicator=ind, ioc_type=ioc_type, threat_type=threat_type,
            severity=severity, confidence=confidence, source=source,
            first_seen=rand_time(720), last_seen=rand_time(24), active=True,
            description=f"{threat_type.title()} indicator from {source}"
        ))
 
session.commit()
print(f"  ✓ {len(threat_data)} threat intel indicators added")
 
# ─── 2. ASSETS ────────────────────────────────────────────────────────────────
assets_data = [
    ("192.168.1.10",  "web-server-01",  "server",      "CRITICAL", "IT Dept",  "ops@company.com"),
    ("192.168.1.20",  "db-server-01",   "server",      "CRITICAL", "IT Dept",  "dba@company.com"),
    ("192.168.1.50",  "mail-server",    "server",      "HIGH",     "IT Dept",  "ops@company.com"),
    ("10.0.0.5",      "dev-machine-01", "workstation", "MEDIUM",   "Dev Team", "john.doe@company.com"),
    ("10.0.0.12",     "hr-laptop-jane", "workstation", "LOW",      "HR Dept",  "jane.smith@company.com"),
    ("172.16.0.3",    "gateway-01",     "network",     "CRITICAL", "NetOps",   "netops@company.com"),
    ("192.168.1.100", "iot-camera-01",  "iot",         "LOW",      "Facilities","fm@company.com"),
]
 
for ip, hostname, atype, crit, dept, owner in assets_data:
    exists = session.query(Asset).filter_by(ip_address=ip).first()
    if not exists:
        session.add(Asset(
            ip_address=ip, hostname=hostname, asset_type=atype,
            criticality=crit, department=dept, owner=owner,
            os_type=random.choice(["Ubuntu 22.04", "Windows Server 2022",
                                    "CentOS 7", "Windows 11"]),
            open_ports=random.sample([22,80,443,3306,5432,8080,3389,25], 3),
            risk_score=round(random.uniform(10, 85), 1),
            alert_count=random.randint(0, 12),
            first_seen=rand_time(720), last_seen=rand_time(2),
            tags=["production"] if crit == "CRITICAL" else ["internal"]
        ))
 
session.commit()
print(f"  ✓ {len(assets_data)} assets added")
 
# ─── 3. EVENTS ────────────────────────────────────────────────────────────────
event_templates = [
    # SSH brute force
    {
        "raw": "Failed password for {user} from {attacker} port {sport} ssh2",
        "category": "auth", "severity": "MEDIUM", "severity_num": 3,
        "source_type": "syslog_tcp", "dest_port": 22, "protocol": "TCP",
        "tags": ["ssh", "failed-login"], "count": 25
    },
    # Successful SSH login
    {
        "raw": "Accepted password for {user} from {internal} port {sport} ssh2",
        "category": "auth", "severity": "LOW", "severity_num": 2,
        "source_type": "syslog_tcp", "dest_port": 22, "protocol": "TCP",
        "tags": ["ssh", "login-success"], "count": 10
    },
    # Sudo usage
    {
        "raw": "sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
        "category": "auth", "severity": "HIGH", "severity_num": 4,
        "source_type": "syslog_tcp", "dest_port": 22, "protocol": "TCP",
        "tags": ["sudo", "privilege-escalation"], "count": 5
    },
    # Nginx 404
    {
        "raw": '{attacker} - - [01/Jan/2024:10:00:00 +0000] "GET /admin HTTP/1.1" 404 512',
        "category": "web", "severity": "LOW", "severity_num": 2,
        "source_type": "file_watcher", "dest_port": 80, "protocol": "HTTP",
        "tags": ["nginx", "http", "404"], "count": 15
    },
    # Nginx 500 error
    {
        "raw": '{internal} - - [01/Jan/2024:12:00:00 +0000] "POST /api/login HTTP/1.1" 500 1024',
        "category": "web", "severity": "HIGH", "severity_num": 4,
        "source_type": "file_watcher", "dest_port": 80, "protocol": "HTTP",
        "tags": ["nginx", "http", "500", "error"], "count": 6
    },
    # Port scan
    {
        "raw": "Connection attempt from {attacker} to port {dport} rejected",
        "category": "network", "severity": "MEDIUM", "severity_num": 3,
        "source_type": "syslog_udp", "dest_port": None, "protocol": "TCP",
        "tags": ["port-scan", "recon"], "count": 20
    },
    # Malware detected
    {
        "raw": "MALWARE DETECTED: Trojan.GenericKD on {hostname} — file: /tmp/.hidden_exe",
        "category": "malware", "severity": "CRITICAL", "severity_num": 5,
        "source_type": "agent_tcp", "dest_port": None, "protocol": None,
        "tags": ["malware", "trojan", "critical"], "count": 3
    },
    # Known threat IP
    {
        "raw": "Inbound connection from known threat IP {attacker} blocked by firewall",
        "category": "network", "severity": "HIGH", "severity_num": 4,
        "source_type": "syslog_udp", "dest_port": 443, "protocol": "TCP",
        "tags": ["threat-ip", "blocked", "firewall"], "count": 8
    },
    # FTP brute force
    {
        "raw": "vsftpd: Failed login attempt for user {user} from {attacker}",
        "category": "auth", "severity": "MEDIUM", "severity_num": 3,
        "source_type": "syslog_tcp", "dest_port": 21, "protocol": "TCP",
        "tags": ["ftp", "failed-login", "brute-force"], "count": 7
    },
    # Firewall block
    {
        "raw": "UFW BLOCK IN on eth0 SRC={attacker} DST={internal} PROTO=TCP DPT={dport}",
        "category": "network", "severity": "LOW", "severity_num": 2,
        "source_type": "syslog_udp", "dest_port": None, "protocol": "TCP",
        "tags": ["firewall", "blocked"], "count": 12
    },
]
 
total_events = 0
for tmpl in event_templates:
    for _ in range(tmpl["count"]):
        attacker = random.choice(ATTACKER_IPS)
        internal = random.choice(INTERNAL_IPS)
        hostname  = random.choice(HOSTNAMES)
        user      = random.choice(USERNAMES)
        sport     = random.randint(1024, 65535)
        dport     = tmpl["dest_port"] or random.randint(1, 1024)
        is_threat = attacker in ATTACKER_IPS
 
        raw = tmpl["raw"].format(
            attacker=attacker, internal=internal,
            hostname=hostname, user=user,
            sport=sport, dport=dport
        )
 
        session.add(Event(
            timestamp=rand_time(72),
            source_ip=attacker if random.random() > 0.3 else internal,
            dest_ip=internal,
            source_port=sport,
            dest_port=dport,
            protocol=tmpl["protocol"],
            source_type=tmpl["source_type"],
            category=tmpl["category"],
            severity=tmpl["severity"],
            severity_num=tmpl["severity_num"],
            raw_message=raw,
            hostname=hostname,
            username=user if tmpl["category"] == "auth" else None,
            is_threat_ip=is_threat,
            tags=tmpl["tags"],
            geo_country=random.choice(["Russia", "China", "Netherlands",
                                        "Germany", "United States", "Pakistan"]),
            geo_city=random.choice(["Moscow", "Beijing", "Amsterdam",
                                     "Frankfurt", "New York", "Karachi"]),
            parsed_data={"auto_seeded": True}
        ))
        total_events += 1
 
session.commit()
print(f"  ✓ {total_events} events added")
 
# ─── 4. ALERTS ────────────────────────────────────────────────────────────────
alerts_data = [
    {
        "title": "SSH Brute Force Detected — 185.220.101.45",
        "description": "25 failed SSH login attempts in 5 minutes from known C2 IP 185.220.101.45. Attacker targeted root, admin, ubuntu accounts.",
        "severity": "CRITICAL", "severity_num": 5,
        "rule_id": "BF-001", "rule_name": "SSH Brute Force",
        "category": "auth", "source_ip": "185.220.101.45",
        "dest_ip": "192.168.1.10", "hostname": "web-server-01",
        "username": "root", "status": "OPEN", "event_count": 25,
        "mitre_tactic": "Credential Access", "mitre_tech": "T1110",
        "tags": ["brute-force", "ssh", "critical"],
        "ioc_list": ["185.220.101.45"],
    },
    {
        "title": "Malware Detected on dev-machine-01",
        "description": "Trojan.GenericKD found in /tmp/.hidden_exe — possible post-exploitation activity.",
        "severity": "CRITICAL", "severity_num": 5,
        "rule_id": "MW-001", "rule_name": "Malware Detection",
        "category": "malware", "source_ip": "10.0.0.5",
        "hostname": "dev-machine-01", "username": "john.doe",
        "status": "OPEN", "event_count": 3,
        "mitre_tactic": "Execution", "mitre_tech": "T1204",
        "tags": ["malware", "trojan"],
        "ioc_list": ["d41d8cd98f00b204e9800998ecf8427e"],
    },
    {
        "title": "Port Scan from 45.33.32.156",
        "description": "20 unique ports scanned from known scanner IP in under 2 minutes.",
        "severity": "HIGH", "severity_num": 4,
        "rule_id": "PS-001", "rule_name": "Port Scan Detection",
        "category": "network", "source_ip": "45.33.32.156",
        "dest_ip": "192.168.1.10", "status": "OPEN", "event_count": 20,
        "mitre_tactic": "Discovery", "mitre_tech": "T1046",
        "tags": ["port-scan", "recon"], "ioc_list": ["45.33.32.156"],
    },
    {
        "title": "Privilege Escalation via sudo — john.doe",
        "description": "User john.doe ran sudo /bin/bash — full root shell obtained on dev-machine-01.",
        "severity": "HIGH", "severity_num": 4,
        "rule_id": "PE-001", "rule_name": "Sudo Privilege Escalation",
        "category": "auth", "source_ip": "10.0.0.5",
        "hostname": "dev-machine-01", "username": "john.doe",
        "status": "ACK", "event_count": 1,
        "mitre_tactic": "Privilege Escalation", "mitre_tech": "T1548",
        "analyst_notes": "Confirmed with john.doe — authorized maintenance task.",
        "tags": ["sudo", "priv-esc"], "ioc_list": [],
    },
    {
        "title": "Known Threat IP Contact — 185.220.101.45",
        "description": "Internal host 192.168.1.10 received inbound connection from Feodo C2 IP.",
        "severity": "HIGH", "severity_num": 4,
        "rule_id": "TI-001", "rule_name": "Threat Intel Match",
        "category": "network", "source_ip": "185.220.101.45",
        "dest_ip": "192.168.1.10", "hostname": "web-server-01",
        "status": "OPEN", "event_count": 8,
        "mitre_tactic": "Command and Control", "mitre_tech": "T1071",
        "tags": ["threat-intel", "c2"], "ioc_list": ["185.220.101.45"],
    },
    {
        "title": "Multiple Web 500 Errors — Possible Attack",
        "description": "6 HTTP 500 errors on /api/login within 10 minutes — possible SQL injection or API abuse.",
        "severity": "MEDIUM", "severity_num": 3,
        "rule_id": "WEB-001", "rule_name": "Web Error Spike",
        "category": "web", "source_ip": "192.168.1.20",
        "dest_ip": "192.168.1.10", "hostname": "web-server-01",
        "status": "OPEN", "event_count": 6,
        "mitre_tactic": "Initial Access", "mitre_tech": "T1190",
        "tags": ["web", "500-error"], "ioc_list": [],
    },
    {
        "title": "FTP Brute Force Attempt",
        "description": "7 failed FTP login attempts from 103.21.244.0.",
        "severity": "MEDIUM", "severity_num": 3,
        "rule_id": "BF-002", "rule_name": "FTP Brute Force",
        "category": "auth", "source_ip": "103.21.244.0",
        "hostname": "fileserver", "status": "CLOSED",
        "event_count": 7, "false_positive": False,
        "mitre_tactic": "Credential Access", "mitre_tech": "T1110",
        "tags": ["ftp", "brute-force"], "ioc_list": ["103.21.244.0"],
    },
    {
        "title": "Admin Login from Unusual Country",
        "description": "User admin logged in successfully from Netherlands IP — first time from this country.",
        "severity": "LOW", "severity_num": 2,
        "rule_id": "GEO-001", "rule_name": "Geo Anomaly",
        "category": "auth", "source_ip": "194.165.16.11",
        "hostname": "web-server-01", "username": "admin",
        "status": "FP", "event_count": 1,
        "analyst_notes": "Employee confirmed — travelling for conference.",
        "false_positive": True,
        "mitre_tactic": "Initial Access", "mitre_tech": "T1078",
        "tags": ["geo-anomaly", "false-positive"], "ioc_list": [],
    },
]
 
for a in alerts_data:
    alert = Alert(
        timestamp=rand_time(48),
        title=a["title"],
        description=a["description"],
        severity=a["severity"],
        severity_num=a["severity_num"],
        rule_id=a.get("rule_id"),
        rule_name=a.get("rule_name"),
        category=a.get("category"),
        source_ip=a.get("source_ip"),
        dest_ip=a.get("dest_ip"),
        hostname=a.get("hostname"),
        username=a.get("username"),
        status=a["status"],
        event_count=a.get("event_count", 1),
        mitre_tactic=a.get("mitre_tactic"),
        mitre_tech=a.get("mitre_tech"),
        analyst_notes=a.get("analyst_notes"),
        false_positive=a.get("false_positive", False),
        ioc_list=a.get("ioc_list", []),
        tags=a.get("tags", []),
        notified=True,
    )
    session.add(alert)
 
session.commit()
print(f"  ✓ {len(alerts_data)} alerts added")
 
# ─── Summary ──────────────────────────────────────────────────────────────────
from models.database import Event as E, Alert as A, Asset as As, ThreatIntel as TI
print("\n─────────────────────────────────")
print("  DATABASE SUMMARY")
print("─────────────────────────────────")
print(f"  Events      : {session.query(E).count()}")
print(f"  Alerts      : {session.query(A).count()}")
print(f"    OPEN      : {session.query(A).filter_by(status='OPEN').count()}")
print(f"    CRITICAL  : {session.query(A).filter_by(severity='CRITICAL').count()}")
print(f"  Assets      : {session.query(As).count()}")
print(f"  Threat IPs  : {session.query(TI).count()}")
print("─────────────────────────────────")
print("  ✓ Done! Ab 'python main.py' chalao")
print("  ✓ Dashboard: http://localhost:5000")
print("─────────────────────────────────")
session.close()