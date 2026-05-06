from collections import defaultdict
from datetime import datetime, timedelta
from models.database import Alert, Event
from extensions import get_session
import config
 
 
class Correlator:
    def __init__(self):
        # In-memory counters: {source_ip: [timestamps]}
        self._fail_tracker: dict[str, list] = defaultdict(list)
        self._port_tracker: dict[str, set]  = defaultdict(set)
 
    def _clean_old(self, ip: str, window: int):
        cutoff = datetime.utcnow() - timedelta(seconds=window)
        self._fail_tracker[ip] = [
            t for t in self._fail_tracker[ip] if t > cutoff
        ]
 
    def process_event(self, event: Event):
        if not event.source_ip:
            return
 
        ip = event.source_ip
 
        # ── Brute Force Detection ─────────────────────────────────────────────
        if event.category == "auth" and "failed-login" in (event.tags or []):
            self._clean_old(ip, config.CORRELATION_WINDOW)
            self._fail_tracker[ip].append(datetime.utcnow())
 
            if len(self._fail_tracker[ip]) >= config.BRUTE_FORCE_THRESHOLD:
                self._create_alert(
                    title       = f"Brute Force Detected from {ip}",
                    description = (
                        f"{len(self._fail_tracker[ip])} failed login attempts "
                        f"from {ip} in {config.CORRELATION_WINDOW}s"
                    ),
                    severity    = "HIGH",
                    severity_num = 4,
                    rule_id     = "BF-001",
                    rule_name   = "SSH Brute Force",
                    category    = "auth",
                    source_ip   = ip,
                    hostname    = event.hostname,
                    username    = event.username,
                    mitre_tactic = "Credential Access",
                    mitre_tech  = "T1110",
                    tags        = ["brute-force", "ssh"],
                )
                # Counter reset karo
                self._fail_tracker[ip] = []
 
        # ── Port Scan Detection ───────────────────────────────────────────────
        if event.category == "network" and event.dest_port:
            self._port_tracker[ip].add(event.dest_port)
 
            if len(self._port_tracker[ip]) >= config.PORT_SCAN_THRESHOLD:
                self._create_alert(
                    title       = f"Port Scan Detected from {ip}",
                    description = (
                        f"{len(self._port_tracker[ip])} unique ports scanned "
                        f"from {ip}"
                    ),
                    severity    = "MEDIUM",
                    severity_num = 3,
                    rule_id     = "PS-001",
                    rule_name   = "Port Scan",
                    category    = "network",
                    source_ip   = ip,
                    mitre_tactic = "Discovery",
                    mitre_tech  = "T1046",
                    tags        = ["port-scan", "recon"],
                )
                self._port_tracker[ip] = set()
 
        # ── Malware Alert ─────────────────────────────────────────────────────
        if event.category == "malware":
            self._create_alert(
                title       = f"Malware Activity on {event.hostname or ip}",
                description = event.raw_message or "Malware signature matched",
                severity    = "CRITICAL",
                severity_num = 5,
                rule_id     = "MW-001",
                rule_name   = "Malware Detection",
                category    = "malware",
                source_ip   = ip,
                hostname    = event.hostname,
                mitre_tactic = "Execution",
                mitre_tech  = "T1204",
                tags        = ["malware", "critical"],
            )
 
    def _create_alert(self, **kwargs):
        session = get_session()
        try:
            alert = Alert(**kwargs)
            session.add(alert)
            session.commit()
            print(f"[ALERT] {kwargs.get('title')}")
        except Exception as ex:
            session.rollback()
            print(f"[ERROR] Alert create failed: {ex}")
        finally:
            session.close()
 
 
# Global instance
correlator = Correlator()
 
