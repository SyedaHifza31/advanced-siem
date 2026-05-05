"""
Engine - Alerter
Alert banane ke baad email ya Slack pe bhejta hai.
"""
 
import smtplib
import json
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import config
 
 
def send_alert_notification(alert_dict: dict):
    """Alert ko configured channels pe bhejo."""
    channels = config.ALERT_CHANNELS
 
    if channels.get("email", {}).get("enabled"):
        _send_email(alert_dict, channels["email"])
 
    if channels.get("slack", {}).get("enabled"):
        _send_slack(alert_dict, channels["slack"])
 
    if channels.get("webhook", {}).get("enabled"):
        _send_webhook(alert_dict, channels["webhook"])
 
 
def _send_email(alert: dict, cfg: dict):
    try:
        msg = MIMEMultipart()
        msg["From"]    = cfg["username"]
        msg["To"]      = ", ".join(cfg["recipients"])
        msg["Subject"] = f"[SIEM ALERT] {alert['severity']} - {alert['title']}"
 
        body = (
            f"Alert ID: {alert['id']}\n"
            f"Severity: {alert['severity']}\n"
            f"Title:    {alert['title']}\n"
            f"Category: {alert['category']}\n"
            f"Source IP: {alert.get('source_ip', 'N/A')}\n"
            f"Time:     {alert['timestamp']}\n\n"
            f"Description:\n{alert.get('description', '')}\n"
        )
        msg.attach(MIMEText(body, "plain"))
 
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as server:
            server.starttls()
            server.login(cfg["username"], cfg["password"])
            server.sendmail(cfg["username"], cfg["recipients"], msg.as_string())
 
        print(f"[EMAIL] Alert sent: {alert['title']}")
    except Exception as ex:
        print(f"[EMAIL ERROR] {ex}")
 
 
def _send_slack(alert: dict, cfg: dict):
    try:
        color = {"CRITICAL": "#FF0000", "HIGH": "#FF6600",
                 "MEDIUM": "#FFCC00", "LOW": "#36A64F"}.get(alert["severity"], "#CCCCCC")
 
        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 {alert['severity']} - {alert['title']}",
                "fields": [
                    {"title": "Category",  "value": alert.get("category", "N/A"),  "short": True},
                    {"title": "Source IP", "value": alert.get("source_ip", "N/A"), "short": True},
                    {"title": "Status",    "value": alert.get("status", "OPEN"),   "short": True},
                    {"title": "Time",      "value": alert.get("timestamp", ""),    "short": True},
                ],
                "text": alert.get("description", ""),
            }]
        }
 
        r = requests.post(cfg["webhook_url"], json=payload, timeout=5)
        r.raise_for_status()
        print(f"[SLACK] Alert sent: {alert['title']}")
    except Exception as ex:
        print(f"[SLACK ERROR] {ex}")
 
 
def _send_webhook(alert: dict, cfg: dict):
    try:
        r = requests.post(
            cfg["url"],
            json=alert,
            headers=cfg.get("headers", {}),
            timeout=5,
        )
        r.raise_for_status()
        print(f"[WEBHOOK] Alert sent: {alert['title']}")
    except Exception as ex:
        print(f"[WEBHOOK ERROR] {ex}")
 