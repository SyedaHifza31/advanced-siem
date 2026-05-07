"""
Advanced SIEM System — main.py
Deploy-safe version: gevent, $PORT support, auto data folder
"""

import os
from datetime import timedelta
from flask import Flask, jsonify, send_from_directory, session, redirect
from flask_cors import CORS

import config
from models.database import init_db, Base
from extensions import init_session_factory, get_session

# ─── App ──────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", static_url_path="")
app.config["SECRET_KEY"]                 = config.SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
CORS(app)

# ─── SocketIO — gevent mode (deploy-safe) ─────────────────────────────────────
try:
    from flask_socketio import SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")
except Exception:
    socketio = None

# ─── Database ─────────────────────────────────────────────────────────────────
os.makedirs("data", exist_ok=True)
engine, Session = init_db(config.DATABASE_URL)
init_session_factory(Session)
Base.metadata.create_all(engine)

# ─── Default users ────────────────────────────────────────────────────────────
def create_default_users():
    from models.user import User
    db = get_session()
    try:
        if not db.query(User).filter_by(username="admin").first():
            admin = User(
                username="admin", email="admin@siem.local",
                role="admin", full_name="SIEM Administrator"
            )
            admin.set_password("Admin@123")
            db.add(admin)

            analyst = User(
                username="analyst", email="analyst@siem.local",
                role="analyst", full_name="Security Analyst"
            )
            analyst.set_password("Analyst@123")
            db.add(analyst)
            db.commit()
            print("[SIEM] Default users created: admin/Admin@123 | analyst/Analyst@123")
    except Exception as ex:
        db.rollback()
        print(f"[WARN] Users: {ex}")
    finally:
        db.close()

create_default_users()

# ─── Blueprints ───────────────────────────────────────────────────────────────
from api.events       import events_bp
from api.alerts       import alerts_bp
from api.assets       import assets_bp
from api.threat_intel import threat_intel_bp
from api.auth         import auth_bp
from api.dashboard    import dashboard_bp

for bp in [events_bp, alerts_bp, assets_bp, threat_intel_bp, auth_bp, dashboard_bp]:
    app.register_blueprint(bp, url_prefix="/api")

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "2.0.0"})

@app.route("/")
def index():
    if not session.get("user_id"):
        return redirect("/login")
    return send_from_directory("static", "index.html")

@app.route("/login")
def login_page():
    if session.get("user_id"):
        return redirect("/")
    return send_from_directory("static", "login.html")

# ─── Background services (only if not in Gunicorn master process) ─────────────
def start_background_services():
    try:
        from engine.ingestion import start_all
        start_all()
        print("[SIEM] Log ingestion started")
    except Exception as ex:
        print(f"[WARN] Ingestion: {ex}")

    try:
        from engine.scheduler import start_scheduler
        start_scheduler()
        print("[SIEM] Threat intel scheduler started")
    except Exception as ex:
        print(f"[WARN] Scheduler: {ex}")

# Gunicorn workers mein ek baar chalao
import sys
if "gunicorn" in sys.modules or __name__ == "__main__":
    start_background_services()

# ─── Dev server ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", config.PORT))
    print(f"\n SIEM-OPS v2.0 → http://localhost:{port}")
    print(f" Login: admin / Admin@123\n")

    if socketio:
        socketio.run(app, host="0.0.0.0", port=port, debug=config.DEBUG)
    else:
        app.run(host="0.0.0.0", port=port, debug=config.DEBUG)