"""
Advanced SIEM System - Main Entry Point
Yahan se sab kuch start hota hai.
 
Run karo:
    python main.py
"""
 
import os
from flask import Flask, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
 
import config
from models.database import init_db
from extensions import init_session_factory
 
# ─── App Initialize ───────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", static_url_path="")
app.config["SECRET_KEY"] = config.SECRET_KEY
 
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
 
# ─── Database Initialize ──────────────────────────────────────────────────────
os.makedirs("data", exist_ok=True)
engine, Session = init_db(config.DATABASE_URL)
init_session_factory(Session)
 
# ─── Register API Blueprints ──────────────────────────────────────────────────
from api.events      import events_bp
from api.alerts      import alerts_bp
from api.assets      import assets_bp
from api.threat_intel import threat_intel_bp
 
app.register_blueprint(events_bp,      url_prefix="/api")
app.register_blueprint(alerts_bp,      url_prefix="/api")
app.register_blueprint(assets_bp,      url_prefix="/api")
app.register_blueprint(threat_intel_bp, url_prefix="/api")
 
 
# ─── Health Check ─────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})
 
 
# ─── Root → Dashboard ─────────────────────────────────────────────────────────
@app.route("/")
def index():
    return app.send_static_file("index.html")
 
 
# ─── Start Log Ingestion (background threads) ─────────────────────────────────
from engine.ingestion import start_all as start_ingestion
start_ingestion()
 
 
# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════╗
║   Advanced SIEM System  v1.0.0       ║
║   URL  → http://localhost:{config.PORT}      ║
║   DB   → {config.DATABASE_URL[:35]}
╚══════════════════════════════════════╝
    """)
    socketio.run(
        app,
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
    )
 