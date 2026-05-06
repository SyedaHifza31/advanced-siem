import os
from flask import Flask, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS

import config
from models.database import init_db
from extensions import init_session_factory

# ─── App Initialize ─────────────────────────────────────────────
app = Flask(__name__, static_folder="static", static_url_path="")
app.config["SECRET_KEY"] = config.SECRET_KEY

CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ─── Database Initialize ────────────────────────────────────────
os.makedirs("data", exist_ok=True)
engine, Session = init_db(config.DATABASE_URL)
init_session_factory(Session)

# ─── Register API Blueprints ────────────────────────────────────
from api.events import events_bp
from api.alerts import alerts_bp
from api.assets import assets_bp
from api.threat_intel import threat_intel_bp

app.register_blueprint(events_bp, url_prefix="/api")
app.register_blueprint(alerts_bp, url_prefix="/api")
app.register_blueprint(assets_bp, url_prefix="/api")
app.register_blueprint(threat_intel_bp, url_prefix="/api")

# ─── Health Check ───────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})

# ─── Root → Dashboard ──────────────────────────────────────────
@app.route("/")
def index():
    return app.send_static_file("index.html")

# ─── REMOVE INGESTION (DEPLOY SAFE) ─────────────────────────────
# start_ingestion()  ❌ removed for deployment stability

# ─── RUN SERVER ────────────────────────────────────────────────
if __name__ == "__main__":
    print("Advanced SIEM running locally...")

    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )