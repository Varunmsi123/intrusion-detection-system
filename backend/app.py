"""
app.py — IDS Dashboard Backend
Real-time packet capture + ML classification with simulation fallback.
"""

from flask import Flask, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
import threading
import time
from datetime import datetime
from collections import deque

from predict import IDSPredictor
from capture import start_capture, get_capture_engine

# ── Flask Setup ────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = "ids-secret"
CORS(app, origins="*", supports_credentials=True)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25,
)

# ── Load Model ─────────────────────────────────────────────
print("Loading IDS model...")
ids = IDSPredictor("models/")

# ── Shared State ───────────────────────────────────────────
stats = {
    "total_packets":   0,
    "total_alerts":    0,
    "packets_per_sec": 0,
    "active_flows":    0,
    "uptime_seconds":  0,
    "is_paused":       False,   # starts ACTIVE (not paused)
}
class_counts = {"Normal": 0, "DoS": 0, "Probe": 0, "R2L": 0, "U2R": 0}
alert_log    = deque(maxlen=300)
raw_log      = deque(maxlen=300)
timeline     = deque(maxlen=60)
start_time   = time.time()


# ── Stats broadcaster (every 1 second) ────────────────────
def broadcast_stats():
    prev_packets = 0
    while True:
        time.sleep(1)

        current = stats["total_packets"]
        stats["packets_per_sec"] = current - prev_packets
        stats["uptime_seconds"]  = int(time.time() - start_time)
        prev_packets = current

        timeline.append({
            "time":   datetime.now().strftime("%H:%M:%S"),
            "Normal": class_counts.get("Normal", 0),
            "DoS":    class_counts.get("DoS",    0),
            "Probe":  class_counts.get("Probe",  0),
            "R2L":    class_counts.get("R2L",    0),
            "U2R":    class_counts.get("U2R",    0),
        })

        socketio.emit("stats_update", {
            "stats":        stats,
            "class_counts": class_counts,
            "timeline":     list(timeline),
        })


# ── Routes ─────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return {"status": "ok", "uptime": stats["uptime_seconds"]}

@app.route("/api/stats")
def get_stats():
    return jsonify({
        "stats":        stats,
        "class_counts": class_counts,
        "timeline":     list(timeline),
    })

@app.route("/api/alerts")
def get_alerts():
    return jsonify(list(alert_log))

@app.route("/api/raw")
def get_raw():
    return jsonify(list(raw_log))

@app.route("/api/pause", methods=["POST", "OPTIONS"])
def pause_capture():
    if not stats.get("is_paused", False):
        engine = get_capture_engine()
        if engine:
            engine.pause()
        stats["is_paused"] = True
        socketio.emit("capture_state", {"is_paused": True})
    return jsonify({"status": "paused", "is_paused": True})

@app.route("/api/resume", methods=["POST", "OPTIONS"])
def resume_capture():
    if stats.get("is_paused", False):
        engine = get_capture_engine()
        if engine:
            engine.resume()
        stats["is_paused"] = False
        socketio.emit("capture_state", {"is_paused": False})
    return jsonify({"status": "resumed", "is_paused": False})


# ── Socket Events ──────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    print("Dashboard connected")
    # Send current state to newly connected client
    socketio.emit("stats_update", {
        "stats":        stats,
        "class_counts": class_counts,
        "timeline":     list(timeline),
    })
    socketio.emit("capture_state", {"is_paused": stats.get("is_paused", False)})
    # Replay recent history
    for alert in list(alert_log)[:50]:
        socketio.emit("new_alert", alert)
    if list(raw_log):
        socketio.emit("raw_batch", list(raw_log)[:50])


# ── Entry Point ────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  IDS Real-Time Dashboard")
    print("  Simulation Mode: ON")
    print("=" * 50)

    start_capture(
        predictor    = ids,
        socketio     = socketio,
        stats        = stats,
        class_counts = class_counts,
        alert_log    = alert_log,
        raw_log      = raw_log,
    )

    t = threading.Thread(target=broadcast_stats, daemon=True)
    t.start()

    print("Backend  → http://localhost:5005")
    print("Frontend → http://localhost:5173")
    print("=" * 50)

    socketio.run(app, host="0.0.0.0", port=5005, debug=False)