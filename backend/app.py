"""
app.py — IDS Dashboard Backend
Real-time packet capture on Windows WiFi + ML classification

Run as Administrator:
    python app.py
"""

from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
import threading
import time
from datetime import datetime
from collections import deque

from predict import IDSPredictor
from capture import start_capture

# ── Flask Setup ────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = "ids-secret"
CORS(app, origins="*")
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
    "total_packets":  0,
    "total_alerts":   0,
    "packets_per_sec": 0,
    "active_flows":   0,
    "uptime_seconds": 0,
}
class_counts = {"Normal": 0, "DoS": 0, "Probe": 0, "R2L": 0, "U2R": 0}
alert_log    = deque(maxlen=200)
timeline     = deque(maxlen=60)
start_time   = time.time()

# ── Stats broadcaster (every 1 second) ────────────────────
def broadcast_stats():
    prev_packets = 0
    while True:
        time.sleep(1)

        # Calculate packets per second
        current = stats["total_packets"]
        stats["packets_per_sec"]  = current - prev_packets
        stats["uptime_seconds"]   = int(time.time() - start_time)
        prev_packets = current

        # Timeline snapshot
        snapshot = {
            "time":   datetime.now().strftime("%H:%M:%S"),
            "Normal": class_counts.get("Normal", 0),
            "DoS":    class_counts.get("DoS", 0),
            "Probe":  class_counts.get("Probe", 0),
            "R2L":    class_counts.get("R2L", 0),
            "U2R":    class_counts.get("U2R", 0),
        }
        timeline.append(snapshot)

        # Emit to all connected clients
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
    return {
        "stats":        stats,
        "class_counts": class_counts,
        "timeline":     list(timeline),
    }

@app.route("/api/alerts")
def get_alerts():
    return list(alert_log)


# ── Socket Events ──────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    print("Dashboard connected")
    socketio.emit("stats_update", {
        "stats":        stats,
        "class_counts": class_counts,
        "timeline":     list(timeline),
    })
    for alert in list(alert_log)[:30]:
        socketio.emit("new_alert", alert)


# ── Entry Point ────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  IDS Real-Time Dashboard")
    print("  WiFi: Intel Wireless-AC 9461")
    print("=" * 50)

    # Start real packet capture
    start_capture(
        predictor    = ids,
        socketio     = socketio,
        stats        = stats,
        class_counts = class_counts,
        alert_log    = alert_log,
    )

    # Start stats broadcaster
    t = threading.Thread(target=broadcast_stats, daemon=True)
    t.start()

    print("Dashboard → http://localhost:5000")
    print("Frontend  → http://localhost:3000")
    print("=" * 50)

    socketio.run(app, host="0.0.0.0", port=5000, debug=False)