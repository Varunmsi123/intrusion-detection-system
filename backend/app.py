"""
app.py — IPS Real-Time Intrusion Prevention & Detection System Backend
Coordinates Scapy capture, ML classification, Redis state, isolated firewall enforcement,
and real-time Socket.IO broadcasts.
"""

from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
import threading
import time
from datetime import datetime
from collections import deque

from predict import IDSPredictor
from capture import start_capture, detect_best_interface
from ips.redis_store import redis_store
from ips.firewall import firewall
from ips.allowlist import allowlist
from ips.policy_engine import policy_engine

# ── Flask Setup ────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = "ids-ips-secret-key-2026"
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
print("[App] Loading IDS/IPS machine learning model...")
ids = IDSPredictor("models/")

# ── Shared State ───────────────────────────────────────────
stats = {
    "total_packets":   0,
    "total_alerts":    0,
    "packets_per_sec": 0,
    "active_flows":    0,
    "uptime_seconds":  0,
    "blocked_hosts":   0,
}
class_counts = {"Normal": 0, "DoS": 0, "Probe": 0, "R2L": 0, "U2R": 0}
alert_log    = deque(maxlen=200)
timeline     = deque(maxlen=60)
start_time   = time.time()
capture_engine = None

# ── Stats broadcaster (every 1 second) ────────────────────
def broadcast_stats():
    prev_packets = 0
    while True:
        time.sleep(1)

        current = stats["total_packets"]
        stats["packets_per_sec"] = current - prev_packets
        stats["uptime_seconds"]  = int(time.time() - start_time)
        stats["blocked_hosts"]   = len(redis_store.get_blocked_ips())
        prev_packets = current

        snapshot = {
            "time":   datetime.now().strftime("%H:%M:%S"),
            "Normal": class_counts.get("Normal", 0),
            "DoS":    class_counts.get("DoS", 0),
            "Probe":  class_counts.get("Probe", 0),
            "R2L":    class_counts.get("R2L", 0),
            "U2R":    class_counts.get("U2R", 0),
        }
        timeline.append(snapshot)

        socketio.emit("stats_update", {
            "stats":           stats,
            "class_counts":    class_counts,
            "timeline":        list(timeline),
            "ips_mode":        firewall.mode,
            "redis_connected": redis_store.is_connected
        })


# ── Core REST Endpoints ────────────────────────────────────
@app.route("/api/health")
def health():
    return {
        "status": "ok",
        "uptime": stats["uptime_seconds"],
        "ips_mode": firewall.mode,
        "redis_connected": redis_store.is_connected
    }

@app.route("/api/stats")
def get_stats():
    return {
        "stats":           stats,
        "class_counts":    class_counts,
        "timeline":        list(timeline),
        "ips_mode":        firewall.mode,
        "redis_connected": redis_store.is_connected
    }

@app.route("/api/alerts")
def get_alerts():
    return list(alert_log)


# ── IPS Prevention REST Endpoints ──────────────────────────
@app.route("/api/ips/status", methods=["GET"])
def get_ips_status():
    """Returns current IPS engine configuration, mode, and allowlist."""
    return jsonify({
        "mode": firewall.mode,
        "redis_connected": redis_store.is_connected,
        "allowlist": allowlist.get_summary(),
        "blocked_count": len(redis_store.get_blocked_ips()),
        "has_nft": firewall.has_nft,
        "has_iptables": firewall.has_iptables
    })

@app.route("/api/ips/mode", methods=["POST"])
def set_ips_mode():
    """Switch mode between 'simulate' (safe default) and 'enforce'."""
    data = request.get_json() or {}
    new_mode = data.get("mode", "simulate")
    mode = firewall.set_mode(new_mode)
    socketio.emit("ips_mode_changed", {"mode": mode})
    return jsonify({"success": True, "mode": mode})

@app.route("/api/ips/blocked", methods=["GET"])
def get_blocked_hosts():
    """Returns all actively blocked hosts with remaining TTL."""
    return jsonify(redis_store.get_blocked_ips())

@app.route("/api/ips/unblock", methods=["POST"])
def manual_unblock():
    """Manually unblocks an IP address."""
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "Missing 'ip' parameter"}), 400

    redis_store.unblock_ip(ip)
    firewall.unblock_ip(ip)

    # Log action
    action = {
        "action": "UNBLOCK",
        "ip": ip,
        "reason": "Manual administrative unblock",
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }
    redis_store.log_action(action)

    # Broadcast updates to dashboard
    updated_list = redis_store.get_blocked_ips()
    socketio.emit("blocked_hosts_update", updated_list)
    socketio.emit("ips_action", action)

    return jsonify({"success": True, "ip": ip, "active_blocks": len(updated_list)})

@app.route("/api/ips/block", methods=["POST"])
def manual_block():
    """Manually blocks a suspicious IP (safe check against allowlist)."""
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    duration = int(data.get("duration", 300))
    reason = data.get("reason", "Manual administrative block")
    attack_type = data.get("attack_type", "Manual")

    if not ip:
        return jsonify({"error": "Missing 'ip' parameter"}), 400

    if allowlist.is_allowed(ip):
        return jsonify({"error": f"Cannot block {ip}: protected in allowlist (loopback/LAN/DNS)"}), 403

    redis_store.block_ip(ip, duration=duration, reason=reason, attack_type=attack_type)
    fw_res = firewall.block_ip(ip, duration=duration, reason=reason, attack_type=attack_type)

    action = {
        "action": "BLOCK",
        "ip": ip,
        "reason": reason,
        "duration": duration,
        "attack_type": attack_type,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }
    redis_store.log_action(action)

    updated_list = redis_store.get_blocked_ips()
    socketio.emit("blocked_hosts_update", updated_list)
    socketio.emit("ips_action", action)

    return jsonify({"success": True, "ip": ip, "duration": duration, "firewall_status": fw_res})

@app.route("/api/ips/reset", methods=["POST"])
def emergency_reset():
    """Emergency Panic Reset: instantly unblocks all IPs and flushes isolated IPS rules."""
    data = request.get_json() or {}
    reset_stats = data.get("reset_stats", False)

    redis_store.clear_all_blocks()
    res = firewall.emergency_reset()

    if reset_stats:
        for k in class_counts:
            class_counts[k] = 0
        stats["total_alerts"] = 0
        stats["total_packets"] = 0
        alert_log.clear()

    socketio.emit("blocked_hosts_update", [])
    socketio.emit("ips_action", {
        "action": "RESET",
        "reason": "Emergency flush of all IPS rules" + (" and stats reset" if reset_stats else ""),
        "timestamp": datetime.now().strftime("%H:%M:%S")
    })
    socketio.emit("stats_update", {
        "stats":           stats,
        "class_counts":    class_counts,
        "timeline":        list(timeline),
        "ips_mode":        firewall.mode,
        "redis_connected": redis_store.is_connected
    })

    return jsonify({"success": True, "message": "Emergency reset completed", "details": res})

@app.route("/api/ips/actions", methods=["GET"])
def get_action_history():
    """Returns recent IPS action events."""
    limit = int(request.args.get("limit", 50))
    return jsonify(redis_store.get_action_history(limit=limit))

@app.route("/api/ips/simulate_attack", methods=["POST"])
def simulate_attack():
    """Simulates an attack flow for live testing without attacking real networks."""
    data = request.get_json() or {}
    attack_type = data.get("attack_type", "DoS")
    src_ip = data.get("src_ip", "198.51.100.42")
    dst_port = int(data.get("dst_port", 80))
    conf = float(data.get("confidence", 0.96))

    # Record packet in Redis sliding-window
    if attack_type == "DoS":
        burst_count = int(data.get("packets", 20))
        for _ in range(burst_count):
            redis_store.record_packet(src_ip, dst_port, 1500)
    elif attack_type == "Probe":
        redis_store.record_packet(src_ip, dst_port, 64)

    # Evaluate flow through policy engine
    decision = policy_engine.evaluate(
        src_ip=src_ip,
        dst_ip="192.168.31.129",
        dst_port=dst_port,
        proto="tcp",
        service=data.get("service", "http"),
        label=attack_type,
        confidence=conf
    )

    # If already DROPPED: do NOT increment alert counters or log new alert!
    if decision["action"] == "DROP":
        stats["total_packets"] += 1
        socketio.emit("ips_action", decision)
        return jsonify({
            "success": True,
            "simulated": attack_type,
            "src_ip": src_ip,
            "decision": decision,
            "dropped": True,
            "message": f"Packet from {src_ip} dropped by IPS firewall rules. Threat blocked."
        })

    # Record in stats and alert log only for active alerts (RATE_LIMIT, BLOCK, etc.)
    class_counts[attack_type] = class_counts.get(attack_type, 0) + 1
    stats["total_alerts"] += 1
    stats["total_packets"] += 50

    alert = {
        "id":            int(time.time() * 1000) % 1000000,
        "time":          datetime.now().strftime("%H:%M:%S"),
        "timestamp":     datetime.now().isoformat(),
        "type":          attack_type,
        "src_ip":        src_ip,
        "dst_ip":        "192.168.31.129",
        "service":       data.get("service", "http"),
        "protocol":      "tcp",
        "duration":      1.2,
        "src_bytes":     125000 if attack_type == "DoS" else 2400,
        "dst_bytes":     540,
        "confidence":    round(conf, 4),
        "action":        decision["action"],
        "action_reason": decision["reason"],
        "color": {
            "DoS":  "#ef4444",
            "Probe":"#3b82f6",
            "R2L":  "#f59e0b",
            "U2R":  "#ec4899",
        }.get(attack_type, "#888"),
    }
    alert_log.appendleft(alert)

    # Emit real-time updates to all connected dashboards
    socketio.emit("new_alert", alert)
    socketio.emit("ips_action", decision)
    if decision["action"] == "BLOCK":
        socketio.emit("blocked_hosts_update", redis_store.get_blocked_ips())

    return jsonify({
        "success": True,
        "simulated": attack_type,
        "src_ip": src_ip,
        "decision": decision,
        "dropped": False
    })



# ── Socket Events ──────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    # Send live initial state to newly connected client
    socketio.emit("stats_update", {
        "stats":           stats,
        "class_counts":    class_counts,
        "timeline":        list(timeline),
        "ips_mode":        firewall.mode,
        "redis_connected": redis_store.is_connected
    })
    socketio.emit("blocked_hosts_update", redis_store.get_blocked_ips())
    for alert in list(alert_log)[:30]:
        socketio.emit("new_alert", alert)


# ── Entry Point ────────────────────────────────────────────
if __name__ == "__main__":
    best_iface = detect_best_interface()
    print("=" * 60)
    print("  IPS Monitor — Real-Time Intrusion Prevention & Detection System")
    print(f"  Interface    : {best_iface}")
    print(f"  IPS Mode     : {firewall.mode.upper()} (Safe Isolated Shield)")
    print(f"  Redis Store  : {'Connected' if redis_store.is_connected else 'In-Memory Fallback'}")
    print("=" * 60)

    # Start packet capture engine
    capture_engine = start_capture(
        predictor    = ids,
        socketio     = socketio,
        stats        = stats,
        class_counts = class_counts,
        alert_log    = alert_log,
        iface        = best_iface
    )

    # Start stats broadcaster thread
    t = threading.Thread(target=broadcast_stats, daemon=True)
    t.start()

    print("Backend API  → http://localhost:5000")
    print("Frontend UI  → http://localhost:3000")
    print("=" * 60)

    socketio.run(app, host="0.0.0.0", port=5000, debug=False)