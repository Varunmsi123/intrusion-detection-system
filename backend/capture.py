"""
capture.py — Real-time packet capture using Scapy (Linux / WiFi)
Falls back to simulation mode automatically if Scapy can't capture.
"""

import time
import random
import threading
from collections import deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# ── Interface (Linux — update for your NIC, e.g. "eth0", "wlan0") ─────────
WIFI_IFACE   = "any"     # "any" = all interfaces on Linux
FLOW_TIMEOUT = 5
WINDOW_SIZE  = 100

# ── Global engine reference ────────────────────────────────────────────────
_capture_engine = None

def get_capture_engine():
    return _capture_engine

# ── Port → Service mapping ─────────────────────────────────────────────────
PORT_SERVICE = {
    80:   "http",    443: "https",   21: "ftp",
    22:   "ssh",     25:  "smtp",    53: "domain",
    23:   "telnet", 110:  "pop_3",  143: "imap4",
    3389: "rdp",   8080:  "http",  8443: "https",
}

# ── TCP flag → NSL-KDD flag string ─────────────────────────────────────────
def get_flag(flags_int):
    SYN = bool(flags_int & 0x02)
    ACK = bool(flags_int & 0x10)
    FIN = bool(flags_int & 0x01)
    RST = bool(flags_int & 0x04)
    if SYN and not ACK:       return "S0"
    if SYN and ACK and FIN:   return "SF"
    if RST:                   return "RSTO"
    if SYN and ACK:           return "S1"
    return "OTH"

# ── Flow record ────────────────────────────────────────────────────────────
class Flow:
    def __init__(self, src, sport, dst, dport, proto):
        self.src       = src
        self.sport     = sport
        self.dst       = dst
        self.dport     = dport
        self.proto     = proto
        self.start     = time.time()
        self.src_bytes = 0
        self.dst_bytes = 0
        self.pkts      = []
        self.flags     = []

# ── Feature extractor ──────────────────────────────────────────────────────
def build_features(flow, recent, cat_encoders):
    pkts = flow.pkts
    n    = max(len(pkts), 1)
    dur  = (pkts[-1]["t"] - pkts[0]["t"]) if len(pkts) > 1 else 0

    service = PORT_SERVICE.get(flow.dport, "private")
    flag    = get_flag(flow.flags[-1]) if flow.flags else "OTH"

    serror  = sum(1 for f in flow.flags if f & 0x04) / n
    rerror  = sum(1 for f in flow.flags if f & 0x14) / n

    w  = recent[-WINDOW_SIZE:]
    wn = max(len(w), 1)
    same_srv      = sum(1 for r in w if PORT_SERVICE.get(r.dport, "private") == service)
    diff_srv      = wn - same_srv
    same_srv_rate = same_srv / wn
    diff_srv_rate = diff_srv / wn
    dst_host_cnt  = sum(1 for r in w if r.dst == flow.dst)
    dst_host_srv  = sum(1 for r in w if r.dst == flow.dst
                        and PORT_SERVICE.get(r.dport, "private") == service)

    def enc(col, val):
        le = cat_encoders.get(col)
        if le is None: return 0
        val = str(val).lower()
        return int(le.transform([val])[0]) if val in le.classes_ else 0

    proto_enc   = enc("protocol_type", flow.proto)
    service_enc = enc("service",       service)
    flag_enc    = enc("flag",          flag)

    v = [0.0] * 41
    v[0]  = dur
    v[1]  = proto_enc
    v[2]  = service_enc
    v[3]  = flag_enc
    v[4]  = flow.src_bytes
    v[5]  = flow.dst_bytes
    v[11] = 1 if flag == "SF" else 0
    v[22] = min(len(w), 511)
    v[23] = min(same_srv, 511)
    v[24] = serror
    v[25] = serror
    v[26] = rerror
    v[27] = rerror
    v[28] = same_srv_rate
    v[29] = diff_srv_rate
    v[31] = min(dst_host_cnt, 255)
    v[32] = min(dst_host_srv, 255)
    v[33] = dst_host_srv / max(dst_host_cnt, 1)
    v[34] = 1 - v[33]
    v[37] = serror
    v[38] = serror
    v[39] = rerror
    v[40] = rerror

    return v, service, flag


# ══════════════════════════════════════════════════════════════════════════
#  SIMULATION ENGINE  (runs when real Scapy capture isn't available)
# ══════════════════════════════════════════════════════════════════════════

SERVICES   = ["http", "https", "ftp", "ssh", "smtp", "domain", "telnet", "private"]
PROTOCOLS  = ["tcp", "udp", "icmp"]

# hand-crafted NSL-KDD feature vectors per attack type (tuned for RF model)
ATTACK_TEMPLATES = {
    "DoS": {
        "src_bytes":  [0,      5000,   50000],
        "dst_bytes":  [0,      0,      10],
        "duration":   [0,      0,      0.01],
        "serror":     [0.9,    1.0,    0.85],
        "rerror":     [0.0,    0.0,    0.0],
        "srv_rate":   [1.0,    1.0,    0.98],
        "count":      [511,    300,    200],
        "flag":       "S0",
        "service":    "http",
        "proto":      "tcp",
    },
    "Probe": {
        "src_bytes":  [100,    200,    50],
        "dst_bytes":  [0,      50,     100],
        "duration":   [0,      1,      2],
        "serror":     [0.0,    0.0,    0.0],
        "rerror":     [0.3,    0.5,    0.4],
        "srv_rate":   [0.0,    0.1,    0.05],
        "count":      [10,     20,     50],
        "flag":       "SF",
        "service":    "private",
        "proto":      "tcp",
    },
    "R2L": {
        "src_bytes":  [200,    1000,   5000],
        "dst_bytes":  [1000,   5000,   20000],
        "duration":   [10,     30,     60],
        "serror":     [0.0,    0.0,    0.0],
        "rerror":     [0.0,    0.0,    0.0],
        "srv_rate":   [0.5,    0.3,    0.2],
        "count":      [5,      10,     3],
        "flag":       "SF",
        "service":    "ftp",
        "proto":      "tcp",
    },
    "U2R": {
        "src_bytes":  [500,    1500,   3000],
        "dst_bytes":  [100,    500,    1000],
        "duration":   [5,      15,     30],
        "serror":     [0.0,    0.0,    0.0],
        "rerror":     [0.0,    0.0,    0.0],
        "srv_rate":   [0.5,    0.5,    0.5],
        "count":      [2,      4,      8],
        "flag":       "SF",
        "service":    "ssh",
        "proto":      "tcp",
    },
}

def _random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _build_sim_features(cat_encoders, attack_type="Normal"):
    """Build a 41-dim feature vector for the given attack type."""
    v = [0.0] * 41

    if attack_type == "Normal":
        service = random.choice(["http", "https", "ftp", "ssh", "domain"])
        proto   = "tcp"
        flag    = "SF"
        v[0]  = round(random.uniform(0, 5), 3)
        v[4]  = random.randint(100, 5000)
        v[5]  = random.randint(100, 5000)
        v[11] = 1
        v[22] = random.randint(1, 80)
        v[23] = random.randint(1, 50)
        v[28] = round(random.uniform(0.6, 1.0), 3)
        v[29] = round(1 - v[28], 3)
        v[31] = random.randint(1, 80)
        v[32] = random.randint(1, 50)
        v[33] = round(random.uniform(0.5, 1.0), 3)
        v[34] = round(1 - v[33], 3)
    else:
        t = ATTACK_TEMPLATES[attack_type]
        idx     = random.randint(0, len(t["src_bytes"]) - 1)
        service = t["service"]
        proto   = t["proto"]
        flag    = t["flag"]
        v[0]  = round(t["duration"][idx], 3)
        v[4]  = t["src_bytes"][idx]
        v[5]  = t["dst_bytes"][idx]
        v[11] = 1 if flag == "SF" else 0
        se    = t["serror"][ idx]
        re    = t["rerror"][ idx]
        cnt   = t["count"][  idx]
        v[22] = cnt
        v[23] = cnt
        v[24] = se; v[25] = se; v[37] = se; v[38] = se
        v[26] = re; v[27] = re; v[39] = re; v[40] = re
        sr    = t["srv_rate"][idx]
        v[28] = sr; v[29] = 1 - sr
        v[31] = cnt; v[32] = cnt
        v[33] = sr;  v[34] = 1 - sr

    def enc(col, val):
        le = cat_encoders.get(col)
        if le is None: return 0
        val = str(val).lower()
        return int(le.transform([val])[0]) if val in le.classes_ else 0

    v[1] = enc("protocol_type", proto)
    v[2] = enc("service",       service)
    v[3] = enc("flag",          flag)

    return v, service, proto, flag


class SimulationEngine:
    """Generates synthetic traffic (Normal + all 4 attack types)."""

    def __init__(self, predictor, socketio, stats, class_counts, alert_log, raw_log):
        self.predictor    = predictor
        self.socketio     = socketio
        self.stats        = stats
        self.class_counts = class_counts
        self.alert_log    = alert_log
        self.raw_log      = raw_log
        self._alert_id    = 0
        self._raw_id      = 0
        self._paused      = False
        self._lock        = threading.Lock()

        # Raw packet emit throttle
        self._raw_batch   = []
        self._last_raw_emit = time.time()

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    def _emit_raw_batch(self):
        """Flush raw packets in batches (max every 0.5s) to avoid socket spam."""
        now = time.time()
        if self._raw_batch and (now - self._last_raw_emit) >= 0.5:
            for pkt in self._raw_batch:
                self.raw_log.appendleft(pkt)
            self.socketio.emit("raw_batch", self._raw_batch[:])
            self._raw_batch.clear()
            self._last_raw_emit = now

    def _simulate_loop(self):
        """Main simulation loop - runs in background thread."""
        attack_types  = ["Normal", "Normal", "Normal", "DoS", "Probe", "R2L", "U2R"]
        attack_weights = [40, 40, 20, 10, 8, 5, 3]  # Normal much more frequent

        while True:
            if self._paused:
                time.sleep(0.5)
                continue

            # Pick an attack type (weighted)
            attack_type = random.choices(attack_types, weights=attack_weights, k=1)[0]

            src_ip = _random_ip()
            dst_ip = _random_ip()

            features, service, proto, flag = _build_sim_features(
                self.predictor.cat_encoders, attack_type
            )
            src_bytes = int(features[4])
            dst_bytes = int(features[5])
            duration  = round(features[0], 3)

            label, conf = self.predictor.classify(features)

            with self._lock:
                self._alert_id   += 1
                self._raw_id     += 1
                self.stats["total_packets"] += 1
                self.class_counts[label]     = self.class_counts.get(label, 0) + 1

                if label != "Normal":
                    self.stats["total_alerts"] += 1

                # ── Classified event ────────────────────────────────
                alert = {
                    "id":         self._alert_id,
                    "time":       datetime.now().strftime("%H:%M:%S"),
                    "timestamp":  datetime.now().isoformat(),
                    "type":       label,
                    "src_ip":     src_ip,
                    "dst_ip":     dst_ip,
                    "service":    service,
                    "protocol":   proto,
                    "duration":   duration,
                    "src_bytes":  src_bytes,
                    "dst_bytes":  dst_bytes,
                    "confidence": round(conf, 4),
                    "features":   [round(f, 4) if isinstance(f, float) else f for f in features],
                    "flag":       flag,
                    "color": {
                        "DoS":   "#ef4444",
                        "Probe": "#3b82f6",
                        "R2L":   "#f59e0b",
                        "U2R":   "#ec4899",
                        "Normal":"#10b981",
                    }.get(label, "#888"),
                }
                self.alert_log.appendleft(alert)
                self.socketio.emit("new_alert", alert)

                # ── Raw packet event (batched) ───────────────────────
                raw_entry = {
                    "id":        self._raw_id,
                    "time":      datetime.now().strftime("%H:%M:%S"),
                    "timestamp": datetime.now().isoformat(),
                    "src_ip":    src_ip,
                    "dst_ip":    dst_ip,
                    "src_port":  random.randint(1024, 65535),
                    "dst_port":  random.choice([80, 443, 22, 21, 25, 53, 8080]),
                    "protocol":  proto,
                    "service":   service,
                    "size":      src_bytes + random.randint(0, 100),
                    "flags":     flag,
                }
                self._raw_batch.append(raw_entry)
                self._emit_raw_batch()

                self.stats["active_flows"] = random.randint(1, 20)

            # Randomize inter-arrival time (0.3 – 1.2 seconds)
            time.sleep(random.uniform(0.3, 1.2))

    def start(self):
        t = threading.Thread(target=self._simulate_loop, daemon=True)
        t.start()
        print("[Simulation] Traffic simulation engine started.")
        return t


# ══════════════════════════════════════════════════════════════════════════
#  REAL CAPTURE ENGINE  (uses Scapy — works on Linux with proper perms)
# ══════════════════════════════════════════════════════════════════════════

class PacketCapture:

    def __init__(self, predictor, socketio, stats, class_counts, alert_log, raw_log):
        self.predictor    = predictor
        self.socketio     = socketio
        self.stats        = stats
        self.class_counts = class_counts
        self.alert_log    = alert_log
        self.raw_log      = raw_log
        self._flows       = {}
        self._recent      = []
        self._lock        = threading.Lock()
        self._alert_id    = 0
        self._raw_id      = 0
        self._paused      = False
        self._raw_batch   = []
        self._last_raw_emit = time.time()

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    def _emit_raw_batch(self):
        now = time.time()
        if self._raw_batch and (now - self._last_raw_emit) >= 0.5:
            for pkt in self._raw_batch:
                self.raw_log.appendleft(pkt)
            self.socketio.emit("raw_batch", self._raw_batch[:])
            self._raw_batch.clear()
            self._last_raw_emit = now

    def _five_tuple(self, pkt):
        if IP not in pkt:
            return None
        proto = ("tcp"  if TCP  in pkt else
                 "udp"  if UDP  in pkt else
                 "icmp" if ICMP in pkt else "other")
        sp = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dp = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        return (pkt[IP].src, sp, pkt[IP].dst, dp, proto)

    def _on_packet(self, pkt):
        if self._paused:
            return

        key = self._five_tuple(pkt)
        if not key:
            return

        src, sp, dst, dp, proto = key
        now = time.time()

        with self._lock:
            if key not in self._flows:
                self._flows[key] = Flow(src, sp, dst, dp, proto)

            flow = self._flows[key]
            if IP in pkt:
                size = len(pkt[IP])
                flow.src_bytes += size
                flow.pkts.append({"t": now, "size": size})
                if TCP in pkt:
                    flow.flags.append(int(pkt[TCP].flags))

            self.stats["total_packets"] += 1

            # Raw packet (batched)
            self._raw_id += 1
            service = PORT_SERVICE.get(dp, "private")
            raw_entry = {
                "id":        self._raw_id,
                "time":      datetime.now().strftime("%H:%M:%S"),
                "timestamp": datetime.now().isoformat(),
                "src_ip":    src,
                "dst_ip":    dst,
                "src_port":  sp,
                "dst_port":  dp,
                "protocol":  proto,
                "service":   service,
                "size":      len(pkt[IP]) if IP in pkt else 0,
                "flags":     str(pkt[TCP].flags) if TCP in pkt else "",
            }
            self._raw_batch.append(raw_entry)
            self._emit_raw_batch()

            # Flush expired flows
            expired = [k for k, f in self._flows.items()
                       if (now - f.start) > FLOW_TIMEOUT and f.pkts]
            for k in expired:
                self._classify_flow(self._flows.pop(k))

            self.stats["active_flows"] = len(self._flows)

    def _classify_flow(self, flow):
        features, service, flag = build_features(
            flow, self._recent, self.predictor.cat_encoders
        )
        self._recent.append(flow)
        if len(self._recent) > WINDOW_SIZE:
            self._recent.pop(0)

        label, conf = self.predictor.classify(features)
        self.class_counts[label] = self.class_counts.get(label, 0) + 1

        self._alert_id += 1
        if label != "Normal":
            self.stats["total_alerts"] += 1

        alert = {
            "id":         self._alert_id,
            "time":       datetime.now().strftime("%H:%M:%S"),
            "timestamp":  datetime.now().isoformat(),
            "type":       label,
            "src_ip":     flow.src,
            "dst_ip":     flow.dst,
            "service":    service,
            "protocol":   flow.proto,
            "duration":   round(flow.pkts[-1]["t"] - flow.start, 3) if len(flow.pkts) > 1 else 0,
            "src_bytes":  flow.src_bytes,
            "dst_bytes":  flow.dst_bytes,
            "confidence": round(conf, 4),
            "features":   [round(f, 4) if isinstance(f, float) else f for f in features],
            "flag":       flag,
            "color": {
                "DoS":   "#ef4444",
                "Probe": "#3b82f6",
                "R2L":   "#f59e0b",
                "U2R":   "#ec4899",
                "Normal":"#10b981",
            }.get(label, "#888"),
        }
        self.alert_log.appendleft(alert)
        self.socketio.emit("new_alert", alert)

    def start(self, iface=WIFI_IFACE):
        def _run():
            print(f"[Capture] Sniffing on interface: {iface}")
            try:
                sniff(iface=iface, prn=self._on_packet, store=False)
            except Exception as e:
                print(f"[Capture] ERROR: {e}")
                print("[Capture] Falling back to simulation mode.")
                sim = SimulationEngine(
                    self.predictor, self.socketio, self.stats,
                    self.class_counts, self.alert_log, self.raw_log
                )
                # Transfer pause state
                sim._paused = self._paused
                # Replace global engine reference
                global _capture_engine
                _capture_engine = sim
                sim._simulate_loop()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        print("[Capture] Capture thread started.")
        return t


# ══════════════════════════════════════════════════════════════════════════
def start_capture(predictor, socketio, stats, class_counts, alert_log,
                  raw_log=None, iface=WIFI_IFACE):
    global _capture_engine
    if raw_log is None:
        raw_log = deque(maxlen=200)

    # Always start simulation on Linux for demo; use PacketCapture for real capture
    engine = SimulationEngine(predictor, socketio, stats, class_counts, alert_log, raw_log)
    _capture_engine = engine
    engine.start()
    return engine