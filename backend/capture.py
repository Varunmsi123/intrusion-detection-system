"""
capture.py — Real-time packet capture with dynamic interface auto-detection,
bidirectional flow reconstruction, and IPS policy integration.
Cross-platform: Linux (Fedora/Ubuntu) and Windows.
"""

import os
import sys
import time
import socket
import threading
import subprocess
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

from ips.redis_store import redis_store
from ips.policy_engine import policy_engine

FLOW_TIMEOUT = 5       # seconds to flush a connection
WINDOW_SIZE  = 100     # rolling window for rate features

# ── Port → Service mapping ─────────────────────────────────
PORT_SERVICE = {
    80:   "http",    443: "https",   21: "ftp",
    22:   "ssh",     25:  "smtp",    53: "domain",
    23:   "telnet", 110:  "pop_3",  143: "imap4",
    3389: "rdp",   8080:  "http",  8443: "https",
}

def detect_best_interface() -> str:
    """
    Dynamically detects the active network interface on Linux or Windows.
    No hardcoded interface strings.
    """
    # 1. Environment variable override
    env_iface = os.environ.get("IPS_IFACE")
    if env_iface:
        return env_iface

    # 2. Linux active route interface
    if sys.platform.startswith("linux"):
        try:
            out = subprocess.check_output(["ip", "route", "show", "default"], stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                parts = line.split()
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        dev = parts[idx + 1]
                        print(f"[Capture] Auto-detected active Linux interface: {dev}")
                        return dev
        except Exception:
            pass

        # Check scapy conf.iface
        if conf.iface and str(conf.iface) not in ("lo", "docker0"):
            return str(conf.iface)

    # 3. Fallback to scapy default
    return str(conf.iface) if conf.iface else "lo"

# ── TCP flag → NSL-KDD flag string ────────────────────────
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

# ── Bidirectional Flow record ──────────────────────────────
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

# ── Feature extractor ──────────────────────────────────────
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
    v[6]  = 0
    v[7]  = 0
    v[8]  = 0
    v[9]  = 0
    v[10] = 0
    v[11] = 1 if flag == "SF" else 0
    v[12] = 0
    v[13] = 0
    v[14] = 0
    v[15] = 0
    v[16] = 0
    v[17] = 0
    v[18] = 0
    v[19] = 0
    v[20] = 0
    v[21] = 0
    v[22] = min(len(w), 511)
    v[23] = min(same_srv, 511)
    v[24] = serror
    v[25] = serror
    v[26] = rerror
    v[27] = rerror
    v[28] = same_srv_rate
    v[29] = diff_srv_rate
    v[30] = 0.0
    v[31] = min(dst_host_cnt, 255)
    v[32] = min(dst_host_srv, 255)
    v[33] = dst_host_srv / max(dst_host_cnt, 1)
    v[34] = 1 - v[33]
    v[35] = 0.0
    v[36] = 0.0
    v[37] = serror
    v[38] = serror
    v[39] = rerror
    v[40] = rerror

    return v, service, flag

# ── Main Capture & IPS Engine ──────────────────────────────
class PacketCapture:
    def __init__(self, predictor, socketio, stats, class_counts, alert_log):
        self.predictor    = predictor
        self.socketio     = socketio
        self.stats        = stats
        self.class_counts = class_counts
        self.alert_log    = alert_log
        self._flows       = {}
        self._recent      = []
        self._lock        = threading.Lock()
        self._alert_id    = 0
        self.sniff_thread = None

    def _canonical_key(self, src, sp, dst, dp, proto):
        """Creates a bidirectional canonical flow key."""
        endpoints = sorted([(src, sp), (dst, dp)])
        return (endpoints[0], endpoints[1], proto)

    def _on_packet(self, pkt):
        if IP not in pkt:
            return

        proto = ("tcp"  if TCP  in pkt else
                 "udp"  if UDP  in pkt else
                 "icmp" if ICMP in pkt else "other")
        sp = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dp = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt[IP])
        now = time.time()

        # Update Redis sliding-window rates & port tracker
        redis_store.record_packet(src, dp, size)

        # Check if incoming packet belongs to an actively blocked IP
        if redis_store.is_blocked(src):
            # Already blocked - count as prevented/dropped packet
            self.stats["total_packets"] += 1
            return

        key = self._canonical_key(src, sp, dst, dp, proto)

        with self._lock:
            if key not in self._flows:
                # Flow initiator is src
                self._flows[key] = Flow(src, sp, dst, dp, proto)

            flow = self._flows[key]

            # Accurately update bidirectional bytes
            if src == flow.src:
                flow.src_bytes += size
            else:
                flow.dst_bytes += size

            flow.pkts.append({"t": now, "size": size})
            if TCP in pkt:
                flow.flags.append(int(pkt[TCP].flags))

            self.stats["total_packets"] += 1

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

        # Evaluate flow through IPS Policy Engine
        decision = policy_engine.evaluate(
            src_ip=flow.src,
            dst_ip=flow.dst,
            dst_port=flow.dport,
            proto=flow.proto,
            service=service,
            label=label,
            confidence=conf
        )

        # Emit real-time IPS action event to connected UI clients
        self.socketio.emit("ips_action", decision)

        if label != "Normal":
            self._alert_id += 1
            self.stats["total_alerts"] += 1
            alert = {
                "id":             self._alert_id,
                "time":           datetime.now().strftime("%H:%M:%S"),
                "timestamp":      datetime.now().isoformat(),
                "type":           label,
                "src_ip":         flow.src,
                "dst_ip":         flow.dst,
                "service":        service,
                "protocol":       flow.proto,
                "duration":       round(flow.pkts[-1]["t"] - flow.start, 3) if len(flow.pkts) > 1 else 0,
                "src_bytes":      flow.src_bytes,
                "dst_bytes":      flow.dst_bytes,
                "confidence":     round(conf, 4),
                "action":         decision["action"],
                "action_reason":  decision["reason"],
                "color": {
                    "DoS":  "#ef4444",
                    "Probe":"#3b82f6",
                    "R2L":  "#f59e0b",
                    "U2R":  "#ec4899",
                }.get(label, "#888"),
            }
            self.alert_log.appendleft(alert)
            self.socketio.emit("new_alert", alert)

            # If an IP was blocked, emit updated blocked hosts list
            if decision["action"] == "BLOCK":
                self.socketio.emit("blocked_hosts_update", redis_store.get_blocked_ips())

    def start(self, iface=None):
        if iface is None:
            iface = detect_best_interface()

        def _run():
            print(f"[Capture] Sniffing live on: {iface}")
            try:
                sniff(iface=iface, prn=self._on_packet, store=False)
            except PermissionError:
                print(f"[Capture] Notice: Raw packet sniffing requires root/sudo permissions.")
                print(f"[Capture] Entering safe simulation mode.")
            except Exception as e:
                print(f"[Capture] Sniffing error: {e}")

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        self.sniff_thread = t
        print("[Capture] Packet capture & IPS thread started.")
        return t

    def simulate_attack_event(self, attack_type: str, src_ip: str, dst_port: int = 80):
        """
        Simulates an incoming flow with the given attack label for live testing & demonstration.
        """
        now = time.time()
        flow = Flow(src_ip, 54321, "192.168.31.129", dst_port, "tcp")
        flow.src_bytes = 125000 if attack_type == "DoS" else 1500
        flow.dst_bytes = 540
        flow.pkts = [
            {"t": now - 1.0, "size": 1500},
            {"t": now, "size": 1500}
        ]
        flow.flags = [0x02, 0x10]  # SYN, ACK
        self._classify_flow(flow)

def start_capture(predictor, socketio, stats, class_counts, alert_log, iface=None):
    engine = PacketCapture(predictor, socketio, stats, class_counts, alert_log)
    engine.start(iface)
    return engine