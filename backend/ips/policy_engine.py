"""
policy_engine.py — IPS Threat Assessment & Policy Decision Engine
Maps ML classifications and real-time Redis traffic metrics to actionable
defense decisions: ALLOW, RATE_LIMIT, BLOCK, and DROP.
"""

from datetime import datetime
from typing import Dict, Any

from ips.allowlist import allowlist
from ips.redis_store import redis_store
from ips.firewall import firewall

# Configurable policy thresholds
MIN_CONFIDENCE_THRESHOLD = 0.65
DOS_BURST_THRESHOLD_PPS  = 25.0
DOS_BLOCK_THRESHOLD_PPS  = 60.0
PROBE_MAX_PORTS_COUNT    = 5

class IPSPolicyEngine:
    def __init__(self):
        pass

    def evaluate(self, src_ip: str, dst_ip: str, dst_port: int,
                 proto: str, service: str, label: str, confidence: float) -> Dict[str, Any]:
        """
        Evaluates a classified flow against IPS policies and real-time metrics.
        Returns the structured policy decision.
        """
        now_str = datetime.now().strftime("%H:%M:%S")

        # 1. Check Allowlist (Strict Protection)
        if allowlist.is_allowed(src_ip):
            decision = {
                "action": "ALLOW",
                "ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "attack_type": label,
                "confidence": round(confidence, 4),
                "reason": "Host/Loopback/Gateway IP is in protected allowlist",
                "duration": 0,
                "timestamp": now_str,
                "mode": firewall.mode
            }
            redis_store.log_action(decision)
            return decision

        # 2. Check if already actively blocked
        if redis_store.is_blocked(src_ip):
            decision = {
                "action": "DROP",
                "ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "attack_type": label,
                "confidence": round(confidence, 4),
                "reason": "Source IP is actively blocked in IPS blocklist",
                "duration": 0,
                "timestamp": now_str,
                "mode": firewall.mode
            }
            redis_store.log_action(decision)
            return decision

        # 3. Normal traffic check
        if label == "Normal":
            decision = {
                "action": "ALLOW",
                "ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "attack_type": "Normal",
                "confidence": round(confidence, 4),
                "reason": "Legitimate baseline traffic",
                "duration": 0,
                "timestamp": now_str,
                "mode": firewall.mode
            }
            return decision

        # 4. Low confidence check (Prevent false positives)
        if confidence < MIN_CONFIDENCE_THRESHOLD:
            decision = {
                "action": "ALLOW",
                "ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "attack_type": label,
                "confidence": round(confidence, 4),
                "reason": f"Confidence ({confidence*100:.1f}%) below threshold ({MIN_CONFIDENCE_THRESHOLD*100:.0f}%)",
                "duration": 0,
                "timestamp": now_str,
                "mode": firewall.mode
            }
            redis_store.log_action(decision)
            return decision

        # 5. Attack-Specific Policy Evaluation
        pkt_rate = redis_store.get_packet_rate(src_ip)
        unique_ports = redis_store.get_unique_ports_count(src_ip)

        action = "ALLOW"
        duration = 0
        reason = ""

        if label == "DoS":
            if pkt_rate >= DOS_BLOCK_THRESHOLD_PPS or (confidence >= 0.90 and pkt_rate >= 15.0) or confidence >= 0.95:
                action = "BLOCK"
                duration = 180  # 3 minutes
                reason = f"High-volume DoS flood ({pkt_rate:.1f} pkts/s, {confidence*100:.1f}% conf)"
            else:
                action = "RATE_LIMIT"
                reason = f"Suspicious traffic volume ({pkt_rate:.1f} pkts/s) - applying rate limit"

        elif label == "Probe":
            if unique_ports >= 4 or (confidence >= 0.90 and unique_ports >= 3):
                action = "BLOCK"
                duration = 300  # 5 minutes
                reason = f"Port scanning detected ({unique_ports} ports accessed, {confidence*100:.1f}% conf)"
            else:
                action = "RATE_LIMIT"
                reason = f"Reconnaissance scan on port {dst_port} ({unique_ports} target ports)"

        elif label == "R2L":
            if confidence >= 0.75:
                action = "BLOCK"
                duration = 600  # 10 minutes
                reason = f"Remote-to-Local exploit attempt on {service} ({confidence*100:.1f}% conf)"
            else:
                action = "RATE_LIMIT"
                reason = f"Suspicious remote access attempt on {service}"

        elif label == "U2R":
            # High priority local privilege escalation
            action = "BLOCK"
            duration = 600  # 10 minutes
            reason = f"High-severity User-to-Root anomaly on {service} ({confidence*100:.1f}% conf)"

        # 6. Apply enforcement if BLOCK
        if action == "BLOCK" and duration > 0:
            redis_store.block_ip(src_ip, duration=duration, reason=reason, attack_type=label)
            firewall.block_ip(src_ip, duration=duration, reason=reason, attack_type=label)

        decision = {
            "action": action,
            "ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "attack_type": label,
            "confidence": round(confidence, 4),
            "reason": reason,
            "duration": duration,
            "packet_rate": pkt_rate,
            "ports_scanned": unique_ports,
            "timestamp": now_str,
            "mode": firewall.mode
        }

        redis_store.log_action(decision)
        return decision

# Global policy engine singleton
policy_engine = IPSPolicyEngine()
