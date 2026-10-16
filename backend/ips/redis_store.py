"""
redis_store.py — Real-Time State & Rate Limiting Storage for IPS
Handles sliding-window packet counts, port-scan detection, temporary blocklists,
and action logs with automatic TTL expiration.
"""

import json
import time
from typing import List, Dict, Optional
import redis

REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379

class IPSRedisStore:
    def __init__(self, host: str = REDIS_HOST, port: int = REDIS_PORT):
        self.host = host
        self.port = port
        self.client: Optional[redis.Redis] = None
        self._memory_blocks: Dict[str, dict] = {}
        self._memory_actions: List[dict] = []
        self._memory_packets: Dict[str, list] = {}
        self._memory_ports: Dict[str, dict] = {}
        self._connect()

    def _connect(self):
        try:
            r = redis.Redis(
                host=self.host,
                port=self.port,
                decode_responses=True,
                socket_timeout=1.5,
                socket_connect_timeout=1.5
            )
            r.ping()
            self.client = r
            print(f"[IPSRedisStore] Connected to Redis at {self.host}:{self.port}")
        except Exception as e:
            self.client = None
            print(f"[IPSRedisStore] Warning: Redis unavailable ({e}). Using in-memory fallback.")

    @property
    def is_connected(self) -> bool:
        if self.client is None:
            return False
        try:
            return bool(self.client.ping())
        except Exception:
            return False

    # ── Sliding-Window Rate Tracking (for DoS Detection) ──────
    def record_packet(self, src_ip: str, dst_port: int, pkt_size: int = 0) -> int:
        """
        Records an incoming packet from src_ip and returns current packet count in the last 5s.
        """
        now = time.time()
        window_sec = 5.0

        if self.client:
            try:
                rate_key = f"ips:rate:{src_ip}"
                pipe = self.client.pipeline()
                # Store timestamp as score and unique member
                pipe.zadd(rate_key, {f"{now}:{pkt_size}": now})
                # Remove timestamps older than window
                pipe.zremrangebyscore(rate_key, 0, now - window_sec)
                # Count current elements in window
                pipe.zcard(rate_key)
                # Set TTL on the set
                pipe.expire(rate_key, int(window_sec * 2))
                results = pipe.execute()
                count = results[2]

                # Also track destination ports for port-scan detection
                port_key = f"ips:ports:{src_ip}"
                self.client.sadd(port_key, dst_port)
                self.client.expire(port_key, 15)

                return count
            except Exception:
                pass

        # In-memory fallback
        if src_ip not in self._memory_packets:
            self._memory_packets[src_ip] = []
        timestamps = self._memory_packets[src_ip]
        timestamps.append(now)
        # Prune old timestamps
        cutoff = now - window_sec
        self._memory_packets[src_ip] = [t for t in timestamps if t >= cutoff]

        if src_ip not in self._memory_ports:
            self._memory_ports[src_ip] = set()
        self._memory_ports[src_ip].add(dst_port)

        return len(self._memory_packets[src_ip])

    def get_packet_rate(self, src_ip: str, window_sec: float = 5.0) -> float:
        """Returns packets per second for src_ip over the window."""
        now = time.time()
        if self.client:
            try:
                rate_key = f"ips:rate:{src_ip}"
                count = self.client.zcount(rate_key, now - window_sec, now)
                return round(count / max(window_sec, 1.0), 2)
            except Exception:
                pass

        timestamps = self._memory_packets.get(src_ip, [])
        valid = [t for t in timestamps if t >= (now - window_sec)]
        return round(len(valid) / max(window_sec, 1.0), 2)

    def get_unique_ports_count(self, src_ip: str) -> int:
        """Returns count of distinct ports accessed by src_ip recently (Probe detection)."""
        if self.client:
            try:
                port_key = f"ips:ports:{src_ip}"
                return self.client.scard(port_key) or 0
            except Exception:
                pass
        return len(self._memory_ports.get(src_ip, set()))

    # ── Temporary Blocklist with TTL ──────────────────────────
    def block_ip(self, ip: str, duration: int = 300, reason: str = "", attack_type: str = "") -> dict:
        """
        Adds IP to blocklist with specified duration in seconds.
        """
        now = time.time()
        block_info = {
            "ip": ip,
            "reason": reason,
            "attack_type": attack_type,
            "blocked_at": int(now),
            "duration": int(duration),
            "expires_at": int(now + duration)
        }

        if self.client:
            try:
                key = f"ips:blocked:{ip}"
                self.client.set(key, json.dumps(block_info), ex=duration)
                self.client.sadd("ips:active_blocks", ip)
            except Exception as e:
                print(f"[IPSRedisStore] Redis block error: {e}")

        self._memory_blocks[ip] = block_info
        return block_info

    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP."""
        if self.client:
            try:
                self.client.delete(f"ips:blocked:{ip}")
                self.client.srem("ips:active_blocks", ip)
            except Exception:
                pass
        if ip in self._memory_blocks:
            del self._memory_blocks[ip]
            return True
        return True

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is actively blocked."""
        if self.client:
            try:
                return bool(self.client.exists(f"ips:blocked:{ip}"))
            except Exception:
                pass
        if ip in self._memory_blocks:
            info = self._memory_blocks[ip]
            if time.time() < info["expires_at"]:
                return True
            else:
                del self._memory_blocks[ip]
                return False
        return False

    def get_blocked_ips(self) -> List[dict]:
        """Returns all actively blocked IPs with remaining TTL in seconds."""
        now = time.time()
        active = []

        if self.client:
            try:
                ips = self.client.smembers("ips:active_blocks")
                expired = []
                for ip in ips:
                    raw = self.client.get(f"ips:blocked:{ip}")
                    if raw:
                        data = json.loads(raw)
                        remaining = max(0, int(data.get("expires_at", now) - now))
                        data["ttl_remaining"] = remaining
                        active.append(data)
                    else:
                        expired.append(ip)
                if expired:
                    self.client.srem("ips:active_blocks", *expired)
                return sorted(active, key=lambda x: x.get("blocked_at", 0), reverse=True)
            except Exception:
                pass

        # Fallback to memory
        clean_memory = {}
        for ip, data in self._memory_blocks.items():
            remaining = max(0, int(data.get("expires_at", now) - now))
            if remaining > 0:
                data["ttl_remaining"] = remaining
                active.append(data)
                clean_memory[ip] = data
        self._memory_blocks = clean_memory
        return sorted(active, key=lambda x: x.get("blocked_at", 0), reverse=True)

    def clear_all_blocks(self):
        """Flushes all IPS blocks from Redis."""
        if self.client:
            try:
                ips = self.client.smembers("ips:active_blocks")
                for ip in ips:
                    self.client.delete(f"ips:blocked:{ip}")
                self.client.delete("ips:active_blocks")
            except Exception:
                pass
        self._memory_blocks.clear()

    # ── Action Audit Log ──────────────────────────────────────
    def log_action(self, action_data: dict):
        """Appends an IPS action (ALLOW, RATE_LIMIT, BLOCK, DROP) to history."""
        action_data["timestamp"] = action_data.get("timestamp", time.strftime("%H:%M:%S"))
        if self.client:
            try:
                self.client.lpush("ips:action_log", json.dumps(action_data))
                self.client.ltrim("ips:action_log", 0, 199)
            except Exception:
                pass
        self._memory_actions.insert(0, action_data)
        if len(self._memory_actions) > 200:
            self._memory_actions = self._memory_actions[:200]

    def get_action_history(self, limit: int = 50) -> List[dict]:
        """Retrieves recent IPS action events."""
        if self.client:
            try:
                items = self.client.lrange("ips:action_log", 0, limit - 1)
                return [json.loads(x) for x in items]
            except Exception:
                pass
        return self._memory_actions[:limit]

# Global store singleton
redis_store = IPSRedisStore()
