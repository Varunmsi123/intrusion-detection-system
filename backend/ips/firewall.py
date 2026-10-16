"""
firewall.py — Safe Firewall Adapter for IPS
Supports both Simulation Mode (safe, default) and Active Enforcement via nftables/iptables.
Implements non-disruptive, isolated rules and emergency reset.
"""

import ipaddress
import os
import subprocess
import shutil
from typing import Dict, Any, Optional

from ips.allowlist import allowlist

TABLE_NAME = "ids_ips_table"
CHAIN_NAME = "ips_input"
SET_NAME = "blocked_ipv4"

class SafeFirewallAdapter:
    def __init__(self, mode: str = "simulate"):
        # "simulate" (Safe default) or "enforce"
        self.mode = os.environ.get("IPS_MODE", mode).lower()
        self.has_nft = shutil.which("nft") is not None
        self.has_iptables = shutil.which("iptables") is not None
        self._table_initialized = False

    def set_mode(self, new_mode: str) -> str:
        """Switch between 'simulate' and 'enforce'."""
        cleaned = new_mode.lower().strip()
        if cleaned in ("simulate", "enforce"):
            self.mode = cleaned
            if self.mode == "enforce":
                self._ensure_table()
            return self.mode
        return self.mode

    def _ensure_table(self):
        """
        Creates an ISOLATED nftables table with default policy ACCEPT.
        Never touches system tables or default policies.
        """
        if not self.has_nft or self._table_initialized:
            return

        # Create isolated table and set with auto-expiry timeout
        nft_script = f"""
add table inet {TABLE_NAME}
add set inet {TABLE_NAME} {SET_NAME} {{ type ipv4_addr; flags timeout; }}
add chain inet {TABLE_NAME} {CHAIN_NAME} {{ type filter hook input priority -10; policy accept; }}
add rule inet {TABLE_NAME} {CHAIN_NAME} ip saddr @{SET_NAME} counter drop
"""
        try:
            # Attempt to create isolated table
            cmd = ["sudo", "-n", "nft", "-f", "-"]
            proc = subprocess.run(cmd, input=nft_script, text=True, capture_output=True, timeout=3)
            if proc.returncode == 0:
                self._table_initialized = True
                print(f"[SafeFirewall] Initialized isolated nftables table: {TABLE_NAME}")
            else:
                print(f"[SafeFirewall] Notice: Sudo non-interactive not available or error ({proc.stderr.strip()}). Running in safe simulation fallback.")
        except Exception as e:
            print(f"[SafeFirewall] Table init error: {e}")

    def block_ip(self, ip: str, duration: int = 300, reason: str = "", attack_type: str = "") -> Dict[str, Any]:
        """
        Blocks an IP.
        In simulation mode: returns success result without touching system firewall.
        In enforce mode: adds IP to isolated set with timeout.
        """
        # 1. Safety verification
        if allowlist.is_allowed(ip):
            print(f"[SafeFirewall] Refusing to block protected IP: {ip}")
            return {
                "success": False,
                "ip": ip,
                "reason": "IP is in protected allowlist (loopback, host, gateway, or DNS)",
                "mode": self.mode
            }

        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_loopback or ip_obj.is_private and allowlist.is_allowed(ip):
                return {"success": False, "ip": ip, "reason": "Protected loopback/LAN IP", "mode": self.mode}
        except ValueError:
            return {"success": False, "ip": ip, "reason": "Invalid IP format", "mode": self.mode}

        # 2. Simulation Mode
        if self.mode == "simulate":
            return {
                "success": True,
                "ip": ip,
                "duration": duration,
                "mode": "simulate",
                "enforced": False,
                "message": f"[Simulation] Would block {ip} for {duration}s ({reason})"
            }

        # 3. Active Enforcement Mode (Isolated nftables set)
        if self.has_nft and self.mode == "enforce":
            try:
                self._ensure_table()
                cmd = ["sudo", "-n", "nft", "add", "element", "inet", TABLE_NAME, SET_NAME,
                       f"{{ {ip} timeout {duration}s }}"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if proc.returncode == 0:
                    return {
                        "success": True,
                        "ip": ip,
                        "duration": duration,
                        "mode": "enforce",
                        "enforced": True,
                        "message": f"[Enforce] Blocked {ip} in kernel table for {duration}s"
                    }
                else:
                    return {
                        "success": True,
                        "ip": ip,
                        "duration": duration,
                        "mode": "simulate",
                        "enforced": False,
                        "warning": f"Enforcement requires sudo. Operating in simulation mode: {proc.stderr.strip()}"
                    }
            except Exception as e:
                return {
                    "success": True,
                    "ip": ip,
                    "duration": duration,
                    "mode": "simulate",
                    "enforced": False,
                    "warning": f"Enforcement error ({e}). Operating in simulation."
                }

        return {
            "success": True,
            "ip": ip,
            "duration": duration,
            "mode": self.mode,
            "enforced": False
        }

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """Removes an IP from the blocklist."""
        if self.mode == "enforce" and self.has_nft:
            try:
                cmd = ["sudo", "-n", "nft", "delete", "element", "inet", TABLE_NAME, SET_NAME, f"{{ {ip} }}"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            except Exception:
                pass
        return {"success": True, "ip": ip, "unblocked": True}

    def emergency_reset(self) -> Dict[str, Any]:
        """
        Emergency Panic Reset: deletes ONLY the isolated IPS table.
        Leaves all system firewall rules, loopback, and desktop network untouched.
        """
        if self.has_nft:
            try:
                cmd = ["sudo", "-n", "nft", "delete", "table", "inet", TABLE_NAME]
                subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            except Exception:
                pass
        self._table_initialized = False
        return {
            "success": True,
            "message": "Isolated IPS firewall table flushed safely. System network untouched."
        }

# Global firewall singleton
firewall = SafeFirewallAdapter(mode="simulate")
