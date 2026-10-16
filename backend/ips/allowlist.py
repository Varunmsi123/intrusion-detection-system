"""
allowlist.py — Dynamic Safe Allowlist Manager for IPS
Ensures critical local, gateway, DNS, and loopback IPs are NEVER blocked.
This prevents any accidental system lockout, session closing, or network cutoff on Linux/Fedora.
"""

import ipaddress
import os
import socket
import subprocess
from typing import Set

# Dynamic default protected networks/addresses
DEFAULT_PROTECTED_RANGES = [
    "127.0.0.0/8",      # Loopback (Wayland, X11, D-Bus, IPC, local sockets)
    "::1/128",          # IPv6 Loopback
    "169.254.0.0/16",   # Link-Local
    "224.0.0.0/4",      # Multicast
    "255.255.255.255/32"# Broadcast
]

class DynamicAllowlist:
    def __init__(self):
        self.exact_ips: Set[str] = set()
        self.ip_networks = []
        self._custom_ips: Set[str] = set()
        self.refresh()

    def refresh(self):
        """Dynamically discovers host IP, default gateway, DNS servers, and network interfaces."""
        self.exact_ips.clear()
        self.ip_networks.clear()

        # Add predefined safe ranges
        for cidr in DEFAULT_PROTECTED_RANGES:
            try:
                self.ip_networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                pass

        # 1. Discover local host IPs from all network interfaces
        try:
            # Query hostname IPs
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                ip = info[4][0]
                self.exact_ips.add(ip)
        except Exception:
            pass

        # 2. Add local routing IP & Gateway
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connect to a public IP (doesn't send packets, just determines outgoing route)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            self.exact_ips.add(local_ip)
            s.close()
        except Exception:
            pass

        # 3. Read default gateway and DNS servers on Linux
        if os.path.exists("/etc/resolv.conf"):
            try:
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                self.exact_ips.add(parts[1])
            except Exception:
                pass

        # 4. Check Linux ip route for default gateway
        try:
            out = subprocess.check_output(["ip", "route", "show", "default"], stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        self.exact_ips.add(parts[idx + 1])
        except Exception:
            pass

        # 5. Add custom environment / user defined allowlist
        env_allowlist = os.environ.get("IPS_ALLOWLIST", "")
        if env_allowlist:
            for item in env_allowlist.split(","):
                item = item.strip()
                if item:
                    self._custom_ips.add(item)

        for ip in self._custom_ips:
            self.exact_ips.add(ip)

    def add_ip(self, ip: str):
        """Manually allow an IP."""
        cleaned = ip.strip()
        if cleaned:
            self._custom_ips.add(cleaned)
            self.exact_ips.add(cleaned)

    def is_allowed(self, ip_str: str) -> bool:
        """
        Check if an IP address is protected.
        Returns True if the IP is safe/whitelisted and MUST NOT be blocked.
        """
        if not ip_str or not isinstance(ip_str, str):
            return True

        ip_clean = ip_str.strip()

        # Check exact matches (Host IP, Gateway, DNS, localhost)
        if ip_clean in self.exact_ips or ip_clean in ("127.0.0.1", "::1", "localhost", "0.0.0.0"):
            return True

        # Check subnet networks
        try:
            ip_obj = ipaddress.ip_address(ip_clean)
            for net in self.ip_networks:
                if ip_obj in net:
                    return True
        except ValueError:
            # If not a valid IP, do not block blindly
            return True

        return False

    def get_summary(self) -> dict:
        """Returns allowlist information for the dashboard."""
        return {
            "exact_ips": sorted(list(self.exact_ips)),
            "protected_subnets": [str(net) for net in self.ip_networks],
            "total_protected": len(self.exact_ips) + len(self.ip_networks)
        }

# Global singleton
allowlist = DynamicAllowlist()
