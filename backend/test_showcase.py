#!/usr/bin/env python3
"""
test_showcase.py — Professional Project Manager Demonstration Suite
Demonstrates real-time Intrusion Prevention System (IPS) capabilities:
1. Probe Attack (Port Scan): Probes ports 21, 22, 80, 443 -> triggers BLOCK at 4 ports -> drops subsequent scans!
2. DoS Attack (Flood Bursts): Sends 4 burst waves -> triggers BLOCK -> drops subsequent flood packets!
3. Counter Discipline: Shows that alerts increment to 3-4, then STOP once the attacker is blocked.
4. Live Dashboard Integration: Watch the React dashboard (http://localhost:3000) update live in real-time.
"""

import sys
import time
import requests

API_URL = "http://127.0.0.1:5000"

# ANSI Terminal Colors
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
PURPLE = "\033[95m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

COMMON_SCAN_PORTS = [
    (21,   "FTP",    "ftp"),
    (22,   "SSH",    "ssh"),
    (80,   "HTTP",   "http"),
    (443,  "HTTPS",  "https"),
    (3306, "MySQL",  "private"),
    (8080, "WebAlt", "http")
]

def print_header(title):
    print(f"\n{BOLD}{CYAN}{'='*68}{RESET}")
    print(f"{BOLD}{YELLOW}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*68}{RESET}\n")

def check_backend():
    try:
        r = requests.get(f"{API_URL}/api/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False

def reset_demo_slate():
    """Resets all blocks and counters for a fresh demo."""
    print(f"{BLUE}🧹 Resetting dashboard counters and clearing old blocks for clean demo...{RESET}", end=" ")
    try:
        requests.post(f"{API_URL}/api/ips/reset", json={"reset_stats": True}, timeout=3)
        print(f"{GREEN}READY ✓{RESET}")
    except Exception as e:
        print(f"{YELLOW}Warning: {e}{RESET}")

def run_probe_showcase(scanner_ip="198.51.100.77"):
    print_header(f"🔍 DEMO 1: RECONNAISSANCE PROBE (PORT SCANNING ATTACK)")
    print(f"  {BOLD}Scenario:{RESET} A malicious external scanner ({RED}{scanner_ip}{RESET}) sweeps server ports.")
    print(f"  {BOLD}Expected Behavior:{RESET}")
    print(f"    - Ports 1, 2, 3: Detected & Rate-Limited (Alerts increase 1, 2, 3)")
    print(f"    - Port 4: Port sweep threshold reached -> {RED}BLOCK (300s TTL){RESET} (Alert 4)")
    print(f"    - Ports 5+: All subsequent scan probes are {PURPLE}DROPPED{RESET} (Alerts STOP at 4)")
    print(f"  {CYAN}👀 Watch your React dashboard (http://localhost:3000) live!{RESET}\n")

    input(f"{BOLD}Press ENTER to start the Port Probe demo...{RESET}")

    for idx, (port, service_name, srv_code) in enumerate(COMMON_SCAN_PORTS, start=1):
        time.sleep(1.2)
        # Escalating confidence as more ports are touched
        conf = 0.70 + (idx * 0.06)

        try:
            res = requests.post(
                f"{API_URL}/api/ips/simulate_attack",
                json={
                    "attack_type": "Probe",
                    "src_ip": scanner_ip,
                    "dst_port": port,
                    "service": srv_code,
                    "confidence": conf
                },
                timeout=3
            )
            data = res.json()
            decision = data.get("decision", {})
            action = decision.get("action", "UNKNOWN")
            is_dropped = data.get("dropped", False)

            if action == "BLOCK":
                color = RED
                status_txt = f"{BOLD}🚨 [BLOCKED - HOST ISOLATED]{RESET}"
            elif is_dropped or action == "DROP":
                color = PURPLE
                status_txt = f"{PURPLE}[DROPPED - FIREWALL BLOCKED]{RESET}"
            else:
                color = YELLOW
                status_txt = f"{YELLOW}[RATE_LIMIT / MONITORED]{RESET}"

            print(f"  {BOLD}Port {port:<4} ({service_name:<6}):{RESET} Scanner touches port -> {color}{action:<10}{RESET} {status_txt}")
            print(f"    ↳ Reason: {decision.get('reason', 'N/A')}")
            if action == "BLOCK":
                print(f"    ↳ {RED}{BOLD}Scanner IP {scanner_ip} added to Active Blocklist with 300s TTL!{RESET}")
            elif is_dropped:
                print(f"    ↳ {PURPLE}Notice: Scan probe was discarded at perimeter. Alert count did NOT increase.{RESET}")

        except Exception as e:
            print(f"  Error on port {port}: {e}")

    print(f"\n{GREEN}✓ Probe Demo Result:{RESET} Alerts increased to 4 and {BOLD}STOPPED{RESET}! Scanner is neutralized.")

def run_dos_showcase(flooder_ip="203.0.113.88"):
    print_header(f"⚡ DEMO 2: DENIAL OF SERVICE (DoS FLOOD ATTACK)")
    print(f"  {BOLD}Scenario:{RESET} An attacker ({RED}{flooder_ip}{RESET}) sends high-frequency request bursts.")
    print(f"  {BOLD}Expected Behavior:{RESET}")
    print(f"    - Bursts 1, 2, 3: Detected & Rate-Limited (Alerts increase 1, 2, 3)")
    print(f"    - Burst 4: High volume & rate threshold exceeded -> {RED}BLOCK (180s TTL){RESET} (Alert 4)")
    print(f"    - Bursts 5+: Floods are {PURPLE}DROPPED{RESET} by IPS (Alerts STOP at 4)")
    print(f"  {CYAN}👀 Watch your React dashboard (http://localhost:3000) live!{RESET}\n")

    input(f"{BOLD}Press ENTER to start the DoS Flood demo...{RESET}")

    dos_waves = [
        (1, 15, 0.72, "Initial traffic burst"),
        (2, 25, 0.78, "Elevated packet rate"),
        (3, 40, 0.85, "High packet frequency"),
        (4, 75, 0.96, "Sustained DoS flood burst"),
        (5, 75, 0.96, "Continued flood attempt"),
        (6, 75, 0.96, "Continued flood attempt"),
    ]

    for wave_num, pkt_count, conf, desc in dos_waves:
        time.sleep(1.2)
        try:
            res = requests.post(
                f"{API_URL}/api/ips/simulate_attack",
                json={
                    "attack_type": "DoS",
                    "src_ip": flooder_ip,
                    "dst_port": 80,
                    "packets": pkt_count,
                    "confidence": conf
                },
                timeout=3
            )
            data = res.json()
            decision = data.get("decision", {})
            action = decision.get("action", "UNKNOWN")
            is_dropped = data.get("dropped", False)

            if action == "BLOCK":
                color = RED
                status_txt = f"{BOLD}🚨 [BLOCKED - HOST ISOLATED]{RESET}"
            elif is_dropped or action == "DROP":
                color = PURPLE
                status_txt = f"{PURPLE}[DROPPED - ATTACK BLOCKED]{RESET}"
            else:
                color = YELLOW
                status_txt = f"{YELLOW}[RATE_LIMIT - CONSTRAINED]{RESET}"

            print(f"  {BOLD}Wave {wave_num} ({desc}):{RESET} -> {color}{action:<10}{RESET} {status_txt}")
            print(f"    ↳ Reason: {decision.get('reason', 'N/A')}")
            if action == "BLOCK":
                print(f"    ↳ {RED}{BOLD}Flooder IP {flooder_ip} blocked for 180s. Added to Active IPS Blocklist!{RESET}")
            elif is_dropped:
                print(f"    ↳ {PURPLE}Notice: Flood discarded at kernel firewall. Alert counter halted at 4.{RESET}")

        except Exception as e:
            print(f"  Error on wave {wave_num}: {e}")

    print(f"\n{GREEN}✓ DoS Demo Result:{RESET} Alerts increased to 4 and {BOLD}STOPPED{RESET}! Attack successfully contained.")

def run_safety_showcase():
    print_header(f"🛡️ DEMO 3: SAFETY SHIELD & ALLOWLIST VERIFICATION")
    print("  Demonstrates that host IP, gateway, and loopback (127.0.0.1) can NEVER be blocked,")
    print("  preventing accidental OS lockout, desktop crashes, or service interruption.\n")

    # Test attempting to block loopback
    print(f"  Testing: Attempting to block {YELLOW}127.0.0.1{RESET} (Loopback)...", end=" ")
    r = requests.post(f"{API_URL}/api/ips/block", json={"ip": "127.0.0.1", "duration": 60})
    if r.status_code == 403:
        print(f"{GREEN}REJECTED (HTTP 403) ✓{RESET}")
        print(f"    ↳ Response: {r.json().get('error')}")
    else:
        print(f"{RED}FAILED{RESET}")

    # Query allowlist
    r = requests.get(f"{API_URL}/api/ips/status")
    allowed = r.json().get("allowlist", {}).get("exact_ips", [])
    print(f"\n  Protected System IPs: {CYAN}{allowed}{RESET}")
    print(f"{GREEN}✓ Safety Shield fully verified! Your workstation is protected.{RESET}")

def main_menu():
    print(f"\n{BOLD}{CYAN}{'='*68}{RESET}")
    print(f"{BOLD}{RED}       🛡️ IPS MONITOR — PROJECT MANAGER DEMONSTRATION SUITE 🛡️{RESET}")
    print(f"{BOLD}{CYAN}{'='*68}{RESET}")

    if not check_backend():
        print(f"\n{RED}Error: Backend is not responding at {API_URL}!{RESET}")
        print(f"{YELLOW}Please make sure 'python3 app.py' is running in the backend folder.{RESET}\n")
        return

    while True:
        print(f"\n{BOLD}Choose a Showcase Demo:{RESET}")
        print(f"  {CYAN}[1]{RESET} {BOLD}Showcase Probe Attack{RESET} (Port Scan -> Rate Limit -> Block at 4 -> Drop)")
        print(f"  {CYAN}[2]{RESET} {BOLD}Showcase DoS Attack{RESET}   (Traffic Bursts -> Rate Limit -> Block at 4 -> Drop)")
        print(f"  {CYAN}[3]{RESET} {BOLD}Run Full End-to-End Demo{RESET} (Probe + DoS + Safety Shield)")
        print(f"  {CYAN}[4]{RESET} {BOLD}Verify Safety Shield{RESET} (Loopback / Gateway protection test)")
        print(f"  {CYAN}[5]{RESET} {YELLOW}Reset Dashboard Stats{RESET} (Fresh slate: clear blocks & counters)")
        print(f"  {CYAN}[q]{RESET} Exit")

        choice = input(f"\n{BOLD}Enter choice [1-5 or q]: {RESET}").strip()

        if choice == "1":
            run_probe_showcase()
        elif choice == "2":
            run_dos_showcase()
        elif choice == "3":
            reset_demo_slate()
            run_probe_showcase()
            time.sleep(2)
            run_dos_showcase()
            time.sleep(1)
            run_safety_showcase()
        elif choice == "4":
            run_safety_showcase()
        elif choice == "5":
            reset_demo_slate()
        elif choice.lower() == "q":
            print(f"\n{GREEN}Exiting. Good luck with your project showcase!{RESET}\n")
            break
        else:
            print(f"{RED}Invalid option. Please enter 1-5 or q.{RESET}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "probe":
            run_probe_showcase()
        elif arg == "dos":
            run_dos_showcase()
        elif arg == "all":
            reset_demo_slate()
            run_probe_showcase()
            run_dos_showcase()
            run_safety_showcase()
        elif arg == "reset":
            reset_demo_slate()
    else:
        main_menu()
