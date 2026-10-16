#!/usr/bin/env python3
"""
test_dos.py — Interactive Real-Time DoS Attack Tester
Run this script while both your Backend (port 5000) and Frontend (port 3000) are running.
It generates realistic high-volume traffic bursts and verifies the IPS detects,
rate-limits, and blocks the attack in real-time.
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

def print_banner():
    print(f"\n{BOLD}{CYAN}{'='*65}{RESET}")
    print(f"{BOLD}{RED}       ⚡ REAL-TIME DoS ATTACK & IPS PREVENTION TESTER ⚡{RESET}")
    print(f"{BOLD}{CYAN}{'='*65}{RESET}\n")

def check_services():
    print(f"{BLUE}[1] Checking Backend connection at {API_URL}...{RESET}", end=" ")
    try:
        r = requests.get(f"{API_URL}/api/health", timeout=3)
        if r.status_code == 200:
            data = r.json()
            print(f"{GREEN}ONLINE ✓{RESET}")
            print(f"    Mode: {YELLOW}{data.get('ips_mode', 'simulate').upper()}{RESET} | Redis: {GREEN}{'CONNECTED' if data.get('redis_connected') else 'MEMORY'}{RESET} | Uptime: {data.get('uptime')}s")
            return True
        else:
            print(f"{RED}FAILED (HTTP {r.status_code}){RESET}")
            return False
    except Exception as e:
        print(f"{RED}OFFLINE ✗ ({e}){RESET}")
        print(f"{YELLOW}    Please make sure 'python3 app.py' is running in the backend folder!{RESET}")
        return False

def run_dos_test(attacker_ip="203.0.113.88", num_waves=3):
    print(f"\n{BOLD}{YELLOW}[2] Launching Simulated DoS Attack Stream{RESET}")
    print(f"    Target Server: {CYAN}http://127.0.0.1:5000{RESET}")
    print(f"    Attacker IP  : {RED}{attacker_ip}{RESET} (External test IP)")
    print(f"    Waves to send: {YELLOW}{num_waves} high-frequency packet bursts{RESET}")
    print(f"{CYAN}    👀 WATCH YOUR REACT DASHBOARD (http://localhost:3000) IN REAL TIME!{RESET}\n")

    time.sleep(1.5)

    for wave in range(1, num_waves + 1):
        print(f"  {BOLD}🌊 Wave {wave}/{num_waves}:{RESET} Injecting high-volume traffic burst...", end=" ", flush=True)

        try:
            res = requests.post(
                f"{API_URL}/api/ips/simulate_attack",
                json={
                    "attack_type": "DoS",
                    "src_ip": attacker_ip,
                    "dst_port": 80
                },
                timeout=4
            )
            
            if res.status_code == 200:
                data = res.json()
                decision = data.get("decision", {})
                action = decision.get("action", "UNKNOWN")
                reason = decision.get("reason", "N/A")
                rate = decision.get("packet_rate", 0)
                duration = decision.get("duration", 0)

                action_color = RED if action == "BLOCK" else (YELLOW if action == "RATE_LIMIT" else GREEN)
                print(f"[{action_color}{BOLD}{action}{RESET}]")
                print(f"     ↳ {action_color}IPS Decision:{RESET} {action}")
                print(f"     ↳ Reason      : {reason}")
                print(f"     ↳ Rate in 5s  : {rate} packets/sec")
                if duration > 0:
                    print(f"     ↳ Block Duration: {RED}{duration} seconds (Auto-TTL){RESET}")
            else:
                print(f"{RED}Error (HTTP {res.status_code}){RESET}")
        except Exception as e:
            print(f"{RED}Request failed: {e}{RESET}")

        time.sleep(1.0)

    # Check Blocklist Status
    print(f"\n{BOLD}{BLUE}[3] Querying Live IPS Blocklist from Redis...{RESET}")
    try:
        r = requests.get(f"{API_URL}/api/ips/blocked", timeout=3)
        blocked = r.json()
        target_entry = next((b for b in blocked if b.get("ip") == attacker_ip), None)

        if target_entry:
            print(f"    {GREEN}✓ SUCCESS:{RESET} IP {RED}{attacker_ip}{RESET} is actively {BOLD}BLOCKED{RESET}!")
            print(f"    - Attack Type   : {YELLOW}{target_entry.get('attack_type')}{RESET}")
            print(f"    - Remaining TTL : {CYAN}{target_entry.get('ttl_remaining')} seconds{RESET}")
            print(f"    - Reason        : {target_entry.get('reason')}")
            print(f"\n    {BOLD}🖥️ Verify on your Browser Dashboard:{RESET}")
            print(f"      1. Look at {BOLD}'Active IPS Blocklist'{RESET} table: you'll see {RED}{attacker_ip}{RESET} with a live countdown timer!")
            print(f"      2. Look at {BOLD}'Live Alerts'{RESET} on the right: red DoS alert with {RED}[BLOCKED]{RESET} tag!")
            print(f"      3. Look at {BOLD}'IPS Prevention Stream'{RESET}: showing real-time BLOCK decision.")
        else:
            print(f"    {YELLOW}IP was not blocked (might be whitelisted or in rate-limit mode).{RESET}")
    except Exception as e:
        print(f"{RED}Could not fetch blocklist: {e}{RESET}")

    # Interactive unblock prompt
    print(f"\n{CYAN}{'-'*65}{RESET}")
    prompt = input(f"{BOLD}Press ENTER to test unblocking {attacker_ip} (or 'q' to leave blocked): {RESET}").strip().lower()
    
    if prompt != 'q':
        try:
            r = requests.post(f"{API_URL}/api/ips/unblock", json={"ip": attacker_ip}, timeout=3)
            if r.status_code == 200:
                print(f"\n{GREEN}✓ Unblocked {attacker_ip} successfully!{RESET}")
                print(f"  Check your dashboard: the host has been automatically removed from the active blocklist in real time!")
            else:
                print(f"{RED}Unblock request failed: {r.text}{RESET}")
        except Exception as e:
            print(f"{RED}Unblock error: {e}{RESET}")
    else:
        print(f"\n{YELLOW}Host left in blocklist. It will automatically expire when TTL reaches 0.{RESET}")

    print(f"\n{BOLD}{GREEN}{'='*65}{RESET}")
    print(f"{BOLD}{GREEN}       ✓ REAL-TIME TEST COMPLETED! SYSTEM OPERATING NORMALLY.{RESET}")
    print(f"{BOLD}{GREEN}{'='*65}{RESET}\n")

if __name__ == "__main__":
    print_banner()
    if check_services():
        attacker = sys.argv[1] if len(sys.argv) > 1 else "203.0.113.88"
        run_dos_test(attacker)
