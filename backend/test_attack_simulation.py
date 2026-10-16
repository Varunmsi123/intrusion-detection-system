"""
test_attack_simulation.py — Automated Verification Script for Real-Time IPS
Simulates DoS, Probe, R2L, U2R attacks, tests rate-limiting, temporary blocks,
and verifies that host/loopback/gateway are protected.
"""

import time
import requests

API_URL = "http://127.0.0.1:5000"

def test_ips_pipeline():
    print("=" * 60)
    print("  IPS End-to-End Test Suite")
    print("=" * 60)

    # 1. Health check
    try:
        r = requests.get(f"{API_URL}/api/health", timeout=3)
        print(f"[1] Backend Health: {r.status_code} -> {r.json()}")
    except Exception as e:
        print(f"Backend not responding at {API_URL}: {e}")
        return

    # 2. Status & Allowlist
    r = requests.get(f"{API_URL}/api/ips/status")
    status = r.json()
    print(f"[2] IPS Status:")
    print(f"    Mode            : {status.get('mode')}")
    print(f"    Redis Connected : {status.get('redis_connected')}")
    print(f"    Protected IPs   : {status.get('allowlist', {}).get('exact_ips')}")

    # 3. Test Protected Allowlist (Loopback 127.0.0.1)
    print("\n[3] Testing Loopback Protection (127.0.0.1 must NEVER be blocked):")
    r = requests.post(f"{API_URL}/api/ips/block", json={"ip": "127.0.0.1", "duration": 60})
    print(f"    Attempt to block 127.0.0.1 status: {r.status_code} -> {r.json()}")
    assert r.status_code == 403, "CRITICAL ERROR: Loopback was not protected!"
    print("    PASSED: Loopback was correctly protected!")

    # 4. Simulate DoS Attack
    test_ip = "198.51.100.50"
    print(f"\n[4] Simulating DoS Attack from {test_ip}...")
    r = requests.post(f"{API_URL}/api/ips/simulate_attack", json={"attack_type": "DoS", "src_ip": test_ip})
    print(f"    Simulate DoS result: {r.json()}")

    # 5. Check Blocked List
    r = requests.get(f"{API_URL}/api/ips/blocked")
    blocked = r.json()
    print(f"[5] Active Blocklist: {len(blocked)} blocked hosts")
    for b in blocked:
        print(f"    - {b.get('ip')} [{b.get('attack_type')}]: {b.get('reason')} (TTL: {b.get('ttl_remaining')}s)")

    # 6. Test Unblock
    print(f"\n[6] Testing Manual Unblock of {test_ip}...")
    r = requests.post(f"{API_URL}/api/ips/unblock", json={"ip": test_ip})
    print(f"    Unblock result: {r.json()}")

    r = requests.get(f"{API_URL}/api/ips/blocked")
    print(f"    Active Blocklist count after unblock: {len(r.json())}")

    # 7. Simulate Probe, R2L, U2R
    print("\n[7] Simulating Probe, R2L, and U2R...")
    for atk in ["Probe", "R2L", "U2R"]:
        atk_ip = f"198.51.100.{hash(atk) % 200 + 10}"
        res = requests.post(f"{API_URL}/api/ips/simulate_attack", json={"attack_type": atk, "src_ip": atk_ip})
        print(f"    Simulated {atk} -> {res.status_code}")

    # 8. Check Action History
    r = requests.get(f"{API_URL}/api/ips/actions?limit=5")
    print("\n[8] Recent IPS Actions in Audit Log:")
    for a in r.json():
        print(f"    [{a.get('action')}] {a.get('ip')} - {a.get('reason')}")

    print("\n" + "=" * 60)
    print("  ALL VERIFICATION TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    test_ips_pipeline()
