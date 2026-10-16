"""
test_policy_engine.py — Unit Tests for IPS Policy Engine & Protection
"""

import unittest
from ips.allowlist import allowlist
from ips.redis_store import redis_store
from ips.firewall import firewall
from ips.policy_engine import policy_engine

class TestIPSPolicyEngine(unittest.TestCase):
    def setUp(self):
        redis_store.clear_all_blocks()
        firewall.set_mode("simulate")

    def tearDown(self):
        redis_store.clear_all_blocks()

    def test_allow_normal_traffic(self):
        decision = policy_engine.evaluate(
            src_ip="203.0.113.10",
            dst_ip="192.168.31.129",
            dst_port=80,
            proto="tcp",
            service="http",
            label="Normal",
            confidence=0.99
        )
        self.assertEqual(decision["action"], "ALLOW")
        self.assertFalse(redis_store.is_blocked("203.0.113.10"))

    def test_never_block_allowlisted_loopback_or_gateway(self):
        # Even with 100% confidence DoS, loopback MUST NOT be blocked!
        decision = policy_engine.evaluate(
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            dst_port=80,
            proto="tcp",
            service="http",
            label="DoS",
            confidence=1.00
        )
        self.assertEqual(decision["action"], "ALLOW")
        self.assertIn("protected allowlist", decision["reason"])
        self.assertFalse(redis_store.is_blocked("127.0.0.1"))

    def test_low_confidence_suppression(self):
        decision = policy_engine.evaluate(
            src_ip="203.0.113.20",
            dst_ip="192.168.31.129",
            dst_port=80,
            proto="tcp",
            service="http",
            label="DoS",
            confidence=0.45
        )
        self.assertEqual(decision["action"], "ALLOW")
        self.assertIn("below threshold", decision["reason"])

    def test_block_high_confidence_dos(self):
        ip = "198.51.100.99"
        decision = policy_engine.evaluate(
            src_ip=ip,
            dst_ip="192.168.31.129",
            dst_port=80,
            proto="tcp",
            service="http",
            label="DoS",
            confidence=0.95
        )
        self.assertEqual(decision["action"], "BLOCK")
        self.assertTrue(decision["duration"] > 0)
        self.assertTrue(redis_store.is_blocked(ip))

        # Subsequent packets from this IP must be DROPPED
        drop_decision = policy_engine.evaluate(
            src_ip=ip,
            dst_ip="192.168.31.129",
            dst_port=80,
            proto="tcp",
            service="http",
            label="DoS",
            confidence=0.95
        )
        self.assertEqual(drop_decision["action"], "DROP")

    def test_manual_unblock(self):
        ip = "198.51.100.88"
        policy_engine.evaluate(
            src_ip=ip,
            dst_ip="192.168.31.129",
            dst_port=80,
            proto="tcp",
            service="http",
            label="DoS",
            confidence=0.95
        )
        self.assertTrue(redis_store.is_blocked(ip))

        # Manual unblock
        redis_store.unblock_ip(ip)
        firewall.unblock_ip(ip)
        self.assertFalse(redis_store.is_blocked(ip))

    def test_probe_port_scan_detection(self):
        ip = "198.51.100.77"
        # Simulate accessing 6 distinct ports
        for port in [21, 22, 23, 25, 80, 443]:
            redis_store.record_packet(ip, port)

        decision = policy_engine.evaluate(
            src_ip=ip,
            dst_ip="192.168.31.129",
            dst_port=8080,
            proto="tcp",
            service="http",
            label="Probe",
            confidence=0.88
        )
        self.assertEqual(decision["action"], "BLOCK")
        self.assertTrue(redis_store.is_blocked(ip))

if __name__ == "__main__":
    unittest.main()
