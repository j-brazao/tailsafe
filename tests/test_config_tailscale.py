import unittest

from tailsafe.config import ConfigError, TailscaleConfig, parse_config
from tailsafe.tailscale import TailscaleChecker

SRC = [{"name": "lan", "type": "cidr", "value": "10.0.0.0/8"}]


class ConfigTest(unittest.TestCase):
    def test_defaults(self):
        cfg = parse_config({"sources": SRC})
        self.assertEqual(cfg.firewall.type, "ufw")
        self.assertEqual(cfg.ssh_port, 22)

    def test_firewall_options(self):
        cfg = parse_config({"sources": SRC, "firewall": {"type": "ufw", "position": "prepend"}})
        self.assertEqual(cfg.firewall.options, {"position": "prepend"})

    def test_invalid(self):
        for data in (
            {},
            {"sources": [{"name": "x", "type": "cidr", "value": "nope"}]},
            {"sources": [{"name": "bad name", "type": "cidr", "value": "10.0.0.0/8"}]},
            {"sources": [{"name": "x", "type": "ftp", "value": "a"}]},
            {"sources": SRC * 2},
            {"sources": SRC, "ssh": {"port": 70000}},
        ):
            with self.assertRaises(ConfigError, msg=data):
                parse_config(data)


class TailscaleTest(unittest.TestCase):
    def test_evaluate(self):
        checker = TailscaleChecker(TailscaleConfig())
        self.assertTrue(checker.evaluate({"BackendState": "Running", "Self": {"Online": True}}))
        self.assertFalse(checker.evaluate({"BackendState": "Running", "Self": {"Online": False}}))
        self.assertFalse(checker.evaluate({"BackendState": "Stopped"}))
        self.assertFalse(checker.evaluate({"BackendState": "NeedsLogin"}))
        lax = TailscaleChecker(TailscaleConfig(require_online=False))
        self.assertTrue(lax.evaluate({"BackendState": "Running", "Self": {"Online": False}}))

    def test_missing_binary(self):
        self.assertFalse(TailscaleChecker(TailscaleConfig(binary="/nonexistent/tailscale")).is_connected())


if __name__ == "__main__":
    unittest.main()
