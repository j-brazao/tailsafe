import ipaddress
import unittest

from tailsafe.config import parse_config
from tailsafe.engine import Action, plan_open
from tailsafe.engine import run_once as _run_once
from tailsafe.firewall.base import Firewall, Rule, managed_rule
from tailsafe.sources import ResolveError
from tailsafe.state import State


class FakeFirewall(Firewall):
    name = "fake"

    def __init__(self, rules=()):
        super().__init__(runner=None)
        self.rules = list(rules)

    def is_active(self):
        return True

    def list_rules(self):
        return list(self.rules)

    def add_rule(self, rule):
        self.rules.append(rule)

    def delete_rule(self, rule):
        self.rules.remove(rule)


class FakeChecker:
    def __init__(self, connected):
        self.connected = connected

    def is_connected(self):
        return self.connected


def config(**check):
    return parse_config({
        "check": {"failure_threshold": 2, "recovery_threshold": 1, **check},
        "state_file": "/nonexistent/state.json",
        "sources": [
            {"name": "office", "type": "cidr", "value": "203.0.113.0/24"},
            {"name": "home", "type": "dns", "value": "home.example.com"},
        ],
    })


class FakeResolver:
    def __init__(self, home):
        self.home = home

    def __call__(self, src):
        if src.type == "cidr":
            return [ipaddress.ip_network(src.value)]
        if self.home is None:
            raise ResolveError("lookup failed")
        return [ipaddress.ip_network(a) for a in self.home]


class PlanTest(unittest.TestCase):
    def test_open_from_scratch(self):
        plan = plan_open(config(), [], FakeResolver(["198.51.100.7"]))
        self.assertEqual(plan.add, sorted([
            managed_rule("203.0.113.0/24", 22, "office"),
            managed_rule("198.51.100.7", 22, "home"),
        ]))
        self.assertEqual(plan.delete, [])

    def test_dns_change_replaces_rule(self):
        old = managed_rule("198.51.100.7", 22, "home")
        office = managed_rule("203.0.113.0/24", 22, "office")
        plan = plan_open(config(), [old, office], FakeResolver(["198.51.100.8"]))
        self.assertEqual(plan.add, [managed_rule("198.51.100.8", 22, "home")])
        self.assertEqual(plan.delete, [old])

    def test_dns_failure_keeps_existing(self):
        old = managed_rule("198.51.100.7", 22, "home")
        plan = plan_open(config(), [old], FakeResolver(None))
        self.assertEqual(plan.add, [managed_rule("203.0.113.0/24", 22, "office")])
        self.assertEqual(plan.delete, [])

    def test_existing_unmanaged_rule_is_not_touched(self):
        existing = Rule("203.0.0.0/16", ((22, 22),), "tcp")
        plan = plan_open(config(), [existing], FakeResolver(["198.51.100.7"]))
        self.assertEqual(plan.add, [managed_rule("198.51.100.7", 22, "home")])
        self.assertEqual(plan.covered, [managed_rule("203.0.113.0/24", 22, "office")])

    def test_open_ssh_to_world_covers_everything(self):
        plan = plan_open(config(), [Rule("any", ((22, 22),), "any")], FakeResolver(["198.51.100.7"]))
        self.assertTrue(plan.empty)
        self.assertEqual(len(plan.covered), 2)


def run_once(cfg, state, checker, fw):
    return _run_once(cfg, state, checker, fw, FakeResolver(["198.51.100.7"]))


class RunOnceTest(unittest.TestCase):
    def test_full_cycle_restores_original_rules(self):
        cfg = config()
        original = [Rule("any", ((80, 80),), "tcp"), Rule("10.0.0.0/8", ((443, 443),), "tcp")]
        fw = FakeFirewall(original)
        state = State()
        down, up = FakeChecker(False), FakeChecker(True)

        self.assertEqual(run_once(cfg, state, down, fw), Action.HOLD)
        self.assertEqual(fw.rules, original)

        self.assertEqual(run_once(cfg, state, down, fw), Action.OPEN)
        self.assertEqual(len(fw.managed_rules()), 2)
        self.assertIsNotNone(state.opened_at)

        self.assertEqual(run_once(cfg, state, down, fw), Action.OPEN)  # idempotent
        self.assertEqual(len(fw.managed_rules()), 2)

        self.assertEqual(run_once(cfg, state, up, fw), Action.RESTORE)
        self.assertEqual(fw.rules, original)
        self.assertIsNone(state.opened_at)

    def test_recovery_threshold(self):
        cfg = config(recovery_threshold=2)
        fw = FakeFirewall()
        state = State()
        for _ in range(2):
            run_once(cfg, state, FakeChecker(False), fw)
        self.assertEqual(run_once(cfg, state, FakeChecker(True), fw), Action.HOLD)
        self.assertEqual(len(fw.managed_rules()), 2)
        self.assertEqual(run_once(cfg, state, FakeChecker(True), fw), Action.RESTORE)
        self.assertEqual(fw.rules, [])

    def test_failed_dns_rule_addition_keeps_old_fallback_until_retry(self):
        old = managed_rule("198.51.100.7", 22, "home")
        new = managed_rule("198.51.100.8", 22, "home")

        class FailingAddFirewall(FakeFirewall):
            fail_add = True

            def add_rule(self, rule):
                if self.fail_add and rule == new:
                    raise RuntimeError("simulated firewall add failure")
                super().add_rule(rule)

        fw = FailingAddFirewall([old])
        state = State(consecutive_failures=1, last_connected=False, opened_at=1)
        with self.assertRaisesRegex(RuntimeError, "firewall operation"):
            _run_once(config(), state, FakeChecker(False), fw, FakeResolver(["198.51.100.8"]))
        self.assertIn(old, fw.rules)
        self.assertNotIn(new, fw.rules)
        self.assertIn(managed_rule("203.0.113.0/24", 22, "office"), fw.rules)

        fw.fail_add = False
        self.assertEqual(
            _run_once(config(), state, FakeChecker(False), fw, FakeResolver(["198.51.100.8"])),
            Action.OPEN,
        )
        self.assertIn(new, fw.rules)
        self.assertNotIn(old, fw.rules)


if __name__ == "__main__":
    unittest.main()
