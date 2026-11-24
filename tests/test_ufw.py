import unittest

from tailsafe.firewall.base import CommandRunner, Rule, managed_rule
from tailsafe.firewall.ufw import UfwFirewall, parse_rule

SHOW_ADDED = """\
Added user rules (see 'ufw status' for running firewall):
ufw allow 80/tcp
ufw allow ssh comment 'admin access'
ufw limit 2222/tcp
ufw allow from 203.0.113.0/24 to any port 22 proto tcp comment 'tailsafe:office'
ufw allow from 198.51.100.7 to any port 22 proto tcp comment 'tailsafe:home'
ufw allow from 2001:db8::/32 to any port 22 proto tcp comment 'tailsafe:office'
ufw allow in on eth0 to any port 22
ufw deny from 10.0.0.0/8
ufw allow OpenSSH
"""


class FakeRunner(CommandRunner):
    def __init__(self, outputs):
        super().__init__()
        self.outputs = outputs
        self.calls = []

    def run(self, args, mutating=False):
        self.calls.append(args)
        return self.outputs.get(tuple(args[1:]), "")


class ParseTest(unittest.TestCase):
    def test_managed_rule(self):
        rule = parse_rule("ufw allow from 203.0.113.0/24 to any port 22 proto tcp comment 'tailsafe:office'")
        self.assertEqual(rule, managed_rule("203.0.113.0/24", 22, "office"))

    def test_host_source_normalized(self):
        rule = parse_rule("ufw allow from 198.51.100.7 to any port 22 proto tcp comment 'tailsafe:home'")
        self.assertEqual(rule.source, "198.51.100.7/32")

    def test_simple_and_service_rules(self):
        self.assertEqual(parse_rule("ufw allow 80/tcp"), Rule("any", ((80, 80),), "tcp"))
        self.assertEqual(parse_rule("ufw allow ssh comment 'x'"), Rule("any", ((22, 22),), "any"))
        self.assertEqual(parse_rule("ufw allow 1000:2000/udp"), Rule("any", ((1000, 2000),), "udp"))

    def test_all_ports_from_source(self):
        rule = parse_rule("ufw allow from 10.0.0.0/8")
        self.assertEqual(rule, Rule("10.0.0.0/8", ((1, 65535),), "any"))

    def test_unparseable_rules_ignored(self):
        for line in (
            "ufw deny from 10.0.0.0/8",
            "ufw allow OpenSSH",
            "ufw allow in on eth0 to any port 22",
            "ufw allow out 53",
            "ufw allow from 1.2.3.4 port 999 to any port 22",
            "ufw allow from 1.2.3.4 to 10.0.0.1 port 22",
            "Added user rules (see 'ufw status' for running firewall):",
            "(None)",
        ):
            self.assertIsNone(parse_rule(line), line)

    def test_foreign_rule_with_tailsafe_comment_not_managed(self):
        rule = parse_rule("ufw allow 22/tcp comment 'tailsafe:office'")
        self.assertIsNotNone(rule)
        self.assertFalse(rule.managed)


class UfwFirewallTest(unittest.TestCase):
    def test_list_and_managed(self):
        fw = UfwFirewall(FakeRunner({("show", "added"): SHOW_ADDED}))
        managed = fw.managed_rules()
        self.assertEqual(
            managed,
            {
                managed_rule("203.0.113.0/24", 22, "office"),
                managed_rule("198.51.100.7", 22, "home"),
                managed_rule("2001:db8::/32", 22, "office"),
            },
        )
        self.assertEqual(len(fw.list_rules()), 6)

    def test_commands(self):
        runner = FakeRunner({})
        fw = UfwFirewall(runner)
        rule = managed_rule("198.51.100.7", 22, "home")
        fw.add_rule(rule)
        fw.delete_rule(rule)
        self.assertEqual(runner.calls, [
            ["ufw", "allow", "from", "198.51.100.7", "to", "any", "port", "22", "proto", "tcp",
             "comment", "tailsafe:home"],
            ["ufw", "--force", "delete", "allow", "from", "198.51.100.7", "to", "any", "port", "22",
             "proto", "tcp"],
        ])

    def test_prepend_option(self):
        runner = FakeRunner({})
        UfwFirewall(runner, {"position": "prepend"}).add_rule(managed_rule("10.0.0.0/8", 22, "lan"))
        self.assertEqual(runner.calls[0][:3], ["ufw", "prepend", "allow"])

    def test_refuses_unmanaged(self):
        fw = UfwFirewall(FakeRunner({}))
        with self.assertRaises(Exception):
            fw.delete_rule(Rule("any", ((22, 22),), "tcp"))

    def test_is_active(self):
        self.assertTrue(UfwFirewall(FakeRunner({("status",): "Status: active\n"})).is_active())
        self.assertFalse(UfwFirewall(FakeRunner({("status",): "Status: inactive\n"})).is_active())


if __name__ == "__main__":
    unittest.main()
