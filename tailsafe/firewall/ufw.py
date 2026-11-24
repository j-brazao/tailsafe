"""ufw backend.

Managed rules are created with a ``comment 'tailsafe:<source>'`` and read
back from ``ufw show added``, which prints user rules in CLI syntax, e.g.::

    Added user rules (see 'ufw status' for running firewall):
    ufw allow 22/tcp
    ufw allow from 203.0.113.0/24 to any port 22 proto tcp comment 'tailsafe:office'
"""

from __future__ import annotations

import ipaddress
import logging
import shlex
import socket

from tailsafe.firewall.base import ANY, TAG_PREFIX, Firewall, FirewallError, Rule, normalize_source

log = logging.getLogger(__name__)

_ALLOW_ACTIONS = ("allow", "limit")
_PROTOS = ("tcp", "udp")


def _port_number(value: str) -> int:
    if value.isdigit():
        return int(value)
    try:
        return socket.getservbyname(value)
    except OSError:
        raise ValueError(f"unknown service {value!r}") from None


def _parse_ports(spec: str) -> tuple[tuple[int, int], ...]:
    ranges = []
    for part in spec.split(","):
        low, _, high = part.partition(":")
        ranges.append((_port_number(low), _port_number(high or low)))
    return tuple(ranges)


def parse_rule(line: str) -> Rule | None:
    """Parse one ``ufw show added`` line into an inbound allow Rule, or None.

    Rules that can't be interpreted (app profiles, outbound, interface-bound,
    routed, deny, ...) return None: they are neither managed by tailsafe nor
    used to decide whether access is already allowed.
    """
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    if not tokens or tokens[0] != "ufw":
        return None
    tokens = tokens[1:]
    if not tokens or tokens[0] not in _ALLOW_ACTIONS:
        return None
    tokens = tokens[1:]
    if tokens and tokens[0] == "in":
        tokens = tokens[1:]
    if not tokens or tokens[0] in ("out", "on"):
        return None

    fields: dict[str, str] = {}
    if tokens[0] not in ("from", "to", "proto"):
        # Simple syntax: "ufw allow 22/tcp [comment '...']"
        port, _, proto = tokens[0].partition("/")
        fields["port"] = port
        if proto:
            fields["proto"] = proto
        tokens = tokens[1:]
        if tokens and tokens[0] != "comment":
            return None
    try:
        it = iter(tokens)
        for key in it:
            if key not in ("from", "to", "port", "proto", "comment"):
                return None
            if key == "port" and "to" not in fields:
                key = "from_port"
            fields[key] = next(it)
    except StopIteration:
        return None

    if "from_port" in fields or fields.get("to", ANY) != ANY:
        return None
    proto = fields.get("proto", ANY)
    if proto not in _PROTOS and proto != ANY:
        return None
    comment = fields.get("comment", "")
    tag = comment[len(TAG_PREFIX):] if comment.startswith(TAG_PREFIX) else None
    try:
        source = normalize_source(fields.get("from", ANY))
        ports = _parse_ports(fields["port"]) if "port" in fields else ((1, 65535),)
    except ValueError:
        return None
    if tag is not None and (source == ANY or len(ports) != 1 or ports[0][0] != ports[0][1]):
        # tailsafe never creates rules of this shape; leave it alone.
        tag = None
    return Rule(source=source, ports=ports, proto=proto, tag=tag)


def _ufw_source(source: str) -> str:
    net = ipaddress.ip_network(source)
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


class UfwFirewall(Firewall):
    name = "ufw"

    @property
    def binary(self) -> str:
        return str(self.options.get("binary", "ufw"))

    def _rule_spec(self, rule: Rule) -> list[str]:
        if not rule.managed or rule.source == ANY:
            raise FirewallError(f"refusing to manipulate unmanaged rule {rule}")
        return [
            "allow", "from", _ufw_source(rule.source),
            "to", "any", "port", str(rule.port), "proto", rule.proto,
        ]

    def is_active(self) -> bool:
        out = self.runner.run([self.binary, "status"])
        return any(line.strip().lower() == "status: active" for line in out.splitlines())

    def list_rules(self) -> list[Rule]:
        out = self.runner.run([self.binary, "show", "added"])
        rules = []
        for line in out.splitlines():
            rule = parse_rule(line.strip())
            if rule is not None:
                rules.append(rule)
        return rules

    def add_rule(self, rule: Rule) -> None:
        spec = self._rule_spec(rule)
        if self.options.get("position", "append") == "prepend":
            spec = ["prepend", *spec]
        self.runner.run([self.binary, *spec, "comment", TAG_PREFIX + rule.tag], mutating=True)

    def delete_rule(self, rule: Rule) -> None:
        self.runner.run([self.binary, "--force", "delete", *self._rule_spec(rule)], mutating=True)
