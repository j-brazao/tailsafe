"""Firewall backends.

To add a backend, subclass :class:`Firewall` and register it in ``BACKENDS``.
"""

from __future__ import annotations

from tailsafe.config import FirewallConfig
from tailsafe.firewall.base import CommandRunner, Firewall, FirewallError, Rule, managed_rule
from tailsafe.firewall.ufw import UfwFirewall

BACKENDS: dict[str, type[Firewall]] = {
    UfwFirewall.name: UfwFirewall,
}


def get_firewall(cfg: FirewallConfig, runner: CommandRunner) -> Firewall:
    try:
        cls = BACKENDS[cfg.type]
    except KeyError:
        raise FirewallError(
            f"unsupported firewall type {cfg.type!r}; available: {', '.join(sorted(BACKENDS))}"
        ) from None
    return cls(runner, cfg.options)


__all__ = ["BACKENDS", "CommandRunner", "Firewall", "FirewallError", "Rule", "get_firewall", "managed_rule"]
