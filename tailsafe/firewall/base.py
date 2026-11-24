"""Firewall backend interface.

Every backend manages rules tagged as belonging to tailsafe. Restoring the
original firewall means deleting exactly those tagged rules, so backends must
be able to tell managed rules apart from rules the administrator created.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass

log = logging.getLogger(__name__)

TAG_PREFIX = "tailsafe:"
ANY = "any"


class FirewallError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class Rule:
    """An inbound allow rule.

    ``source`` is a normalized network string (e.g. ``203.0.113.0/24``) or
    ``"any"``. ``ports`` is a tuple of inclusive (low, high) ranges. ``tag`` is
    the tailsafe source name for managed rules and ``None`` for rules owned by
    someone else.
    """

    source: str
    ports: tuple[tuple[int, int], ...]
    proto: str  # "tcp", "udp" or "any"
    tag: str | None = None

    @property
    def managed(self) -> bool:
        return self.tag is not None

    @property
    def port(self) -> int:
        """The single port of a managed rule."""
        (low, high), = self.ports
        assert low == high
        return low

    def covers(self, other: Rule) -> bool:
        """True if this rule already allows all traffic ``other`` would allow."""
        if self.proto != ANY and self.proto != other.proto:
            return False
        if not all(any(lo <= olo and ohi <= hi for lo, hi in self.ports) for olo, ohi in other.ports):
            return False
        if self.source == ANY:
            return True
        if other.source == ANY:
            return False
        mine = ipaddress.ip_network(self.source)
        theirs = ipaddress.ip_network(other.source)
        return mine.version == theirs.version and theirs.subnet_of(mine)


def normalize_source(value: str) -> str:
    if value == ANY:
        return ANY
    return str(ipaddress.ip_network(value, strict=False))


def managed_rule(source: str, port: int, tag: str, proto: str = "tcp") -> Rule:
    return Rule(source=normalize_source(source), ports=((port, port),), proto=proto, tag=tag)


class CommandRunner:
    """Runs firewall commands. In dry-run mode mutating commands are only logged."""

    def __init__(self, dry_run: bool = False, timeout: float = 30.0):
        self.dry_run = dry_run
        self.timeout = timeout

    def run(self, args: list[str], mutating: bool = False) -> str:
        if mutating and self.dry_run:
            log.info("[dry-run] would run: %s", " ".join(args))
            return ""
        log.debug("running: %s", " ".join(args))
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(f"failed to run {args[0]}: {exc}") from exc
        if proc.returncode != 0:
            raise FirewallError(
                f"command {' '.join(args)!r} exited {proc.returncode}: "
                f"{(proc.stderr or proc.stdout).strip()}"
            )
        return proc.stdout


class Firewall(ABC):
    """Base class for firewall backends. Register new backends in ``tailsafe.firewall``."""

    name: str = ""

    def __init__(self, runner: CommandRunner, options: dict | None = None):
        self.runner = runner
        self.options = options or {}

    @abstractmethod
    def is_active(self) -> bool:
        """Whether the firewall is currently enforcing rules."""

    @abstractmethod
    def list_rules(self) -> list[Rule]:
        """All inbound allow rules that can be parsed, managed or not."""

    @abstractmethod
    def add_rule(self, rule: Rule) -> None:
        """Add a managed rule (``rule.tag`` is set)."""

    @abstractmethod
    def delete_rule(self, rule: Rule) -> None:
        """Delete a managed rule previously returned by ``list_rules``."""

    def managed_rules(self) -> set[Rule]:
        return {r for r in self.list_rules() if r.managed}
