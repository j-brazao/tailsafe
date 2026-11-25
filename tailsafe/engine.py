"""Decide whether SSH fallback should be open and reconcile the firewall."""

from __future__ import annotations

import enum
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from tailsafe.config import Config, SourceConfig
from tailsafe.firewall import Firewall, Rule, managed_rule
from tailsafe.sources import Network, ResolveError, resolve_source
from tailsafe.state import State

log = logging.getLogger(__name__)


class Checker(Protocol):
    def is_connected(self) -> bool: ...


class Action(enum.Enum):
    OPEN = "open"        # Tailscale is down: ensure SSH fallback rules exist
    RESTORE = "restore"  # Tailscale is up: remove all tailsafe rules
    HOLD = "hold"        # Threshold not reached yet: leave the firewall as is


@dataclass
class Plan:
    add: list[Rule] = field(default_factory=list)
    delete: list[Rule] = field(default_factory=list)
    # Desired rules skipped because an existing unmanaged rule already allows them.
    covered: list[Rule] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.add and not self.delete


def decide(cfg: Config, state: State) -> Action:
    if state.last_connected is False and state.consecutive_failures >= cfg.failure_threshold:
        return Action.OPEN
    if state.last_connected and state.consecutive_successes >= cfg.recovery_threshold:
        return Action.RESTORE
    return Action.HOLD


def plan_open(
    cfg: Config,
    rules: list[Rule],
    resolve: Callable[[SourceConfig], list[Network]] = resolve_source,
) -> Plan:
    managed = {r for r in rules if r.managed}
    unmanaged = [r for r in rules if not r.managed]
    desired: set[Rule] = set()
    plan = Plan()

    for src in cfg.sources:
        try:
            nets = resolve(src)
        except ResolveError as exc:
            # Don't drop working access just because a lookup failed this time.
            kept = {r for r in managed if r.tag == src.name}
            log.warning("%s; keeping %d existing rule(s) for this source", exc, len(kept))
            desired |= kept
            continue
        for net in nets:
            rule = managed_rule(str(net), cfg.ssh_port, src.name)
            if any(u.covers(rule) for u in unmanaged):
                plan.covered.append(rule)
            else:
                desired.add(rule)

    plan.add = sorted(desired - managed)
    plan.delete = sorted(managed - desired)
    return plan


def plan_restore(rules: list[Rule]) -> Plan:
    return Plan(delete=sorted(r for r in rules if r.managed))


def apply(firewall: Firewall, plan: Plan) -> None:
    # Add before deleting so a changed DNS address never leaves a gap.
    errors = []
    for rule in plan.add:
        log.info("allowing ssh from %s (%s)", rule.source, rule.tag)
        try:
            firewall.add_rule(rule)
        except Exception as exc:  # keep going so other sources still get access
            log.error("failed to add %s: %s", rule, exc)
            errors.append(exc)
    if errors:
        # Keep every existing fallback rule until all replacements are in place.
        # Successful additions remain, and the next check will retry the rest.
        if plan.delete:
            log.warning("skipping %d rule deletion(s) after failed addition", len(plan.delete))
        raise RuntimeError(f"{len(errors)} firewall operation(s) failed")
    for rule in plan.delete:
        log.info("removing ssh rule for %s (%s)", rule.source, rule.tag)
        try:
            firewall.delete_rule(rule)
        except Exception as exc:
            log.error("failed to delete %s: %s", rule, exc)
            errors.append(exc)
    if errors:
        raise RuntimeError(f"{len(errors)} firewall operation(s) failed")


def run_once(
    cfg: Config,
    state: State,
    checker: Checker,
    firewall: Firewall,
    resolve: Callable[[SourceConfig], list[Network]] = resolve_source,
) -> Action:
    """One check/reconcile cycle. Mutates ``state``; the caller persists it."""
    connected = checker.is_connected()
    state.record(connected)
    action = decide(cfg, state)
    log.debug(
        "connected=%s failures=%d successes=%d action=%s",
        connected, state.consecutive_failures, state.consecutive_successes, action.value,
    )
    if action is Action.HOLD:
        return action

    rules = firewall.list_rules()
    if action is Action.OPEN:
        if state.opened_at is None:
            log.warning("tailscale down for %d check(s); opening ssh fallback", state.consecutive_failures)
            if not firewall.is_active():
                log.warning("%s is not active; rules are added but not enforced", firewall.name)
        plan = plan_open(cfg, rules, resolve)
        for rule in plan.covered:
            log.debug("ssh from %s already allowed by an existing rule", rule.source)
    else:
        plan = plan_restore(rules)
        if not plan.empty:
            log.info("tailscale is back; restoring original firewall rules")

    if not plan.empty:
        apply(firewall, plan)
    if action is Action.OPEN:
        state.opened_at = state.opened_at or time.time()
    else:
        state.opened_at = None
    return action
